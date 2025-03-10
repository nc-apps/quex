use std::sync::Arc;

use libsql::{named_params, params::IntoParams, Builder, Database as LibsqlDatabase};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::survey::{
    attrakdiff, format_date, net_promoter_score,
    system_usability_score::{self, Response2, Score},
    FormatDateError, Survey, Surveys,
};

#[derive(thiserror::Error, Debug)]
#[error("Error creating database: {0}")]
pub(crate) struct CreateError(#[from] libsql::Error);

#[derive(thiserror::Error, Debug)]
pub(crate) enum InitializationError {
    #[error("Error creating databse: {0}")]
    Create(#[from] CreateError),
    #[error("Error connecting to database: {0}")]
    Connection(libsql::Error),
    #[error("Error executing create tables batch query: {0}")]
    CreateTables(libsql::Error),
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum StatementError {
    #[error("Error connecting to database: {0}")]
    Connection(libsql::Error),
    #[error("Error preparing statement: {0}")]
    Prepare(libsql::Error),
    #[error("Error exectuing statement: {0}")]
    Execute(libsql::Error),
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum SingleRowQueryError {
    #[error("Error running statement: {0}")]
    StatementError(#[from] StatementError),
    #[error("Error reading value from row: {0}")]
    RowError(libsql::Error),
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum MultiRowQueryError {
    #[error("Error running statement: {0}")]
    Statement(#[from] StatementError),
    #[error("Error getting next row: {0}")]
    NextRow(libsql::Error),
    #[error("Error reading value from row: {0}")]
    Row(libsql::Error),
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum GetUserSurveysError {
    #[error(transparent)]
    MultiRowQueryError(#[from] MultiRowQueryError),
    #[error("Error transforming date: {0}")]
    DateError(#[from] time::error::ComponentRange),
    #[error("Error formatting date")]
    FormatError(#[from] time::error::Format),
    #[error("Error formatting date for humans: {0}")]
    HumanReadableDateError(#[from] FormatDateError),
    #[error("Encountered unexpected unsupported survey type: {0}")]
    UnsupportedSurveyType(Arc<str>),
}

/// Survey type for a get/create surveys and create responses to a survey
#[derive(Deserialize, Debug)]
pub(crate) enum SurveyType {
    #[serde(rename = "ad")]
    Attrakdiff,
    #[serde(rename = "nps")]
    NetPromoterScore,
    #[serde(rename = "sus")]
    SystemUsabilityScore,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum GetSurveyError {
    #[error("Error running statement: {0}")]
    StatementError(#[from] StatementError),
    #[error("Error reading value from row: {0}")]
    RowError(#[from] SingleRowQueryError),
    #[error("Unexpected survey type: {0}")]
    UnexpectedSurveyType(Arc<str>),
}

/// A wrapper around the libsql database to hide the database and provide access to predefined queries
pub(crate) struct Database(LibsqlDatabase);

impl Database {
    async fn create(
        turso_database_url: String,
        turso_auth_token: String,
    ) -> Result<Database, CreateError> {
        let database = Builder::new_remote(turso_database_url, turso_auth_token)
            .build()
            .await?;

        Ok(Self(database))
    }

    /// Creates the database and initializes it with the tables
    pub(crate) async fn initialize(
        turso_database_url: String,
        turso_auth_token: String,
    ) -> Result<Database, InitializationError> {
        let database = Self::create(turso_database_url, turso_auth_token).await?;

        let connection = database
            .0
            .connect()
            .map_err(InitializationError::Connection)?;

        let query = include_str!("./create_tables.sql");
        connection
            .execute_batch(query)
            .await
            .map_err(InitializationError::CreateTables)?;

        tracing::debug!("Tables created");

        Ok(database)
    }

    async fn connect(&self) -> Result<libsql::Connection, StatementError> {
        self.0.connect().map_err(StatementError::Connection)
    }

    async fn insert(
        &self,
        sql: &'static str,
        parameters: impl IntoParams,
    ) -> Result<(), StatementError> {
        let connection = self.connect().await?;

        let mut statement = connection
            .prepare(sql)
            .await
            .map_err(StatementError::Prepare)?;

        statement
            .execute(parameters)
            .await
            .map_err(StatementError::Execute)?;

        Ok(())
    }

    async fn query_row(
        &self,
        sql: &'static str,
        parameters: impl IntoParams,
    ) -> Result<libsql::Row, StatementError> {
        let connection = self.connect().await?;
        let mut statement = connection
            .prepare(sql)
            .await
            .map_err(StatementError::Prepare)?;

        statement
            .query_row(parameters)
            .await
            .map_err(StatementError::Execute)
    }

    async fn query(
        &self,
        sql: &'static str,
        parameters: impl IntoParams,
    ) -> Result<libsql::Rows, StatementError> {
        let connection = self.connect().await?;
        let mut statement = connection
            .prepare(sql)
            .await
            .map_err(StatementError::Prepare)?;

        statement
            .query(parameters)
            .await
            .map_err(StatementError::Execute)
    }

    pub(crate) async fn insert_user(
        &self,
        user_id: &str,
        name: &str,
    ) -> Result<(), StatementError> {
        self.insert(
            "INSERT INTO users (id, name) VALUES (:id, :name)",
            named_params![
                ":id": user_id,
                ":name": name,
            ],
        )
        .await
    }

    pub(crate) async fn insert_google_account_connection(
        &self,
        user_id: &str,
        google_user_id: &str,
    ) -> Result<(), StatementError> {
        self.insert(
            "INSERT INTO google_account_connections (user_id, google_user_id) VALUES (:user_id, :google_user_id)",
            named_params![
                ":user_id": user_id,
                ":google_user_id": google_user_id,
            ],
        )
        .await
    }

    pub(crate) async fn get_user_id_by_google_user_id(
        &self,
        google_user_id: &str,
    ) -> Result<Option<Arc<str>>, SingleRowQueryError> {
        let connection = self.connect().await?;
        let mut statement = connection
            .prepare("SELECT user_id FROM google_account_connections WHERE google_user_id = :id")
            .await
            .map_err(StatementError::Prepare)?;

        let result = statement
            .query_row(named_params![":id": google_user_id])
            .await;

        match result.and_then(|row| row.get_str(0).map(Arc::from)) {
            Ok(user_id) => Ok(Some(user_id)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(SingleRowQueryError::RowError(error)),
        }
    }

    pub(crate) async fn insert_attrakdiff_survey(
        &self,
        survey_id: &str,
        user_id: &str,
        survey_name: &str,
        created_at_utc: i64,
    ) -> Result<(), StatementError> {
        self.insert(
            "INSERT INTO attrakdiff_surveys (\
            id,\
            user_id,\
            name,\
            created_at_utc\
            ) \
            VALUES (\
                :id,\
                :user_id,\
                :name,\
                :created_at_utc\
            )",
            named_params! {
                ":id": survey_id,
                ":user_id": user_id,
                ":name": survey_name,
                ":created_at_utc": created_at_utc
            },
        )
        .await
    }

    pub(crate) async fn insert_attrakdiff_response(
        &self,
        survey_id: &str,
        response_id: &str,
        created_at_utc: i64,
        response: attrakdiff::Response,
    ) -> Result<(), StatementError> {
        self.insert(
            "INSERT INTO attrakdiff_responses (
            id,
            survey_id,
            created_at_utc,
            answer_1,
            answer_2,
            answer_3,
            answer_4,
            answer_5,
            answer_6,
            answer_7,
            answer_8,
            answer_9,
            answer_10,
            answer_11,
            answer_12,
            answer_13,
            answer_14,
            answer_15,
            answer_16,
            answer_17,
            answer_18,
            answer_19,
            answer_20,
            answer_21,
            answer_22,
            answer_23,
            answer_24,
            answer_25,
            answer_26,
            answer_27,
            answer_28
        ) VALUES (
            ?1,
            ?2,
            ?3,
            ?4,
            ?5,
            ?6,
            ?7,
            ?8,
            ?9,
            ?10,
            ?11,
            ?12,
            ?13,
            ?14,
            ?15,
            ?16,
            ?17,
            ?18,
            ?19,
            ?20,
            ?21,
            ?22,
            ?23,
            ?24,
            ?25,
            ?26,
            ?27,
            ?28,
            ?29,
            ?30,
            ?31
        )",
            libsql::params![
                response_id,
                survey_id,
                created_at_utc,
                response.q1,
                response.q2,
                response.q3,
                response.q4,
                response.q5,
                response.q6,
                response.q7,
                response.q8,
                response.q9,
                response.q10,
                response.q11,
                response.q12,
                response.q13,
                response.q14,
                response.q15,
                response.q16,
                response.q17,
                response.q18,
                response.q19,
                response.q20,
                response.q21,
                response.q22,
                response.q23,
                response.q24,
                response.q25,
                response.q26,
                response.q27,
                response.q28,
            ],
        )
        .await
    }

    /// This implicitly checks if a user has access to a survey
    pub(crate) async fn get_attrakdiff_survey_name(
        &self,
        survey_id: &str,
        user_id: &str,
    ) -> Result<Option<Arc<str>>, SingleRowQueryError> {
        let connection = self.connect().await?;
        let mut statement = connection
            .prepare("SELECT name FROM attrakdiff_surveys WHERE id = :id AND user_id = :user_id")
            .await
            .map_err(StatementError::Prepare)?;

        let result = statement
            .query_row(named_params! {
                ":id": survey_id,
                ":user_id": user_id,
            })
            .await;

        match result.and_then(|row| row.get_str(0).map(Arc::from)) {
            Ok(name) => Ok(Some(name)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(SingleRowQueryError::RowError(error)),
        }
    }

    pub(crate) async fn get_attrakdiff_survey_responses(
        &self,
        survey_id: &str,
    ) -> Result<Vec<[i32; 28]>, MultiRowQueryError> {
        let mut rows = self
            .query(
                "SELECT * FROM attrakdiff_responses WHERE survey_id = :survey_id",
                named_params![":survey_id": survey_id],
            )
            .await?;

        let mut responses = Vec::new();

        while let Some(row) = rows.next().await.map_err(MultiRowQueryError::NextRow)? {
            let mut response = [0; 28];
            for index in 3u8..31 {
                let question_value = row
                    .get::<i32>(index.into())
                    .map_err(MultiRowQueryError::Row)?;

                response[usize::from(index - 3)] = question_value;
            }

            responses.push(response);
        }

        Ok(responses)
    }

    pub(crate) async fn get_user_surveys(
        &self,
        user_id: &str,
    ) -> Result<Surveys, GetUserSurveysError> {
        let mut rows = self
            .query(
                "SELECT type, id, name, created_at_utc FROM (
                    SELECT 'attrakdiff' as type, * FROM attrakdiff_surveys
                    UNION ALL
                    SELECT 'net promoter score' as type, * FROM net_promoter_score_surveys
                    UNION ALL
                    SELECT 'system usability score' as type, * FROM system_usability_score_surveys
                )
                    WHERE user_id = :user_id",
                named_params![":user_id": user_id],
            )
            .await
            .map_err(MultiRowQueryError::Statement)?;

        let mut surveys = Surveys::default();

        while let Some(row) = rows.next().await.map_err(MultiRowQueryError::NextRow)? {
            //TOOO use row deserialize functionality
            let survey_type = row.get_str(0).map_err(MultiRowQueryError::Row)?;
            let survey_id = row.get_str(1).map_err(MultiRowQueryError::Row)?;
            let survey_name = row.get_str(2).map_err(MultiRowQueryError::Row)?;
            let created_at_utc = row.get::<i64>(3).map_err(MultiRowQueryError::Row)?;
            let created_at_utc = OffsetDateTime::from_unix_timestamp(created_at_utc)?;
            // More information on the correct datetime format
            // - https://html.spec.whatwg.org/multipage/text-level-semantics.html#datetime-value
            // - https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#valid-local-date-and-time-string
            // ISO 8601 format should be fine though 🥴
            let machine_formatted_date =
                created_at_utc.format(&time::format_description::well_known::Iso8601::DEFAULT)?;

            let survey = Survey {
                id: survey_id.into(),
                name: survey_name.into(),
                //TODO add user timezone offset
                created_human_readable: format_date(created_at_utc)?,
                created_machine_readable: machine_formatted_date,
            };

            match survey_type {
                "attrakdiff" => surveys.attrakdiff.push(survey),
                "net promoter score" => surveys.net_promoter_score.push(survey),
                "system usability score" => surveys.system_usability_score.push(survey),
                other => {
                    return Err(GetUserSurveysError::UnsupportedSurveyType(Arc::from(other)));
                }
            }
        }

        Ok(surveys)
    }

    pub(crate) async fn get_survey_type(
        &self,
        survey_id: &str,
    ) -> Result<Option<SurveyType>, GetSurveyError> {
        //TODO possibly optimize this as we don't know the type of the survey from the path alone,
        // but also want the path to be easy to enter for users and don't reveal information that could
        // bias the responses like the survey type
        // This is a hot path as respondents will use this
        // Could maybe optimize this by filtering on each subquery but that needs to be measured first
        // maybe with EXPLAIN SQLite query plan if you understand how that works

        let result  =  self.query_row(
            "SELECT * FROM (
                            SELECT 'attrakdiff' as type, * FROM attrakdiff_surveys
                            UNION ALL
                            SELECT 'net promoter score' as type, * FROM net_promoter_score_surveys
                            UNION ALL
                            SELECT 'system usability score' as type, * FROM system_usability_score_surveys
                        )
                            WHERE id = :survey_id", named_params![":survey_id": survey_id]).await;

        let row = match result {
            Ok(row) => row,
            Err(StatementError::Execute(libsql::Error::QueryReturnedNoRows)) => return Ok(None),
            Err(error) => return Err(GetSurveyError::StatementError(error)),
        };

        let survey_type = row.get_str(0).map_err(SingleRowQueryError::RowError)?;
        match survey_type {
            "attrakdiff" => Ok(Some(SurveyType::Attrakdiff)),
            "net promoter score" => Ok(Some(SurveyType::NetPromoterScore)),
            "system usability score" => Ok(Some(SurveyType::SystemUsabilityScore)),
            other => Err(GetSurveyError::UnexpectedSurveyType(other.into())),
        }
    }

    pub(crate) async fn insert_net_promoter_score_survey(
        &self,
        survey_id: &str,
        user_id: &str,
        survey_name: &str,
        created_at_utc: i64,
    ) -> Result<(), StatementError> {
        self.insert(
            "INSERT INTO net_promoter_score_surveys (\
            id,\
            user_id,\
            name,\
            created_at_utc\
            ) \
            VALUES (\
                :id,\
                :user_id,\
                :name,\
                :created_at_utc\
            )",
            named_params! {
                ":id": survey_id,
                ":user_id": user_id,
                ":name": survey_name,
                ":created_at_utc": created_at_utc,
            },
        )
        .await
    }

    pub(crate) async fn insert_system_usability_score_survey(
        &self,
        survey_id: &str,
        user_id: &str,
        survey_name: &str,
        created_at_utc: i64,
    ) -> Result<(), StatementError> {
        self.insert(
            "INSERT INTO system_usability_score_surveys (\
                id,\
                user_id,\
                name,\
                created_at_utc\
                ) \
                VALUES (\
                    :id,\
                    :user_id,\
                    :name,\
                    :created_at_utc\
                )",
            named_params! {
                ":id": survey_id,
                ":user_id": user_id,
                ":name": survey_name,
                ":created_at_utc": created_at_utc,
            },
        )
        .await
    }

    pub(crate) async fn insert_net_promoter_score_response(
        &self,
        survey_id: &str,
        response_id: &str,
        created_at_utc: i64,
        response: net_promoter_score::Response,
    ) -> Result<(), StatementError> {
        self.insert(
            "INSERT INTO net_promoter_score_responses (
            id,
            survey_id,
            created_at_utc,
            answer_1,
            answer_2
        ) VALUES (
            ?1,
            ?2,
            ?3,
            ?4
        )",
            libsql::named_params! {
                ":id": response_id,
                ":survey_id": survey_id,
                ":created_at_utc": created_at_utc,
                ":answer_1": response.q1,
                ":answer_2": response.q2,
            },
        )
        .await
    }

    /// This implicitly checks if a user has access to a survey
    pub(crate) async fn get_net_promoter_score_survey_name(
        &self,
        survey_id: &str,
        user_id: &str,
    ) -> Result<Option<Arc<str>>, SingleRowQueryError> {
        let connection = self.connect().await?;
        let mut statement = connection
            .prepare("SELECT name FROM net_promoter_score_surveys WHERE user_id = :user_id AND id = :survey_id")
            .await
            .map_err(StatementError::Prepare)?;

        let result = statement
            .query_row(named_params! {
                ":user_id": user_id,
                ":survey_id": survey_id,
            })
            .await;

        match result.and_then(|row| row.get_str(0).map(Arc::from)) {
            Ok(name) => Ok(Some(name)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(SingleRowQueryError::RowError(error)),
        }
    }

    pub(crate) async fn get_net_promoter_score_survey_responses(
        &self,
        survey_id: &str,
    ) -> Result<Vec<(i32, Option<String>)>, MultiRowQueryError> {
        let mut rows = self
            .query(
                "SELECT * FROM net_promoter_score_responses WHERE survey_id = :survey_id",
                named_params![":survey_id": survey_id],
            )
            .await?;

        let mut responses = Vec::new();

        while let Some(row) = rows.next().await.map_err(MultiRowQueryError::NextRow)? {
            let answer_1: i32 = row.get(3).map_err(MultiRowQueryError::Row)?;
            let answer_2: Option<String> = row.get(3).map_err(MultiRowQueryError::Row)?;

            responses.push((answer_1, answer_2));
        }

        Ok(responses)
    }

    pub(crate) async fn insert_system_usability_score_response(
        &self,
        survey_id: &str,
        response_id: &str,
        created_at_utc: i64,
        response: system_usability_score::Response,
    ) -> Result<(), StatementError> {
        self.insert(
            "INSERT INTO system_usability_score_responses (
                id,
                survey_id,
                created_at_utc,
                answer_1,
                answer_2,
                answer_3,
                answer_4,
                answer_5,
                answer_6,
                answer_7,
                answer_8,
                answer_9,
                answer_10
            ) VALUES (
                ?1,
                ?2,
                ?3,
                ?4,
                ?5,
                ?6,
                ?7,
                ?8,
                ?9,
                ?10,
                ?11,
                ?12,
                ?13)",
            libsql::params![
                response_id,
                survey_id,
                created_at_utc,
                response.q1,
                response.q2,
                response.q3,
                response.q4,
                response.q5,
                response.q6,
                response.q7,
                response.q8,
                response.q9,
                response.q10
            ],
        )
        .await
    }

    /// This implicitly checks if a user has access to a survey
    pub(crate) async fn get_system_usability_score_survey_name(
        &self,
        survey_id: &str,
        user_id: &str,
    ) -> Result<Option<Arc<str>>, SingleRowQueryError> {
        let connection = self.connect().await?;
        let mut statement = connection
            .prepare("SELECT name FROM system_usability_score_surveys WHERE user_id = :user_id AND id = :survey_id")
            .await
            .map_err(StatementError::Prepare)?;

        let result = statement
            .query_row(named_params! {
                ":survey_id": survey_id,
                ":user_id": user_id,
            })
            .await;

        match result.and_then(|row| row.get_str(0).map(Arc::from)) {
            Ok(name) => Ok(Some(name)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(SingleRowQueryError::RowError(error)),
        }
    }

    pub(crate) async fn get_system_usability_score_survey_responses(
        &self,
        survey_id: &str,
    ) -> Result<(Score, Vec<Response2>), MultiRowQueryError> {
        let mut rows = self
            .query(
                "SELECT * FROM system_usability_score_responses WHERE survey_id = :survey_id",
                named_params![":survey_id": survey_id],
            )
            .await?;

        let mut responses = Vec::new();
        let mut scores = Vec::new();

        while let Some(row) = rows.next().await.map_err(MultiRowQueryError::NextRow)? {
            let mut user_scores = [0; 10];
            let mut score_sum = 0;
            for index in 3u8..13 {
                let score = row
                    .get::<u32>(index.into())
                    .map_err(MultiRowQueryError::Row)?;

                user_scores[usize::from(index - 3)] = score;

                let is_positive_statement = index - 3 % 2 == 0;
                if is_positive_statement {
                    score_sum += score - 1;
                } else {
                    score_sum += 5 - score;
                }
            }

            // Score multiplied by 100 to get a percentage that can be displayed
            let score = score_sum as f64 * 100.0 / 40.0;
            // Make it to whole numbers with 2 decimal places e.g. 72.12 -> 7212 so we can sort it (floats are not sortable)
            let score = (score * 100.0).round() as u64;

            responses.push(Response2 {
                scores: user_scores,
                //TODO number formatting localization
                score: score as f64 / 100.0,
            });
        }

        let score = if !scores.is_empty() {
            let mean = scores.iter().sum::<u64>() as f64 / scores.len() as f64;
            let variance = scores
                .iter()
                .map(|score| (*score as f64 - mean).powi(2))
                .sum::<f64>()
                / scores.len() as f64;
            let standard_deviation = (variance).sqrt();
            scores.sort_unstable();
            let median = scores[scores.len() / 2] as f64 / 100.0;

            let min = scores.iter().min().copied().unwrap_or_default() as f64 / 100.0;
            let max = scores.iter().max().copied().unwrap_or_default() as f64 / 100.0;
            Score {
                mean: mean / 100.0,
                variance: variance / 100.0,
                standard_deviation: standard_deviation / 100.0,
                median,
                min,
                max,
            }
        } else {
            Score::default()
        };

        Ok((score, responses))
    }
}
