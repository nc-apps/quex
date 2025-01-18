use crate::auth::authenticated_user::AuthenticatedUser;
use crate::routes::create_share_link;
use crate::AppState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{Path, State};
use axum::response::Redirect;
use axum::Form;
use libsql::named_params;
use nanoid::nanoid;
use reqwest::StatusCode;
use serde::Deserialize;
use std::ops::Mul;
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Template)]
#[template(path = "surveys/responses/system usability score.html")]
struct SusTemplate {
    id: String,
}

pub(super) fn get_page(id: String) -> askama_axum::Response {
    let sus_template = SusTemplate { id };

    sus_template.into_response()
}

#[derive(Deserialize, Debug)]
pub(super) struct CreateResponseRequest {
    #[serde(rename = "Q1")]
    q1: u8,
    #[serde(rename = "Q2")]
    q2: u8,
    #[serde(rename = "Q3")]
    q3: u8,
    #[serde(rename = "Q4")]
    q4: u8,
    #[serde(rename = "Q5")]
    q5: u8,
    #[serde(rename = "Q6")]
    q6: u8,
    #[serde(rename = "Q7")]
    q7: u8,
    #[serde(rename = "Q8")]
    q8: u8,
    #[serde(rename = "Q9")]
    q9: u8,
    #[serde(rename = "Q10")]
    q10: u8,
}

pub(super) async fn create_response(
    State(app_state): State<AppState>,
    Form(sus_answers): Form<CreateResponseRequest>,
    survey_id: String,
) -> Redirect {
    tracing::debug!("Answers for SUS: {:?}", sus_answers);
    let response_id = nanoid!();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    app_state
        .connection
        .execute(
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
                now,
                sus_answers.q1,
                sus_answers.q2,
                sus_answers.q3,
                sus_answers.q4,
                sus_answers.q5,
                sus_answers.q6,
                sus_answers.q7,
                sus_answers.q8,
                sus_answers.q9,
                sus_answers.q10
            ],
        )
        .await
        .expect("Failed to insert into database");

    tracing::debug!("Inserted into database");

    Redirect::to("/thanks")
}

/// Handler that creates a new System Usability Score survey from a create survey form submission
pub(super) async fn create_new_survey(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    name: Option<String>,
) -> Redirect {
    let survey_id = nanoid!();

    let name: Arc<str> = match name.as_deref() {
        // Use the first 6 characters of the survey id as the name if no name is provided
        Some("") | None => format!("System Usability Score Survey {}", &survey_id[..7]).into(),
        Some(name) => name.into(),
    };

    // Create timestamp
    // We could use the database timestamp, but I prefer to have the application dictate the time in
    // case something goes wrong
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let result = state
        .connection
        .execute(
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
                ":id":survey_id.clone(),
                ":user_id":user.id,
                ":name":name,
                ":created_at_utc":now
            },
        )
        .await;

    if let Err(error) = result {
        tracing::error!("Error creating new survey: {:?}", error);
        //TODO: inform user creation has failed and it's not their fault
        return Redirect::to("/");
    }

    // Redirect to newly created survey overview
    Redirect::to(format!("/surveys/sus/{}", survey_id).as_ref())
}

struct Response {
    scores: [u32; 10],
    score: f64,
}

#[derive(Default)]
struct Score {
    mean: f64,
    variance: f64,
    standard_deviation: f64,
    median: f64,
    min: f64,
    max: f64,
}

//TODO consider renaming to evaluation or something more fitting
/// The HTML template for the System Usability Score survey details and results page
#[derive(Template)]
#[template(path = "surveys/results/system usability score.html")]
struct SystemUsabilityScoreResultsTemplate {
    id: String,
    name: String,
    responses: Vec<Response>,
    survey_url: String,
    score: Score,
}

/// Gets the details page that displays the results of the survey and gives insights to the responses
pub(super) async fn get_results_page(
    State(state): State<AppState>,
    Path(survey_id): Path<String>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    let result = state.connection.query(
        "SELECT name FROM system_usability_score_surveys WHERE user_id = :user_id AND id = :survey_id",
        named_params![":user_id": user.id, ":survey_id": survey_id.clone()]).await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(
                "Error querying for System Usability Score survey: {:?}",
                error
            );
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    let result = rows.next().await;
    //TODO put data we want to display into template
    let row = match result {
        Ok(Some(row)) => row,
        // Survey not found. It wasn't created (yet), or deleted
        //TODO display user error message
        Ok(None) => return Redirect::to("/surveys").into_response(),
        Err(error) => {
            tracing::error!("Error reading query result: {:?}", error);
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    let survey_name_result: Result<String, _> = row.get::<String>(0);
    let name = match survey_name_result {
        Ok(name) => name,
        Err(error) => {
            tracing::error!("Error reading survey name: {:?}", error);
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    // Read results
    let result = state
        .connection
        .query(
            "SELECT * FROM system_usability_score_responses WHERE survey_id = :survey_id",
            named_params![":survey_id": survey_id.clone()],
        )
        .await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(
                "Error querying for System Usability Score responses: {:?}",
                error
            );
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    let mut answers = Vec::new();

    /// The offset of the metadata columns in the database
    const METADATA_OFFSET: usize = 3;

    let mut scores = Vec::new();

    loop {
        let result = rows.next().await;
        match result {
            Ok(Some(row)) => {
                let mut user_scores = [0; 10];
                // User score out of 40
                let mut score_sum = 0;
                for answer_index in 0usize..10 {
                    let answer = row.get((METADATA_OFFSET + answer_index).try_into().unwrap());
                    let score = match answer {
                        Ok(answer) => answer,
                        Err(error) => {
                            tracing::error!(
                                "Error reading response number {answer_index}: {error:?}"
                            );
                            //TODO display user error message it's not their fault
                            return Redirect::to("/surveys").into_response();
                        }
                    };

                    let is_positive_statement = answer_index % 2 == 0;
                    if is_positive_statement {
                        score_sum += score - 1;
                    } else {
                        score_sum += 5 - score;
                    }

                    user_scores[answer_index] = score;
                }

                // Score multiplied by 100 to get a percentage that can be displayed
                let score = score_sum as f64 * 100.0 / 40.0;
                // Make it to whole numbers with 2 decimal places e.g. 72.12 -> 7212 so we can sort it (floats are not sortable)
                let score = (score * 100.0).round() as u64;
                scores.push(score);
                answers.push(Response {
                    scores: user_scores,
                    //TODO number formatting localization
                    score: score as f64 / 100.0,
                });
            }
            Ok(None) => break,
            Err(error) => {
                tracing::error!("Error reading query result: {:?}", error);
                //TODO display user error message it's not their fault
                return Redirect::to("/surveys").into_response();
            }
        }
    }

    let score = if scores.len() > 0 {
        let mean = scores.iter().sum::<u64>() as f64 / scores.len() as f64;
        let variance = scores
            .iter()
            .map(|score| (*score as f64 - mean).powi(2))
            .sum::<f64>()
            / scores.len() as f64;
        let standard_deviation = (variance).sqrt();
        scores.sort_unstable();
        let median = scores[scores.len() / 2] as f64 / 100.0;
        let min = scores.iter().min().copied().unwrap() as f64 / 100.0;
        let max = scores.iter().max().copied().unwrap() as f64 / 100.0;
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

    let survey_url = create_share_link(&state.configuration.server_url, &survey_id);
    SystemUsabilityScoreResultsTemplate {
        id: survey_id,
        name,
        responses: answers,
        survey_url,
        score,
    }
    .into_response()
}

pub(super) async fn download_results(
    State(state): State<AppState>,
    Path(survey_id): Path<String>,
) -> Result<String, StatusCode> {
    let result = state
        .connection
        .query(
            "SELECT * FROM system_usability_score_responses WHERE survey_id = :survey_id",
            named_params![":survey_id": survey_id.clone()],
        )
        .await;
    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Error querying for AttrakDiff survey: {:?}", error);
            //TODO display user error message it's not their fault
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut csv = String::new();

    csv += "I think that I would like to use this system frequently, I found the system unnecessarily complex, I thought the system was easy to use, I think that I would need the support of a technical person to be able to use this system, I found the various functions in this system were well integrated, I thought there was too much inconsistency in this system, I would imagine that most people would learn to use this system very quickly, I found the system very cumbersome to use, I felt very confident using the system, I needed to learn a lot of things before I could get going with this system\n";

    loop {
        let result = rows.next().await;
        match result {
            Ok(None) => break,
            Ok(Some(row)) => {
                for i in 2i32..12 {
                    let answer = row.get::<i32>(i);
                    let answer = match answer {
                        Ok(answer) => answer,
                        Err(error) => {
                            tracing::error!("Error reading survey id: {:?}", error);
                            //TODO display user error message it's not their fault
                            return Err(StatusCode::INTERNAL_SERVER_ERROR);
                        }
                    };
                    csv += &format!("{}, ", answer);
                }
                // geht schöner iwie
                csv.pop();
                csv.pop();
                csv.push('\n');
            }
            Err(error) => {
                tracing::error!("Error reading query result: {:?}", error);
                //TODO display user error message it's not their fault
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }
    tracing::debug!("csv: {:?}", csv);

    return Ok(csv);
}
