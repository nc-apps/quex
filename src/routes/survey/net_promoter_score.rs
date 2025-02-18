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
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Template)]
#[template(path = "surveys/responses/net promoter score.html")]
struct NpsTemplate {
    id: String,
}

pub(super) fn get_page(id: String) -> askama_axum::Response {
    let nps_template = NpsTemplate { id };

    nps_template.into_response()
}

#[derive(Deserialize, Debug)]
pub(super) struct Response {
    #[serde(rename = "Q1")]
    q1: u8,
    #[serde(rename = "Q2")]
    q2: Option<String>,
}

pub(super) async fn create_response(
    State(app_state): State<AppState>,
    Form(nps_answers): Form<Response>,
    survey_id: String,
) -> Redirect {
    tracing::debug!("Answers for NPS: {:?}", nps_answers);
    let response_id = nanoid!();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let connection = app_state
        .database
        .connect()
        .expect("Error connecting to database");

    connection
        .execute(
            "INSERT INTO net_promoter_score_responses (id, created_at_utc, survey_id, answer_1, answer_2) VALUES (:id, :survey_id, :created_at_utc, :answer_1, :answer_2)",
            libsql::named_params! {
                ":id": response_id,
                ":survey_id": survey_id,
                ":created_at_utc": now,
                ":answer_1": nps_answers.q1,
                ":answer_2": nps_answers.q2,
            },
        )
        .await
        .expect("Failed to insert into database");

    tracing::debug!("Inserted into database");

    Redirect::to("/thanks")
}

/// Handler that creates a new Net Promoter Score survey from a create survey form submission
pub(super) async fn create_new_survey(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    name: Option<String>,
) -> Redirect {
    let survey_id = nanoid!();

    let name: Arc<str> = match name.as_deref() {
        // Use the first 6 characters of the survey id as the name if no name is provided
        Some("") | None => format!("Net Promoter Score Survey {}", &survey_id[..7]).into(),
        Some(name) => name.into(),
    };

    // Create timestamp
    // We could use the database timestamp, but I prefer to have the application dictate the time in
    // case something goes wrong
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let connection = state
        .database
        .connect()
        .expect("Error connecting to database");

    let result = connection
        .execute(
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
    Redirect::to(format!("/surveys/nps/{}", survey_id).as_ref())
}

//TODO consider renaming to evaluation or something more fitting
/// The HTML template for the Net Promoter Score survey details and results page
#[derive(Template)]
#[template(path = "surveys/results/net promoter score.html")]
struct NetPromoterScoreResultsTemplate {
    id: String,
    name: String,
    answers: Vec<(i32, String)>,
    survey_url: String,
}

/// Gets the details page that displays the results of the survey and gives insights to the responses
pub(super) async fn get_results_page(
    State(state): State<AppState>,
    Path(survey_id): Path<String>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    let connection = state
        .database
        .connect()
        .expect("Error connecting to database");

    let result = connection
        .query(
            "SELECT name FROM net_promoter_score_surveys WHERE user_id = :user_id AND id = :survey_id",
            named_params![":user_id": user.id, ":survey_id": survey_id.clone()],
        )
        .await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Error querying for Net Promoter Score survey: {:?}", error);
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

    let survey_name_result = row.get::<String>(0);
    let name = match survey_name_result {
        Ok(name) => name,
        Err(error) => {
            tracing::error!("Error reading survey name: {:?}", error);
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    // Read results
    let connection = state
        .database
        .connect()
        .expect("Error connecting to database");
    let result = connection
        .query(
            "SELECT * FROM net_promoter_score_responses WHERE survey_id = :survey_id",
            named_params![":survey_id": survey_id.clone()],
        )
        .await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(
                "Error querying for Net Promoter Score responses: {:?}",
                error
            );
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    let mut answers: Vec<(i32, String)> = Vec::new();

    loop {
        let result = rows.next().await;
        match result {
            Ok(Some(row)) => {
                let answer_1 = row.get::<i32>(3);
                let answer_1 = match answer_1 {
                    Ok(answer_1) => answer_1,
                    Err(error) => {
                        tracing::error!("Error reading survey id: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Redirect::to("/surveys").into_response();
                    }
                };

                let answer_2 = row.get::<String>(4);
                let answer_2 = match answer_2 {
                    Ok(answer_2) => answer_2,
                    Err(error) => {
                        tracing::error!("Error reading survey id: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Redirect::to("/surveys").into_response();
                    }
                };

                answers.push((answer_1, answer_2));
            }
            Ok(None) => break,
            Err(error) => {
                tracing::error!("Error reading query result: {:?}", error);
                //TODO display user error message it's not their fault
                return Redirect::to("/surveys").into_response();
            }
        }
    }

    let survey_url = create_share_link(&state.configuration.server_url, &survey_id);
    NetPromoterScoreResultsTemplate {
        id: survey_id,
        name,
        answers,
        survey_url,
    }
    .into_response()
}

pub(super) async fn download_results(
    State(state): State<AppState>,
    Path(survey_id): Path<String>,
) -> Result<String, StatusCode> {
    let connection = state
        .database
        .connect()
        .expect("Error connecting to database");
    let result = connection
        .query(
            "SELECT * FROM net_promoter_score_responses WHERE survey_id = :survey_id",
            named_params![":survey_id": survey_id.clone()],
        )
        .await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Error querying for Net Promoter Score survey: {:?}", error);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut csv = String::new();
    csv += "How likely are you to recommend us on a scale from 0 to 10?, And why?\n";

    loop {
        let result = rows.next().await;
        match result {
            Ok(None) => break,
            Ok(Some(row)) => {
                let result = row.get::<i32>(2);

                let value1 = match result {
                    Ok(value) => value.to_string(),
                    Err(error) => {
                        tracing::error!("Error reading value at index 2: {:?}", error);
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                };

                let result = row.get::<String>(3);

                let value2 = match result {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!("Error reading value at index 3: {:?}", error);
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                };

                // Füge alle Werte der Zeile als CSV hinzu
                csv += &format!("{}, {}\n", value1, value2);
            }
            Err(error) => {
                tracing::error!("Error reading query result: {:?}", error);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    tracing::debug!("csv: {:?}", csv);
    Ok(csv)
}
