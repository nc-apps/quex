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
use serde::Deserialize;
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
pub(super) struct Response {
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
    Form(sus_answers): Form<Response>,
    survey_id: String,
) -> Redirect {
    tracing::debug!("Answers for SUS: {:?}", sus_answers);
    let response_id = nanoid!();

    app_state
        .connection
        .execute(
            "INSERT INTO system_usability_score_responses (
                id,
                survey_id,
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
                ?12)",
            libsql::params![
                response_id,
                survey_id,
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

//TODO consider renaming to evaluation or something more fitting
/// The HTML template for the System Usability Score survey details and results page
#[derive(Template)]
#[template(path = "surveys/results/system usability score.html")]
struct SystemUsabilityScoreResultsTemplate {
    id: String,
    name: String,
    answers: Vec<[i32; 10]>,
    survey_url: String,
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

    loop {
        let result = rows.next().await;
        match result {
            Ok(Some(row)) => {
                let mut response = [0; 10];
                for i in 0usize..10 {
                    let answer = row.get::<i32>((i + 2).try_into().unwrap());
                    let answer = match answer {
                        Ok(answer) => answer,
                        Err(error) => {
                            tracing::error!("Error reading response number {i}: {error:?}");
                            //TODO display user error message it's not their fault
                            return Redirect::to("/surveys").into_response();
                        }
                    };
                    response[i] = answer;
                }
                answers.push(response);
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
    SystemUsabilityScoreResultsTemplate {
        id: survey_id,
        name,
        answers,
        survey_url,
    }
    .into_response()
}
