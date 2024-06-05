use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::State;
use axum::Form;
use axum::response::Redirect;
use serde::Deserialize;
use crate::AppState;


#[derive(Template)]
#[template(path = "sus.html")]
struct SusTemplate {}

pub(crate) async fn get_page() -> impl IntoResponse {
    let sus_template = SusTemplate {};

    sus_template
}

#[derive(Deserialize, Debug)]
pub(crate) struct Response {
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

pub(crate) async fn create_response(
    State(app_state): State<AppState>,
    Form(sus_answers): Form<Response>,
) -> impl IntoResponse {
    tracing::debug!("Answers for SUS: {:?}", sus_answers);

    app_state
        .connection
        .execute(
            "INSERT INTO system_usability_score_responses (
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
                ?10)",
            libsql::params![
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

    Redirect::to("/")
}