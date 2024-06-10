use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::State;
use axum::Form;
use axum::response::Redirect;
use libsql::named_params;
use nanoid::nanoid;
use serde::Deserialize;
use crate::AppState;
use crate::auth::authenticated_user::AuthenticatedUser;

#[derive(Template)]
#[template(path = "nps.html")]
struct NpsTemplate {}

pub(crate) async fn get_page() -> impl IntoResponse {
    let nps_template = NpsTemplate {};

    nps_template
}

#[derive(Deserialize, Debug)]
pub(crate) struct NpsResponse {
    #[serde(rename = "Q1")]
    q1: u8,
    #[serde(rename = "Q2")]
    q2: String,
}

pub(crate) async fn create_response(
    State(app_state): State<AppState>,
    Form(nps_answers): Form<NpsResponse>,
) -> impl IntoResponse {
    tracing::debug!("Answers for NPS: {:?}", nps_answers);

    app_state
        .connection
        .execute(
            "INSERT INTO net_promoter_score_responses (answer_1, answer_2) VALUES (?1, ?2)",
            libsql::params![nps_answers.q1, nps_answers.q2],
        )
        .await
        .expect("Failed to insert into database");

    tracing::debug!("Inserted into database");

    Redirect::to("/")
}


pub(crate) async fn create_new_survey(State(state): State<AppState>, user: AuthenticatedUser) -> impl IntoResponse {
    let survey_id = nanoid!();
    let result = state.connection.execute(
        "INSERT INTO net_promoter_score_surveys (id, user_id) VALUES (:id, :user_id)",
        named_params! {":id":survey_id.clone(), ":user_id":user.id }).await;

    if let Err(error) = result {
        tracing::error!("Error creating new survey: {:?}", error);
        //TODO: inform user creation has failed and it's not their fault
        return Redirect::to("/");
    }

    // Redirect to newly created survey
    Redirect::to(format!("/{}", survey_id).as_ref())
}