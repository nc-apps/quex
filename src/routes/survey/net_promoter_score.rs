use std::sync::Arc;
use crate::auth::authenticated_user::AuthenticatedUser;
use crate::AppState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{Path, State};
use axum::response::Redirect;
use axum::Form;
use libsql::named_params;
use nanoid::nanoid;
use serde::Deserialize;
use time::OffsetDateTime;
use crate::routes::survey::CreateSurveyRequest;

#[derive(Template)]
#[template(path = "nps.html")]
struct NpsTemplate {}

pub(super) fn get_page() -> askama_axum::Response {
    let nps_template = NpsTemplate {};

    nps_template.into_response()
}

#[derive(Deserialize, Debug)]
pub(super) struct Response {
    #[serde(rename = "Q1")]
    q1: u8,
    #[serde(rename = "Q2")]
    q2: String,
}

pub(super) async fn create_response(
    State(app_state): State<AppState>,
    Form(nps_answers): Form<Response>,
) -> Redirect {
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

    Redirect::to("/thanks")
}

pub(super) async fn create_new_survey(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(request): Form<CreateSurveyRequest>,
) -> impl IntoResponse {
    let survey_id = nanoid!();

    let name: Arc<str> = match request.name.as_deref() {
        // Use the first 6 characters of the survey id as the name if no name is provided
        Some("") | None => format!("Net Promoter Score Survey {}", &survey_id[..7]).into(),
        Some(name) => name.into()
    };

    // Create timestamp
    // We could use the database timestamp, but I prefer to have the application dictate the time in
    // case something goes wrong
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let result = state
        .connection
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
#[derive(Template)]
#[template(path = "results/net promoter score.html")]
struct NetPromoterScoreResultsTemplate {}

pub(super) async fn get_results_page(
    State(state): State<AppState>,
    Path(survey_id): Path<String>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    let result = state
        .connection
        .query(
            "SELECT * FROM net_promoter_score_surveys WHERE user_id = :user_id AND id = :survey_id",
            named_params![":user_id": user.id, ":survey_id": survey_id],
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
    let _row = match result {
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

    NetPromoterScoreResultsTemplate {}.into_response()
}
