use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Router;
use axum::routing::get;
use libsql::named_params;
use crate::{AppState, routes};
use crate::auth::authenticated_user::AuthenticatedUser;

mod net_promoter_score;
mod attrakdiff;
mod system_usability_score;


pub(crate) fn create_router() -> Router<AppState> {
    Router::new()
        .route("/surveys", get(surveys_page))
        .route("/nps", get(net_promoter_score::get_page).post(net_promoter_score::create_response))
        .route("/nps/new", get(net_promoter_score::create_new_survey))
        .route("/sus", get(system_usability_score::get_page).post(system_usability_score::create_response))
        .route("/sus/new", get(system_usability_score::create_new_survey))
        .route(
            "/ad",
            get(attrakdiff::get_page).post(attrakdiff::create_response),
        )
        .route("/ad/new", get(attrakdiff::create_new_survey))
}

#[derive(Template)]
#[template(path = "surveys.html")]
struct SurveysTemplate {
    surveys: Vec<String>,
}

async fn surveys_page(
    user: AuthenticatedUser,
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    let mut rows = app_state
        .connection
        .query(
            "SELECT id FROM system_usability_score_surveys WHERE user_id = :user_id",
            named_params![":user_id": user.id],
        )
        .await
        .expect("Failed to query surveys");

    let mut surveys = Vec::new();

    loop {
        let result = rows.next().await;
        match result {
            Ok(Some(row)) => {
                let result: Result<String, libsql::Error> = row.get(0);
                match result {
                    Ok(id) => surveys.push(id),
                    Err(error) => {
                        tracing::error!("Error reading survey id: {:?}", error);
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
            }
            // No more rows
            Ok(None) => break,
            Err(error) => {
                tracing::error!("Error getting surveys: {:?}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }
    
    let surveys_template = SurveysTemplate { surveys };
    surveys_template.into_response()
}
