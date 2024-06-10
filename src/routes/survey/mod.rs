use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Redirect;
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
        //TODO currently this is the results page but we want the survey
        .route("/:survey_id", get(get_survey_results_page))
    //TODO add results page
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


//TODO consider renaming to evaluation or something more fitting
#[derive(Template)]
#[template(path = "results/attrakdiff.html")]
struct AdResultsTemplate {}

//TODO consider renaming to evaluation or something more fitting
#[derive(Template)]
#[template(path = "results/net promoter score.html")]
struct NpsResultsTemplate {}

//TODO consider renaming to evaluation or something more fitting
#[derive(Template)]
#[template(path = "results/system usability score.html")]
struct SusResultsTemplate {}

async fn get_survey_results_page(State(state): State<AppState>, Path(survey_id): Path<String>, user: AuthenticatedUser) -> impl IntoResponse {
    //TODO possibly optimize this as we don't know the type of the survey from the path alone,
    // but also want the path to be easy to enter for users and don't reveal information that could
    // bias the responses like the survey type

    // Could maybe optimize this by filtering on each subquery but that needs to be measured first
    // maybe with EXPLAIN SQLite query plan if you understand how that works
    const QUERY: &str =
        "SELECT * FROM (
            SELECT 'attrakdiff' as type, * FROM attrakdiff_surveys
            UNION ALL
            SELECT 'net promoter score' as type, * FROM net_promoter_score_surveys
            UNION ALL
            SELECT 'system usability score' as type, * FROM system_usability_score_surveys
        )
            WHERE user_id = :user_id
            AND id = :survey_id";

    let result = state.connection.query(QUERY, named_params![":user_id": user.id, ":survey_id": survey_id]).await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Error querying for survey: {:?}", error);
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    let result = rows.next().await;
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

    let result = row.get::<String>(0);
    let survey_type = match result {
        Ok(survey_type) => survey_type,
        Err(error) => {
            tracing::error!("Error reading survey type: {:?}", error);
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    //TODO use constants for survey types or an enum to avoid errors from random strings or unintentional changes
    // basically improve compile time enforcement
    match survey_type.as_str() {
        "attrakdiff" => AdResultsTemplate {}.into_response(),
        "net promoter score" => NpsResultsTemplate {}.into_response(),
        "system usability score" => SusResultsTemplate {}.into_response(),
        other => {
            tracing::error!("Unexpected unknown survey type: {}", other);
            Redirect::to("/surveys").into_response()
        }
    }
}
