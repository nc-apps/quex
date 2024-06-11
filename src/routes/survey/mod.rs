use crate::auth::authenticated_user::AuthenticatedUser;
use crate::{AppState, routes};
use askama::Template;
use askama_axum::IntoResponse;
use axum::body::Body;
use axum::extract::rejection::FormRejection;
use axum::extract::{FromRequest, Path, Request, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use libsql::{Connection, named_params};
use std::sync::Arc;
use nanoid::nanoid;
use serde::Deserialize;
use time::OffsetDateTime;

mod attrakdiff;
mod net_promoter_score;
mod system_usability_score;

pub(crate) fn create_router() -> Router<AppState> {
    let survey_routes = Router::new()
        .route("/nps", post(net_promoter_score::create_new_survey))
        .route("/nps/:id", get(net_promoter_score::get_results_page))
        .route("/sus", post(system_usability_score::create_new_survey))
        .route("/sus/:id", get(system_usability_score::get_results_page))
        .route("/ad", post(attrakdiff::create_new_survey))
        .route("/ad/:id", get(attrakdiff::get_results_page));

    Router::new()
        .route("/surveys", get(surveys_page).post(create_survey))
        .nest("/surveys", survey_routes)
        // These are the public endpoints that respondents can use to access a questionnaire
        // and submit their responses.
        // There are multiple things to reduce friction for respondents:
        // 1. They don't need an account/sign in to access the survey
        // 2. They don't need a long URL to access the survey. The survey id is enough
        // Additionally the survey type is not leaked in the URL to avoid biasing the responses
        .route("/q/:survey_id", get(get_survey_page).post(create_response))
}

/// Contains vectors for each survey type with the survey ids
#[derive(Default)]
struct Surveys {
    attrakdiff: Vec<String>,
    net_promoter_score: Vec<String>,
    system_usability_score: Vec<String>,
}

#[derive(Template)]
#[template(path = "surveys.html")]
struct SurveysTemplate {
    surveys: Surveys,
}

async fn surveys_page(
    user: AuthenticatedUser,
    State(app_state): State<AppState>,
) -> Result<askama_axum::Response, Redirect> {
    const GET_USER_SURVEYS_QUERY: &str = "SELECT * FROM (
                SELECT 'attrakdiff' as type, * FROM attrakdiff_surveys
                UNION ALL
                SELECT 'net promoter score' as type, * FROM net_promoter_score_surveys
                UNION ALL
                SELECT 'system usability score' as type, * FROM system_usability_score_surveys
            )
                WHERE user_id = :user_id";

    let result = app_state
        .connection
        .query(GET_USER_SURVEYS_QUERY, named_params![":user_id": user.id])
        .await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Error getting surveys: {:?}", error);
            //TODO display user error message it's not their fault
            return Err(Redirect::to("/surveys/error"));
        }
    };

    let mut surveys = Surveys::default();

    loop {
        let result = rows.next().await;
        match result {
            Ok(Some(row)) => {
                let result: Result<String, libsql::Error> = row.get(0);
                let survey_type = match result {
                    Ok(survey_type) => survey_type,
                    Err(error) => {
                        tracing::error!("Error reading survey id: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Err(Redirect::to("/surveys/error"));
                    }
                };

                let result: Result<String, libsql::Error> = row.get(1);
                let id = match result {
                    Ok(id) => id,
                    Err(error) => {
                        tracing::error!("Error reading survey id: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Err(Redirect::to("/surveys/error"));
                    }
                };

                match survey_type.as_str() {
                    "attrakdiff" => surveys.attrakdiff.push(id),
                    "net promoter score" => surveys.net_promoter_score.push(id),
                    "system usability score" => surveys.system_usability_score.push(id),
                    other => {
                        tracing::error!("Unexpected unknown survey type: {}", other);
                        return Err(Redirect::to("/surveys/error"));
                    }
                }
            }
            // No more rows
            Ok(None) => break,
            Err(error) => {
                tracing::error!("Error getting surveys: {:?}", error);
                //TODO display user error message it's not their fault
                return Err(Redirect::to("/surveys/error"));
            }
        }
    }

    let surveys_template = SurveysTemplate { surveys };
    Ok(surveys_template.into_response())
}

const GET_SURVEY_QUERY: &str = "SELECT * FROM (
            SELECT 'attrakdiff' as type, * FROM attrakdiff_surveys
            UNION ALL
            SELECT 'net promoter score' as type, * FROM net_promoter_score_surveys
            UNION ALL
            SELECT 'system usability score' as type, * FROM system_usability_score_surveys
        )
            WHERE id = :survey_id";

#[derive(Deserialize, Debug)]
enum SurveyType {
    #[serde(rename = "ad")]
    Attrakdiff,
    #[serde(rename = "nps")]
    NetPromoterScore,
    #[serde(rename = "sus")]
    SystemUsabilityScore,
}

#[derive(thiserror::Error, Debug)]
enum GetSurveyError {
    #[error("Error reading survey from database")]
    DatabaseError(#[from] libsql::Error),
    #[error("Unexpected survey type: {0}")]
    UnexpectedSurveyType(Arc<str>),
}

/// Helper function to get a survey from the database
async fn get_survey(
    connection: &Connection,
    survey_id: &str,
) -> Result<Option<SurveyType>, GetSurveyError> {
    //TODO possibly optimize this as we don't know the type of the survey from the path alone,
    // but also want the path to be easy to enter for users and don't reveal information that could
    // bias the responses like the survey type
    // This is a hot path as respondents will use this
    // Could maybe optimize this by filtering on each subquery but that needs to be measured first
    // maybe with EXPLAIN SQLite query plan if you understand how that works

    let mut rows = connection
        .query(GET_SURVEY_QUERY, named_params![":survey_id": survey_id])
        .await?;

    let row = rows.next().await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let survey_type = row.get::<String>(0)?;
    match survey_type.as_str() {
        "attrakdiff" => Ok(Some(SurveyType::Attrakdiff)),
        "net promoter score" => Ok(Some(SurveyType::NetPromoterScore)),
        "system usability score" => Ok(Some(SurveyType::SystemUsabilityScore)),
        other => {
            tracing::error!("Unexpected unknown survey type: {}", other);
            Err(GetSurveyError::UnexpectedSurveyType(other.into()))
        }
    }
}

/// Handler for the public endpoint where respondents submit their responses
async fn create_response(
    state: State<AppState>,
    Path(survey_id): Path<String>,
    request: Request,
) -> Result<Redirect, Response> {
    // Get survey to check if it even exists
    //TODO optimize as get_survey_page and this is a hot path
    let result = get_survey(&state.connection, &survey_id).await;
    let survey = match result {
        Ok(survey) => survey,
        Err(error) => {
            tracing::error!("Error getting survey: {:?}", error);
            //TODO display user error message it's not their fault
            return Err(Redirect::to("/surveys").into_response());
        }
    };

    // Check if survey exists
    let Some(survey) = survey else {
        tracing::warn!("User submitted a response to a survey that doesn't exist");
        // User submitted a response to a survey that doesn't exist
        // This doesn't happen normally but if it happens we say thanks anyway since they put in
        // the effort
        return Ok(Redirect::to("/thanks"));
    };

    // Forward survey to correct survey page response handler
    // Wrote this very late. Might not be the best code
    match survey {
        SurveyType::Attrakdiff => {
            let form = Form::<attrakdiff::Response>::from_request(request, &state)
                .await
                .map_err(|error| error.into_response())?;
            Ok(attrakdiff::create_response(state, form).await)
        }
        SurveyType::NetPromoterScore => {
            let form = Form::<net_promoter_score::Response>::from_request(request, &state)
                .await
                .map_err(|error| error.into_response())?;
            Ok(net_promoter_score::create_response(state, form).await)
        }
        SurveyType::SystemUsabilityScore => {
            let form = Form::<system_usability_score::Response>::from_request(request, &state)
                .await
                .map_err(|error| error.into_response())?;
            Ok(system_usability_score::create_response(state, form).await)
        }
    }
}

/// This gets the survey page for a specific survey so that a respondent can answer the questions
/// and then submit them
async fn get_survey_page(
    State(state): State<AppState>,
    Path(survey_id): Path<String>,
) -> Result<Response, Redirect> {
    // Get survey to check if it even exists
    //TODO optimize as get_survey_page and this is a hot path
    let result = get_survey(&state.connection, &survey_id).await;
    let survey = match result {
        Ok(survey) => survey,
        Err(error) => {
            tracing::error!("Error getting survey: {:?}", error);
            //TODO display user error message it's not their fault
            return Err(Redirect::to("/surveys/error"));
        }
    };

    // Check if survey exists
    let Some(survey) = survey else {
        // Survey not found
        return Err(Redirect::to("/surveys/notfound"));
    };

    Ok(match survey {
        SurveyType::Attrakdiff => attrakdiff::get_page(),
        SurveyType::NetPromoterScore => net_promoter_score::get_page(),
        SurveyType::SystemUsabilityScore => system_usability_score::get_page(),
    })
}

#[derive(Deserialize, Debug)]
struct CreateSurveyRequest {
    /// The name of the survey. It is optional to reduce user friction, and we crate a random name if
    /// it is not provided.
    name: Option<String>,
    r#type: SurveyType,
}

async fn create_survey(
    state: State<AppState>,
    user: AuthenticatedUser,
    Form(request): Form<CreateSurveyRequest>,
) -> Redirect {
    match request.r#type {
        SurveyType::Attrakdiff => attrakdiff::create_new_survey(state, user, request.name).await,
        SurveyType::NetPromoterScore => net_promoter_score::create_new_survey(state, user, request.name).await,
        SurveyType::SystemUsabilityScore => system_usability_score::create_new_survey(state, user, request.name).await,
    }
}
