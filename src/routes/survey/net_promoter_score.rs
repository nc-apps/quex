use crate::auth::authenticated_user::AuthenticatedUser;
use crate::database::StatementError;
use crate::routes::create_share_link;
use crate::survey::get_file_name;
use crate::AppState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Redirect;
use axum::Form;
use nanoid::nanoid;
use reqwest::{header, StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use time::OffsetDateTime;

use super::{CreateSurveyError, DownloadResultsError, GetResultsPageError};

#[derive(Template)]
#[template(path = "surveys/responses/net promoter score.html")]
struct NpsTemplate {
    id: Arc<str>,
}

pub(super) fn get_page(id: Arc<str>) -> askama_axum::Response {
    let nps_template = NpsTemplate { id };

    nps_template.into_response()
}

#[derive(Deserialize, Debug)]
pub(crate) struct Response {
    #[serde(rename = "Q1")]
    pub(crate) q1: u8,
    #[serde(rename = "Q2")]
    pub(crate) q2: Option<String>,
}

pub(super) async fn create_response(
    State(state): State<AppState>,
    Form(response): Form<Response>,
    survey_id: Arc<str>,
) -> Result<Redirect, StatementError> {
    tracing::debug!("Answers for NPS: {:?}", response);
    let response_id = nanoid!();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    state
        .database
        .insert_net_promoter_score_response(&response_id, &survey_id, now, response)
        .await?;

    Ok(Redirect::to("/thanks"))
}

/// Handler that creates a new Net Promoter Score survey from a create survey form submission
pub(super) async fn create_new_survey(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    name: Option<String>,
) -> Result<Redirect, CreateSurveyError> {
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

    state
        .database
        .insert_net_promoter_score_survey(&survey_id, &user.id, &name, now)
        .await?;

    // Redirect to newly created survey overview
    Ok(Redirect::to(format!("/surveys/nps/{}", survey_id).as_ref()))
}

//TODO consider renaming to evaluation or something more fitting
/// The HTML template for the Net Promoter Score survey details and results page
#[derive(Template)]
#[template(path = "surveys/results/net promoter score.html")]
struct NetPromoterScoreResultsTemplate {
    id: Arc<str>,
    name: Arc<str>,
    answers: Vec<(i32, Option<String>)>,
    survey_url: String,
}

/// Gets the details page that displays the results of the survey and gives insights to the responses
pub(super) async fn get_results_page(
    State(state): State<AppState>,
    Path(survey_id): Path<Arc<str>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, GetResultsPageError> {
    let survey_name = state
        .database
        .get_net_promoter_score_survey_name(&survey_id, &user.id)
        .await
        .map_err(GetResultsPageError::GetSurveyError)?;

    let Some(survey_name) = survey_name else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    // Read results
    let responses = state
        .database
        .get_net_promoter_score_survey_responses(&survey_id)
        .await
        .map_err(GetResultsPageError::GetSurveyResponsesError)?;

    let survey_url = create_share_link(&state.configuration.server_url, &survey_id);
    Ok(NetPromoterScoreResultsTemplate {
        id: survey_id,
        name: survey_name,
        answers: responses,
        survey_url,
    }
    .into_response())
}

pub(super) async fn download_results(
    State(state): State<AppState>,
    Path(survey_id): Path<String>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, DownloadResultsError> {
    // This also checks if the user has access to the survey
    let survey_name = state
        .database
        .get_net_promoter_score_survey_name(&survey_id, &user.id)
        .await
        .map_err(DownloadResultsError::GetSurveyError)?;

    if survey_name.is_none() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    //TODO check if this file can be streamed line by line and row by row
    let responses = state
        .database
        .get_net_promoter_score_survey_responses(&survey_id)
        .await
        .map_err(DownloadResultsError::GetSurveyResponsesError)?;

    let mut csv = String::new();
    csv += "How likely are you to recommend us on a scale from 0 to 10?, And why?\n";

    for (answer_1, answer_2) in responses {
        csv += &if let Some(answer_2) = answer_2 {
            format!("{}, {}\n", answer_1, answer_2)
        } else {
            format!("{},\n", answer_1)
        };
    }

    let mut headers = HeaderMap::new();
    const TEXT_CSV: HeaderValue = HeaderValue::from_static("text/csv");
    headers.insert(header::CONTENT_TYPE, TEXT_CSV);
    // The survey id should be URL safe and ASCII only by default
    let value = format!("attachment; filename=\"{}\"", get_file_name(&survey_id));
    let value = HeaderValue::try_from(value).expect("Invalid characters in survey id");
    headers.insert(header::CONTENT_DISPOSITION, value);

    Ok((headers, csv).into_response())
}
