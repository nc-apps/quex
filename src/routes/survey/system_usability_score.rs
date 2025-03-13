use crate::auth::authenticated_user::AuthenticatedUser;
use crate::database::StatementError;
use crate::preferred_language::PreferredLanguage;
use crate::routes::create_share_link;
use crate::AppState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{Path, State};
use axum::response::Redirect;
use axum::Form;
use nanoid::nanoid;
use reqwest::StatusCode;
use serde::Deserialize;
use std::sync::Arc;
use time::OffsetDateTime;
use unic_langid::LanguageIdentifier;

use super::{
    create_csv_download_headers, CreateSurveyError, DownloadResultsError, GetResultsPageError,
};

pub const QUESTIONS: [&str; 10] = [
    "I think that I would like to use this system frequently",
    "I found the system unnecessarily complex",
    "I thought the system was easy to use",
    "I think that I would need the support of a technical person to be able to use this system",
    "I found the various functions in this system were well integrated",
    "I thought there was too much inconsistency in this system",
    "I would imagine that most people would learn to use this system very quickly",
    "I found the system very cumbersome to use",
    "I felt very confident using the system",
    "I needed to learn a lot of things before I could get going with this system",
];

#[derive(Template)]
#[template(path = "surveys/responses/system usability score.html")]
struct SusTemplate {
    id: Arc<str>,
}

pub(super) fn get_page(id: Arc<str>) -> askama_axum::Response {
    let sus_template = SusTemplate { id };

    sus_template.into_response()
}

#[derive(Deserialize, Debug)]
pub(crate) struct Response {
    #[serde(rename = "Q1")]
    pub(crate) q1: u8,
    #[serde(rename = "Q2")]
    pub(crate) q2: u8,
    #[serde(rename = "Q3")]
    pub(crate) q3: u8,
    #[serde(rename = "Q4")]
    pub(crate) q4: u8,
    #[serde(rename = "Q5")]
    pub(crate) q5: u8,
    #[serde(rename = "Q6")]
    pub(crate) q6: u8,
    #[serde(rename = "Q7")]
    pub(crate) q7: u8,
    #[serde(rename = "Q8")]
    pub(crate) q8: u8,
    #[serde(rename = "Q9")]
    pub(crate) q9: u8,
    #[serde(rename = "Q10")]
    pub(crate) q10: u8,
}

pub(super) async fn create_response(
    State(state): State<AppState>,
    Form(response): Form<Response>,
    survey_id: Arc<str>,
) -> Result<Redirect, StatementError> {
    let response_id = nanoid!();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    state
        .database
        .insert_system_usability_score_response(&response_id, &survey_id, now, response)
        .await?;

    Ok(Redirect::to("/thanks"))
}

/// Handler that creates a new System Usability Score survey from a create survey form submission
pub(super) async fn create_new_survey(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    name: Option<String>,
) -> Result<Redirect, CreateSurveyError> {
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

    state
        .database
        .insert_system_usability_score_survey(&survey_id, &user.id, &name, now)
        .await?;

    // Redirect to newly created survey overview
    Ok(Redirect::to(format!("/surveys/sus/{}", survey_id).as_ref()))
}

pub(crate) struct Response2 {
    pub(crate) scores: [u32; 10],
    pub(crate) score: f64,
}

#[derive(Default)]
pub(crate) struct Score {
    pub(crate) mean: f64,
    pub(crate) variance: f64,
    pub(crate) standard_deviation: f64,
    pub(crate) median: f64,
    pub(crate) min: f64,
    pub(crate) max: f64,
}

//TODO consider renaming to evaluation or something more fitting
/// The HTML template for the System Usability Score survey details and results page
#[derive(Template)]
#[template(path = "surveys/results/system usability score.html")]
struct SystemUsabilityScoreResultsTemplate {
    id: Arc<str>,
    name: Arc<str>,
    responses: Vec<Response2>,
    survey_url: String,
    score: Score,
    language: LanguageIdentifier,
}

/// Gets the details page that displays the results of the survey and gives insights to the responses
pub(super) async fn get_results_page(
    State(state): State<AppState>,
    Path(survey_id): Path<Arc<str>>,
    user: AuthenticatedUser,
    PreferredLanguage(language): PreferredLanguage,
) -> Result<impl IntoResponse, GetResultsPageError> {
    let survey_name = state
        .database
        .get_system_usability_score_survey_name(&survey_id, &user.id)
        .await
        .map_err(GetResultsPageError::GetSurveyError)?;

    let Some(survey_name) = survey_name else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let (score, responses) = state
        .database
        .get_system_usability_score_survey_responses(&survey_id)
        .await
        .map_err(GetResultsPageError::GetSurveyResponsesError)?;

    let survey_url = create_share_link(&state.configuration.server_url, &survey_id);
    Ok(SystemUsabilityScoreResultsTemplate {
        id: survey_id,
        name: survey_name,
        responses,
        survey_url,
        score,
        language,
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
        .get_system_usability_score_survey_name(&survey_id, &user.id)
        .await?;

    if survey_name.is_none() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    let (_score, responses) = state
        .database
        .get_system_usability_score_survey_responses(&survey_id)
        .await?;

    let mut csv = String::new();

    csv += "Score, I think that I would like to use this system frequently, I found the system unnecessarily complex, I thought the system was easy to use, I think that I would need the support of a technical person to be able to use this system, I found the various functions in this system were well integrated, I thought there was too much inconsistency in this system, I would imagine that most people would learn to use this system very quickly, I found the system very cumbersome to use, I felt very confident using the system, I needed to learn a lot of things before I could get going with this system\n";

    for response in responses {
        csv += &format!(
            "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\n",
            response.score,
            response.scores[0],
            response.scores[1],
            response.scores[2],
            response.scores[3],
            response.scores[4],
            response.scores[5],
            response.scores[6],
            response.scores[7],
            response.scores[8],
            response.scores[9]
        );
    }

    let headers = create_csv_download_headers(&survey_id)?;

    Ok((headers, csv).into_response())
}
