use crate::auth::authenticated_user::AuthenticatedUser;
use crate::database::{MultiRowQueryError, SingleRowQueryError, StatementError};
use crate::routes::create_share_link;
use crate::routes::survey::get_file_name;
use crate::AppState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{Path, State};
use axum::http::{self, HeaderMap};
use axum::response::Redirect;
use axum::Form;
use nanoid::nanoid;
use reqwest::header::HeaderValue;
use reqwest::{header, StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use time::OffsetDateTime;

use super::{CreateSurveyError, DownloadResultsError, GetResultsPageError};

/// The HTML template for the AttrakDiff survey
#[derive(Template)]
#[template(path = "surveys/responses/attrakdiff.html")]
struct AttrakDiffTemplate {
    id: Arc<str>,
    questions: Vec<(String, String)>,
}

/// Handler for the AttrakDiff survey page
pub(super) fn get_page(id: Arc<str>) -> askama_axum::Response {
    let attrakdiff_template = AttrakDiffTemplate {
        id,
        questions: vec![
            ("Human".to_string(), "Technical".to_string()),
            ("Isolating".to_string(), "Connective".to_string()),
            ("Pleasant".to_string(), "Unpleasant".to_string()),
            ("Inventive".to_string(), "Conventional".to_string()),
            ("Simple".to_string(), "Complicated".to_string()),
            ("Professional".to_string(), "Unprofessional".to_string()),
            ("Ugly".to_string(), "Attractive".to_string()),
            ("Practical".to_string(), "Impractical".to_string()),
            ("Likable".to_string(), "Disagreeable".to_string()),
            ("Cumbersome".to_string(), "Straightforward".to_string()),
            ("Stylish".to_string(), "Tacky".to_string()),
            ("Predictable".to_string(), "Unpredictable".to_string()),
            ("Cheap".to_string(), "Premium".to_string()),
            ("Alienating".to_string(), "Integrating".to_string()),
            (
                "Brings me closer to people".to_string(),
                "Separates me from people".to_string(),
            ),
            ("Unpresentable".to_string(), "Presentable".to_string()),
            ("Rejecting".to_string(), "Inviting".to_string()),
            ("Unimaginative".to_string(), "Creative".to_string()),
            ("Good".to_string(), "Bad".to_string()),
            ("Confusing".to_string(), "Clearly structured".to_string()),
            ("Repelling".to_string(), "Appealing".to_string()),
            ("Bold".to_string(), "Cautious".to_string()),
            ("Innovative".to_string(), "Conservative".to_string()),
            ("Dull".to_string(), "Captivating".to_string()),
            ("Undemanding".to_string(), "Challenging".to_string()),
            ("Motivating".to_string(), "Discouraging".to_string()),
            ("Novel".to_string(), "Ordinary".to_string()),
            ("Unruly".to_string(), "Manageable".to_string()),
        ],
    };

    attrakdiff_template.into_response()
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
    #[serde(rename = "Q11")]
    pub(crate) q11: u8,
    #[serde(rename = "Q12")]
    pub(crate) q12: u8,
    #[serde(rename = "Q13")]
    pub(crate) q13: u8,
    #[serde(rename = "Q14")]
    pub(crate) q14: u8,
    #[serde(rename = "Q15")]
    pub(crate) q15: u8,
    #[serde(rename = "Q16")]
    pub(crate) q16: u8,
    #[serde(rename = "Q17")]
    pub(crate) q17: u8,
    #[serde(rename = "Q18")]
    pub(crate) q18: u8,
    #[serde(rename = "Q19")]
    pub(crate) q19: u8,
    #[serde(rename = "Q20")]
    pub(crate) q20: u8,
    #[serde(rename = "Q21")]
    pub(crate) q21: u8,
    #[serde(rename = "Q22")]
    pub(crate) q22: u8,
    #[serde(rename = "Q23")]
    pub(crate) q23: u8,
    #[serde(rename = "Q24")]
    pub(crate) q24: u8,
    #[serde(rename = "Q25")]
    pub(crate) q25: u8,
    #[serde(rename = "Q26")]
    pub(crate) q26: u8,
    #[serde(rename = "Q27")]
    pub(crate) q27: u8,
    #[serde(rename = "Q28")]
    pub(crate) q28: u8,
}

/// Handler that creates a response from an attrakdiff survey response
pub(super) async fn create_response(
    State(state): State<AppState>,
    Form(response): Form<Response>,
    survey_id: Arc<str>,
) -> Result<Redirect, StatementError> {
    let response_id = nanoid!();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    state
        .database
        .insert_attrakdiff_response(&survey_id, &response_id, now, response)
        .await?;

    tracing::debug!("Inserted into database");

    Ok(Redirect::to("/thanks"))
}

/// Handler that creates a new AttrakDiff survey from a create survey form submission
pub(super) async fn create_new_survey(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    name: Option<String>,
) -> Result<Redirect, CreateSurveyError> {
    let survey_id = nanoid!();

    let name: Arc<str> = match name.as_deref() {
        // Use the first 6 characters of the survey id as the name if no name is provided
        Some("") | None => format!("AttrakDiff Survey {}", &survey_id[..7]).into(),
        Some(name) => name.into(),
    };

    // Create timestamp
    // We could use the database timestamp, but I prefer to have the application dictate the time in
    // case something goes wrong
    let now = OffsetDateTime::now_utc().unix_timestamp();

    state
        .database
        .insert_attrakdiff_survey(&survey_id, &user.id, &name, now)
        .await?;

    // Redirect to newly created survey overview
    Ok(Redirect::to(format!("/surveys/ad/{}", survey_id).as_ref()))
}

//TODO consider renaming to evaluation or something more fitting
/// The HTML template for the AttrakDiff survey details and results page
#[derive(Template)]
#[template(path = "surveys/results/attrakdiff.html")]
struct AttrakdiffResultsTemplate {
    id: Arc<str>,
    name: Arc<str>,
    responses: Vec<[i32; 28]>,
    /// The url that can be used to share the survey with respondents
    survey_url: String,
}

impl IntoResponse for GetResultsPageError {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error getting results page: {}", self);
        http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

/// Gets the details page that displays the results of the survey and gives insights to the responses
pub(super) async fn get_results_page(
    State(state): State<AppState>,
    Path(survey_id): Path<Arc<str>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, GetResultsPageError> {
    // This also checks if the user has access to the survey
    let survey_name = state
        .database
        .get_attrakdiff_survey_name(&survey_id, &user.id)
        .await
        .map_err(GetResultsPageError::GetSurveyError)?;

    let Some(survey_name) = survey_name else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let responses = state
        .database
        .get_attrakdiff_survey_responses(&survey_id)
        .await
        .map_err(GetResultsPageError::GetSurveyResponsesError)?;

    let survey_url = create_share_link(&state.configuration.server_url, &survey_id);
    Ok(AttrakdiffResultsTemplate {
        id: survey_id,
        name: survey_name,
        responses,
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
        .get_attrakdiff_survey_name(&survey_id, &user.id)
        .await
        .map_err(DownloadResultsError::GetSurveyError)?;

    if survey_name.is_none() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    //TODO check if this file can be streamed line by line and row by row
    let responses = state
        .database
        .get_attrakdiff_survey_responses(&survey_id)
        .await
        .map_err(DownloadResultsError::GetSurveyResponsesError)?;

    let mut csv = String::new();

    csv += "Human-Technical, Isolating-Connective, Pleasant-Unpleasant, Inventive-Conventional, Simple-Complicated, Professional-Unprofessional, Ugly-Attractive, Practical-Impractical, Likable-Disagreeable, Cumbersome-Straightforward, Stylish-Tacky, Predictable-Unpredictable, Cheap-Premium, Alienating-Integrating, Brings me closer to people-Separates me from people, Unpresentable-Respondents, Rejecting-Inviting, Unimaginative-Creative, Good-Bad, Confusing-Clearly structured, Repelling-Appealing, Bold-Cautious, Innovative-Conservative, Dull-Captivating, Undemanding-Challenging, Motivating-Discouraging, Novel-Ordinary, Unruly-Manageable\n";

    for response in responses {
        for answer in response {
            csv += &format!("{}, ", answer);
        }
        // Pop the trailing comma and space
        csv.pop();
        csv.pop();
        csv.push('\n');
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
