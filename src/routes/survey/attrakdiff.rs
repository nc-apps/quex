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

/// The HTML template for the AttrakDiff survey
#[derive(Template)]
#[template(path = "surveys/responses/attrakdiff.html")]
struct AttrakDiffTemplate {
    id: Arc<str>,
    questions: Vec<(String, String)>,
}

/// Handler for the AttrakDiff survey page
pub(super) fn get_page(id: Arc<str>, language: &LanguageIdentifier) -> askama_axum::Response {
    let translate = |key: &str| crate::translate(key, language);
    let attrakdiff_template = AttrakDiffTemplate {
        id,
        questions: vec![
            (
                translate("attrakdiff-human"),
                translate("attrakdiff-technical"),
            ),
            (
                translate("attrakdiff-isolating"),
                translate("attrakdiff-connective"),
            ),
            (
                translate("attrakdiff-pleasant"),
                translate("attrakdiff-unpleasant"),
            ),
            (
                translate("attrakdiff-inventive"),
                translate("attrakdiff-conventional"),
            ),
            (
                translate("attrakdiff-simple"),
                translate("attrakdiff-complicated"),
            ),
            (
                translate("attrakdiff-professional"),
                translate("attrakdiff-unprofessional"),
            ),
            (
                translate("attrakdiff-ugly"),
                translate("attrakdiff-attractive"),
            ),
            (
                translate("attrakdiff-practical"),
                translate("attrakdiff-impractical"),
            ),
            (
                translate("attrakdiff-likable"),
                translate("attrakdiff-disagreeable"),
            ),
            (
                translate("attrakdiff-cumbersome"),
                translate("attrakdiff-straightforward"),
            ),
            (
                translate("attrakdiff-stylish"),
                translate("attrakdiff-tacky"),
            ),
            (
                translate("attrakdiff-predictable"),
                translate("attrakdiff-unpredictable"),
            ),
            (
                translate("attrakdiff-cheap"),
                translate("attrakdiff-premium"),
            ),
            (
                translate("attrakdiff-alienating"),
                translate("attrakdiff-integrating"),
            ),
            (
                translate("attrakdiff-brings-me-closer-to-people"),
                translate("attrakdiff-separates-me-from-people"),
            ),
            (
                translate("attrakdiff-unpresentable"),
                translate("attrakdiff-presentable"),
            ),
            (
                translate("attrakdiff-rejecting"),
                translate("attrakdiff-inviting"),
            ),
            (
                translate("attrakdiff-unimaginative"),
                translate("attrakdiff-creative"),
            ),
            (translate("attrakdiff-good"), translate("attrakdiff-bad")),
            (
                translate("attrakdiff-confusing"),
                translate("attrakdiff-clearly-structured"),
            ),
            (
                translate("attrakdiff-repelling"),
                translate("attrakdiff-appealing"),
            ),
            (
                translate("attrakdiff-bold"),
                translate("attrakdiff-cautious"),
            ),
            (
                translate("attrakdiff-innovative"),
                translate("attrakdiff-conservative"),
            ),
            (
                translate("attrakdiff-dull"),
                translate("attrakdiff-captivating"),
            ),
            (
                translate("attrakdiff-undemanding"),
                translate("attrakdiff-challenging"),
            ),
            (
                translate("attrakdiff-motivating"),
                translate("attrakdiff-discouraging"),
            ),
            (
                translate("attrakdiff-novel"),
                translate("attrakdiff-ordinary"),
            ),
            (
                translate("attrakdiff-unruly"),
                translate("attrakdiff-manageable"),
            ),
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
    PreferredLanguage(language): PreferredLanguage,
    name: Option<String>,
) -> Result<Redirect, CreateSurveyError> {
    let survey_id = nanoid!();

    let name: Arc<str> = match name.as_deref() {
        // Use the first 6 characters of the survey id as the name if no name is provided
        Some("") | None => format!(
            "AttrakDiff {} {}",
            crate::translate("Survey", &language),
            &survey_id[..7]
        )
        .into(),
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
    language: LanguageIdentifier,
}

impl IntoResponse for GetResultsPageError {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error getting results page: {}", self);
        Redirect::to("/error").into_response()
    }
}

/// Gets the details page that displays the results of the survey and gives insights to the responses
pub(super) async fn get_results_page(
    State(state): State<AppState>,
    Path(survey_id): Path<Arc<str>>,
    user: AuthenticatedUser,
    PreferredLanguage(language): PreferredLanguage,
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

    let headers = create_csv_download_headers(&survey_id)?;

    Ok((headers, csv).into_response())
}
