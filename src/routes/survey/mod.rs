use crate::auth::authenticated_user::AuthenticatedUser;
use crate::database::{
    MultiRowQueryError, SingleRowQueryError, StatementError, Survey, SurveyType, Surveys,
};
use crate::preferred_language::PreferredLanguage;
use crate::{database, AppState};
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::rejection::FormRejection;
use axum::extract::{FromRequest, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use reqwest::header::{self, InvalidHeaderValue};
use serde::Deserialize;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use time::OffsetDateTime;
use unic_langid::LanguageIdentifier;

pub(crate) mod attrakdiff;
pub(crate) mod net_promoter_score;
pub(crate) mod system_usability_score;

/// Creates a router for the surveys sub-routes.
/// This enables us to only expose the router creation and don't need to expose the individual
/// routes and their handlers to the rest of the application.
pub(crate) fn create_router() -> Router<AppState> {
    let survey_routes = Router::new()
        .route("/nps", post(net_promoter_score::create_new_survey))
        .route("/nps/:id", get(net_promoter_score::get_results_page))
        .route(
            "/nps/:id/download",
            get(net_promoter_score::download_results),
        )
        .route("/sus", post(system_usability_score::create_new_survey))
        .route("/sus/:id", get(system_usability_score::get_results_page))
        .route(
            "/sus/:id/download",
            get(system_usability_score::download_results),
        )
        .route("/ad", post(attrakdiff::create_new_survey))
        .route("/ad/:id", get(attrakdiff::get_results_page))
        .route("/ad/:id/download", get(attrakdiff::download_results));

    Router::new()
        .route("/surveys", get(get_surveys_page))
        .route("/surveys/new", get(get_new_survey_page).post(create_survey))
        .nest("/surveys", survey_routes)
        // These are the public endpoints that respondents can use to access a questionnaire
        // and submit their responses.
        // There are multiple things to reduce friction for respondents:
        // 1. They don't need an account/sign in to access the survey
        // 2. They don't need a long URL to access the survey. The survey id is enough
        // Additionally the survey type is not leaked in the URL to avoid biasing the responses
        // The /q/ is necessary as it would otherwise catch all requests that to files that the router
        // doesn't know about. It would lead to CSS and JS not being served
        .route("/thanks", get(thanks))
        .route("/q/:survey_id", get(get_survey_page).post(create_response))
}

struct Entry {
    survey: Survey,
    created_human_readable: String,
    created_machine_readable: String,
}
/// The HTML template for the surveys overview page
#[derive(Template)]
#[template(path = "surveys/index.html")]
struct SurveysTemplate {
    attrakdiff_surveys: Vec<Entry>,
    net_promoter_score_surveys: Vec<Entry>,
    system_usability_score_surveys: Vec<Entry>,
    language: LanguageIdentifier,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum GetSurveysPageError {
    #[error("Error reading surveys from database: {0}")]
    Database(#[from] database::GetUserSurveysError),
    #[error("Error formatting date")]
    Format(#[from] time::error::Format),
    #[error("Error formatting date for humans: {0}")]
    HumanReadableDate(#[from] FormatDateError),
}

impl IntoResponse for GetSurveysPageError {
    fn into_response(self) -> Response {
        tracing::error!("Error getting surveys page: {:?}", self);
        Redirect::to("/error").into_response()
    }
}

/// Handler for the surveys overview page. Loads all surveys for the user and displays them.
async fn get_surveys_page(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    PreferredLanguage(language): PreferredLanguage,
) -> Result<SurveysTemplate, GetSurveysPageError> {
    let Surveys {
        attrakdiff,
        net_promoter_score,
        system_usability_score,
    } = state.database.get_user_surveys(&user.id).await?;

    // More information on the correct datetime format
    // - https://html.spec.whatwg.org/multipage/text-level-semantics.html#datetime-value
    // - https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#valid-local-date-and-time-string
    // ISO 8601 format should be fine though 🥴

    let to_entry = |survey: Survey| -> Result<Entry, GetSurveysPageError> {
        Ok(Entry {
            created_human_readable: format_date(survey.created_at_utc, &language)?,
            created_machine_readable: survey
                .created_at_utc
                .format(&time::format_description::well_known::Iso8601::DEFAULT)?,
            survey,
        })
    };

    let attrakdiff_surveys = attrakdiff
        .into_iter()
        .map(to_entry)
        .collect::<Result<Vec<_>, _>>()?;

    let net_promoter_score_surveys = net_promoter_score
        .into_iter()
        .map(to_entry)
        .collect::<Result<Vec<_>, _>>()?;

    let system_usability_score_surveys = system_usability_score
        .into_iter()
        .map(to_entry)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(SurveysTemplate {
        attrakdiff_surveys,
        net_promoter_score_surveys,
        system_usability_score_surveys,
        language,
    })
}

#[derive(thiserror::Error, Debug)]
enum CreateResponseError {
    #[error("Error reading survey from database: {0}")]
    GetData(#[from] database::GetSurveyError),
    #[error("Error creating response: {0}")]
    Insert(#[from] StatementError),
    #[error("Error deserializing form values for survey type {0:?} response: {1}")]
    Form(SurveyType, FormRejection),
}

impl IntoResponse for CreateResponseError {
    fn into_response(self) -> Response {
        tracing::error!("Error creating response: {:?}", self);
        Redirect::to("/error").into_response()
    }
}

/// Handler for the public endpoint where respondents submit their responses
async fn create_response(
    state: State<AppState>,
    Path(survey_id): Path<Arc<str>>,
    request: Request,
) -> Result<Redirect, CreateResponseError> {
    // Get survey type to check if it even exists
    let survey = state.database.get_survey_type(&survey_id).await?;

    // Check if survey exists
    let Some(survey_type) = survey else {
        tracing::warn!("User submitted a response to survey {survey_id} that doesn't exist");
        // User submitted a response to a survey that doesn't exist meaning they opened an invalid survey before or are possibly acting maliciously
        // This doesn't happen normally but if it happens we say thanks anyway since they put in
        // the effort
        return Ok(Redirect::to("/thanks"));
    };

    // Forward survey to correct survey page response handler
    match survey_type {
        SurveyType::Attrakdiff => {
            let form = Form::<attrakdiff::Response>::from_request(request, &state)
                .await
                .map_err(|error| CreateResponseError::Form(SurveyType::Attrakdiff, error))?;

            attrakdiff::create_response(state, form, survey_id)
                .await
                .map_err(CreateResponseError::Insert)
        }
        SurveyType::NetPromoterScore => {
            let form = Form::<net_promoter_score::Response>::from_request(request, &state)
                .await
                .map_err(|error| CreateResponseError::Form(SurveyType::NetPromoterScore, error))?;

            net_promoter_score::create_response(state, form, survey_id)
                .await
                .map_err(CreateResponseError::Insert)
        }
        SurveyType::SystemUsabilityScore => {
            let form = Form::<system_usability_score::Response>::from_request(request, &state)
                .await
                .map_err(|error| {
                    CreateResponseError::Form(SurveyType::SystemUsabilityScore, error)
                })?;

            system_usability_score::create_response(state, form, survey_id)
                .await
                .map_err(CreateResponseError::Insert)
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum GetSurveyError {
    #[error("Error getting survey: {0}")]
    DatabaseError(#[from] database::GetSurveyError),
}

impl IntoResponse for GetSurveyError {
    fn into_response(self) -> Response {
        tracing::error!("Error getting survey: {:?}", self);
        Redirect::to("/error").into_response()
    }
}

/// Handler to get the form page for a specific survey for respondents to submit their responses
async fn get_survey_page(
    State(state): State<AppState>,
    Path(survey_id): Path<Arc<str>>,
) -> Result<Response, GetSurveyError> {
    // Get survey to check if it even exists
    let survey_type = state.database.get_survey_type(&survey_id).await?;

    // Check if survey exists
    let Some(survey_type) = survey_type else {
        // Survey not found
        return Ok(Redirect::to("/surveys/notfound").into_response());
    };

    Ok(match survey_type {
        SurveyType::Attrakdiff => attrakdiff::get_page(survey_id),
        SurveyType::NetPromoterScore => net_promoter_score::get_page(survey_id),
        SurveyType::SystemUsabilityScore => system_usability_score::get_page(survey_id),
    })
}

#[derive(Template)]
#[template(path = "surveys/new.html")]
struct NewSurveyTemplate {
    language: LanguageIdentifier,
}

async fn get_new_survey_page(PreferredLanguage(language): PreferredLanguage) -> impl IntoResponse {
    NewSurveyTemplate { language }.into_response()
}

#[derive(Deserialize, Debug)]
struct CreateSurveyRequest {
    /// The name of the survey. It is optional to reduce user friction, and we crate a random name if
    /// it is not provided.
    name: Option<String>,
    r#type: SurveyType,
}

#[derive(thiserror::Error, Debug)]
pub(super) enum CreateSurveyError {
    #[error("Error creating survey: {0}")]
    Database(#[from] StatementError),
}

impl IntoResponse for CreateSurveyError {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error creating survey: {}", self);
        Redirect::to("/error").into_response()
    }
}

async fn create_survey(
    state: State<AppState>,
    user: AuthenticatedUser,
    Form(request): Form<CreateSurveyRequest>,
) -> Result<Redirect, CreateSurveyError> {
    match request.r#type {
        SurveyType::Attrakdiff => attrakdiff::create_new_survey(state, user, request.name).await,
        SurveyType::NetPromoterScore => {
            net_promoter_score::create_new_survey(state, user, request.name).await
        }
        SurveyType::SystemUsabilityScore => {
            system_usability_score::create_new_survey(state, user, request.name).await
        }
    }
}

#[derive(Template)]
#[template(path = "surveys/responses/thanks.html")]
struct ThanksTemplate {}

async fn thanks() -> impl IntoResponse {
    ThanksTemplate {}.into_response()
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum FormatDateError {
    #[error("Error creating formatter: {0}")]
    CreateFormatter(icu::datetime::DateTimeError),
    #[error("Error formatting date: {0}")]
    Format(icu::calendar::CalendarError),
}

pub(crate) fn format_date(
    date: OffsetDateTime,
    identifier: &LanguageIdentifier,
) -> Result<String, FormatDateError> {
    // The icu example
    use icu::calendar::{DateTime, Gregorian};
    use icu::datetime::{options::length, DateTimeFormatterOptions, TypedDateTimeFormatter};
    use icu::locid::locale;

    // See the next code example for a more ergonomic example with .into().
    let options = DateTimeFormatterOptions::Length(length::Bag::from_date_time_style(
        length::Date::Medium,
        length::Time::Short,
    ));

    // There is probably a way to use the identifier directly
    let language = identifier.language.as_str();
    let locale = icu::locid::Locale::from_str(language)
        .inspect_err(|error| tracing::error!("Error parsing locale \"{}\": {}", language, error))
        .unwrap_or(locale!("en-US"));

    // Can use DateFormatter alternatively to dynamically format date based on accept-language header (see icu crate examples)
    // This uses unicode locale identifiers which might not line up with accept language header but should 99% of the time
    let formatter = TypedDateTimeFormatter::<Gregorian>::try_new(&locale.into(), options)
        .map_err(FormatDateError::CreateFormatter)?;

    let date = DateTime::try_new_gregorian_datetime(
        date.year(),
        date.month().into(),
        date.day(),
        date.hour(),
        date.minute(),
        date.second(),
    )
    .map_err(FormatDateError::Format)?;

    // let formatted = formatter.format(&date);

    Ok(formatter.format_to_string(&date))
}

#[test]
fn format_date_test() {
    // The icu crate example
    use icu::calendar::{DateTime, Gregorian};
    use icu::datetime::{
        options::length, DateTimeFormatter, DateTimeFormatterOptions, TypedDateTimeFormatter,
    };
    use icu::locid::{locale, Locale};
    use std::str::FromStr;

    // See the next code example for a more ergonomic example with .into().
    let options = DateTimeFormatterOptions::Length(length::Bag::from_date_time_style(
        length::Date::Medium,
        length::Time::Short,
    ));

    // You can work with a formatter that can select the calendar at runtime:
    let locale = Locale::from_str("en-u-ca-gregory").unwrap();
    let dtf = DateTimeFormatter::try_new(&locale.into(), options)
        .expect("Failed to create DateTimeFormatter instance.");

    // Or one that selects a calendar at compile time:
    let typed_dtf = TypedDateTimeFormatter::<Gregorian>::try_new(&locale!("en").into(), options)
        .expect("Failed to create TypedDateTimeFormatter instance.");

    let typed_date = DateTime::try_new_gregorian_datetime(2020, 9, 12, 12, 34, 28).unwrap();
    // prefer using ISO dates with DateTimeFormatter
    let date = typed_date.to_iso().to_any();

    let _formatted_date = dtf.format(&date).expect("Calendars should match");
    let _typed_formatted_date = typed_dtf.format(&typed_date);

    let formatted_date_string = dtf.format_to_string(&date).expect("Calendars should match");
    let typed_formatted_date_string = typed_dtf.format_to_string(&typed_date);

    assert_eq!(formatted_date_string, "Sep 12, 2020, 12:34 PM");
    assert_eq!(typed_formatted_date_string, "Sep 12, 2020, 12:34 PM");
}

pub(crate) fn get_file_name(survey_id: &str) -> String {
    // The survey id should be URL safe and ASCII only by default
    assert!(survey_id.is_ascii());
    format!("survey responses {}.csv", survey_id)
}

#[derive(thiserror::Error, Debug)]
enum GetResultsPageError {
    #[error("Error getting survey: {0}")]
    GetSurveyError(SingleRowQueryError),
    #[error("Error getting survey responses: {0}")]
    GetSurveyResponsesError(MultiRowQueryError),
}

#[derive(thiserror::Error, Debug)]
enum DownloadResultsError {
    #[error("Error getting survey: {0}")]
    GetSurveyError(#[from] SingleRowQueryError),

    #[error("Error getting survey responses: {0}")]
    GetSurveyResponsesError(#[from] MultiRowQueryError),

    #[error("Invalid survey id characters for header value: {0}")]
    InvalidSurveyId(#[from] InvalidHeaderValue),
}

impl IntoResponse for DownloadResultsError {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error downloading results: {}", self);
        Redirect::to("/error").into_response()
    }
}

fn create_csv_download_headers(survey_id: &str) -> Result<HeaderMap, InvalidHeaderValue> {
    let mut headers = HeaderMap::new();
    const TEXT_CSV: HeaderValue = HeaderValue::from_static("text/csv");
    headers.insert(header::CONTENT_TYPE, TEXT_CSV);
    // The survey id should be URL safe and ASCII only by default
    let value = format!("attachment; filename=\"{}\"", get_file_name(survey_id));
    let value = HeaderValue::try_from(value)?;
    headers.insert(header::CONTENT_DISPOSITION, value);

    Ok(headers)
}
