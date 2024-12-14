use crate::auth::authenticated_user::AuthenticatedUser;
use crate::AppState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{FromRequest, Path, Request, State};
use axum::response::{Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use libsql::{named_params, Connection};
use serde::Deserialize;
use std::fmt::Debug;
use std::sync::Arc;
use time::OffsetDateTime;

mod attrakdiff;
mod net_promoter_score;
mod system_usability_score;

/// Creates a router for the surveys sub-routes.
/// This enables us to only expose the router creation and don't need to expose the individual
/// routes and their handlers to the rest of the application.
pub(crate) fn create_router() -> Router<AppState> {
    let survey_routes = Router::new()
        .route("/nps", post(net_promoter_score::create_new_survey))
        .route("/nps/:id", get(net_promoter_score::get_results_page))
        .route("/sus", post(system_usability_score::create_new_survey))
        .route("/sus/:id", get(system_usability_score::get_results_page))
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

/// Represents a survey in the surveys overview page and list.
struct Survey {
    id: String,
    name: String,
    created_human_readable: String,
    created_machine_readable: String,
}

/// Contains vectors for each survey type with the survey ids
#[derive(Default)]
struct Surveys {
    attrakdiff: Vec<Survey>,
    net_promoter_score: Vec<Survey>,
    system_usability_score: Vec<Survey>,
}

/// The HTML template for the surveys overview page
#[derive(Template)]
#[template(path = "surveys/index.html")]
struct SurveysTemplate {
    surveys: Surveys,
}

/// Handler for the surveys overview page. Loads all surveys for the user and displays them.
async fn get_surveys_page(
    user: AuthenticatedUser,
    State(app_state): State<AppState>,
) -> Result<askama_axum::Response, Redirect> {
    const GET_USER_SURVEYS_QUERY: &str = "SELECT type, id, name, created_at_utc FROM (
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
                // Load type
                let result: Result<String, libsql::Error> = row.get(0);
                let survey_type = match result {
                    Ok(survey_type) => survey_type,
                    Err(error) => {
                        tracing::error!("Error reading survey id: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Err(Redirect::to("/surveys/error"));
                    }
                };

                // Load id
                let result: Result<String, libsql::Error> = row.get(1);
                let id = match result {
                    Ok(id) => id,
                    Err(error) => {
                        tracing::error!("Error reading survey id: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Err(Redirect::to("/surveys/error"));
                    }
                };

                // Load survey name
                let result: Result<String, libsql::Error> = row.get(2);
                let name = match result {
                    Ok(name) => name,
                    Err(error) => {
                        tracing::error!("Error reading survey name: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Err(Redirect::to("/surveys/error"));
                    }
                };

                //TODO load created_at_utc to display date created to user
                let result: Result<i64, libsql::Error> = row.get(3);
                let created_at_utc = match result {
                    Ok(created_at_utc) => created_at_utc,
                    Err(error) => {
                        tracing::error!("Error reading survey created_at_utc: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Err(Redirect::to("/surveys/error"));
                    }
                };

                let result = OffsetDateTime::from_unix_timestamp(created_at_utc);
                let created_at_utc = match result {
                    Ok(created_at_utc) => created_at_utc,
                    Err(error) => {
                        tracing::error!(
                            "Error converting created_at_utc to OffsetDateTime: {:?}",
                            error
                        );
                        //TODO display user error message it's not their fault
                        return Err(Redirect::to("/surveys/error"));
                    }
                };

                // More information on the correct datetime format
                // - https://html.spec.whatwg.org/multipage/text-level-semantics.html#datetime-value
                // - https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#valid-local-date-and-time-string
                // ISO 8601 format should be fine though 🥴
                let machine_formatted_date = match created_at_utc
                    .format(&time::format_description::well_known::Iso8601::DEFAULT)
                {
                    Ok(date) => date,
                    Err(error) => {
                        tracing::error!("Error formatting date: {:?}", error);
                        //TODO display user error message it's not their fault
                        return Err(Redirect::to("/surveys/error"));
                    }
                };

                let survey = Survey {
                    id,
                    name,
                    //TODO add user timezone offset
                    created_human_readable: format_date(created_at_utc),
                    created_machine_readable: machine_formatted_date,
                };

                match survey_type.as_str() {
                    "attrakdiff" => surveys.attrakdiff.push(survey),
                    "net promoter score" => surveys.net_promoter_score.push(survey),
                    "system usability score" => surveys.system_usability_score.push(survey),
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

/// SQL query to get a single survey from the database by id
const GET_SURVEY_QUERY: &str = "SELECT * FROM (
            SELECT 'attrakdiff' as type, * FROM attrakdiff_surveys
            UNION ALL
            SELECT 'net promoter score' as type, * FROM net_promoter_score_surveys
            UNION ALL
            SELECT 'system usability score' as type, * FROM system_usability_score_surveys
        )
            WHERE id = :survey_id";

/// Survey type for a get/create surveys and create responses to a survey
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
            Ok(attrakdiff::create_response(state, form, survey_id).await)
        }
        SurveyType::NetPromoterScore => {
            let form = Form::<net_promoter_score::Response>::from_request(request, &state)
                .await
                .map_err(|error| error.into_response())?;
            Ok(net_promoter_score::create_response(state, form, survey_id).await)
        }
        SurveyType::SystemUsabilityScore => {
            let form = Form::<system_usability_score::Response>::from_request(request, &state)
                .await
                .map_err(|error| error.into_response())?;
            Ok(system_usability_score::create_response(state, form, survey_id).await)
        }
    }
}

/// Handler to get the form page for a specific survey for respondents to submit their responses
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
        SurveyType::Attrakdiff => attrakdiff::get_page(survey_id),
        SurveyType::NetPromoterScore => net_promoter_score::get_page(survey_id),
        SurveyType::SystemUsabilityScore => system_usability_score::get_page(survey_id),
    })
}

#[derive(Template)]
#[template(path = "surveys/new.html")]
struct NewSurveyTemplate;

async fn get_new_survey_page() -> impl IntoResponse {
    NewSurveyTemplate {}.into_response()
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
        SurveyType::NetPromoterScore => {
            net_promoter_score::create_new_survey(state, user, request.name).await
        }
        SurveyType::SystemUsabilityScore => {
            system_usability_score::create_new_survey(state, user, request.name).await
        }
    }
}

#[derive(Template)]
#[template(path = "thanks.html")]
struct ThanksTemplate {}

async fn thanks() -> impl IntoResponse {
    ThanksTemplate {}.into_response()
}

fn format_date(date: OffsetDateTime) -> String {
    // The icu example
    use icu::calendar::{DateTime, Gregorian};
    use icu::datetime::{options::length, DateTimeFormatterOptions, TypedDateTimeFormatter};
    use icu::locid::locale;

    // See the next code example for a more ergonomic example with .into().
    let options = DateTimeFormatterOptions::Length(length::Bag::from_date_time_style(
        length::Date::Medium,
        length::Time::Short,
    ));

    // Can use DateFormatter alternatively to dynamically format date based on accept-language header (see icu crate examples)
    // This uses unicode locale identifiers which might not line up with accept language header but should 99% of the time
    let formatter = TypedDateTimeFormatter::<Gregorian>::try_new(&locale!("en-US").into(), options)
        .expect("Failed to create TypedDateTimeFormatter instance.");

    let date = DateTime::try_new_gregorian_datetime(
        date.year(),
        date.month().into(),
        date.day(),
        date.hour(),
        date.minute(),
        date.second(),
    )
    .unwrap();

    let formatted = formatter.format(&date);

    let date_string = formatter.format_to_string(&date);
    date_string
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
    let dtf = DateTimeFormatter::try_new(&locale.into(), options.clone())
        .expect("Failed to create DateTimeFormatter instance.");

    // Or one that selects a calendar at compile time:
    let typed_dtf = TypedDateTimeFormatter::<Gregorian>::try_new(&locale!("en").into(), options)
        .expect("Failed to create TypedDateTimeFormatter instance.");

    let typed_date = DateTime::try_new_gregorian_datetime(2020, 9, 12, 12, 34, 28).unwrap();
    // prefer using ISO dates with DateTimeFormatter
    let date = typed_date.to_iso().to_any();

    let formatted_date = dtf.format(&date).expect("Calendars should match");
    let typed_formatted_date = typed_dtf.format(&typed_date);

    let formatted_date_string = dtf.format_to_string(&date).expect("Calendars should match");
    let typed_formatted_date_string = typed_dtf.format_to_string(&typed_date);

    assert_eq!(formatted_date_string, "Sep 12, 2020, 12:34 PM");
    assert_eq!(typed_formatted_date_string, "Sep 12, 2020, 12:34 PM");
}
