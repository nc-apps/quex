use crate::auth::authenticated_user::AuthenticatedUser;
use crate::routes::create_share_link;
use crate::AppState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{Path, State};
use axum::response::Redirect;
use axum::Form;
use libsql::named_params;
use nanoid::nanoid;
use serde::Deserialize;
use std::sync::Arc;
use time::OffsetDateTime;

/// The HTML template for the AttrakDiff survey
#[derive(Template)]
#[template(path = "attrakdiff.html")]
struct AttrakDiffTemplate {
    id: String,
    questions: Vec<(String, String)>,
}

/// Handler for the AttrakDiff survey page
pub(super) fn get_page(id: String) -> askama_axum::Response {
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
pub(super) struct Response {
    #[serde(rename = "Q1")]
    q1: u8,
    #[serde(rename = "Q2")]
    q2: u8,
    #[serde(rename = "Q3")]
    q3: u8,
    #[serde(rename = "Q4")]
    q4: u8,
    #[serde(rename = "Q5")]
    q5: u8,
    #[serde(rename = "Q6")]
    q6: u8,
    #[serde(rename = "Q7")]
    q7: u8,
    #[serde(rename = "Q8")]
    q8: u8,
    #[serde(rename = "Q9")]
    q9: u8,
    #[serde(rename = "Q10")]
    q10: u8,
    #[serde(rename = "Q11")]
    q11: u8,
    #[serde(rename = "Q12")]
    q12: u8,
    #[serde(rename = "Q13")]
    q13: u8,
    #[serde(rename = "Q14")]
    q14: u8,
    #[serde(rename = "Q15")]
    q15: u8,
    #[serde(rename = "Q16")]
    q16: u8,
    #[serde(rename = "Q17")]
    q17: u8,
    #[serde(rename = "Q18")]
    q18: u8,
    #[serde(rename = "Q19")]
    q19: u8,
    #[serde(rename = "Q20")]
    q20: u8,
    #[serde(rename = "Q21")]
    q21: u8,
    #[serde(rename = "Q22")]
    q22: u8,
    #[serde(rename = "Q23")]
    q23: u8,
    #[serde(rename = "Q24")]
    q24: u8,
    #[serde(rename = "Q25")]
    q25: u8,
    #[serde(rename = "Q26")]
    q26: u8,
    #[serde(rename = "Q27")]
    q27: u8,
    #[serde(rename = "Q28")]
    q28: u8,
}

/// Handler that creates a response from an attrakdiff survey response
pub(super) async fn create_response(
    State(app_state): State<AppState>,
    Form(attrakdiff_answers): Form<Response>,
    survey_id: String,
) -> Redirect {
    tracing::debug!("Answers for AttrakDiff: {:?}", attrakdiff_answers);
    let response_id = nanoid!();

    app_state
        .connection
        .execute(
            // insert answers 1 to 28 into database
            "INSERT INTO attrakdiff_responses (
                id,
                survey_id,
                answer_1,
                answer_2,
                answer_3,
                answer_4,
                answer_5,
                answer_6,
                answer_7,
                answer_8,
                answer_9,
                answer_10,
                answer_11,
                answer_12,
                answer_13,
                answer_14,
                answer_15,
                answer_16,
                answer_17,
                answer_18,
                answer_19,
                answer_20,
                answer_21,
                answer_22,
                answer_23,
                answer_24,
                answer_25,
                answer_26,
                answer_27,
                answer_28
            ) VALUES (
                ?1,
                ?2,
                ?3,
                ?4,
                ?5,
                ?6,
                ?7,
                ?8,
                ?9,
                ?10,
                ?11,
                ?12,
                ?13,
                ?14,
                ?15,
                ?16,
                ?17,
                ?18,
                ?19,
                ?20,
                ?21,
                ?22,
                ?23,
                ?24,
                ?25,
                ?26,
                ?27,
                ?28,
                ?29,
                ?30
            )",
            libsql::params![
                response_id,
                survey_id,
                attrakdiff_answers.q1,
                attrakdiff_answers.q2,
                attrakdiff_answers.q3,
                attrakdiff_answers.q4,
                attrakdiff_answers.q5,
                attrakdiff_answers.q6,
                attrakdiff_answers.q7,
                attrakdiff_answers.q8,
                attrakdiff_answers.q9,
                attrakdiff_answers.q10,
                attrakdiff_answers.q11,
                attrakdiff_answers.q12,
                attrakdiff_answers.q13,
                attrakdiff_answers.q14,
                attrakdiff_answers.q15,
                attrakdiff_answers.q16,
                attrakdiff_answers.q17,
                attrakdiff_answers.q18,
                attrakdiff_answers.q19,
                attrakdiff_answers.q20,
                attrakdiff_answers.q21,
                attrakdiff_answers.q22,
                attrakdiff_answers.q23,
                attrakdiff_answers.q24,
                attrakdiff_answers.q25,
                attrakdiff_answers.q26,
                attrakdiff_answers.q27,
                attrakdiff_answers.q28,
            ],
        )
        .await
        .expect("Failed to insert into database");

    tracing::debug!("Inserted into database");

    Redirect::to("/thanks")
}

/// Handler that creates a new AttrakDiff survey from a create survey form submission
pub(super) async fn create_new_survey(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    name: Option<String>,
) -> Redirect {
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

    let result = state
        .connection
        .execute(
            "INSERT INTO attrakdiff_surveys (\
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
    Redirect::to(format!("/surveys/ad/{}", survey_id).as_ref())
}

//TODO consider renaming to evaluation or something more fitting
/// The HTML template for the AttrakDiff survey details and results page
#[derive(Template)]
#[template(path = "results/attrakdiff.html")]
struct AttrakdiffResultsTemplate {
    id: String,
    name: String,
    answers: Vec<[i32; 28]>,
    /// The url that can be used to share the survey with respondants
    survey_url: String,
}

/// Gets the details page that displays the results of the survey and gives insights to the responses
pub(super) async fn get_results_page(
    State(state): State<AppState>,
    Path(survey_id): Path<String>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    let result = state
        .connection
        .query(
            "SELECT name FROM attrakdiff_surveys WHERE user_id = :user_id AND id = :survey_id",
            named_params![":user_id": user.id, ":survey_id": survey_id.clone()],
        )
        .await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Error querying for AttrakDiff survey: {:?}", error);
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    let result = rows.next().await;
    //TODO put data we want to display into template
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

    let survey_name_result = row.get::<String>(0);
    let name = match survey_name_result {
        Ok(name) => name,
        Err(error) => {
            tracing::error!("Error reading survey name: {:?}", error);
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    // Read results
    let result = state
        .connection
        .query(
            "SELECT * FROM attrakdiff_responses WHERE survey_id = :survey_id",
            named_params![":survey_id": survey_id.clone()],
        )
        .await;

    let mut rows = match result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Error querying for AttrakDiff responses: {:?}", error);
            //TODO display user error message it's not their fault
            return Redirect::to("/surveys").into_response();
        }
    };

    let mut answers = Vec::new();

    loop {
        let result = rows.next().await;
        match result {
            Ok(Some(row)) => {
                let mut response = [0; 28];
                for i in 0usize..28 {
                    let answer = row.get::<i32>((i + 2).try_into().unwrap());
                    let answer = match answer {
                        Ok(answer) => answer,
                        Err(error) => {
                            tracing::error!("Error reading answer number {i}: {error:?}");
                            //TODO display user error message it's not their fault
                            return Redirect::to("/surveys").into_response();
                        }
                    };
                    response[i] = answer;
                }
                answers.push(response);
            }
            Ok(None) => break,
            Err(error) => {
                tracing::error!("Error reading query result: {:?}", error);
                //TODO display user error message it's not their fault
                return Redirect::to("/surveys").into_response();
            }
        }
    }

    let survey_url = create_share_link(&state.configuration.server_url, &survey_id);
    AttrakdiffResultsTemplate {
        id: survey_id,
        name,
        answers,
        survey_url,
    }
    .into_response()
}
