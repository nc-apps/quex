use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::State;
use axum::Form;
use axum::response::Redirect;
use serde::Deserialize;
use crate::AppState;

#[derive(Template)]
#[template(path = "attrakdiff.html")]
struct AttrakDiffTemplate {
    questions: Vec<(String, String)>,
}


pub(crate) async fn get_page() -> impl IntoResponse {
    let attrakdiff_template = AttrakDiffTemplate {
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

    attrakdiff_template
}


#[derive(Deserialize, Debug)]
pub(crate) struct AttrakdiffResponses {
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

pub(crate) async fn create_response(
    State(app_state): State<AppState>,
    Form(attrakdiff_answers): Form<AttrakdiffResponses>,
) -> impl IntoResponse {
    tracing::debug!("Answers for AttrakDiff: {:?}", attrakdiff_answers);

    app_state
        .connection
        .execute(
            // insert answers 1 to 28 into database
            "INSERT INTO attrakdiff_responses (
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
                ?28
            )",
            libsql::params![
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

    Redirect::to("/")
}