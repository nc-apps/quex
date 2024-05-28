use std::{env, net::Ipv4Addr, time::Duration};

use crate::auth::authenticated_user::AuthenticatedUser;
use askama_axum::{IntoResponse, Template};
use axum::{extract::State, http::Uri, response::Redirect, routing::get, Form, Router};
use dotenv::dotenv;
use libsql::{named_params, Builder, Connection, Database};
use serde::{self, Deserialize};
use tower_http::services::ServeDir;

mod auth;
mod email;

// Use local database for debugging
#[cfg(debug_assertions)]
async fn create_database() -> Database {
    Builder::new_local("database.db").build().await.unwrap()
}

#[cfg(not(debug_assertions))]
async fn create_database() -> Database {
    let url = env::var("TURSO_DATABASE_URL")
        .expect("TURSO_DATABASE_URL environment variable must be set. Did you forget to set up the .env file?");
    let token = env::var("TURSO_AUTH_TOKEN").unwrap_or_default();

    Builder::new_remote(url, token)
        .build()
        .await
        .expect("Failed to connect to database")
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database = create_database().await;

    let connection = database.connect().unwrap();

    let query = include_str!("./create_tables.sql");
    connection
        .execute_batch(&query)
        .await
        .expect("Failed to create tables");

    println!("Tables created");
    // Set up background workers
    let _handle = tokio::spawn(collect_garbage(connection.clone()));

    // Configuration
    //TODO implmement fallback to localhost
    //TODO implement warning that users can not follow links (e.g. in emails) if host is localhost or 127.0.0.1
    let url = env::var("QUEX_URL").expect("QUEX_URL environment variable must be set");

    let url = Uri::try_from(url).expect("Invalid URL in QUEX_URL environment variable");
    let port = url.port().map(|port| port.as_u16()).unwrap_or(80);
    let configuration = Configuration { server_url: url };

    let client = reqwest::Client::new();
    let app_state = AppState {
        connection,
        client,
        configuration,
    };

    let auth_routes = auth::create_router();

    // Build our application with a route
    let app = Router::new()
        .route("/", get(handler))
        .route("/nps", get(nps_handler).post(create_nps))
        .route("/sus", get(sus_handler).post(create_sus))
        .route(
            "/attrakdiff",
            get(attrakdiff_handler).post(create_attrakdiff),
        )
        .route("/surveys", get(surveys_page))
        .merge(auth_routes)
        // If the route could not be matched it might be a file
        .fallback_service(ServeDir::new("public"))
        .with_state(app_state);

    // Run the server
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), port))
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {}

#[derive(Template)]
#[template(path = "nps.html")]
struct NpsTemplate {}

#[derive(Template)]
#[template(path = "sus.html")]
struct SusTemplate {}

#[derive(Template)]
#[template(path = "attrakdiff.html")]
struct AtrrakDiffTemplate {
    questions: Vec<(String, String)>,
}

async fn handler() -> impl IntoResponse {
    let index_template = IndexTemplate {};

    index_template
}

async fn nps_handler() -> impl IntoResponse {
    let nps_template = NpsTemplate {};

    nps_template
}

async fn sus_handler() -> impl IntoResponse {
    let sus_template = SusTemplate {};

    sus_template
}

async fn attrakdiff_handler() -> impl IntoResponse {
    let attrakdiff_template = AtrrakDiffTemplate {
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
            ("Cumbersone".to_string(), "Straightforward".to_string()),
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
struct NpsAnswers {
    #[serde(rename = "Q1")]
    q1: u8,
    #[serde(rename = "Q2")]
    q2: String,
}

#[derive(Deserialize, Debug)]
struct AttrakDiffAnswers {
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

#[derive(Deserialize, Debug)]
struct SusAnswers {
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
}

async fn create_attrakdiff(
    State(app_state): State<AppState>,
    Form(attrakdiff_answers): Form<AttrakDiffAnswers>,
) -> impl IntoResponse {
    println!("Answers for AtrrakDiff: {:?}", attrakdiff_answers);

    app_state
        .connection
        .execute(
            // insert ansewrs 1 to 28 into database
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

    println!("Inserted into database");

    Redirect::to("/")
}

#[derive(Clone)]
pub(crate) struct Configuration {
    /// The server URL under which the server can be reached publicly for clients.
    /// A user clicking an email link will be brought to this URL.
    server_url: Uri,
}

#[derive(Clone)]
pub(crate) struct AppState {
    connection: Connection,
    client: reqwest::Client,
    configuration: Configuration,
}

async fn create_nps(
    State(app_state): State<AppState>,
    Form(nps_answers): Form<NpsAnswers>,
) -> impl IntoResponse {
    println!("Answers for NPS: {:?}", nps_answers);

    app_state
        .connection
        .execute(
            "INSERT INTO net_promoter_score_responses (answer_1, answer_2) VALUES (?1, ?2)",
            libsql::params![nps_answers.q1, nps_answers.q2],
        )
        .await
        .expect("Failed to insert into database");

    println!("Inserted into database");

    Redirect::to("/")
}

async fn create_sus(
    State(app_state): State<AppState>,
    Form(sus_answers): Form<SusAnswers>,
) -> impl IntoResponse {
    println!("Answers for SUS: {:?}", sus_answers);

    app_state
        .connection
        .execute(
            "INSERT INTO system_usability_score_responses (
                answer_1,
                answer_2,
                answer_3,
                answer_4,
                answer_5,
                answer_6,
                answer_7,
                answer_8,
                answer_9,
                answer_10
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
                ?10)",
            libsql::params![
                sus_answers.q1,
                sus_answers.q2,
                sus_answers.q3,
                sus_answers.q4,
                sus_answers.q5,
                sus_answers.q6,
                sus_answers.q7,
                sus_answers.q8,
                sus_answers.q9,
                sus_answers.q10
            ],
        )
        .await
        .expect("Failed to insert into database");

    println!("Inserted into database");

    Redirect::to("/")
}

#[derive(Template)]
#[template(path = "surveys.html")]
struct SurveysTemplate {}

async fn surveys_page(user: AuthenticatedUser) -> impl IntoResponse {
    let surveys_template = SurveysTemplate {};
    //TODO identify user with cookie
    //TODO query database for surveys by user
    //TODO add surveys to template
    //TODO render surveys in template
    surveys_template
}

/// Runs forever and cleans up expired app data about every 5 minutes
async fn collect_garbage(connection: Connection) {
    // It is not important that it cleans exactly every 5 minutes but it is important that it happens regularly
    // Duration from minutes is experimental currently
    let mut interval = tokio::time::interval(Duration::from_secs(5 * 60));
    loop {
        interval.tick().await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // Clean up expired sessions
        connection
            .execute(
                "DELETE FROM sessions WHERE expires_at_utc < :now",
                named_params![":now": now],
            )
            .await
            .expect("Failed to delete expired sessions");

        // Clean up expired sign in attemps
        connection
            .execute(
                "DELETE FROM signin_attempts WHERE expires_at_utc < :now",
                named_params![":now": now],
            )
            .await
            .expect("Failed to delete expired signin attempts");
    }
}
