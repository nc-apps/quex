use std::env;

use askama_axum::{IntoResponse, Template};
use axum::{extract::State, response::Redirect, routing::get, Form, Router};
use dotenv::dotenv;
use libsql::{Builder, Connection};
use serde::Deserialize;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let url = env::var("TURSO_DATABASE_URL")
        .expect("TURSO_DATABASE_URL environment variable must be set. Did you forget to set up the .env file?");
    let token = env::var("TURSO_AUTH_TOKEN").unwrap_or_default();
    let database = Builder::new_remote(url, token)
        .build()
        .await
        .expect("Failed to connect to database");

    let connection = database.connect().unwrap();

    let query = include_str!("./create_tables.sql");
    connection
        .execute(&query, ())
        .await
        .expect("Failed to create tables");

    println!("Tables created");

    let app_state = AppState { connection };

    // build our application with a route
    let app = Router::new()
        .route("/", get(handler))
        .route("/nps", get(nps_handler).post(create_nps))
        .route("/sus", get(sus_handler).post(create_sus))
        .route(
            "/attrakdiff",
            get(attrakdiff_handler).post(create_attrakdiff),
        )
        .with_state(app_state);

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
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

async fn create_attrakdiff() -> impl IntoResponse {
    Redirect::to("/")
}
#[derive(Clone)]
struct AppState {
    connection: Connection,
}

async fn create_nps(
    State(app_state): State<AppState>,
    Form(nps_answers): Form<NpsAnswers>,
) -> impl IntoResponse {
    println!("Answers for NPS: {:?}", nps_answers);

    app_state
        .connection
        .execute(
            "INSERT INTO net_promoter_score (answer_1, answer_2) VALUES (?1, ?2)",
            libsql::params![nps_answers.q1, nps_answers.q2],
        )
        .await
        .expect("Failed to insert into database");

    println!("Inserted into database");

    Redirect::to("/")
}

async fn create_sus() -> impl IntoResponse {
    Redirect::to("/")
}
