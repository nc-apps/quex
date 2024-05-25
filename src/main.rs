use std::{env, net::Ipv4Addr};

use askama_axum::{IntoResponse, Template};
use axum::{
    extract::{Path, State},
    http::{uri::Port, Uri},
    response::Redirect,
    routing::get,
    Form, Json, Router,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use base64::prelude::*;
use dotenv::dotenv;
use email::Email;
use libsql::{named_params, Builder, Connection};
use nanoid::nanoid;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_repr::Serialize_repr;
use tower_http::services::ServeDir;

mod email;

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
        .execute_batch(&query)
        .await
        .expect("Failed to create tables");

    println!("Tables created");

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

    let serve_directory = ServeDir::new("public");
    // Build our application with a route
    let app = Router::new()
        .route("/", get(handler))
        .route("/nps", get(nps_handler).post(create_nps))
        .route("/sus", get(sus_handler).post(create_sus))
        .route(
            "/attrakdiff",
            get(attrakdiff_handler).post(create_attrakdiff),
        )
        .route("/signup", get(sign_up_handler).post(create_account))
        .route("/signup/completed", get(signup_completed))
        .route("/signin", get(sign_in_handler).post(sign_in))
        .route("/signin/:attempt_id", get(complete_signin))
        .route("/surveys", get(surveys_page))
        .route("/challenge", get(get_challenge))
        // If the route could not be matched it might be a file
        .fallback_service(serve_directory)
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

#[derive(Template)]
#[template(path = "sign_up.html")]
struct SignUpTemplate {}

#[derive(Template)]
#[template(path = "sign_in.html")]
struct SignInTemplate {}

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

async fn sign_up_handler() -> impl IntoResponse {
    let sign_up_template = SignUpTemplate {};

    sign_up_template
}

async fn sign_in_handler() -> impl IntoResponse {
    let sign_in_template = SignInTemplate {};

    sign_in_template
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
struct Configuration {
    server_url: Uri,
}

#[derive(Clone)]
struct AppState {
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

#[derive(Deserialize, Debug)]
struct CreateAccountRequest {
    email: String,
    name: String,
}

async fn create_account(
    State(AppState {
        connection,
        configuration,
        client,
    }): State<AppState>,
    Form(request): Form<CreateAccountRequest>,
) -> impl IntoResponse {
    //TODO check if user aleady exists
    let user_id = nanoid!();
    connection
        .execute(
            "INSERT INTO researchers (id, name, email_address) VALUES (:id, :name, :email_address)",
            named_params![
                ":id": user_id.clone(),
                ":name": request.name,
                ":email_address": request.email.clone(),
            ],
        )
        .await
        .unwrap();

    let attempt_id = nanoid!();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(15);
    let expires_at = expires_at.unix_timestamp();
    connection
        .execute(
            "INSERT INTO signin_attempts VALUES (:id, :researcher_id, :expires_at)",
            named_params![
                ":id": attempt_id.clone(),
                ":researcher_id": user_id,
                ":expires_at": expires_at,
            ],
        )
        .await
        .unwrap();

    //TODO email adress validation
    email::send_sign_in_email(
        Email(request.email),
        &client,
        attempt_id,
        configuration.server_url,
    )
    .await
    .unwrap();

    Redirect::to("/signup/completed")
}

async fn complete_signin(
    State(AppState { connection, .. }): State<AppState>,
    jar: CookieJar,
    Path(attempt_id): Path<String>,
) -> impl IntoResponse {
    // Check if sign in attempt exists
    let mut rows = connection
        .query(
            "SELECT researcher_id, expires_at_utc FROM signin_attempts WHERE id = :id",
            named_params![":id": attempt_id],
        )
        .await
        .unwrap();

    let Some(row) = rows.next().await.unwrap() else {
        //TODO display error link has expired (even if it did not exist in the first place)
        // Don't give away if the link existed or not
        return Redirect::to("/signin").into_response();
    };

    let expires_at: i64 = row.get(1).unwrap();
    if expires_at < time::OffsetDateTime::now_utc().unix_timestamp() {
        //TODO display error link has expired
        return Redirect::to("/signin").into_response();
    }

    let researcher_id: String = row.get(0).unwrap();
    // Create session
    let session_id = nanoid!();
    //TODO decide how long a session should live
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::days(30);

    connection
        .execute(
            "INSERT INTO sessions (id, researcher_id, expires_at_utc) VALUES (:id, :researcher_id, :expires_at_utc)",
            named_params![
                ":id": session_id.clone(),
                ":researcher_id": researcher_id,
                ":expires_at_utc": expires_at.unix_timestamp(),
            ],
        )
        .await
        .unwrap();

    // Set session cookie
    //TODO should the cookie be encrypted?
    let cookie = Cookie::build(("session", session_id))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .expires(expires_at);

    (jar.add(cookie), Redirect::to("/")).into_response()
}

#[derive(Template)]
#[template(path = "signup_completed.html")]
struct SignupCompletedTemplate {}

async fn signup_completed() -> impl IntoResponse {
    let sign_up_completed_template = SignupCompletedTemplate {};
    sign_up_completed_template
}

#[derive(Deserialize, Debug)]
struct SignInRequest {
    username: String,
}

async fn sign_in(
    jar: CookieJar,
    Form(sign_in_request): Form<SignInRequest>,
) -> (CookieJar, Redirect) {
    //TODO authentication
    let cookie = Cookie::build(("user", sign_in_request.username))
        .path("/")
        .secure(true)
        .http_only(true)
        // Prevents CRSF attack
        .same_site(SameSite::Strict)
        .expires(time::OffsetDateTime::now_utc() + time::Duration::days(1));

    (jar.add(cookie), Redirect::to("/"))
}

#[derive(Template)]
#[template(path = "surveys.html")]
struct SurveysTemplate {}

async fn surveys_page() -> impl IntoResponse {
    let surveys_template = SurveysTemplate {};
    //TODO identify user with cookie
    //TODO query database for surveys by user
    //TODO add surveys to template
    //TODO render surveys in template
    surveys_template
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RelyingParty {
    id: String,
    name: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    name: String,
    display_name: String,
}

#[derive(Debug, Serialize_repr)]
#[repr(i16)]
enum Algorithm {
    Ed25519 = -8,
    ES256 = -7,
    RS256 = -257,
}

#[derive(Serialize, Debug)]
enum PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

#[derive(Serialize, Debug)]
struct PublicKeyCredentialParameters {
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    r#type: PublicKeyCredentialType,
}

/// Public key creation options for Passkeys/WebAuthn API
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PublicKeyCreationOptions {
    challenge: String,
    #[serde(rename = "rp")]
    relying_party: RelyingParty,
    user: User,
    #[serde(rename = "pubKeyCredParams")]
    public_key_credential_parameters: Vec<PublicKeyCredentialParameters>,
}

async fn get_challenge() -> impl IntoResponse {
    let random = SystemRandom::new();
    let mut challenge = [0u8; 32];
    random
        .fill(&mut challenge)
        .expect("Expected to generate challenge");
    let challenge = BASE64_STANDARD.encode(&challenge);
    let relying_party = RelyingParty {
        id: "localhost".to_string(),
        name: "localhost name".to_string(),
    };

    let user = User {
        id: BASE64_STANDARD.encode([1]),
        name: "user name".to_string(),
        display_name: "user display name".to_string(),
    };

    let public_key_credential_parameters = vec![PublicKeyCredentialParameters {
        algorithm: Algorithm::ES256,
        r#type: PublicKeyCredentialType::PublicKey,
    }];

    let public_key_creation_options = PublicKeyCreationOptions {
        challenge,
        relying_party,
        user,
        public_key_credential_parameters,
    };

    Json(public_key_creation_options)
}
