use crate::{
    email::{send_sign_in_email, Email},
    AppState,
};
use askama_axum::{IntoResponse, Template};
use axum::{
    extract::{Path, State},
    response::Redirect,
    routing::get,
    Form, Router,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use libsql::named_params;
use nanoid::nanoid;
use serde::Deserialize;

pub(crate) mod authenticated_user;
mod passkey;

const SESSION_LIFETIME: time::Duration = time::Duration::days(30);
const SIGNIN_ATTEMPT_LIFETIME: time::Duration = time::Duration::minutes(15);

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
    let expires_at = time::OffsetDateTime::now_utc() + SIGNIN_ATTEMPT_LIFETIME;
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
    send_sign_in_email(
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
            named_params![":id": attempt_id.clone()],
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

    // Delete sign in attempt to prevent reusage
    connection
        .execute(
            "DELETE FROM signin_attempts WHERE id = :id",
            named_params![":id": attempt_id],
        )
        .await
        .unwrap();

    // Create session
    let session_id = nanoid!();
    //TODO decide how long a session should live
    let expires_at = time::OffsetDateTime::now_utc() + SESSION_LIFETIME;

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
    // The cookie does not need to be encrypted as it doesn't contain any sensitive information
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
#[template(path = "sign_up.html")]
struct SignUpTemplate {}

#[derive(Template)]
#[template(path = "sign_in.html")]
struct SignInTemplate {}
async fn sign_up_handler() -> impl IntoResponse {
    let sign_up_template = SignUpTemplate {};

    sign_up_template
}

async fn sign_in_handler() -> impl IntoResponse {
    let sign_in_template = SignInTemplate {};

    sign_in_template
}

pub(crate) fn create_router() -> Router<AppState> {
    Router::new()
        .route("/signup", get(sign_up_handler).post(create_account))
        .route("/signup/completed", get(signup_completed))
        .route("/signin", get(sign_in_handler).post(sign_in))
        .route("/signin/:attempt_id", get(complete_signin))
        .route("/challenge", get(passkey::get_challenge))
}
