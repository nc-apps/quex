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

//TODO decide how long a session should live
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
        // Don't give away if the link existed or not
        return Redirect::to("/signin/expired").into_response();
    };

    let expires_at: i64 = row.get(1).unwrap();
    if expires_at < time::OffsetDateTime::now_utc().unix_timestamp() {
        return Redirect::to("/signin/expired").into_response();
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
        // Tell browsers to not allow JavaScript to access the cookie. Prevents some XSS attacks
        // (JS can still indirectly find out if user is authenticated by trying to access authenticated endpoints)
        .http_only(true)
        // Prevents CRSF attack
        .same_site(SameSite::Strict)
        .expires(expires_at);

    (jar.add(cookie), Redirect::to("/surveys")).into_response()
}

#[derive(Template)]
#[template(path = "signup_completed.html")]
struct SignupCompletedTemplate {}

async fn signup_completed() -> impl IntoResponse {
    let sign_up_completed_template = SignupCompletedTemplate {};
    sign_up_completed_template
}

#[derive(Template)]
#[template(path = "signin_completed.html")]
struct SigninCompletedTemplate {}

async fn signin_completed() -> impl IntoResponse {
    let sign_up_completed_template = SigninCompletedTemplate {};
    sign_up_completed_template
}

#[derive(Deserialize, Debug)]
struct SignInRequest {
    email: String,
}

async fn sign_in(
    State(AppState {
        connection,
        configuration,
        client,
    }): State<AppState>,
    Form(request): Form<SignInRequest>,
) -> Redirect {
    // Get user id
    let mut rows = connection
        .query(
            "SELECT id, email_address FROM researchers WHERE email_address = :email",
            named_params![":email": request.email],
        )
        .await
        .unwrap();

    let Some(row) = rows.next().await.unwrap() else {
        // Navigate user to complete sign in even if they don't have an account
        // This is to prevent snooping on which emails are registered
        return Redirect::to("/signin/completed");
    };

    let user_id: String = row.get(0).unwrap();
    let email_address: String = row.get(1).unwrap();

    // Create signin attempt
    let attempt_id = nanoid!();
    let expires_at = time::OffsetDateTime::now_utc() + SIGNIN_ATTEMPT_LIFETIME;
    let expires_at = expires_at.unix_timestamp();
    dbg!(&attempt_id);
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

    // Email address should be validated at this point
    send_sign_in_email(
        Email(email_address),
        &client,
        attempt_id,
        configuration.server_url,
    )
    .await
    .unwrap();

    Redirect::to("/signin/completed")
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

#[derive(Template)]
#[template(path = "signin_expired.html")]
struct SigninExpiredTemplate {}
async fn sign_in_expired() -> impl IntoResponse {
    let sign_in_expired_template = SigninExpiredTemplate {};

    sign_in_expired_template
}

pub(crate) fn create_router() -> Router<AppState> {
    Router::new()
        .route("/signup", get(sign_up_handler).post(create_account))
        .route("/signup/completed", get(signup_completed))
        .route("/signin", get(sign_in_handler).post(sign_in))
        .route("/signin/completed", get(signin_completed))
        .route("/signin/:attempt_id", get(complete_signin))
        .route("/signin/expired", get(sign_in_expired))
        .route("/challenge", get(passkey::get_challenge))
}
