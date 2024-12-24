use std::convert::Infallible;
use std::ops::{Range, RangeFrom};
use std::sync::Arc;

use crate::{
    email::{send_sign_in_email, Email},
    AppState,
};
use askama_axum::{IntoResponse, Template};
use axum::extract::FromRef;
use axum::http::{HeaderMap, HeaderValue};
use axum::routing::post;
use axum::{
    async_trait,
    extract::{rejection::PathRejection, FromRequestParts, Path, Query, State},
    http::{self, request::Parts, Uri},
    response::Redirect,
    routing::get,
    Form, Router,
};
use axum_extra::extract::SignedCookieJar;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use getrandom::getrandom;
use jsonwebtoken::{jwk::JwkSet, DecodingKey, Validation};
use libsql::named_params;
use nanoid::nanoid;
use open_id_connect::{authentication_response, discovery, get_sign_in_with_google_url};
use reqwest::header::LOCATION;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use signer::{AntiforgeryToken, CreateAntiforgeryTokenError, Signer};
use time::{Duration, OffsetDateTime};
use token::complete_signin::{CompleteSignInToken, DecodeTokenError, EncodeTokenError};
use url::Url;

use self::authenticated_user::AuthenticatedUser;

pub(crate) mod authenticated_user;
pub(crate) mod cookie;
pub(crate) mod open_id_connect;
pub(crate) mod signer;
mod token;

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
        ..
    }): State<AppState>,
    Form(request): Form<CreateAccountRequest>,
) -> impl IntoResponse {
    //TODO check if user aleady exists
    let user_id = nanoid!();
    connection
        .execute(
            "INSERT INTO users (id, name, email_address) VALUES (:id, :name, :email_address)",
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
            "INSERT INTO signin_attempts VALUES (:id, :user_id, :expires_at)",
            named_params![
                ":id": attempt_id.clone(),
                ":user_id": user_id,
                ":expires_at": expires_at,
            ],
        )
        .await
        .unwrap();

    //TODO email address validation
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
    jar: SignedCookieJar,
    Path(attempt_id): Path<String>,
) -> impl IntoResponse {
    // Check if sign in attempt exists
    //TODO remove database round trips with signed value and expiration time
    let mut rows = connection
        .query(
            "SELECT user_id, expires_at_utc FROM signin_attempts WHERE id = :id",
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

    let user_id: String = row.get(0).unwrap();

    // Delete sign in attempt to prevent reusage
    connection
        .execute(
            "DELETE FROM signin_attempts WHERE id = :id",
            named_params![":id": attempt_id],
        )
        .await
        .unwrap();

    // Set session cookie
    // The cookie does not need to be encrypted as it doesn't contain any sensitive information
    let cookie = match cookie::create(Arc::from(user_id)) {
        Ok(builder) => builder,
        Err(error) => {
            tracing::error!("Error building cookie: {}", error);
            return Redirect::to("/").into_response();
        }
    };

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
        ..
    }): State<AppState>,
    Form(request): Form<SignInRequest>,
) -> Redirect {
    // Get user id
    let mut rows = connection
        .query(
            "SELECT id, email_address FROM users WHERE email_address = :email",
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

    connection
        .execute(
            "INSERT INTO signin_attempts VALUES (:id, :user_id, :expires_at)",
            named_params![
                ":id": attempt_id.clone(),
                ":user_id": user_id,
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
#[template(path = "auth/signin.html")]
struct SignInTemplate {
    sign_in_with_google_url: Option<Url>,
}

async fn sign_up_handler(user: Option<AuthenticatedUser>) -> impl IntoResponse {
    // Check if is already authenticated and redirect to surveys
    // Ideally they should not land on the signup page if they are already authenticated
    if user.is_some() {
        return Redirect::to("/surveys").into_response();
    }

    let sign_up_template = SignUpTemplate {};

    sign_up_template.into_response()
}

async fn sign_in_handler(
    State(state): State<AppState>,
    user: Option<AuthenticatedUser>,
) -> impl IntoResponse {
    // Check if is already authenticated and redirect to surveys
    // Ideally they should not land on the signin page if they are already authenticated
    if user.is_some() {
        return Redirect::to("/surveys").into_response();
    }

    // Must include "openid" https://developers.google.com/identity/openid-connect/openid-connect#scope-param
    let url = get_sign_in_with_google_url(&state, Scopes(["openid"]))
        .await
        .inspect_err(|error| tracing::error!("Error creating sign in with google url: {}", error))
        .ok();

    let sign_in_template = SignInTemplate {
        sign_in_with_google_url: url,
    };

    sign_in_template.into_response()
}

#[derive(Template)]
#[template(path = "signin_expired.html")]
struct SigninExpiredTemplate {}

async fn sign_in_expired() -> impl IntoResponse {
    let sign_in_expired_template = SigninExpiredTemplate {};

    sign_in_expired_template
}

async fn sign_out(jar: SignedCookieJar) -> (SignedCookieJar, Redirect) {
    // This should be a no-op if the cookie doesn't exist
    (jar.remove(cookie::NAME), Redirect::to("/"))
}

#[derive(Debug)]
struct Scopes<'a, const N: usize>([&'a str; N]);

impl<const N: usize> Serialize for Scopes<'_, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let scopes = self.0.join(" ");
        serializer.serialize_str(&scopes)
    }
}

#[derive(Serialize, Debug)]
struct Nonce(String);
impl Nonce {
    fn new() -> Self {
        // Length is arbitrary there seems to be no requirement
        let mut nonce = [0; 30];
        getrandom(&mut nonce).unwrap();
        let nonce = BASE64_URL_SAFE_NO_PAD.encode(&nonce);
        Self(nonce)
    }
}

#[derive(Serialize, Debug)]
enum ResponseType {
    #[serde(rename = "code")]
    Code,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
enum Prompt {
    Consent,
    SelectAccount,
}

#[derive(Serialize, Debug)]
struct AuthenticationRequest<'a, const SCOPES_LENGTH: usize> {
    client_id: &'a str,
    response_type: ResponseType,
    #[serde(rename = "scope")]
    scopes: Scopes<'a, SCOPES_LENGTH>,
    redirect_uri: Url,
    state: AntiforgeryToken,
    nonce: Nonce,
    prompt: Option<Prompt>,
    include_granted_scopes: Option<bool>,
}

const REDIRECT_PATH: &str = "/redirect";
#[derive(thiserror::Error, Debug)]
#[error("Failed to parse server url")]
struct BadServerUrl(#[from] url::ParseError);
fn create_redirect_url(server_url: Uri) -> Result<Url, BadServerUrl> {
    let mut redirect_url = server_url.to_string().parse::<Url>()?;
    redirect_url.set_path(REDIRECT_PATH);
    Ok(redirect_url)
}

#[derive(thiserror::Error, Debug)]
enum CompleteSignInError {
    #[error("Signin token and link is expired")]
    Expired,
    #[error("Error encoding token again: {0}")]
    EncodeTokenError(#[from] EncodeTokenError),
}

impl IntoResponse for CompleteSignInError {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error getting complete sign in page: {}", self);
        http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[derive(Template)]
#[template(path = "auth/complete_signin.html")]
struct CompleteSigninTemplate {
    name: Option<Arc<str>>,
    email_address: Option<Arc<str>>,
    token: Arc<str>,
    request_data_url: Option<Url>,
}

#[derive(Deserialize, Debug)]
struct CompleteSigninRequest {
    #[serde(rename = "email")]
    email_address: Option<Arc<str>>,
    name: Option<Arc<str>>,
}

/// # Possible attack vectors
/// ## Replaying the url with the signed google account id
/// If a user already created an account associated with the google id this page is
/// not valid and they should be returned to the sign in page
/// ## Getting someones google account id
/// They can't create a valid link as they can't provide a valid signature. They are returned to sign in.
/// ## User abandonds the sign in but the link is leaked
/// This is probably very unlikely as the link is only shared with the user.
/// An "issued at" value with a expire duration invalidates abandoned links after some time.
async fn get_complete_signup_page(
    State(state): State<AppState>,
    token: CompleteSignInToken,
    Query(query): Query<CompleteSigninRequest>,
) -> Result<CompleteSigninTemplate, CompleteSignInError> {
    let expires_at = token.issued_at + Duration::minutes(15);
    if expires_at < OffsetDateTime::now_utc() {
        return Err(CompleteSignInError::Expired);
    }

    let token = token.try_encode(&state.google_id_signer)?;

    let request_data_url = if query.email_address.is_none() && query.name.is_none() {
        let scopes = Scopes(["openid", "email", "profile"]);
        get_sign_in_with_google_url(&state, scopes)
            .await
            .inspect_err(|error| {
                tracing::error!("Error creating sign in with google url: {}", error)
            })
            .ok()
    } else {
        None
    };

    Ok(CompleteSigninTemplate {
        email_address: query.email_address,
        name: query.name,
        token: Arc::from(token),
        request_data_url,
    })
}

#[derive(Deserialize, Debug)]
struct CompleteSignUpRequest {
    name: Arc<str>,
    #[serde(rename = "email")]
    email_address: Arc<str>,
    token: Arc<str>,
}

#[derive(thiserror::Error, Debug)]
enum CompleteSignUpError {
    #[error("Error decoding token: {0}")]
    DecodeError(#[from] DecodeTokenError),
    #[error("Signin token is expired")]
    Expired,
    #[error("Error creating cookie: {0}")]
    CreateCookieError(#[from] postcard::Error),
}

impl IntoResponse for CompleteSignUpError {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error completing sign in: {}", self);
        http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

async fn complete_signup(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(request): Form<CompleteSignUpRequest>,
) -> Result<impl IntoResponse, CompleteSignUpError> {
    let token = CompleteSignInToken::try_decode(request.token.as_bytes(), &state.google_id_signer)?;
    let expires_at = token.issued_at + Duration::minutes(15);
    if expires_at < OffsetDateTime::now_utc() {
        return Err(CompleteSignUpError::Expired);
    }

    let user_id = nanoid!();
    state
        .connection
        .execute(
            "INSERT INTO users (id, name, email_address) VALUES (:id, :name, :email_address)",
            named_params![
                ":id": user_id.clone(),
                ":name": request.name,
                ":email_address": request.email_address.clone(),
            ],
        )
        .await
        .unwrap();

    state
        .connection
        .execute(
            "INSERT INTO google_account_connections (user_id, google_user_id) VALUES (:user_id, :google_user_id)",
            named_params![
                ":user_id": user_id.clone(),
                ":google_user_id": token.user_id,
            ],
        )
        .await
        .unwrap();

    let cookie = cookie::create(user_id.into())?;

    Ok((jar.add(cookie), Redirect::to("/surveys")).into_response())
}

pub(crate) fn create_router() -> Router<AppState> {
    Router::new()
        .route("/signup", get(sign_up_handler).post(create_account))
        .route("/signup/completed", get(signup_completed))
        .route("/signin", get(sign_in_handler).post(sign_in))
        .route("/signin/completed", get(signin_completed))
        .route("/signin/:attempt_id", get(complete_signin))
        .route("/signin/expired", get(sign_in_expired))
        // Sign out has to be post to prevent other sites from signing users out by linking to the sign out link
        // (See SameSite lax and CRSF)
        .route("/signout", post(sign_out))
        .route("/signup/complete", post(complete_signup))
        .route(
            "/signup/complete/:signin_token",
            get(get_complete_signup_page),
        )
        .route(REDIRECT_PATH, get(authentication_response::handle))
}
