use std::sync::Arc;

use crate::database::StatementError;
use crate::preferred_language::PreferredLanguage;
use crate::AppState;
use askama_axum::{IntoResponse, Template};
use authenticated_user::AuthenticatedUser;
use axum::routing::post;
use axum::{
    extract::{Query, State},
    http::Uri,
    response::Redirect,
    routing::get,
    Form, Router,
};
use axum_extra::extract::SignedCookieJar;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use getrandom::getrandom;
use nanoid::nanoid;
use open_id_connect::{authentication_response, get_sign_in_with_google_url};
use serde::{Deserialize, Serialize};
use signer::{AntiForgeryToken, Signer};
use time::{Duration, OffsetDateTime};
use token::complete_signin::{CompleteSignInToken, DecodeTokenError, EncodeTokenError};
use unic_langid::LanguageIdentifier;
use url::Url;

pub(crate) mod authenticated_user;
pub(crate) mod cookie;
pub(crate) mod open_id_connect;
pub(crate) mod signer;
mod token;

#[derive(Template)]
#[template(path = "auth/signin.html")]
struct SignInTemplate {
    sign_in_with_google_url: Option<Url>,
    language: LanguageIdentifier,
}

async fn get_sign_in_page(
    State(state): State<AppState>,
    PreferredLanguage(language): PreferredLanguage,
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
        language,
    };

    sign_in_template.into_response()
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
    fn new() -> Result<Self, getrandom::Error> {
        // Length is arbitrary there seems to be no requirement
        let mut nonce = [0; 30];
        getrandom(&mut nonce)?;
        let nonce = BASE64_URL_SAFE_NO_PAD.encode(nonce);
        Ok(Self(nonce))
    }
}

#[derive(Serialize, Debug)]
enum ResponseType {
    #[serde(rename = "code")]
    Code,
}

#[allow(
    unused,
    reason = "Kept for reference. Expected to be removed when compiled"
)]
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
    state: AntiForgeryToken,
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
    #[error("Signin token/link is expired")]
    Expired,
    #[error("Error encoding token again: {0}")]
    EncodeTokenError(#[from] EncodeTokenError),
}

impl IntoResponse for CompleteSignInError {
    fn into_response(self) -> askama_axum::Response {
        match self {
            //TODO display error message to user
            CompleteSignInError::Expired => Redirect::to("/signin").into_response(),
            other => {
                tracing::error!("Error getting complete sign in page: {}", other);
                Redirect::to("/error").into_response()
            }
        }
    }
}

#[derive(Template)]
#[template(path = "auth/complete signup.html")]
struct CompleteSignInTemplate {
    name: Option<Arc<str>>,
    token: Arc<str>,
    request_data_url: Option<Url>,
    language: LanguageIdentifier,
}

#[derive(Deserialize, Debug)]
struct CompleteSignInRequest {
    name: Option<Arc<str>>,
}

/// # Possible attack vectors
/// ## Replaying the url with the signed google account id
/// If a user already created an account associated with the google id this page is
/// not valid and they should be returned to the sign in page
/// ## Getting someones google account id
/// They can't create a valid link as they can't provide a valid signature. They are returned to sign in.
/// ## User abandons the sign in but the link is leaked
/// This is probably very unlikely as the link is only shared with the user.
/// An "issued at" value with a expire duration invalidates abandoned links after some time.
async fn get_complete_signup_page(
    State(state): State<AppState>,
    PreferredLanguage(language): PreferredLanguage,
    token: CompleteSignInToken,
    Query(query): Query<CompleteSignInRequest>,
) -> Result<CompleteSignInTemplate, CompleteSignInError> {
    let expires_at = token.issued_at + Duration::minutes(15);
    if expires_at < OffsetDateTime::now_utc() {
        return Err(CompleteSignInError::Expired);
    }

    let token = token.try_encode(&state.google_id_signer)?;

    let request_data_url = if query.name.is_none() {
        let scopes = Scopes(["openid", "profile"]);
        get_sign_in_with_google_url(&state, scopes)
            .await
            .inspect_err(|error| {
                tracing::error!("Error creating sign in with google url: {}", error)
            })
            .ok()
    } else {
        None
    };

    Ok(CompleteSignInTemplate {
        name: query.name,
        token: Arc::from(token),
        request_data_url,
        language,
    })
}

#[derive(Deserialize, Debug)]
struct CompleteSignUpRequest {
    name: Arc<str>,
    token: Arc<str>,
}

#[derive(thiserror::Error, Debug)]
enum CompleteSignUpError {
    #[error("Error connecting to database: {0}")]
    Database(#[from] libsql::Error),
    #[error("Error decoding token: {0}")]
    DecodeError(#[from] DecodeTokenError),
    #[error("Signin token is expired")]
    Expired,
    #[error("Error inserting user: {0}")]
    InsertUserError(StatementError),
    #[error("Error inserting google account connection: {0}")]
    InsertGoogleAccountConnectionError(StatementError),
    #[error("Error creating cookie: {0}")]
    CreateCookieError(#[from] postcard::Error),
}

impl IntoResponse for CompleteSignUpError {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error completing sign in: {}", self);
        Redirect::to("/error").into_response()
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
        .database
        .insert_user(&user_id, &request.name)
        .await
        .map_err(CompleteSignUpError::InsertUserError)?;

    state
        .database
        .insert_google_account_connection(&user_id, &token.user_id)
        .await
        .map_err(CompleteSignUpError::InsertGoogleAccountConnectionError)?;

    let cookie = cookie::create(user_id.into())?;

    Ok((jar.add(cookie), Redirect::to("/surveys")).into_response())
}

pub(crate) fn create_router() -> Router<AppState> {
    Router::new()
        .route("/signin", get(get_sign_in_page))
        // Sign out has to be post to prevent other sites from signing users out by linking to the sign out link
        // (See SameSite lax and CSRF)
        .route("/signout", post(sign_out))
        .route("/signup/complete", post(complete_signup))
        .route(
            "/signup/complete/:signin_token",
            get(get_complete_signup_page),
        )
        .route(REDIRECT_PATH, get(authentication_response::handle))
}
