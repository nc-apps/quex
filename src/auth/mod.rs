use std::sync::Arc;

use crate::{
    email::{send_sign_in_email, Email},
    AppState, ClientCredentials,
};
use askama_axum::{IntoResponse, Template};
use axum::{
    extract::{Path, Query, State},
    http::{self, Uri},
    response::Redirect,
    routing::get,
    Form, Router,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use getrandom::getrandom;
use jsonwebtoken::{
    jwk::{Jwk, JwkSet},
    DecodingKey, Validation,
};
use libsql::named_params;
use nanoid::nanoid;
use open_id_connect::discovery;
use serde::{Deserialize, Serialize};
use signer::{AntiforgeryToken, CreateAntiforgeryTokenError};
use time::OffsetDateTime;
use url::Url;

use self::authenticated_user::AuthenticatedUser;

pub(crate) mod authenticated_user;
pub(crate) mod open_id_connect;
pub(crate) mod signer;

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

    // Create session
    let session_id = nanoid!();
    let expires_at = time::OffsetDateTime::now_utc() + SESSION_LIFETIME;

    connection
        .execute(
            "INSERT INTO sessions (id, user_id, expires_at_utc) VALUES (:id, :user_id, :expires_at_utc)",
            named_params![
                ":id": session_id.clone(),
                ":user_id": user_id,
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
#[template(path = "sign_in.html")]
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
    state: State<AppState>,
    user: Option<AuthenticatedUser>,
) -> impl IntoResponse {
    // Check if is already authenticated and redirect to surveys
    // Ideally they should not land on the signin page if they are already authenticated
    if user.is_some() {
        return Redirect::to("/surveys").into_response();
    }

    let url = get_sign_in_with_google_url(state)
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

async fn sign_out(jar: CookieJar) -> (CookieJar, Redirect) {
    // This should be a no-op if the cookie doesn't exist
    (jar.remove("session"), Redirect::to("/"))
}

#[derive(thiserror::Error, Debug)]
enum SignInWithGoogleError {
    #[error("Client credentials not configured")]
    NoClientCredentials,
    #[error("Failed to get discovery document")]
    GetDiscoveryDocumentError(#[from] discovery::GetDocumentError),
    #[error("Failed to ensure url uses https")]
    EnsureHttpsError(#[from] SetSchemeError),

    #[error("Configured server uri is not a valid url")]
    BadServerUrl(#[from] BadServerUrl),

    #[error("Failed to serialize query parameters")]
    QueryError(#[from] serde_urlencoded::ser::Error),

    #[error("Failed creating anti-forgery token")]
    CreateAntiforgeryTokenError(#[from] CreateAntiforgeryTokenError),
}

#[derive(thiserror::Error, Debug)]
#[error("Failed to set scheme to https")]
struct SetSchemeError;

fn ensure_https(url: &mut Url) -> Result<(), SetSchemeError> {
    if url.scheme() != "https" {
        return url.set_scheme("https").map_err(|_| SetSchemeError);
    }

    Ok(())
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
struct AuthenticationRequest<'a, const SCOPES_LENGTH: usize> {
    client_id: &'a str,
    response_type: ResponseType,
    #[serde(rename = "scope")]
    scropes: Scopes<'a, SCOPES_LENGTH>,
    redirect_uri: Url,
    state: AntiforgeryToken,
    nonce: Nonce,
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

async fn get_sign_in_with_google_url(
    State(state): State<AppState>,
) -> Result<Url, SignInWithGoogleError> {
    let Some(ClientCredentials { id: client_id, .. }) = state.configuration.client_credentials
    else {
        return Err(SignInWithGoogleError::NoClientCredentials);
    };

    let url = Url::parse("https://accounts.google.com").unwrap();

    let mut authorization_endpoint = state
        .discovery_cache
        .get(url)
        .await?
        .authorization_endpoint
        .clone();

    ensure_https(&mut authorization_endpoint)?;

    let redirect_url = create_redirect_url(state.configuration.server_url)?;

    // Create anti-forgery token
    let antiforgery_token = state.anti_forgery_signer.create_antiforgery_token()?;
    let request = AuthenticationRequest {
        client_id: client_id.as_ref(),
        nonce: Nonce::new(),
        redirect_uri: redirect_url,
        response_type: ResponseType::Code,
        scropes: Scopes(["openid", "email"]),
        state: antiforgery_token,
    };

    let query = serde_urlencoded::to_string(request)?;
    authorization_endpoint.set_query(Some(&query));

    Ok(authorization_endpoint)
}

#[derive(Deserialize, Debug)]
struct AuthenticationResponse {
    state: AntiforgeryToken,
    code: Arc<str>,
    #[serde(rename = "scope")]
    scopes: Arc<str>,
}

#[derive(thiserror::Error, Debug)]
enum HandleAuthenticationResponseError {
    #[error("Invalid anti-forgery token in state parameter")]
    InvalidAntiForgeryToken,
    #[error("Failed to get discovery document")]
    GetDiscoveryDocumentError(#[from] discovery::GetDocumentError),
    #[error("Failed to ensure url uses https")]
    EnsureHttpsError(#[from] SetSchemeError),
    #[error("No client credentials are configured even though authentication response was received which should only be called if client id is configured")]
    NoClientCredentials,
    #[error("Failed to create redirect url")]
    CreateRedirectUrlError(#[from] BadServerUrl),
    #[error("Failed to send request for access token")]
    RequestError(#[from] reqwest::Error),
    #[error("Received response but response indicates an error")]
    ResponseError(reqwest::Error),
    #[error("Failed to deserialize response: {0}")]
    DeserializeError(reqwest::Error),
    #[error("Failed to validate id token: {0}")]
    VerifyIdTokenError(#[from] ValidateIdTokenError),
}

impl IntoResponse for HandleAuthenticationResponseError {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error handling authentication response: {}", self);
        http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
enum GrantType {
    AuthorizationCode,
}

#[derive(Serialize, Debug)]
struct AccessTokenRequest {
    code: Arc<str>,
    client_id: Arc<str>,
    client_secret: Arc<str>,
    redirect_uri: Url,
    grant_type: GrantType,
}

#[derive(Deserialize, Debug)]
enum TokenType {
    Bearer,
}

#[derive(Deserialize, Debug)]
struct AccessTokenResponse {
    access_token: Arc<str>,
    #[serde(rename = "expires_in")]
    expires_in_seconds: u64,
    id_token: Arc<str>,
    token_type: TokenType,
    refresh_token: Option<Arc<str>>,
}

#[derive(thiserror::Error, Debug)]
enum ValidateIdTokenError {
    #[error("Failed to ensure url uses https: {0}")]
    EnsureHttpsError(#[from] SetSchemeError),
    #[error("Failed to send request for verification keys: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Error decoding id token header: {0}")]
    DecodeHeaderError(#[from] jsonwebtoken::errors::Error),
    #[error("Expected key id (kid) in header but none was found")]
    NoKeyId,
    #[error("Header key not in jwks")]
    MissingKey,
    #[error("Failed to construct decoding key from jwk: {0}")]
    DecodingKeyError(jsonwebtoken::errors::Error),
    #[error("Error validating token: {0}")]
    ValidationError(jsonwebtoken::errors::Error),
}

#[derive(Deserialize, Debug)]
enum GoogleIssuer {
    #[serde(rename = "accounts.google.com")]
    Accounts,
    #[serde(rename = "https://accounts.google.com")]
    HttpsAccounts,
}

#[derive(Deserialize, Debug)]
struct Claims<I> {
    #[serde(rename = "aud")]
    audience: Arc<str>,
    #[serde(
        rename = "exp",
        deserialize_with = "time::serde::timestamp::deserialize"
    )]
    expiration_time: OffsetDateTime,
    #[serde(
        rename = "iat",
        deserialize_with = "time::serde::timestamp::deserialize"
    )]
    issued_at: OffsetDateTime,
    #[serde(rename = "iss")]
    issuer: I,
    #[serde(rename = "sub")]
    subject: Arc<str>,
}

async fn validate_id_token(
    id_token: &str,
    client: &reqwest::Client,
    mut jwks_uri: Url,
    client_id: &str,
) -> Result<Claims<GoogleIssuer>, ValidateIdTokenError> {
    ensure_https(&mut jwks_uri)?;
    // jsonwebtoken::jwk::Jwk
    let response = client.get(jwks_uri).send().await?.error_for_status()?;
    let jwks: JwkSet = response.json().await?;

    let header = jsonwebtoken::decode_header(&id_token)?;
    let key_id = header.kid.ok_or(ValidateIdTokenError::NoKeyId)?;
    let key = jwks.find(&key_id).ok_or(ValidateIdTokenError::MissingKey)?;

    let decoding_key =
        DecodingKey::from_jwk(key).map_err(ValidateIdTokenError::DecodingKeyError)?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[client_id]);

    let data = jsonwebtoken::decode::<Claims<GoogleIssuer>>(id_token, &decoding_key, &validation)
        .map_err(ValidateIdTokenError::ValidationError)?;

    Ok(data.claims)
}

async fn handle_authentication_response(
    State(state): State<AppState>,
    Query(response): Query<AuthenticationResponse>,
) -> Result<(), HandleAuthenticationResponseError> {
    tracing::debug!("Received redirect after authentication {:?}", response);

    // Anti replay protection should come from the code parameter as the IDP won't accept it twice
    if !state.anti_forgery_signer.is_token_valid(response.state) {
        tracing::error!("Invalid anti-forgery token in state parameter");
        return Err(HandleAuthenticationResponseError::InvalidAntiForgeryToken);
    }

    tracing::debug!("Anti forgery token is valid");

    let url = Url::parse("https://accounts.google.com").unwrap();
    // Exchange code for access token
    let discovery_document = state.discovery_cache.get(url).await?;
    let mut token_endpoint = discovery_document.token_endpoint.clone();

    ensure_https(&mut token_endpoint)?;

    let credentials = state
        .configuration
        .client_credentials
        .ok_or(HandleAuthenticationResponseError::NoClientCredentials)?;

    let request = AccessTokenRequest {
        code: response.code,
        client_id: credentials.id.clone(),
        client_secret: credentials.secret,
        redirect_uri: create_redirect_url(state.configuration.server_url)?,
        grant_type: GrantType::AuthorizationCode,
    };

    let response = state
        .client
        .post(token_endpoint)
        .form(&request)
        .send()
        .await?
        .error_for_status()
        .map_err(HandleAuthenticationResponseError::ResponseError)?;

    let response: AccessTokenResponse = response
        .json()
        .await
        .map_err(HandleAuthenticationResponseError::DeserializeError)?;

    tracing::debug!("Received access token response: {:?}", response);

    let keys_url = discovery_document.jwks_uri.clone();
    let claims =
        validate_id_token(&response.id_token, &state.client, keys_url, &credentials.id).await?;

    tracing::debug!("Claims: {:?}", claims);

    Ok(())
}

pub(crate) fn create_router() -> Router<AppState> {
    Router::new()
        .route("/signup", get(sign_up_handler).post(create_account))
        .route("/signup/completed", get(signup_completed))
        .route("/signin", get(sign_in_handler).post(sign_in))
        .route("/signin/completed", get(signin_completed))
        .route("/signin/:attempt_id", get(complete_signin))
        .route("/signin/expired", get(sign_in_expired))
        .route("/signout", get(sign_out))
        .route(REDIRECT_PATH, get(handle_authentication_response))
}
