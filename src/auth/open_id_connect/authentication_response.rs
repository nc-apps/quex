use std::sync::Arc;

use axum::response::{IntoResponse, Redirect};
use axum::{
    extract::{Query, State},
    http,
};
use axum_extra::extract::SignedCookieJar;
use libsql::named_params;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{discovery, SetSchemeError, ValidateIdTokenError};
use crate::auth::open_id_connect::{ensure_https, validate_id_token};
use crate::auth::token::complete_signin::{CompleteSignInToken, EncodeTokenError};
use crate::auth::{cookie, create_redirect_url};
use crate::{
    auth::{AntiforgeryToken, BadServerUrl},
    AppState,
};

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AuthenticationResponseErrorCode {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
}

#[derive(Deserialize, thiserror::Error, Debug)]
#[error("Error response from google")]
pub(in crate::auth) struct AuthenticationError {
    #[serde(rename = "error")]
    code: AuthenticationResponseErrorCode,
    #[serde(rename = "error_description")]
    description: Option<Arc<str>>,
    #[serde(rename = "error_uri")]
    uri: Option<Url>,
}

#[derive(Deserialize, Debug)]
pub(in crate::auth) struct AuthenticationSuccess {
    code: Arc<str>,
    #[serde(rename = "scope")]
    scopes: Arc<str>,
}

/// This is very much like `Result<T, E>` but we can't mark that as untagged
#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum AuthenticationResult {
    Success(AuthenticationSuccess),
    Error(AuthenticationError),
}

#[derive(Deserialize, Debug)]
pub(in crate::auth) struct AuthenticationResponse {
    state: AntiforgeryToken,
    #[serde(flatten)]
    result: AuthenticationResult,
}

#[derive(thiserror::Error, Debug)]
pub(in crate::auth) enum HandleAuthenticationResponseError {
    #[error("Invalid anti-forgery token in state parameter")]
    InvalidAntiForgeryToken,
    #[error("Error response from google. This can happen when the user cancels the sign in flow")]
    ErrorResponse(#[from] AuthenticationError),
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
    #[error("Received response but response indicates an error: {0}")]
    ResponseError(reqwest::StatusCode),
    #[error("Failed to deserialize response: {0}")]
    DeserializeError(reqwest::Error),
    #[error("Failed to validate id token: {0}")]
    VerifyIdTokenError(#[from] ValidateIdTokenError),
    #[error("Error creating complete sign in token: {0}")]
    EncodeTokenError(#[from] EncodeTokenError),
    #[error("Error checking for existing user: {0}")]
    GetUserError(#[from] libsql::Error),
    #[error("Error creating cookie: {0}")]
    CreateCookieError(#[from] postcard::Error),
    #[error("Error creating complete signup redirect url: {0}")]
    CreateCompleteSignupUrlError(#[from] url::ParseError),
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

#[derive(Deserialize, Debug)]
enum TokenType {
    Bearer,
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
struct AccessTokenResponse {
    access_token: Arc<str>,
    #[serde(rename = "expires_in")]
    expires_in_seconds: u64,
    id_token: Arc<str>,
    token_type: TokenType,
    refresh_token: Option<Arc<str>>,
}

pub(in crate::auth) async fn handle(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(response): Query<AuthenticationResponse>,
) -> Result<impl IntoResponse, HandleAuthenticationResponseError> {
    // Anti replay protection should come from the code parameter as the IDP won't accept it twice
    if !state
        .anti_forgery_token_provider
        .is_token_valid(&response.state)
    {
        tracing::error!("Invalid anti-forgery token in state parameter");
        return Err(HandleAuthenticationResponseError::InvalidAntiForgeryToken);
    }

    tracing::debug!("Anti forgery token is valid");

    let response = match response.result {
        AuthenticationResult::Success(response) => response,
        AuthenticationResult::Error(error) => return Err(error.into()),
    };

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
        .await?;

    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        let text = response.text().await?;
        tracing::error!("Error response from google: {}", text);

        return Err(HandleAuthenticationResponseError::ResponseError(status));
    }

    let response: AccessTokenResponse = response
        .json()
        .await
        .map_err(HandleAuthenticationResponseError::DeserializeError)?;

    let keys_url = discovery_document.jwks_uri.clone();
    let claims =
        validate_id_token(&response.id_token, &state.client, keys_url, &credentials.id).await?;

    // Check if user already exists
    let mut rows = state
        .connection
        .query(
            "SELECT user_id FROM google_account_connections WHERE google_user_id = :id",
            named_params![":id": claims.subject],
        )
        .await?;

    let row = rows.next().await?;
    let existing_user_id = row.map(|row| row.get::<String>(0)).transpose()?;
    if let Some(existing_user_id) = existing_user_id {
        let cookie = cookie::create(existing_user_id.into())?;

        return Ok((jar.add(cookie), Redirect::to("/surveys")).into_response());
    }

    let token = CompleteSignInToken::new(claims.subject);
    let signin_token = token.try_encode(&state.google_id_signer)?;

    let mut url = format!("/signup/complete/{signin_token}");

    // These values can be changed by the user in the next sign up step
    // so they don't need to be signed
    if let Some(name) = claims.name {
        url.push_str(&format!("?name={}", name));
    }

    Ok(Redirect::to(&url).into_response())
}

#[cfg(test)]
mod test {
    use super::*;

    /// This tests not if serde works but if we constructed the structs and enums in a way serde
    /// can deserialize the query parameters
    #[test]
    fn can_deserialize() {
        let query = "error=invalid_request&error_description=Invalid+request&state=123";

        let _response: AuthenticationResponse = serde_urlencoded::from_str(query).unwrap();
        let response: AuthenticationError = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(
            response.code,
            AuthenticationResponseErrorCode::InvalidRequest
        );
        assert_eq!(response.description, Some(Arc::from("Invalid request")));

        let query = "code=123&scope=openid+email&state=123";
        let _response: AuthenticationResponse = serde_urlencoded::from_str(query).unwrap();
        let response: AuthenticationSuccess = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(response.code.as_ref(), "123");
        assert_eq!(response.scopes.as_ref(), "openid email");
    }
}
