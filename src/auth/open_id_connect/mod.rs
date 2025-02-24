use std::sync::Arc;

use jsonwebtoken::{jwk::JwkSet, DecodingKey, Validation};
use serde::Deserialize;
use time::OffsetDateTime;
use url::Url;

use super::{
    create_redirect_url, signer::CreateAntiForgeryTokenError, AppState, AuthenticationRequest,
    BadServerUrl, Nonce, ResponseType, Scopes,
};

pub(in crate::auth) mod authentication_response;
pub(crate) mod discovery;

#[derive(thiserror::Error, Debug)]
#[error("Failed to set scheme to https")]
pub(crate) struct SetSchemeError;

fn ensure_https(url: &mut Url) -> Result<(), SetSchemeError> {
    if url.scheme() != "https" {
        return url.set_scheme("https").map_err(|_| SetSchemeError);
    }

    Ok(())
}

#[derive(Deserialize, Debug)]
enum GoogleIssuer {
    #[serde(rename = "accounts.google.com")]
    Accounts,
    #[serde(rename = "https://accounts.google.com")]
    HttpsAccounts,
}

#[allow(
    unused,
    reason = "Kept for reference. Expected to be removed when compiled"
)]
#[derive(Deserialize, Debug)]
struct Claims {
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
    issuer: GoogleIssuer,
    #[serde(rename = "sub")]
    subject: Arc<str>,
    email: Option<Arc<str>>,
    #[serde(rename = "email_verified")]
    is_email_verified: Option<bool>,
    name: Option<Arc<str>>,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum ValidateIdTokenError {
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

async fn validate_id_token(
    id_token: &str,
    client: &reqwest::Client,
    mut jwks_uri: Url,
    client_id: &str,
) -> Result<Claims, ValidateIdTokenError> {
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

    let data = jsonwebtoken::decode::<Claims>(id_token, &decoding_key, &validation)
        .map_err(ValidateIdTokenError::ValidationError)?;

    Ok(data.claims)
}

#[derive(thiserror::Error, Debug)]
pub(in crate::auth) enum SignInWithGoogleError {
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
    CreateAntiForgeryTokenError(#[from] CreateAntiForgeryTokenError),

    #[error("Error creating nonce: {0}")]
    CreateNonceError(#[from] getrandom::Error),
}

pub(in crate::auth) async fn get_sign_in_with_google_url<const SCOPES_LENGTH: usize>(
    state: &AppState,
    scopes: Scopes<'_, SCOPES_LENGTH>,
) -> Result<Url, SignInWithGoogleError> {
    let Some(client_id) = state
        .configuration
        .client_credentials
        .clone()
        .map(|credentials| credentials.id)
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

    let redirect_url = create_redirect_url(state.configuration.server_url.clone())?;

    // Create anti-forgery token
    let anti_forgery_token = state
        .anti_forgery_token_provider
        .create_anti_forgery_token()?;

    let request = AuthenticationRequest {
        client_id: client_id.as_ref(),
        nonce: Nonce::new()?,
        redirect_uri: redirect_url,
        response_type: ResponseType::Code,
        scopes,
        state: anti_forgery_token,
        include_granted_scopes: None,
        prompt: None,
    };

    let query = serde_urlencoded::to_string(request)?;
    authorization_endpoint.set_query(Some(&query));

    Ok(authorization_endpoint)
}
