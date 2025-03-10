use std::{
    collections::HashMap,
    env::{self},
    rc::Rc,
    sync::Arc,
};

use bitwarden::{
    auth::login::AccessTokenLoginRequest,
    secrets_manager::{secrets::SecretsGetRequest, ClientSecretsExt},
    Client,
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub(super) enum ErrorType {
    #[error("Error loading secret id from environment variables: {0}")]
    VarError(#[from] env::VarError),
    #[error("Error parsing user secret id: {0}")]
    ParseError(#[from] uuid::Error),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Secret {
    CookieSigning,
    LibSqlAuthToken,
    GoogleClient,
    AntiForgeryTokenSigningKey,
    GoogleIdSigningKey,
}

impl Secret {
    const fn get_variable(&self) -> &'static str {
        match self {
            Secret::CookieSigning => "COOKIE_SIGNING_SECRET_ID",
            Secret::LibSqlAuthToken => "LIBSQL_AUTH_TOKEN_ID",
            Secret::GoogleClient => "GOOGLE_CLIENT_SECRET_ID",
            Secret::AntiForgeryTokenSigningKey => "ANTI_FORGERY_SIGNING_SECRET_ID",
            Secret::GoogleIdSigningKey => "GOOGLE_ID_SIGNING_SECRET_ID",
        }
    }
}

#[derive(Error, Debug)]
#[error("Error loading secret id {variable}: {source}")]
pub(super) struct LoadSecretIdError {
    variable: Rc<str>,
    #[source]
    source: ErrorType,
}

#[derive(Error, Debug)]
pub(super) enum Error {
    #[error("Failed to load token from environment variables: {0}")]
    LoadToken(#[source] env::VarError),
    #[error("Error getting secrets from Bitwarden Secrets Manager")]
    Bws(#[from] bitwarden::Error),
    #[error("Error authenticating with Bitwarden")]
    BwsAuthenticationFailed,
    #[error("Error loading secret id from environment variables: {0}")]
    LoadSecretId(#[from] LoadSecretIdError),
    #[error("Secret not provided by Bitwarden: {0:?}")]
    SecretNotProvided(Secret),
}

#[derive(Clone)]
pub(crate) struct Secrets {
    pub(crate) cookie_signing_secret: Arc<str>,
    pub(crate) lib_sql_auth_token: String,
    pub(crate) google_client_secret: Arc<str>,
    pub(crate) anti_forgery_token_signing_key: Arc<str>,
    pub(crate) google_id_signing_key: Arc<str>,
}

fn load_secret_ids() -> Result<HashMap<Uuid, Secret>, LoadSecretIdError> {
    const SECRETS: &[Secret] = &[
        Secret::CookieSigning,
        Secret::LibSqlAuthToken,
        Secret::GoogleClient,
        Secret::AntiForgeryTokenSigningKey,
        Secret::GoogleIdSigningKey,
    ];

    let mut secret_ids = HashMap::with_capacity(SECRETS.len());

    for secret in SECRETS {
        let value = env::var(secret.get_variable()).map_err(|error| LoadSecretIdError {
            variable: secret.get_variable().into(),
            source: ErrorType::VarError(error),
        })?;

        let id: Uuid = value.parse().map_err(|error| LoadSecretIdError {
            variable: secret.get_variable().into(),
            source: ErrorType::ParseError(error),
        })?;

        secret_ids.insert(id, *secret);
    }

    Ok(secret_ids)
}

pub(super) async fn setup() -> Result<Secrets, Error> {
    let client = Client::new(None);

    let request = AccessTokenLoginRequest {
        access_token: env::var("BWS_TOKEN").map_err(Error::LoadToken)?,
        state_file: None,
    };

    let response = client.auth().login_access_token(&request).await?;

    if !response.authenticated {
        return Err(Error::BwsAuthenticationFailed);
    }

    let ids_by_variable = load_secret_ids()?;
    let request = SecretsGetRequest {
        ids: ids_by_variable.keys().copied().collect(),
    };

    let responses = client.secrets().get_by_ids(request).await?;
    let mut cookie_signing_secret = None;
    let mut lib_sql_auth_token = None;
    let mut google_client_secret = None;
    let mut anti_forgery_token_signing_key = None;
    let mut google_id_signing_key = None;

    for secret in responses.data {
        let Some(variable) = ids_by_variable.get(&secret.id) else {
            tracing::warn!(
                "Received secret with id {} that was not requested",
                secret.id
            );
            continue;
        };

        match variable {
            Secret::CookieSigning => cookie_signing_secret = Some(secret.value),
            Secret::LibSqlAuthToken => lib_sql_auth_token = Some(secret.value),
            Secret::GoogleClient => google_client_secret = Some(secret.value),
            Secret::AntiForgeryTokenSigningKey => {
                anti_forgery_token_signing_key = Some(secret.value)
            }
            Secret::GoogleIdSigningKey => google_id_signing_key = Some(secret.value),
        }
    }

    let cookie_signing_secret = cookie_signing_secret
        .ok_or_else(|| Error::SecretNotProvided(Secret::CookieSigning))?
        .into();

    let lib_sql_auth_token =
        lib_sql_auth_token.ok_or_else(|| Error::SecretNotProvided(Secret::LibSqlAuthToken))?;

    let google_client_secret = google_client_secret
        .ok_or_else(|| Error::SecretNotProvided(Secret::GoogleClient))?
        .into();

    let anti_forgery_token_signing_key = anti_forgery_token_signing_key
        .ok_or_else(|| Error::SecretNotProvided(Secret::AntiForgeryTokenSigningKey))?
        .into();

    let google_id_signing_key = google_id_signing_key
        .ok_or_else(|| Error::SecretNotProvided(Secret::GoogleIdSigningKey))?
        .into();

    Ok(Secrets {
        cookie_signing_secret,
        lib_sql_auth_token,
        google_client_secret,
        anti_forgery_token_signing_key,
        google_id_signing_key,
    })
}
