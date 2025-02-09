use std::sync::Arc;
use std::{env, net::Ipv4Addr};

use crate::routes::survey;
use auth::cookie::{self};
use auth::open_id_connect::discovery;
use auth::signer::{AntiForgeryTokenProvider, Signer};
use axum::http::uri::InvalidUri;
use axum::{http::Uri, routing::get, Router};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use dotenvy::dotenv;
use libsql::Connection;
use tokio::signal;
use tower_http::services::ServeDir;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod auth;
mod database;
mod routes;
mod secret;

#[derive(thiserror::Error, Debug)]
enum SigningSecretError {
    #[error("Error reading signing secret")]
    ReadError(env::VarError),
    #[error("Error decoding signing secret")]
    DecodeError(base64::DecodeError),
    #[error("Signing secret is not {expected_length} bytes long")]
    LengthError { expected_length: usize },
}

fn transform_signing_secret(signing_secret: Arc<str>) -> Result<Signer, SigningSecretError> {
    let secret: [u8; 32] = BASE64_URL_SAFE_NO_PAD
        .decode(signing_secret.as_ref())
        .map_err(SigningSecretError::DecodeError)?
        .try_into()
        .map_err(|_| SigningSecretError::LengthError {
            expected_length: 32,
        })?;

    Ok(Signer::new(secret))
}

fn transform_cookie_signing_key(
    signing_secret: Arc<str>,
) -> Result<cookie::Key, SigningSecretError> {
    let secret: [u8; 64] = BASE64_URL_SAFE_NO_PAD
        .decode(signing_secret.as_ref())
        .map_err(SigningSecretError::DecodeError)?
        .try_into()
        .map_err(|_| SigningSecretError::LengthError {
            expected_length: 64,
        })?;

    Ok(cookie::Key::from(&secret))
}

#[derive(thiserror::Error, Debug)]
enum AppError {
    #[error("No quex url was configured with environment variables or there was an error reading it. {0}")]
    NoUrlConfigured(env::VarError),

    #[error("Quex url is badly formatted. {0}")]
    BadUrl(#[from] InvalidUri),

    #[error("Error reading google client id")]
    ReadClientIdError(env::VarError),
    #[error("Error reading google client secret")]
    ReadClientSecretError(env::VarError),
    #[error("Error reading Turso database url")]
    ReadDatabaseUrlError(env::VarError),

    #[error("Either google client id or secret is missing")]
    MissingClientIdOrSecret,

    #[error("Error reading anti forgery token signing secret")]
    AntiForgerySecretError(SigningSecretError),
    #[error("Error reading google user id signing secret")]
    GoogleUserIdSigningSecretError(SigningSecretError),
    #[error("Error reading cookie signing secret")]
    CookieSigningSecretError(SigningSecretError),
    #[error("Error creating cookie key")]
    CreateCookieKeyError,

    #[error("Error setting up secrets")]
    SecretError(#[from] secret::Error),
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "quex=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenv().ok();
    // Secrets
    let secrets = secret::setup().await?;

    let url = std::env::var("TURSO_DATABASE_URL").map_err(AppError::ReadDatabaseUrlError)?;

    // Set up database
    let connection = database::initialize_database(url, secrets.lib_sql_auth_token).await;

    // Configuration
    //TODO implement fallback to localhost
    //TODO implement warning that users can not follow links if host is localhost or 127.0.0.1
    let url = env::var("QUEX_URL").map_err(AppError::NoUrlConfigured)?;

    let url = Uri::try_from(url)?;
    let port = url.port().map(|port| port.as_u16()).unwrap_or(3_000);

    let client_id: Option<Arc<str>> = match env::var("GOOGLE_CLIENT_ID") {
        Ok(client_id) => Some(client_id.into()),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(AppError::ReadClientIdError(error)),
    };

    // Either need to have both or none
    let client_credentials = client_id.map(|id| ClientCredentials {
        id,
        secret: secrets.google_client_secret,
    });

    let configuration = Configuration {
        server_url: url,
        client_credentials,
    };

    let signer = transform_signing_secret(secrets.anti_forgery_token_signing_key)
        .map_err(AppError::AntiForgerySecretError)?;
    let anti_forgery_token_provider = AntiForgeryTokenProvider::new(signer);

    let google_id_signer = transform_signing_secret(secrets.google_id_signing_key)
        .map_err(AppError::GoogleUserIdSigningSecretError)?;

    let cookie_key = transform_cookie_signing_key(secrets.cookie_signing_secret)
        .map_err(AppError::CookieSigningSecretError)?;

    let client = reqwest::Client::new();
    let app_state = AppState {
        connection,
        configuration,
        anti_forgery_token_provider,
        discovery_cache: discovery::DocumentCache::new(client.clone()),
        client,
        google_id_signer,
        cookie_key,
    };

    let auth_routes = auth::create_router();
    let survey_routes = survey::create_router();

    // Build our application with a route
    let app = Router::new()
        .route("/", get(routes::index::get_index_page))
        .merge(auth_routes)
        .merge(survey_routes)
        // If the route could not be matched it might be a file
        .fallback_service(ServeDir::new("public"))
        .with_state(app_state);

    // Run the server
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), port))
        .await
        .unwrap();

    tracing::debug!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    Ok(())
}

#[derive(Clone)]
struct ClientCredentials {
    id: Arc<str>,
    secret: Arc<str>,
}

#[derive(Clone)]
pub(crate) struct Configuration {
    /// The server URL under which the server can be reached publicly for clients.
    /// Used by various systems that need to provide an url to users.
    server_url: Uri,
    /// Google Auth Platform Client id and secret for OpenID Connect authenticaton flow
    client_credentials: Option<ClientCredentials>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    connection: Connection,
    client: reqwest::Client,
    configuration: Configuration,
    anti_forgery_token_provider: AntiForgeryTokenProvider,
    discovery_cache: discovery::DocumentCache,
    google_id_signer: Signer,
    pub(crate) cookie_key: cookie::Key,
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
