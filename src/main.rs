#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Use more specific error handling. If there is an exception to this rule, opt out with a code comment"
)]

use std::sync::Arc;
use std::{env, net::Ipv4Addr};

use crate::routes::survey;
use auth::cookie::{self};
use auth::open_id_connect::discovery;
use auth::signer::{AntiForgeryTokenProvider, Signer};
use axum::http::uri::InvalidUri;
use axum::middleware;
use axum::{http::Uri, routing::get, Router};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use database::Database;
use dotenvy::dotenv;
use tokio::signal;
use tower_http::services::ServeDir;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod accept_language;
mod auth;
mod database;
mod routes;
mod secret;

fluent_templates::static_loader! {
    static LOCALES = {
        locales: "./translations",
        fallback_language: "en",
    };
}

const ENGLISH: LanguageIdentifier = langid!("en");
const GERMAN: LanguageIdentifier = langid!("de");

#[derive(thiserror::Error, Debug)]
enum SigningSecretError {
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
    #[error("Error reading Turso database url")]
    ReadDatabaseUrlError(env::VarError),
    #[error("Error initializing database: {0}")]
    DatabaseInitializationError(#[from] database::InitializationError),

    #[error("Error reading anti forgery token signing secret")]
    AntiForgerySecretError(SigningSecretError),
    #[error("Error reading google user id signing secret")]
    GoogleUserIdSigningSecretError(SigningSecretError),
    #[error("Error reading cookie signing secret")]
    CookieSigningSecretError(SigningSecretError),

    #[error("Error setting up secrets")]
    SecretError(#[from] secret::Error),

    #[error("Error binding port: {0}")]
    BindError(std::io::Error),
    #[error("Error serving app: {0}")]
    ServeError(std::io::Error),
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
    let database = Database::initialize(url, secrets.lib_sql_auth_token).await?;

    // Configuration
    //TODO implement fallback to localhost
    //TODO implement warning that users can not follow links if host is localhost or 127.0.0.1
    let url = env::var("QUEX_URL").map_err(AppError::NoUrlConfigured)?;

    let url: Uri = Uri::try_from(url)?;

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
        database: database.into(),
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
        .route("/error", get(routes::error::get_error_page))
        .merge(auth_routes)
        .merge(survey_routes)
        .layer(axum::middleware::from_fn(
            accept_language::middleware::extract,
        ))
        // If the route could not be matched it might be a file
        .fallback_service(ServeDir::new("public"))
        .with_state(app_state);

    let address = if cfg!(debug_assertions) {
        Ipv4Addr::new(127, 0, 0, 1)
    } else {
        Ipv4Addr::new(0, 0, 0, 0)
    };

    // Run the server
    let listener = tokio::net::TcpListener::bind((address, 3000))
        .await
        .map_err(AppError::BindError)?;

    if let Ok(address) = listener.local_addr() {
        tracing::debug!("listening on http://{}", address);
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(AppError::ServeError)
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
    /// Google Auth Platform Client id and secret for OpenID Connect authentication flow
    client_credentials: Option<ClientCredentials>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    database: Arc<Database>,
    client: reqwest::Client,
    configuration: Configuration,
    anti_forgery_token_provider: AntiForgeryTokenProvider,
    discovery_cache: discovery::DocumentCache,
    google_id_signer: Signer,
    pub(crate) cookie_key: cookie::Key,
}

#[derive(thiserror::Error, Debug)]
enum GracefulShutdownError {
    #[error("Failed to install Ctrl-C handler: {0}")]
    FailedCtrlCHandlerInstall(std::io::Error),
    #[cfg(unix)]
    #[error("Failed to install terminate signal handler: {0}")]
    FailedTerminateHandlerInstall(std::io::Error),
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .map_err(GracefulShutdownError::FailedCtrlCHandlerInstall)
    };

    #[cfg(unix)]
    async fn wait_for_terminate() -> Result<(), GracefulShutdownError> {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .map_err(GracefulShutdownError::FailedTerminateHandlerInstall)?
            .recv()
            .await;

        Ok(())
    }

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    let error = tokio::select! {
        result = ctrl_c => {
            result
        },
        result = wait_for_terminate() => {
            result
        },
    };

    if let Err(error) = error {
        tracing::error!("Error with shutdown signals: {}", error);
    }
}
