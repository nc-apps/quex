use std::sync::Arc;
use std::{env, net::Ipv4Addr, time::Duration};

use crate::routes::survey;
use auth::open_id_connect::discovery;
use auth::signer::Signer;
use axum::http::uri::InvalidUri;
use axum::{http::Uri, routing::get, Router};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use dotenvy::dotenv;
use libsql::{named_params, Connection};
use tower_http::services::ServeDir;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod auth;
mod database;
mod email;
mod routes;

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
    #[error("Either google client id or secret is missing")]
    MissingClientIdOrSecret,

    #[error("Could not read anti-forgery signing secret")]
    ReadAntiForgerySigningSecretError(env::VarError),

    #[error("Error decoding anti-forgery signing secret")]
    DecodeAntiForgerySigningSecretError(base64::DecodeError),

    #[error("Anti-forgery signing secret is not 32 bytes long")]
    AntiForgerySigningSecretLengthError,
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

    // Set up database
    let connection = database::initialize_database().await;

    // Set up background workers
    let _handle = tokio::spawn(collect_garbage(connection.clone()));

    // Configuration
    //TODO implement fallback to localhost
    //TODO implement warning that users can not follow links (e.g. in emails) if host is localhost or 127.0.0.1
    let url = env::var("QUEX_URL").map_err(AppError::NoUrlConfigured)?;

    let url = Uri::try_from(url)?;
    let port = url.port().map(|port| port.as_u16()).unwrap_or(80);

    let client_id: Option<Arc<str>> = match env::var("GOOGLE_CLIENT_ID") {
        Ok(client_id) => Some(client_id.into()),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(AppError::ReadClientIdError(error)),
    };

    let client_secret: Option<Arc<str>> = match env::var("GOOGLE_CLIENT_SECRET") {
        Ok(client_secret) => Some(client_secret.into()),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(AppError::ReadClientIdError(error)),
    };

    // Either need to have both or none
    let client_credentials = match (client_id, client_secret) {
        (Some(client_id), Some(client_secret)) => Some(ClientCredentials {
            id: client_id,
            secret: client_secret,
        }),
        (None, None) => None,
        _ => {
            return Err(AppError::MissingClientIdOrSecret);
        }
    };

    let configuration = Configuration {
        server_url: url,
        client_credentials,
    };

    let signing_secret = env::var("ANTI_FORGERY_SIGNING_SECRET")
        .map_err(AppError::ReadAntiForgerySigningSecretError)?;
    let signing_secret: [u8; 32] = BASE64_URL_SAFE_NO_PAD
        .decode(signing_secret)
        .map_err(AppError::DecodeAntiForgerySigningSecretError)?
        .try_into()
        .map_err(|_| AppError::AntiForgerySigningSecretLengthError)?;

    let signer = Signer::new(signing_secret);

    let client = reqwest::Client::new();
    let app_state = AppState {
        connection,
        configuration,
        anti_forgery_signer: signer,
        discovery_cache: discovery::DocumentCache::new(client.clone()),
        client,
    };

    let auth_routes = auth::create_router();
    let survey_routes = survey::create_router();

    // Build our application with a route
    let app = Router::new()
        .route("/", get(routes::index::get_page))
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
    axum::serve(listener, app).await.unwrap();

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
    /// A user clicking an email link will be brought to this URL.
    server_url: Uri,
    /// Google Auth Platform Client id and secret for OpenID Connect authenticaton flow
    client_credentials: Option<ClientCredentials>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    connection: Connection,
    client: reqwest::Client,
    configuration: Configuration,
    anti_forgery_signer: Signer,
    discovery_cache: discovery::DocumentCache,
}

/// Runs forever and cleans up expired app data about every 5 minutes
async fn collect_garbage(connection: Connection) {
    // It is not important that it cleans exactly every 5 minutes, but it is important that it happens regularly
    // Duration from minutes is experimental currently
    let mut interval = tokio::time::interval(Duration::from_secs(5 * 60));
    loop {
        interval.tick().await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // Clean up expired sessions
        connection
            .execute(
                "DELETE FROM sessions WHERE expires_at_utc < :now",
                named_params![":now": now],
            )
            .await
            .expect("Failed to delete expired sessions");

        // Clean up expired sign in attempts
        connection
            .execute(
                "DELETE FROM signin_attempts WHERE expires_at_utc < :now",
                named_params![":now": now],
            )
            .await
            .expect("Failed to delete expired signin attempts");
    }
}
