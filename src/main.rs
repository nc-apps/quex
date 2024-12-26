use std::{env, net::Ipv4Addr, time::Duration};

use crate::routes::survey;
use axum::{http::Uri, routing::get, Router};
use dotenvy::dotenv;
use libsql::{named_params, Connection};
use tower_http::services::ServeDir;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod auth;
mod database;
mod email;
mod routes;

#[tokio::main]
async fn main() {
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
    let url = env::var("QUEX_URL").expect("QUEX_URL environment variable must be set");

    let url = Uri::try_from(url).expect("Invalid URL in QUEX_URL environment variable");
    let port = url.port().map(|port| port.as_u16()).unwrap_or(80);
    let configuration = Configuration { server_url: url };

    let client = reqwest::Client::new();
    let app_state = AppState {
        connection,
        client,
        configuration,
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
}

#[derive(Clone)]
pub(crate) struct Configuration {
    /// The server URL under which the server can be reached publicly for clients.
    /// A user clicking an email link will be brought to this URL.
    server_url: Uri,
}

#[derive(Clone)]
pub(crate) struct AppState {
    connection: Connection,
    client: reqwest::Client,
    configuration: Configuration,
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
