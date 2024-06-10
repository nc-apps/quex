use std::{env, net::Ipv4Addr, time::Duration};
use std::sync::Arc;

use crate::auth::authenticated_user::AuthenticatedUser;
use askama_axum::{IntoResponse, Template};
use axum::{extract::State, http::Uri, response::Redirect, routing::get, Form, Router};
use axum::http::StatusCode;
use dotenv::dotenv;
use libsql::{named_params, Builder, Connection, Database};
use serde::{self, Deserialize};
use tower_http::services::ServeDir;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod auth;
mod email;
mod database;
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

    // Build our application with a route
    let app = Router::new()
        .route("/", get(routes::index::get_page))
        .route("/nps", get(routes::net_promoter_score::get_page).post(routes::net_promoter_score::create_response))
        .route("/nps/new", get(routes::net_promoter_score::create_new_survey))
        .route("/sus", get(routes::system_usability_score::get_page).post(routes::system_usability_score::create_response))
        .route("/sus/new", get(routes::system_usability_score::create_new_survey))
        .route(
            "/ad",
            get(routes::attrakdiff::get_page).post(routes::attrakdiff::create_response),
        )
        .route("/ad/new", get(routes::attrakdiff::create_new_survey))
        .route("/surveys", get(surveys_page))
        .merge(auth_routes)
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


#[derive(Template)]
#[template(path = "surveys.html")]
struct SurveysTemplate {
    surveys: Vec<String>,
}

async fn surveys_page(
    user: AuthenticatedUser,
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    let mut rows = app_state
        .connection
        .query(
            "SELECT id FROM system_usability_score_surveys WHERE user_id = :user_id",
            named_params![":user_id": user.id],
        )
        .await
        .expect("Failed to query surveys");

    let mut surveys = Vec::new();

    loop {
        let result = rows.next().await;
        match result {
            Ok(Some(row)) => {
                let result: Result<String, libsql::Error> = row.get(0);
                match result {
                    Ok(id) => surveys.push(id),
                    Err(error) => {
                        tracing::error!("Error reading survey id: {:?}", error);
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
            }
            // No more rows
            Ok(None) => break,
            Err(error) => {
                tracing::error!("Error getting surveys: {:?}", error);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }


    let surveys_template = SurveysTemplate { surveys };
    surveys_template.into_response()
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
