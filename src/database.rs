use std::sync::Arc;

use libsql::{Builder, Connection, Database};

// Use local database for debugging
// #[cfg(debug_assertions)]
// async fn create_database(_turso_database_url: Arc<str>, _turso_auth_token: Arc<str>) -> Database {
//     Builder::new_local("database.db").build().await.unwrap()
// }

// #[cfg(not(debug_assertions))]
async fn create_database(turso_database_url: String, turso_auth_token: String) -> Database {
    Builder::new_remote(turso_database_url, turso_auth_token)
        .build()
        .await
        .expect("Failed to connect to database")
}

/// Creates the database and initializes it with the tables
pub(super) async fn initialize_database(
    turso_database_url: String,
    turso_auth_token: String,
) -> Connection {
    let database = create_database(turso_database_url, turso_auth_token).await;

    let connection = database.connect().unwrap();

    let query = include_str!("./create_tables.sql");
    connection
        .execute_batch(&query)
        .await
        .expect("Failed to create tables");

    tracing::debug!("Tables created");

    connection
}
