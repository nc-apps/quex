use libsql::{Builder, Database};

async fn create_database(turso_database_url: String, turso_auth_token: String) -> Database {
    Builder::new_remote(turso_database_url, turso_auth_token)
        .build()
        .await
        .expect("Failed to connect to database")
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum InitializationError {
    #[error("Error connecting to database")]
    ConnectionError(libsql::Error),
    #[error("Error executing create tables batch query")]
    CreateTablesError(libsql::Error),
}

/// Creates the database and initializes it with the tables
pub(super) async fn initialize(
    turso_database_url: String,
    turso_auth_token: String,
) -> Result<Database, InitializationError> {
    let database = create_database(turso_database_url, turso_auth_token).await;

    let connection = database
        .connect()
        .map_err(InitializationError::ConnectionError)?;

    let query = include_str!("./create_tables.sql");
    connection
        .execute_batch(&query)
        .await
        .map_err(InitializationError::CreateTablesError)?;

    tracing::debug!("Tables created");

    Ok(database)
}
