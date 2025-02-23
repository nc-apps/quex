use libsql::{named_params, params::IntoParams, Builder, Database as LibsqlDatabase};

#[derive(thiserror::Error, Debug)]
#[error("Error creating database: {0}")]
pub(crate) struct CreateError(#[from] libsql::Error);

#[derive(thiserror::Error, Debug)]
pub(crate) enum InitializationError {
    #[error("Error creating databse: {0}")]
    CreateError(#[from] CreateError),
    #[error("Error connecting to database: {0}")]
    ConnectionError(libsql::Error),
    #[error("Error executing create tables batch query: {0}")]
    CreateTablesError(libsql::Error),
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum QueryError {
    #[error("Error connecting to database: {0}")]
    ConnectionError(libsql::Error),
    #[error("Error preparing statement: {0}")]
    PrepareError(libsql::Error),
    #[error("Error exectuing statement: {0}")]
    ExecuteError(libsql::Error),
}

/// A wrapper around the libsql database to hide the database and provide access to predefined queries
pub(crate) struct Database(LibsqlDatabase);

impl Database {
    async fn create(
        turso_database_url: String,
        turso_auth_token: String,
    ) -> Result<Database, CreateError> {
        let database = Builder::new_remote(turso_database_url, turso_auth_token)
            .build()
            .await?;

        Ok(Self(database))
    }

    /// Creates the database and initializes it with the tables
    pub(crate) async fn initialize(
        turso_database_url: String,
        turso_auth_token: String,
    ) -> Result<Database, InitializationError> {
        let database = Self::create(turso_database_url, turso_auth_token).await?;

        let connection = database
            .0
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

    async fn connect(&self) -> Result<libsql::Connection, QueryError> {
        self.0.connect().map_err(QueryError::ConnectionError)
    }

    async fn insert(
        &self,
        sql: &'static str,
        parameters: impl IntoParams,
    ) -> Result<(), QueryError> {
        let connection = self.connect().await?;

        let mut statement = connection
            .prepare(sql)
            .await
            .map_err(QueryError::PrepareError)?;

        statement
            .execute(parameters)
            .await
            .map_err(QueryError::ExecuteError)?;

        Ok(())
    }

    pub(crate) async fn insert_user(&self, user_id: &str, name: &str) -> Result<(), QueryError> {
        self.insert(
            "INSERT INTO users (id, name) VALUES (:id, :name)",
            named_params![
                ":id": user_id,
                ":name": name,
            ],
        )
        .await
    }

    pub(crate) async fn insert_google_account_connection(
        &self,
        user_id: &str,
        google_user_id: &str,
    ) -> Result<(), QueryError> {
        self.insert(
            "INSERT INTO google_account_connections (user_id, google_user_id) VALUES (:user_id, :google_user_id)",
            named_params![
                ":user_id": user_id,
                ":google_user_id": google_user_id,
            ],
        )
        .await
    }
}
