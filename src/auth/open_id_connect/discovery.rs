use std::sync::Arc;

use axum::http;
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;

#[derive(thiserror::Error, Debug)]
pub(crate) enum GetDocumentError {
    #[error("Failed to build URI for authority")]
    BuildUriError(#[from] http::Error),
    #[error("Failed to send request for discovery document")]
    RequestError(reqwest::Error),
    #[error("Request succeeded but server returned error status code")]
    ErrorResponse(reqwest::Error),
    #[error("Error deserializing discovery document")]
    DeserializeError(reqwest::Error),
}

#[derive(Deserialize, Debug)]
pub(crate) struct Document {
    pub(crate) authorization_endpoint: Url,
    pub(crate) token_endpoint: Url,
    pub(crate) jwks_uri: Url,
}

#[derive(Clone)]
pub(crate) struct DocumentCache {
    // The first Arc is to allow us to easily clone the document cache
    // The Mutex prevents racing conditions where multiple threads try to update the document
    // The Option is to indicate that we haven't fetched the document yet or that it is expired
    // And the Arc<Document> is the actual document and makes it clonable without cloning the document
    document: Arc<Mutex<Option<Arc<Document>>>>,
    client: reqwest::Client,
}

impl DocumentCache {
    pub(crate) fn new(client: reqwest::Client) -> Self {
        Self {
            document: Default::default(),
            client,
        }
    }

    pub(crate) async fn get(&self, mut url: Url) -> Result<Arc<Document>, GetDocumentError> {
        //TODO use Cache-Control header and Age to determine if we should fetch a new document
        let mut document = self.document.lock().await;
        if let Some(document) = document.as_ref() {
            return Ok(document.clone());
        }

        url.set_path("/.well-known/openid-configuration");

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(GetDocumentError::RequestError)?
            .error_for_status()
            .map_err(GetDocumentError::ErrorResponse)?;

        let new_document: Document = response
            .json()
            .await
            .map_err(GetDocumentError::DeserializeError)?;

        let reference = Arc::new(new_document);

        *document = Some(reference.clone());

        Ok(reference)
    }
}
