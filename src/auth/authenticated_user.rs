use std::sync::Arc;

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::{cookie::Key, SignedCookieJar};
use thiserror::Error;
use time::OffsetDateTime;

use crate::AppState;

use super::cookie;

pub(crate) struct AuthenticatedUser {
    pub(crate) id: Arc<str>,
}

#[derive(Error, Debug)]
pub(crate) enum CookieError {
    #[error("No cookie")]
    Missing,
    #[error(transparent)]
    BadFormat(#[from] cookie::Error),
    #[error("Expired cookie")]
    Expired,
}

impl IntoResponse for CookieError {
    fn into_response(self) -> Response {
        match self {
            CookieError::Missing | CookieError::BadFormat(_) | CookieError::Expired => {
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = CookieError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let key = Key::from_ref(&app_state);
        // Infallible 🙂
        let Ok(headers) = HeaderMap::from_request_parts(parts, state).await;
        let jar = SignedCookieJar::from_headers(&headers, key);

        let cookie = jar.get(cookie::NAME).ok_or(CookieError::Missing)?;

        // Expires can be set by users.
        // So additional validation is required when not expired.
        // The worst case here is the user sets it lower and is signed out earlier but that is their fault.
        // But they should not be allowed to set it higher and stay signed in.
        let is_expired = cookie
            .expires_datetime()
            .is_some_and(|datetime| OffsetDateTime::now_utc() > datetime);

        if is_expired {
            return Err(CookieError::Expired);
        }

        let session = cookie::Session::try_from(cookie)?;
        if session.is_expired() {
            return Err(CookieError::Expired);
        }

        Ok(AuthenticatedUser {
            id: session.user_id,
        })
    }
}
