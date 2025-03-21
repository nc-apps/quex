use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::{Cookie, Key as AxumKey};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use cookie::{CookieBuilder, SameSite};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use super::AppState;

#[derive(Clone)]
pub(crate) struct Key(AxumKey);

pub(super) const NAME: &str = "session";

impl From<&[u8; 64]> for Key {
    fn from(key: &[u8; 64]) -> Self {
        Self(AxumKey::from(key))
    }
}

impl FromRef<AppState> for AxumKey {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.0.clone()
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct Session {
    #[serde(with = "time::serde::timestamp")]
    expires_at: OffsetDateTime,
    pub(super) user_id: Arc<str>,
}

impl Session {
    const NAME: &str = "session";
    const LIFETIME: time::Duration = time::Duration::days(30);

    fn build<'a>(user_id: Arc<str>) -> Result<CookieBuilder<'a>, postcard::Error> {
        let expires_at = OffsetDateTime::now_utc() + Self::LIFETIME;
        let cookie = Self::new(expires_at, user_id);
        let serialized = postcard::to_allocvec(&cookie)?;

        //TODO this does not need to be valid and printable characters.
        // Just UTF-8 as it is encrypted and base64 encoded again by the private cookie jar
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(serialized);
        Ok(Cookie::build((Self::NAME, encoded)).expires(expires_at))
    }

    fn new(expires_at: OffsetDateTime, user_id: Arc<str>) -> Self {
        Self {
            expires_at,
            user_id,
        }
    }

    pub(super) fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() > self.expires_at
    }
}

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("Bad cookie encoding: {0}")]
    BadCookieEncoding(#[from] base64::DecodeError),
    #[error("Bad cookie: {0}")]
    BadCookieFormat(#[from] postcard::Error),
}

impl TryFrom<Cookie<'_>> for Session {
    type Error = Error;

    fn try_from(cookie: Cookie) -> Result<Self, Self::Error> {
        let encoded = cookie.value();
        let serialied = BASE64_URL_SAFE_NO_PAD.decode(encoded)?;
        let value = postcard::from_bytes(&serialied)?;
        Ok(value)
    }
}

pub(super) fn create<'a>(user_id: Arc<str>) -> Result<CookieBuilder<'a>, postcard::Error> {
    Ok(Session::build(user_id)?
        .path("/")
        .secure(true)
        // Tell browsers to not allow JavaScript to access the cookie. Prevents some XSS attacks
        // (JS can still indirectly find out if user is authenticated by trying to access authenticated endpoints)
        .http_only(true)
        // Strict prevents any cross site request
        // Lax allows requests from other sites if it is a get request
        // But we need lax as otherwise OpenID Connect redirects to our site break the flow
        // as it is considered part of the redirect chain where our cookies get set but are no sent.
        // Additionally CORS should be set up correctly to prevent requests from other sites.
        // https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
        .same_site(SameSite::Lax))
}
