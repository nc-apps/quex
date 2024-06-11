use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use libsql::named_params;
use reqwest::StatusCode;

use crate::AppState;

pub(crate) struct AuthenticatedUser {
    pub id: String,
    name: String,
    email_address: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|error| error.into_response())?;

        let cookie = jar.get("session");

        let Some(cookie) = cookie else {
            //TODO display error message
            return Err(Redirect::to("/signin").into_response());
        };

        let session_id = cookie.value();
        // TODO use stateful cookies to reduce round trips to the database
        let state = AppState::from_ref(state);
        let mut rows = state
            .connection
            .query(
                "SELECT
                user_id,
                name,
                email_address,
                expires_at_utc
            FROM sessions
            JOIN users
                ON sessions.user_id = users.id
                AND sessions.id = :session_id",
                named_params![
                    ":session_id": session_id
                ],
            )
            .await
            .unwrap();

        let Some(row) = rows.next().await.unwrap() else {
            // Remove invalid cookie
            let jar = jar.remove(Cookie::from("session"));
            return Err((jar, Redirect::to("/signin")).into_response());
        };

        let user = AuthenticatedUser {
            id: row.get(0).unwrap(),
            name: row.get(1).unwrap(),
            email_address: row.get(2).unwrap(),
        };

        Ok(user)
    }
}
