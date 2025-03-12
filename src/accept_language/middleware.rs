//! This is based on:
//! - https://yieldcode.blog/post/webapp-localization-in-rust/
//! - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
//! - https://httpwg.org/specs/rfc9110.html#field.accept-language
//! - https://docs.rs/axum/latest/axum/middleware/index.html#passing-state-from-middleware-to-handlers

use axum::{
    extract::Request,
    http::{self},
    middleware::Next,
    response::IntoResponse,
};
use unic_langid::LanguageIdentifier;

use crate::translation::{ENGLISH, SUPPORTED_LOCALES};

#[derive(Clone)]
pub(crate) struct AcceptedLanguage(pub(crate) LanguageIdentifier);

impl Default for AcceptedLanguage {
    fn default() -> Self {
        Self(ENGLISH)
    }
}

pub(crate) async fn extract(mut request: Request, next: Next) -> impl IntoResponse {
    let header = request.headers().get(http::header::ACCEPT_LANGUAGE);
    let Some(value) = header else {
        return next.run(request).await;
    };

    let value = match value.to_str() {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!("Expected accept language header to contain a string value: {error}");
            return next.run(request).await;
        }
    };

    const SUPPORTED_LANGUAGES: [&str; 2] = ["en", "de"];
    let mut accepted_language = None;

    for value in value.split(',') {
        let value = value.trim();

        let mut parts = value.split(';').map(str::trim);
        let Some(language) = parts.next() else {
            tracing::warn!("Expected accept language header to contain a language value");
            continue;
        };

        if language.is_empty() {
            tracing::warn!("Expected accept language header to contain a non-empty value");
            continue;
        }

        let quality: f32 = match parts
            .next()
            .and_then(|value| value.strip_prefix("q="))
            .map(|value| value.parse())
            .transpose()
        {
            Ok(quality) => quality.unwrap_or(1.0),
            Err(error) => {
                tracing::warn!(
                    "Expected accept language header to contain a quality value for {language}: {error}"
                );
                continue;
            }
        };

        let Ok(identifier) = language.parse() else {
            tracing::warn!(
                "Expected accept language header to contain a valid language identifier but got: \"{language}\""
            );
            continue;
        };

        if !SUPPORTED_LOCALES.contains(&identifier) {
            continue;
        }

        accepted_language = match accepted_language {
            None => Some((identifier, quality)),
            Some((_, accepted_quality)) if accepted_quality < quality => {
                Some((identifier, quality))
            }
            _ => continue,
        }
    }

    // "The server may send back a 406 Not Acceptable error code when unable to serve content in a matching language"
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
    // Browsers usually send en with en-US as fallback when users only set en-US
    let Some((identifier, _)) = accepted_language else {
        return http::StatusCode::NOT_ACCEPTABLE.into_response();
    };

    tracing::debug!("Accepted language: {identifier}");
    let extension = AcceptedLanguage(identifier);

    request.extensions_mut().insert(extension);

    next.run(request).await
}
