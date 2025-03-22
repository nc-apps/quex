//! This is based on:
//! - https://yieldcode.blog/post/webapp-localization-in-rust/
//! - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
//! - https://httpwg.org/specs/rfc9110.html#field.accept-language
//! - https://docs.rs/axum/latest/axum/middleware/index.html#passing-state-from-middleware-to-handlers

use std::convert::Infallible;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{self, request::Parts},
};
use unic_langid::LanguageIdentifier;

use crate::translation::{ENGLISH, SUPPORTED_LOCALES};

#[derive(Clone)]
pub(crate) struct PreferredLanguage(pub(crate) LanguageIdentifier);

impl Default for PreferredLanguage {
    fn default() -> Self {
        Self(ENGLISH)
    }
}

fn try_from_header(request: &Parts) -> Option<LanguageIdentifier> {
    let value = request.headers.get(http::header::ACCEPT_LANGUAGE)?;

    let value = value
        .to_str()
        .inspect_err(|error| {
            tracing::warn!("Expected accept language header to contain a string value: {error}")
        })
        .ok()?;

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

        // Could also match en-US to en but most requests for en-US also contain en
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

    accepted_language.map(|(language, _)| language)
}

#[async_trait]
impl<S> FromRequestParts<S> for PreferredLanguage
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Could also add a preferred language cookie read here if we add that
        Ok(try_from_header(parts)
            .map(PreferredLanguage)
            .unwrap_or_default())
    }
}
