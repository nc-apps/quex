use std::{
    convert::Infallible,
    ops::{Range, RangeFrom},
    sync::Arc,
};

use crate::{auth::Signer, AppState};

use axum::{
    async_trait,
    extract::{rejection::PathRejection, FromRef, FromRequestParts, Path, State},
    http::{self, request::Parts},
    response::IntoResponse,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use getrandom::getrandom;
use time::OffsetDateTime;

#[derive(Debug)]
pub(in crate::auth) struct CompleteSignInToken {
    pub(in crate::auth) user_id: Arc<str>,
    pub(in crate::auth) issued_at: OffsetDateTime,
}

#[derive(thiserror::Error, Debug)]
pub(in crate::auth) enum EncodeTokenError {
    #[error("Error creating salt for complete sign in token signing: {0}")]
    CreateSaltError(#[from] getrandom::Error),
}

#[derive(thiserror::Error, Debug)]
pub(in crate::auth) enum DecodeTokenError {
    #[error("Error decoding base64: {0}")]
    DecodeError(#[from] base64::DecodeError),
    #[error("Invalid signature")]
    InvalidSignature,
    //TODO make minimum length constant
    #[error("Bad token length")]
    BadTokenLength {
        mininum_expected: usize,
        actual: usize,
    },
    #[error("Bad timestamp: {0}")]
    BadTimestamp(#[from] time::error::ComponentRange),
    #[error("Bad token encoding: {0}")]
    BadTokenEncoding(#[from] core::str::Utf8Error),
    /// Google ensures as per documentation that the user id is ASCII
    #[error("User is is not ASCII")]
    NonAsciiUserId,
}

impl CompleteSignInToken {
    const TIMESTAMP_LENGTH: usize = size_of::<i64>();
    const SALT_LENGTH: usize = 16;
    const SIGNATURE_LENGTH: usize = 32;
    const MINIMUM_LENGTH: usize =
        Self::SIGNATURE_LENGTH + Self::SALT_LENGTH + Self::TIMESTAMP_LENGTH + 1;
    const SIGNATURE: Range<usize> = 0..Self::SIGNATURE_LENGTH;
    const PAYLOAD: RangeFrom<usize> = Self::SIGNATURE.end..;
    const SALT: Range<usize> = Self::SIGNATURE.end..Self::SIGNATURE.end + Self::SALT_LENGTH;
    const TIME_STAMP: Range<usize> = Self::SALT.end..Self::SALT.end + Self::TIMESTAMP_LENGTH;
    const USER_ID: RangeFrom<usize> = Self::TIME_STAMP.end..;

    const fn get_length(user_id_length: usize) -> usize {
        Self::SIGNATURE_LENGTH + Self::SALT_LENGTH + Self::TIMESTAMP_LENGTH + user_id_length
    }

    pub(in crate::auth) fn new(user_id: Arc<str>) -> Self {
        let issued_at = OffsetDateTime::now_utc();
        Self { user_id, issued_at }
    }

    pub(in crate::auth) fn try_encode(&self, signer: &Signer) -> Result<String, EncodeTokenError> {
        // Sign user id to prevent others from creating accounts for unauthorized google accounts
        let user_id = self.user_id.as_bytes();
        let issued_at = self.issued_at.unix_timestamp().to_be_bytes();
        // Only unknown size is the user id
        let length = Self::get_length(user_id.len());
        let mut data = vec![0; length];

        getrandom(&mut data[Self::SALT])?;
        data[Self::TIME_STAMP].copy_from_slice(&issued_at);
        data[Self::USER_ID].copy_from_slice(user_id);
        let signature = signer.sign(&data[Self::PAYLOAD]);
        tracing::debug!("Payload {:x?}", &data[Self::PAYLOAD]);
        assert_eq!(signature.as_ref().len(), Self::SIGNATURE_LENGTH);
        data[Self::SIGNATURE].copy_from_slice(signature.as_ref());

        Ok(BASE64_URL_SAFE_NO_PAD.encode(data))
    }

    pub(in crate::auth) fn try_decode(
        data: impl AsRef<[u8]>,
        signer: &Signer,
    ) -> Result<Self, DecodeTokenError> {
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(data)?;

        let signature = decoded
            .get(Self::SIGNATURE)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(DecodeTokenError::BadTokenLength {
                mininum_expected: Self::MINIMUM_LENGTH,
                actual: decoded.len(),
            })?;

        let payload = decoded
            .get(Self::PAYLOAD)
            .ok_or(DecodeTokenError::BadTokenLength {
                mininum_expected: Self::MINIMUM_LENGTH,
                actual: decoded.len(),
            })?;
        tracing::debug!("Payload {:x?}", payload);

        if !signer.is_valid(payload, signature) {
            return Err(DecodeTokenError::InvalidSignature);
        }

        let timestamp = decoded
            .get(Self::TIME_STAMP)
            .ok_or(DecodeTokenError::BadTokenLength {
                // User id is minimum one byte long
                mininum_expected: Self::MINIMUM_LENGTH,
                actual: decoded.len(),
            })?;

        let timestamp = i64::from_be_bytes(timestamp.try_into().expect("Expected 8 bytes"));
        let issued_at = OffsetDateTime::from_unix_timestamp(timestamp)?;

        let user_id = decoded
            .get(Self::USER_ID)
            .ok_or(DecodeTokenError::BadTokenLength {
                mininum_expected: Self::MINIMUM_LENGTH,
                actual: decoded.len(),
            })?;

        let user_id = core::str::from_utf8(user_id)?;

        if !user_id.is_ascii() {
            return Err(DecodeTokenError::NonAsciiUserId);
        }

        Ok(Self {
            user_id: Arc::from(user_id),
            issued_at,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub(in crate::auth) enum DecodeTokenRejection {
    #[error("Failed to get path parameter: {0}")]
    CreatePathError(#[from] PathRejection),
    #[error("Failed to decode token: {0}")]
    DecodeError(#[from] DecodeTokenError),
}

impl IntoResponse for DecodeTokenRejection {
    fn into_response(self) -> askama_axum::Response {
        tracing::error!("Error decoding token: {}", self);
        //TODO redirect user
        http::StatusCode::BAD_REQUEST.into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for CompleteSignInToken
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = DecodeTokenRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(signin_token) = Path::<Arc<str>>::from_request_parts(parts, state).await?;
        let Ok(State(state)): Result<State<AppState>, Infallible> =
            State::from_request_parts(parts, state).await;
        let token =
            CompleteSignInToken::try_decode(signin_token.as_bytes(), &state.google_id_signer)?;
        Ok(token)
    }
}
