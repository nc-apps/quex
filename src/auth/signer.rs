use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AntiforgeryToken(String);

#[derive(thiserror::Error, Debug)]
#[error("Error creating antiforgery token")]
pub(super) struct CreateAntiforgeryTokenError(#[from] getrandom::Error);

const TOKEN_LENGTH: usize = 62;
#[derive(Clone)]
pub(crate) struct Signer {
    key: [u8; 32],
}

impl Signer {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn sign(&self, data: &[u8]) -> impl AsRef<[u8]> {
        let mut hmac: Hmac<Sha256> =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key should be 32 bytes");
        hmac.update(data);
        let result = hmac.finalize().into_bytes();

        result
    }

    pub(super) fn create_antiforgery_token(
        &self,
    ) -> Result<AntiforgeryToken, CreateAntiforgeryTokenError> {
        let mut token = [0; TOKEN_LENGTH];
        let mut unique = &mut token[..30];
        getrandom::getrandom(&mut unique)?;
        let signature = self.sign(&unique);

        token[30..].copy_from_slice(signature.as_ref());

        Ok(AntiforgeryToken(BASE64_URL_SAFE_NO_PAD.encode(&token)))
    }

    pub(super) fn is_token_valid(&self, AntiforgeryToken(token): AntiforgeryToken) -> bool {
        let mut token_bytes = [0; TOKEN_LENGTH];
        let bytes_written = BASE64_URL_SAFE_NO_PAD.decode_slice(token, &mut token_bytes);
        if !matches!(bytes_written, Ok(TOKEN_LENGTH)) {
            return false;
        }

        let mut hmac: Hmac<Sha256> =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key should be 32 bytes");

        hmac.update(&token_bytes[..30]);
        hmac.verify_slice(&token_bytes[30..]).is_ok()
    }
}
