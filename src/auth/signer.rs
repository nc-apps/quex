use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AntiForgeryToken(String);

#[derive(thiserror::Error, Debug)]
#[error("Error creating anti forgery token")]
pub(super) struct CreateAntiForgeryTokenError(#[from] getrandom::Error);

const TOKEN_LENGTH: usize = 62;

#[derive(Clone)]
pub(crate) struct Signer {
    key: [u8; 32],
}

impl Signer {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub(crate) fn sign(&self, data: &[u8]) -> impl AsRef<[u8]> {
        let mut hmac: Hmac<Sha256> =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key should be 32 bytes");
        hmac.update(data);

        hmac.finalize().into_bytes()
    }

    pub(crate) fn is_valid(&self, data: &[u8], signature: &[u8; 32]) -> bool {
        let mut hmac: Hmac<Sha256> =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key should be 32 bytes");

        hmac.update(data);
        hmac.verify_slice(signature).is_ok()
    }
}

#[derive(Clone)]
pub(crate) struct AntiForgeryTokenProvider {
    signer: Signer,
}

const SIGNATURE_LENGTH: usize = 32;
impl AntiForgeryTokenProvider {
    pub(crate) fn new(signer: Signer) -> Self {
        Self { signer }
    }

    pub(super) fn create_anti_forgery_token(
        &self,
    ) -> Result<AntiForgeryToken, CreateAntiForgeryTokenError> {
        let mut token = [0; TOKEN_LENGTH];

        let unique = &mut token[SIGNATURE_LENGTH..];
        getrandom::getrandom(unique)?;
        let signature = self.signer.sign(unique);

        token[..SIGNATURE_LENGTH].copy_from_slice(signature.as_ref());

        Ok(AntiForgeryToken(BASE64_URL_SAFE_NO_PAD.encode(token)))
    }

    pub(super) fn is_token_valid(&self, AntiForgeryToken(token): &AntiForgeryToken) -> bool {
        let mut token_bytes = [0; TOKEN_LENGTH];
        let bytes_written = BASE64_URL_SAFE_NO_PAD.decode_slice(token, &mut token_bytes);
        if !matches!(bytes_written, Ok(TOKEN_LENGTH)) {
            return false;
        }

        let Ok(signature) = token_bytes[..SIGNATURE_LENGTH].try_into() else {
            return false;
        };

        self.signer
            .is_valid(&token_bytes[SIGNATURE_LENGTH..], &signature)
    }
}
