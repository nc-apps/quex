use askama_axum::IntoResponse;
use axum::Json;
use base64::prelude::*;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_repr::Serialize_repr;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RelyingParty {
    id: String,
    name: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    name: String,
    display_name: String,
}

#[derive(Debug, Serialize_repr)]
#[repr(i16)]
enum Algorithm {
    // Ed25519 = -8,
    ES256 = -7,
    // RS256 = -257,
}

#[derive(Serialize, Debug)]
enum PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

#[derive(Serialize, Debug)]
struct PublicKeyCredentialParameters {
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    r#type: PublicKeyCredentialType,
}

/// Public key creation options for Passkeys/WebAuthn API
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PublicKeyCreationOptions {
    challenge: String,
    #[serde(rename = "rp")]
    relying_party: RelyingParty,
    user: User,
    #[serde(rename = "pubKeyCredParams")]
    public_key_credential_parameters: Vec<PublicKeyCredentialParameters>,
}

pub(super) async fn get_challenge() -> impl IntoResponse {
    let random = SystemRandom::new();
    let mut challenge = [0u8; 32];
    random
        .fill(&mut challenge)
        .expect("Expected to generate challenge");
    let challenge = BASE64_STANDARD.encode(&challenge);
    let relying_party = RelyingParty {
        id: "localhost".to_string(),
        name: "localhost name".to_string(),
    };

    let user = User {
        id: BASE64_STANDARD.encode([1]),
        name: "user name".to_string(),
        display_name: "user display name".to_string(),
    };

    let public_key_credential_parameters = vec![PublicKeyCredentialParameters {
        algorithm: Algorithm::ES256,
        r#type: PublicKeyCredentialType::PublicKey,
    }];

    let public_key_creation_options = PublicKeyCreationOptions {
        challenge,
        relying_party,
        user,
        public_key_credential_parameters,
    };

    Json(public_key_creation_options)
}
