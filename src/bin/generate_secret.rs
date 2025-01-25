use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

fn main() {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).unwrap();
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(&key);
    println!("{}", encoded);
}
