use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

fn main() {
    let mut arguments = std::env::args();
    _ = arguments.next();
    let argument = arguments.next().unwrap();
    let mut key = vec![0u8; argument.parse().unwrap()];
    getrandom::getrandom(&mut key).unwrap();
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(&key);
    println!("{}", encoded);
}
