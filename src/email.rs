use axum::http::{uri, Uri};
use reqwest::Client;
use serde::Serialize;

#[derive(Serialize, Debug)]
struct SendEmailRequest {
    to: String,
    from: String,
    subject: String,
    html: String,
}

pub(crate) struct Email(pub(crate) String);

pub(crate) async fn send_sign_in_email(
    Email(email): Email,
    client: &Client,
    sign_in_attempt_id: String,
    server_url: Uri,
) -> Result<(), reqwest::Error> {
    // Using resend.com
    let url = uri::Builder::from(server_url)
        .path_and_query(format!("/signin/{}", sign_in_attempt_id).as_str())
        .build()
        .unwrap();

    let request = SendEmailRequest {
        to: email.to_string(),
        from: "testing.quex@humhy.me".to_owned(),
        subject: "Sign in to your account".to_owned(),
        html: format!("<h1><a href=\"{}\">Sign in to your account</a></h1>", url).to_owned(),
    };

    if cfg!(debug_assertions) {
        tracing::info!("Not sending email in debug mode: {}", request.html);
    } else {
        let token = std::env::var("RESEND_API_KEY").expect("RESEND_API_KEY is not set");
        client
            .post("https://api.resend.com/emails")
            .bearer_auth(token)
            .json(&request)
            .send()
            .await?;
    }
    Ok(())
}
