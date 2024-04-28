use askama_axum::{IntoResponse, Template};
use axum::{routing::get, Router};

#[tokio::main]
async fn main() {
    // build our application with a route
    let app = Router::new()
        .route("/", get(handler))
        .route("/nps", get(nps_handler))
        .route("/sus", get(sus_handler))
        .route("/attrakdiff", get(attrakdiff_handler));
    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {}

#[derive(Template)]
#[template(path = "nps.html")]
struct NpsTemplate {}

#[derive(Template)]
#[template(path = "sus.html")]
struct SusTemplate {}

#[derive(Template)]
#[template(path = "attrakdiff.html")]
struct AtrrakDiffTemplate {}

async fn handler() -> impl IntoResponse {
    let index_template = IndexTemplate {};

    index_template
}

async fn nps_handler() -> impl IntoResponse {
    let nps_template = NpsTemplate {};

    nps_template
}
async fn sus_handler() -> impl IntoResponse {
    let sus_template = SusTemplate {};

    sus_template
}

async fn attrakdiff_handler() -> impl IntoResponse {
    let attrakdiff_template = AtrrakDiffTemplate {};

    attrakdiff_template
}
