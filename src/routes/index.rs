use crate::auth::authenticated_user::AuthenticatedUser;
use askama::Template;
use askama_axum::IntoResponse;
use axum::response::Redirect;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    is_authenticated: bool,
}

pub(crate) async fn get_index_page(user: Option<AuthenticatedUser>) -> impl IntoResponse {
    if user.is_some() {
        return Redirect::to("/surveys");
    }

    Redirect::to("/signin")
}
