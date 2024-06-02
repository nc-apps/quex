use askama::Template;
use askama_axum::IntoResponse;
use crate::auth::authenticated_user::AuthenticatedUser;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    is_authenticated: bool,
}

pub(crate) async fn get_page(user: Option<AuthenticatedUser>) -> impl IntoResponse {
    let index_template = IndexTemplate {
        is_authenticated: user.is_some(),
    };

    index_template
}
