use crate::auth::authenticated_user::AuthenticatedUser;
use askama_axum::IntoResponse;
use axum::response::Redirect;

pub(crate) async fn get_index_page(user: Option<AuthenticatedUser>) -> impl IntoResponse {
    if user.is_some() {
        return Redirect::to("/surveys");
    }

    Redirect::to("/signin")
}
