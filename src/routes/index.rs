use crate::auth::authenticated_user::AuthenticatedUser;
use axum::response::{IntoResponse, Redirect};

pub(crate) async fn get_index_page(user: Option<AuthenticatedUser>) -> impl IntoResponse {
    if user.is_some() {
        return Redirect::to("/surveys");
    }

    Redirect::to("/signin")
}
