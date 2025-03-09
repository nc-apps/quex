use askama::Template;

use crate::auth::authenticated_user::AuthenticatedUser;

#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct ErrorTemplate {
    is_authenticated: bool,
}

pub(crate) async fn get_error_page(user: Option<AuthenticatedUser>) -> ErrorTemplate {
    ErrorTemplate {
        is_authenticated: user.is_some(),
    }
}
