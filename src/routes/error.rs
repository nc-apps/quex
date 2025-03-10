use askama::Template;

#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct ErrorTemplate;

pub(crate) async fn get_error_page() -> ErrorTemplate {
    ErrorTemplate
}
