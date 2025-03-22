use askama::Template;
use unic_langid::LanguageIdentifier;

use crate::preferred_language::PreferredLanguage;

#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct ErrorTemplate {
    language: LanguageIdentifier,
}

pub(crate) async fn get_error_page(
    PreferredLanguage(language): PreferredLanguage,
) -> ErrorTemplate {
    ErrorTemplate { language }
}
