use axum::http::Uri;

pub(crate) mod error;
pub(crate) mod index;
pub(crate) mod survey;

fn create_share_link(quex_url: &Uri, survey_id: &str) -> String {
    format!("{}q/{}", quex_url, survey_id,)
}
