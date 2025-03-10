use std::sync::Arc;

pub(crate) mod middleware;

pub(crate) struct Language {
    value: Arc<str>,
    quality: f32,
}
