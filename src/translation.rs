use std::{borrow::Cow, collections::HashMap};

use fluent_templates::Loader;
use unic_langid::{langid, LanguageIdentifier};

fluent_templates::static_loader! {
    pub(crate) static LOCALES = {
        locales: "./translations",
        fallback_language: "en",
    };
}

pub(crate) const ENGLISH: LanguageIdentifier = langid!("en");
pub(crate) const GERMAN: LanguageIdentifier = langid!("de");

pub(crate) const SUPPORTED_LOCALES: [LanguageIdentifier; 2] = [ENGLISH, GERMAN];
/// Convenience function
pub(crate) fn translate(text_id: &str, language: &LanguageIdentifier) -> String {
    LOCALES.lookup(language, text_id)
}

pub(crate) fn translate_1(
    text_id: &str,
    language: &LanguageIdentifier,
    key: &'static str,
    value: &str,
) -> String {
    let arguments = {
        let mut map = HashMap::new();
        map.insert(Cow::from(key), value.into());
        map
    };

    LOCALES.lookup_with_args(language, text_id, &arguments)
}
