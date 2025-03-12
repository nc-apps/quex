use fluent_templates::Loader;
use unic_langid::{langid, LanguageIdentifier};

fluent_templates::static_loader! {
    static LOCALES = {
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
