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
