//! Internationally-applicable detectors that aren't tied to a single country.
//!
//! Country-specific national IDs / tax numbers are intentionally NOT hardcoded
//! here — they belong in optional, per-org *regional rule packs* (configurable,
//! off by default) so the product stays globally applicable. These detectors
//! cover formats that are standardized across borders.

use once_cell::sync::Lazy;
use regex::Regex;

// IBAN: 2-letter country code + 2 check digits + up to 30 alphanumerics.
static IBAN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b").unwrap());
// IPv4 address.
static IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap()
});
// Passport: common 1-2 letters followed by 6-9 digits (generic, no country lock).
static PASSPORT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Z]{1,2}\d{6,9}\b").unwrap());
// E.164-style international phone (leading '+' and country code).
static E164_PHONE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\+\d{6,15}\b").unwrap());

pub fn iban() -> &'static Lazy<Regex> {
    &IBAN
}
pub fn ipv4() -> &'static Lazy<Regex> {
    &IPV4
}
pub fn passport() -> &'static Lazy<Regex> {
    &PASSPORT
}
pub fn e164_phone() -> &'static Lazy<Regex> {
    &E164_PHONE
}
