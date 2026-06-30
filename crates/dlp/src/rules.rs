//! Built-in regex detectors for the DLP hot path.
//!
//! Each [`Detector`] maps a `pattern` key (matching the `patterns[]` column on
//! the `policies` table, e.g. `email`, `api_key`) to a compiled regex. Detectors
//! are compiled once via `once_cell` and shared across requests.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::intl;

/// A named PII/secret detector.
pub struct Detector {
    /// Stable key referenced by `policies.patterns` (e.g. "email").
    pub pattern: &'static str,
    /// Human label used in `[REDACTED:label]` and alerts.
    pub label: &'static str,
    pub regex: &'static Lazy<Regex>,
}

macro_rules! detector {
    ($name:ident, $re:expr) => {
        static $name: Lazy<Regex> = Lazy::new(|| Regex::new($re).expect("valid regex"));
    };
}

detector!(EMAIL, r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b");
// Generic high-entropy secrets: OpenAI sk-..., AWS AKIA..., GitHub ghp_..., etc.
detector!(
    API_KEY,
    r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
);
detector!(CREDIT_CARD, r"\b(?:\d[ -]*?){13,16}\b");
detector!(SSN, r"\b\d{3}-\d{2}-\d{4}\b");
// Leading \b omitted so numbers beginning with '+' still match (Rust regex has
// no lookbehind, and there is no word boundary before a leading '+').
detector!(
    PHONE,
    r"\+?\d{1,3}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b"
);

/// The full ordered set of built-in detectors.
pub fn detectors() -> Vec<Detector> {
    vec![
        Detector {
            pattern: "email",
            label: "EMAIL",
            regex: &EMAIL,
        },
        Detector {
            pattern: "api_key",
            label: "API_KEY",
            regex: &API_KEY,
        },
        Detector {
            pattern: "secret",
            label: "API_KEY",
            regex: &API_KEY,
        },
        Detector {
            pattern: "token",
            label: "API_KEY",
            regex: &API_KEY,
        },
        Detector {
            pattern: "credit_card",
            label: "CREDIT_CARD",
            regex: &CREDIT_CARD,
        },
        Detector {
            pattern: "ssn",
            label: "SSN",
            regex: &SSN,
        },
        Detector {
            pattern: "phone",
            label: "PHONE",
            regex: &PHONE,
        },
        // Internationally-standardized formats (country-agnostic).
        Detector {
            pattern: "iban",
            label: "IBAN",
            regex: intl::iban(),
        },
        Detector {
            pattern: "ip_address",
            label: "IP_ADDRESS",
            regex: intl::ipv4(),
        },
        Detector {
            pattern: "passport",
            label: "PASSPORT",
            regex: intl::passport(),
        },
        Detector {
            pattern: "intl_phone",
            label: "INTL_PHONE",
            regex: intl::e164_phone(),
        },
        // NOTE: country-specific national IDs/tax numbers live in optional,
        // per-org regional rule packs (configurable, off by default). Their
        // detectors are appended here so the engine recognizes a pack's pattern
        // keys when a policy enables them, but none match unless selected.
    ]
    .into_iter()
    .chain(crate::packs::detectors())
    .collect()
}
