//! Optional, per-org *regional rule packs*.
//!
//! SafeGuard is **international by default**: no country's national identifiers
//! are ever enabled implicitly. Region-specific detectors (national IDs, tax
//! numbers, etc.) live here as named packs that an org opts into by adding the
//! pack's `pattern` keys to a policy's `patterns[]`. Nothing in this module is
//! active unless explicitly selected — every pack is off by default, and no
//! single jurisdiction is privileged.
//!
//! The detector regexes are registered alongside the built-ins in
//! [`crate::rules::detectors`]; the [`packs`] catalog is what the control-plane
//! exposes so admins can discover and enable them.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::rules::Detector;

/// A region-specific detector: its stable `pattern` key, `[REDACTED:label]`,
/// and compiled regex. Mirrors [`crate::rules::Detector`] but grouped by pack.
macro_rules! re {
    ($name:ident, $re:expr) => {
        static $name: Lazy<Regex> = Lazy::new(|| Regex::new($re).expect("valid regex"));
    };
}

// ── United Kingdom ──────────────────────────────────────────────────────────
// National Insurance Number: 2 prefix letters, 6 digits, 1 suffix letter.
re!(UK_NINO, r"(?i)\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b");

// ── India ───────────────────────────────────────────────────────────────────
// Aadhaar: 12 digits, usually grouped 4-4-4.
re!(IN_AADHAAR, r"\b\d{4}\s?\d{4}\s?\d{4}\b");
// PAN: 5 letters, 4 digits, 1 letter.
re!(IN_PAN, r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b");

// ── Canada ──────────────────────────────────────────────────────────────────
// Social Insurance Number: 9 digits, grouped 3-3-3.
re!(CA_SIN, r"\b\d{3}[\s-]\d{3}[\s-]\d{3}\b");

// ── Australia ───────────────────────────────────────────────────────────────
// Tax File Number: 8-9 digits, grouped 3-3-3.
re!(AU_TFN, r"\b\d{3}\s\d{3}\s\d{2,3}\b");
// Australian Business Number: 11 digits, grouped 2-3-3-3.
re!(AU_ABN, r"\b\d{2}\s\d{3}\s\d{3}\s\d{3}\b");

// ── Brazil ──────────────────────────────────────────────────────────────────
// CPF: 000.000.000-00.
re!(BR_CPF, r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b");
// CNPJ: 00.000.000/0000-00.
re!(BR_CNPJ, r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b");

// ── Spain ───────────────────────────────────────────────────────────────────
// DNI / NIF: 8 digits + checksum letter.
re!(ES_DNI, r"(?i)\b\d{8}[A-Z]\b");

// ── France ──────────────────────────────────────────────────────────────────
// INSEE / social security: sex digit + 14 more, often spaced.
re!(
    FR_INSEE,
    r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2,3}\s?\d{2,3}\s?\d{3}\s?\d{2}\b"
);

// ── South Africa ────────────────────────────────────────────────────────────
// ID number: 13 digits.
re!(ZA_ID, r"\b\d{13}\b");

// ── Singapore ───────────────────────────────────────────────────────────────
// NRIC / FIN: leading S/T/F/G, 7 digits, checksum letter.
re!(SG_NRIC, r"(?i)\b[STFG]\d{7}[A-Z]\b");

/// All region-specific detectors, appended to the built-in detector set so the
/// engine recognizes a pack's `pattern` keys when a policy enables them.
pub fn detectors() -> Vec<Detector> {
    vec![
        Detector {
            pattern: "uk_nino",
            label: "UK_NINO",
            regex: &UK_NINO,
        },
        Detector {
            pattern: "in_aadhaar",
            label: "IN_AADHAAR",
            regex: &IN_AADHAAR,
        },
        Detector {
            pattern: "in_pan",
            label: "IN_PAN",
            regex: &IN_PAN,
        },
        Detector {
            pattern: "ca_sin",
            label: "CA_SIN",
            regex: &CA_SIN,
        },
        Detector {
            pattern: "au_tfn",
            label: "AU_TFN",
            regex: &AU_TFN,
        },
        Detector {
            pattern: "au_abn",
            label: "AU_ABN",
            regex: &AU_ABN,
        },
        Detector {
            pattern: "br_cpf",
            label: "BR_CPF",
            regex: &BR_CPF,
        },
        Detector {
            pattern: "br_cnpj",
            label: "BR_CNPJ",
            regex: &BR_CNPJ,
        },
        Detector {
            pattern: "es_dni",
            label: "ES_DNI",
            regex: &ES_DNI,
        },
        Detector {
            pattern: "fr_insee",
            label: "FR_INSEE",
            regex: &FR_INSEE,
        },
        Detector {
            pattern: "za_id",
            label: "ZA_ID",
            regex: &ZA_ID,
        },
        Detector {
            pattern: "sg_nric",
            label: "SG_NRIC",
            regex: &SG_NRIC,
        },
    ]
}

/// One detector within a [`RulePack`], for catalog/UI display.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PackRule {
    /// Stable key to place in `policies.patterns[]`.
    pub pattern: &'static str,
    /// Human label shown in the policy editor.
    pub label: &'static str,
}

/// A named, opt-in group of region-specific detectors.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RulePack {
    /// Stable pack id (e.g. `"uk"`).
    pub id: &'static str,
    /// Display name (e.g. `"United Kingdom"`).
    pub name: &'static str,
    /// Broad region grouping for the UI (e.g. `"Europe"`).
    pub region: &'static str,
    pub description: &'static str,
    pub rules: Vec<PackRule>,
}

/// The catalog of available regional rule packs. Surfaced by the control-plane
/// so admins can browse and enable them — all off until selected.
pub fn packs() -> Vec<RulePack> {
    vec![
        RulePack {
            id: "uk",
            name: "United Kingdom",
            region: "Europe",
            description: "UK National Insurance Number.",
            rules: vec![PackRule {
                pattern: "uk_nino",
                label: "National Insurance No.",
            }],
        },
        RulePack {
            id: "india",
            name: "India",
            region: "Asia-Pacific",
            description: "Aadhaar and PAN identifiers.",
            rules: vec![
                PackRule {
                    pattern: "in_aadhaar",
                    label: "Aadhaar",
                },
                PackRule {
                    pattern: "in_pan",
                    label: "PAN",
                },
            ],
        },
        RulePack {
            id: "canada",
            name: "Canada",
            region: "Americas",
            description: "Social Insurance Number (SIN).",
            rules: vec![PackRule {
                pattern: "ca_sin",
                label: "Social Insurance No.",
            }],
        },
        RulePack {
            id: "australia",
            name: "Australia",
            region: "Asia-Pacific",
            description: "Tax File Number and Australian Business Number.",
            rules: vec![
                PackRule {
                    pattern: "au_tfn",
                    label: "Tax File Number",
                },
                PackRule {
                    pattern: "au_abn",
                    label: "Business Number (ABN)",
                },
            ],
        },
        RulePack {
            id: "brazil",
            name: "Brazil",
            region: "Americas",
            description: "CPF and CNPJ identifiers.",
            rules: vec![
                PackRule {
                    pattern: "br_cpf",
                    label: "CPF",
                },
                PackRule {
                    pattern: "br_cnpj",
                    label: "CNPJ",
                },
            ],
        },
        RulePack {
            id: "spain",
            name: "Spain",
            region: "Europe",
            description: "DNI / NIF national identifier.",
            rules: vec![PackRule {
                pattern: "es_dni",
                label: "DNI / NIF",
            }],
        },
        RulePack {
            id: "france",
            name: "France",
            region: "Europe",
            description: "INSEE social security number.",
            rules: vec![PackRule {
                pattern: "fr_insee",
                label: "INSEE / Sécu",
            }],
        },
        RulePack {
            id: "south_africa",
            name: "South Africa",
            region: "Africa",
            description: "National ID number.",
            rules: vec![PackRule {
                pattern: "za_id",
                label: "National ID",
            }],
        },
        RulePack {
            id: "singapore",
            name: "Singapore",
            region: "Asia-Pacific",
            description: "NRIC / FIN identifier.",
            rules: vec![PackRule {
                pattern: "sg_nric",
                label: "NRIC / FIN",
            }],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scan, Action, Policy};

    fn policy(patterns: &[&str]) -> Policy {
        Policy {
            name: "t".into(),
            enabled: true,
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            action: Action::Redact,
        }
    }

    #[test]
    fn regional_packs_are_off_until_selected() {
        // A UK NINO is left untouched when no pack pattern is enabled.
        let res = scan("ref AB123456C here", &[policy(&["email"])]);
        assert!(res.findings.is_empty());
        assert_eq!(res.text, "ref AB123456C here");
    }

    #[test]
    fn uk_nino_redacted_when_enabled() {
        let res = scan("ni AB123456C", &[policy(&["uk_nino"])]);
        assert!(res.text.contains("[REDACTED:UK_NINO]"), "got: {}", res.text);
    }

    #[test]
    fn brazil_cpf_redacted_when_enabled() {
        let res = scan("cpf 123.456.789-09", &[policy(&["br_cpf"])]);
        assert!(res.text.contains("[REDACTED:BR_CPF]"), "got: {}", res.text);
    }

    #[test]
    fn every_pack_rule_has_a_detector() {
        let dets = crate::rules::detectors();
        for pack in packs() {
            for rule in &pack.rules {
                assert!(
                    dets.iter().any(|d| d.pattern == rule.pattern),
                    "pack {} rule {} has no detector",
                    pack.id,
                    rule.pattern
                );
            }
        }
    }
}
