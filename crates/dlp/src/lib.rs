//! SafeGuard DLP engine.
//!
//! Hot-path PII/secret detection over text with three policy actions:
//! `redact`, `block`, `flag`. Shared by the gateway (in-process) and exported
//! as rules for the browser/IDE extensions.

pub mod intl;
pub mod packs;
pub mod presidio;
pub mod rules;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use presidio::PresidioClient;

#[derive(Debug, Error)]
pub enum DlpError {
    #[error("presidio request failed: {0}")]
    Presidio(String),
}

/// What to do when a policy's patterns match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Replace matched spans with `[REDACTED:label]` and continue.
    Redact,
    /// Reject the request outright.
    Block,
    /// Allow unchanged but record a finding (and emit an alert).
    Flag,
}

/// One detected sensitive span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub label: String,
    pub start: usize,
    pub end: usize,
}

/// A policy as the engine needs it (subset of the `policies` table).
#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub action: Action,
}

/// Outcome of scanning a piece of text against a set of policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Text after redaction (== input when no redactions applied).
    pub text: String,
    pub findings: Vec<Finding>,
    /// True if any matched policy's action was `Block`.
    pub blocked: bool,
}

impl ScanResult {
    pub fn redactions(&self) -> usize {
        self.findings.len()
    }
}

/// Collect regex hot-path findings (with their policy action) for `input`.
///
/// Returns the findings paired with the action of the policy that matched, plus
/// whether any matched policy's action was `Block`. This is the shared core of
/// both [`scan`] and [`scan_deep`].
fn collect_findings(input: &str, policies: &[Policy]) -> (Vec<(Finding, Action)>, bool) {
    let detectors = rules::detectors();
    let mut findings: Vec<(Finding, Action)> = Vec::new();
    let mut blocked = false;

    for policy in policies.iter().filter(|p| p.enabled) {
        for pat in &policy.patterns {
            let Some(det) = detectors.iter().find(|d| d.pattern == pat) else {
                continue;
            };
            for m in det.regex.find_iter(input) {
                findings.push((
                    Finding {
                        label: det.label.to_string(),
                        start: m.start(),
                        end: m.end(),
                    },
                    policy.action,
                ));
                if policy.action == Action::Block {
                    blocked = true;
                }
            }
        }
    }

    (findings, blocked)
}

/// Apply `Redact` findings to `input`, right-to-left so earlier offsets stay valid.
fn apply_redactions(input: &str, findings: &[(Finding, Action)]) -> String {
    let mut redactable: Vec<&(Finding, Action)> = findings
        .iter()
        .filter(|(_, a)| *a == Action::Redact)
        .collect();
    redactable.sort_by_key(|f| std::cmp::Reverse(f.0.start));

    let mut text = input.to_string();
    for (f, _) in redactable {
        if f.start <= text.len() && f.end <= text.len() {
            text.replace_range(f.start..f.end, &format!("[REDACTED:{}]", f.label));
        }
    }
    text
}

/// True when byte spans `[a0,a1)` and `[b0,b1)` overlap.
fn spans_overlap(a0: usize, a1: usize, b0: usize, b1: usize) -> bool {
    a0 < b1 && b0 < a1
}

/// The more protective of two actions (Block > Redact > Flag), used when
/// overlapping findings from different policies are merged into one span.
fn stronger(a: Action, b: Action) -> Action {
    match (a, b) {
        (Action::Block, _) | (_, Action::Block) => Action::Block,
        (Action::Redact, _) | (_, Action::Redact) => Action::Redact,
        _ => Action::Flag,
    }
}

/// Merge overlapping/duplicate findings into distinct spans.
///
/// Without this, the same bytes can be matched by more than one policy (e.g. two
/// policies both enabling `email`, or a regex hit overlapping an NER entity).
/// Applying those duplicates would redact the same range twice with stale
/// offsets, corrupting the `[REDACTED:…]` token (`…EMAIL]IL]`), and would inflate
/// the redaction count. Overlapping spans are coalesced into their union; the
/// surviving span keeps the leftmost/widest label and the most protective action.
fn dedupe_findings(mut findings: Vec<(Finding, Action)>) -> Vec<(Finding, Action)> {
    if findings.len() < 2 {
        return findings;
    }
    // Leftmost first; on a tie, widest first so the union starts from the widest.
    findings.sort_by(|a, b| a.0.start.cmp(&b.0.start).then(b.0.end.cmp(&a.0.end)));

    let mut merged: Vec<(Finding, Action)> = Vec::with_capacity(findings.len());
    for (f, action) in findings {
        if let Some((last, last_action)) = merged.last_mut() {
            if f.start < last.end {
                // Overlaps the current cluster: extend to the union, keep the
                // existing label, and raise to the stronger action.
                last.end = last.end.max(f.end);
                *last_action = stronger(*last_action, action);
                continue;
            }
        }
        merged.push((f, action));
    }
    merged
}

/// Scan `input` against the active `policies` using the built-in detectors.
///
/// Patterns are matched left-to-right; redactions are applied from the end of
/// the string backwards so byte offsets of earlier findings stay valid. This is
/// the synchronous hot path mirrored by the browser/IDE/MCP extensions.
pub fn scan(input: &str, policies: &[Policy]) -> ScanResult {
    let (findings, blocked) = collect_findings(input, policies);
    let findings = dedupe_findings(findings);
    let text = apply_redactions(input, &findings);
    ScanResult {
        text,
        findings: findings.into_iter().map(|(f, _)| f).collect(),
        blocked,
    }
}

/// Deep scan: the regex hot path **plus** Presidio ML/NER entities.
///
/// Used for policies with `deep_scan = true`. The regex pass stays authoritative
/// for `block`/`flag` (so a configured block still aborts the request); Presidio
/// entities (PERSON, LOCATION, …) are always treated as `redact` — ML matches
/// mask sensitive spans but never hard-block, which avoids NER false positives
/// killing legitimate requests.
///
/// Fails open: if `presidio` is `None`, the request is already blocking, or the
/// sidecar call errors, this returns exactly the regex [`scan`] result. Presidio
/// entities overlapping an existing finding are dropped to avoid double-masking.
pub async fn scan_deep(
    input: &str,
    policies: &[Policy],
    presidio: Option<&PresidioClient>,
) -> ScanResult {
    let (mut findings, blocked) = collect_findings(input, policies);

    // Only call the sidecar when it can change the outcome.
    if let (Some(client), false) = (presidio, blocked) {
        if let Ok(entities) = client.analyze(input).await {
            for f in entities {
                // Drop entities overlapping an existing finding (regex or an
                // already-accepted entity) so spans aren't masked twice.
                let overlaps = findings
                    .iter()
                    .any(|(g, _)| spans_overlap(f.start, f.end, g.start, g.end));
                if !overlaps {
                    findings.push((f, Action::Redact));
                }
            }
        }
    }

    // Coalesce any overlapping regex-vs-regex findings (e.g. two policies sharing
    // a pattern) — the Presidio pass above already skips NER overlaps.
    let findings = dedupe_findings(findings);
    let text = apply_redactions(input, &findings);
    ScanResult {
        text,
        findings: findings.into_iter().map(|(f, _)| f).collect(),
        blocked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(patterns: &[&str], action: Action) -> Policy {
        Policy {
            name: "test".into(),
            enabled: true,
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            action,
        }
    }

    #[test]
    fn redacts_email_and_api_key() {
        let input = "mail me at jane@acme.co with key sk-abcdefghijklmnopqrstuvwx";
        let res = scan(input, &[policy(&["email", "api_key"], Action::Redact)]);
        assert!(res.text.contains("[REDACTED:EMAIL]"));
        assert!(res.text.contains("[REDACTED:API_KEY]"));
        assert!(!res.text.contains("jane@acme.co"));
        assert_eq!(res.redactions(), 2);
        assert!(!res.blocked);
    }

    #[test]
    fn block_action_sets_blocked() {
        let res = scan("ssn 123-45-6789", &[policy(&["ssn"], Action::Block)]);
        assert!(res.blocked);
        assert_eq!(res.findings.len(), 1);
        // Block does not rewrite text.
        assert!(res.text.contains("123-45-6789"));
    }

    #[test]
    fn overlapping_policies_redact_a_span_once() {
        // Two enabled policies both match the same email. The span must be
        // redacted exactly once — no `[REDACTED:EMAIL]IL]` fragment, count == 1.
        let input = "ping jane@acme.co now";
        let res = scan(
            input,
            &[
                policy(&["email"], Action::Redact),
                policy(&["email"], Action::Redact),
            ],
        );
        assert_eq!(res.text, "ping [REDACTED:EMAIL] now");
        assert_eq!(res.redactions(), 1);
        assert!(!res.text.contains("jane@acme.co"));
        assert!(!res.text.contains("EMAIL]IL"));
    }

    #[test]
    fn stronger_action_wins_on_overlap() {
        // Same span flagged by one policy and blocked by another → blocked wins.
        let res = scan(
            "ssn 123-45-6789",
            &[
                policy(&["ssn"], Action::Flag),
                policy(&["ssn"], Action::Block),
            ],
        );
        assert!(res.blocked);
        assert_eq!(res.findings.len(), 1);
    }

    #[test]
    fn detects_international_pii() {
        let input = "iban GB29NWBK60161331926819 ip 192.168.1.42 call +14155552671";
        let res = scan(
            input,
            &[policy(
                &["iban", "ip_address", "intl_phone"],
                Action::Redact,
            )],
        );
        assert!(res.text.contains("[REDACTED:IBAN]"));
        assert!(res.text.contains("[REDACTED:IP_ADDRESS]"));
        assert!(res.text.contains("[REDACTED:INTL_PHONE]"));
    }

    #[test]
    fn disabled_policy_is_skipped() {
        let mut p = policy(&["email"], Action::Redact);
        p.enabled = false;
        let res = scan("a@b.com", &[p]);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.text, "a@b.com");
    }

    #[test]
    fn clean_text_unchanged() {
        let res = scan(
            "nothing sensitive here",
            &[policy(&["email"], Action::Redact)],
        );
        assert_eq!(res.text, "nothing sensitive here");
        assert!(res.findings.is_empty());
    }

    #[tokio::test]
    async fn scan_deep_without_presidio_matches_scan() {
        let input = "mail jane@acme.co";
        let policies = [policy(&["email"], Action::Redact)];
        let deep = scan_deep(input, &policies, None).await;
        let flat = scan(input, &policies);
        assert_eq!(deep.text, flat.text);
        assert_eq!(deep.redactions(), flat.redactions());
        assert!(deep.text.contains("[REDACTED:EMAIL]"));
    }

    #[tokio::test]
    async fn scan_deep_short_circuits_on_block() {
        // A blocking regex policy must abort before any sidecar call.
        let res = scan_deep("ssn 123-45-6789", &[policy(&["ssn"], Action::Block)], None).await;
        assert!(res.blocked);
        assert!(res.text.contains("123-45-6789"));
    }

    #[test]
    fn overlapping_spans_detected() {
        assert!(spans_overlap(0, 5, 3, 8));
        assert!(!spans_overlap(0, 5, 5, 8));
        assert!(!spans_overlap(5, 8, 0, 5));
    }
}
