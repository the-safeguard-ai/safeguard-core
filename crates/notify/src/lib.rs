//! Outbound event notifications (webhooks + Slack/Teams).
//!
//! Shared by the gateway (proxy-time risk alerts) and the control-plane
//! (extension telemetry alerts + a manual "send test"). Delivery targets live in
//! the `integrations` table: rows that are `installed` and carry a
//! `config->>'url'`. All delivery is best-effort and time-bounded — a failing or
//! slow endpoint never blocks or breaks the calling request path.

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// A governance event worth notifying about (a risk alert, or a test ping).
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    pub org_id: Uuid,
    /// Machine kind, e.g. `risk_alert` | `test`.
    pub kind: String,
    /// `high` | `medium` | `low` | `info`.
    pub severity: String,
    pub message: String,
    /// RFC3339 timestamp.
    pub at: String,
}

impl WebhookEvent {
    pub fn new(
        org_id: Uuid,
        kind: &str,
        severity: &str,
        message: impl Into<String>,
        at: impl Into<String>,
    ) -> Self {
        Self {
            org_id,
            kind: kind.to_string(),
            severity: severity.to_string(),
            message: message.into(),
            at: at.into(),
        }
    }
}

/// An installed delivery target.
struct Target {
    slug: String,
    url: String,
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_default()
}

/// Build the request body for a given integration slug.
/// - `slack` / `teams`: a simple `{ "text": ... }` (incoming-webhook format).
/// - anything else (`webhooks`): a structured SafeGuard event envelope.
fn payload(slug: &str, ev: &WebhookEvent) -> Value {
    match slug {
        "slack" | "teams" => json!({
            "text": format!("*SafeGuard* [{}] {}", ev.severity.to_uppercase(), ev.message)
        }),
        _ => json!({
            "source": "safeguard",
            "kind": ev.kind,
            "severity": ev.severity,
            "message": ev.message,
            "orgId": ev.org_id,
            "at": ev.at,
        }),
    }
}

/// Load installed integrations for an org that have a delivery URL configured.
async fn load_targets(pool: &PgPool, org_id: Uuid) -> Vec<Target> {
    sqlx::query_as::<_, (String, String)>(
        r#"SELECT slug, config->>'url'
           FROM integrations
           WHERE org_id = $1
             AND installed = TRUE
             AND slug IN ('slack', 'teams', 'webhooks')
             AND COALESCE(config->>'url', '') <> ''"#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(slug, url)| Target { slug, url })
    .collect()
}

/// Deliver a single event to one target URL. Returns an error string on failure
/// (used by the "send test" endpoint to report success/failure to the admin).
pub async fn deliver(slug: &str, url: &str, ev: &WebhookEvent) -> Result<(), String> {
    let resp = http_client()
        .post(url)
        .json(&payload(slug, ev))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("endpoint returned {}", resp.status()))
    }
}

/// Fan an event out to every installed/configured target for the org.
/// Best-effort: errors are logged, not returned. Safe to `tokio::spawn`.
pub async fn dispatch(pool: PgPool, ev: WebhookEvent) {
    let targets = load_targets(&pool, ev.org_id).await;
    if targets.is_empty() {
        return;
    }
    let client = http_client();
    for t in targets {
        match client
            .post(&t.url)
            .json(&payload(&t.slug, &ev))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => tracing::warn!("notify {} -> {} returned {}", t.slug, t.url, resp.status()),
            Err(e) => tracing::warn!("notify {} delivery failed: {e}", t.slug),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev() -> WebhookEvent {
        WebhookEvent::new(
            Uuid::nil(),
            "risk_alert",
            "high",
            "blocked SSN on chatgpt.com",
            "2026-06-30T00:00:00Z",
        )
    }

    #[test]
    fn slack_payload_is_text() {
        let p = payload("slack", &ev());
        assert!(p.get("text").unwrap().as_str().unwrap().contains("HIGH"));
    }

    #[test]
    fn generic_payload_is_structured() {
        let p = payload("webhooks", &ev());
        assert_eq!(p["source"], "safeguard");
        assert_eq!(p["severity"], "high");
        assert_eq!(p["kind"], "risk_alert");
    }
}
