//! Shadow AI telemetry: ingest events from the browser extension and serve
//! discovery data to the dashboard. Only metadata is stored (site, detector
//! labels, counts, outcome) — never prompt text.
//!
//! Ingest auth is dual: an org API key (`x-safeguard-key`, for IT mass-rollout)
//! OR a user JWT (`Authorization: Bearer`, for individual account login). Each
//! event also raises a risk alert so the dashboard reflects activity in real time.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::{decode_token, Claims};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

/// Resolve the org for an ingest request from either auth method.
async fn resolve_org(s: &AppState, headers: &HeaderMap) -> AppResult<Uuid> {
    if let Some(key) = headers.get("x-safeguard-key").and_then(|v| v.to_str().ok()) {
        let org: Option<Uuid> = sqlx::query_scalar(
            "SELECT org_id FROM api_keys WHERE key_hash = $1 AND revoked = FALSE",
        )
        .bind(hash_key(key))
        .fetch_optional(&s.db)
        .await?;
        if let Some(org) = org {
            return Ok(org);
        }
    }
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        if let Some(claims) = decode_token(s, bearer) {
            return Ok(claims.org);
        }
    }
    Err(AppError::Unauthorized)
}

#[derive(Deserialize)]
pub struct EventIn {
    pub site: String,
    pub host: String,
    pub action: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub count: i32,
    /// Enforcement outcome: redact | block | flag.
    #[serde(default = "default_outcome")]
    pub outcome: String,
}
fn default_outcome() -> String {
    "flag".into()
}

pub async fn ingest(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(ev): Json<EventIn>,
) -> AppResult<axum::http::StatusCode> {
    let org_id = resolve_org(&s, &headers).await?;

    sqlx::query(
        r#"INSERT INTO shadow_events (org_id, site, host, action, labels, count, outcome)
           VALUES ($1,$2,$3,$4,$5,$6,$7)"#,
    )
    .bind(org_id)
    .bind(&ev.site)
    .bind(&ev.host)
    .bind(&ev.action)
    .bind(&ev.labels)
    .bind(ev.count)
    .bind(&ev.outcome)
    .execute(&s.db)
    .await?;

    // Raise a risk alert so it surfaces on the dashboard graph + alerts table.
    if ev.count > 0 {
        let severity = match ev.outcome.as_str() {
            "block" => "high",
            "redact" => "medium",
            _ => "low",
        };
        let verb = match ev.outcome.as_str() {
            "block" => "blocked",
            "redact" => "redacted",
            _ => "flagged",
        };
        let labels = if ev.labels.is_empty() {
            "sensitive data".to_string()
        } else {
            ev.labels.join(", ")
        };
        let message = format!("{verb} {labels} on {}", ev.site);
        let _ =
            sqlx::query("INSERT INTO risk_alerts (org_id, severity, message) VALUES ($1,$2,$3)")
                .bind(org_id)
                .bind(severity)
                .bind(&message)
                .execute(&s.db)
                .await;

        // Fan the alert out to installed Slack/Teams/webhook integrations
        // (best-effort, off the request path).
        let ev_out = notify::WebhookEvent::new(
            org_id,
            "risk_alert",
            severity,
            message,
            chrono::Utc::now().to_rfc3339(),
        );
        tokio::spawn(notify::dispatch(s.db.clone(), ev_out));
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRow {
    pub site: String,
    pub events: i64,
    pub items_caught: i64,
    pub blocked: i64,
    pub redacted: i64,
    pub last_seen: String,
}

/// `GET /api/discovery` — per-tool Shadow AI summary.
pub async fn discovery(
    State(s): State<AppState>,
    claims: Claims,
) -> AppResult<Json<Vec<DiscoveryRow>>> {
    let rows = sqlx::query_as::<_, (String, i64, i64, i64, i64, String)>(
        r#"
        SELECT site,
               count(*)                                            AS events,
               COALESCE(sum(count), 0)::bigint                      AS items_caught,
               count(*) FILTER (WHERE outcome = 'block')            AS blocked,
               count(*) FILTER (WHERE outcome = 'redact')           AS redacted,
               to_char(max(created_at), 'YYYY-MM-DD HH24:MI')       AS last_seen
        FROM shadow_events WHERE org_id = $1 GROUP BY site ORDER BY items_caught DESC
        "#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(site, events, items_caught, blocked, redacted, last_seen)| DiscoveryRow {
                    site,
                    events,
                    items_caught,
                    blocked,
                    redacted,
                    last_seen,
                },
            )
            .collect(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelRow {
    pub label: String,
    pub count: i64,
}

/// `GET /api/discovery/labels` — what kinds of data are being caught (for tuning/training).
pub async fn labels(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<LabelRow>>> {
    let rows = sqlx::query_as::<_, (String, i64)>(
        r#"SELECT label, count(*)::bigint
           FROM shadow_events, unnest(labels) AS label
           WHERE org_id = $1 GROUP BY label ORDER BY count(*) DESC"#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(label, count)| LabelRow { label, count })
            .collect(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRow {
    pub id: String,
    pub site: String,
    pub host: String,
    pub action: String,
    pub outcome: String,
    pub labels: Vec<String>,
    pub count: i32,
    pub at: String,
}

/// `GET /api/discovery/events` — recent events for drill-down.
pub async fn events(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<EventRow>>> {
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            String,
            Vec<String>,
            i32,
            String,
        ),
    >(
        r#"SELECT id, site, host, action, outcome, labels, count,
                  to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS at
           FROM shadow_events WHERE org_id = $1 ORDER BY created_at DESC LIMIT 100"#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, site, host, action, outcome, labels, count, at)| EventRow {
                    id: id.to_string(),
                    site,
                    host,
                    action,
                    outcome,
                    labels,
                    count,
                    at,
                },
            )
            .collect(),
    ))
}
