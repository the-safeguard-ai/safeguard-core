//! Effective DLP policy for the browser extension.
//!
//! The extension runs the same detectors client-side (zero token cost) but
//! shouldn't be limited to its built-in default — an org's admins configure
//! policies in the dashboard, and those should drive in-browser enforcement
//! too. This returns the union of the org's enabled-policy detector patterns
//! plus a single recommended enforcement mode.
//!
//! Auth is dual (mirrors telemetry ingest): a user JWT (`Authorization: Bearer`)
//! or an org API key (`x-safeguard-key`), so it works for both individual
//! sign-in and IT mass-rollout.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::auth::decode_token;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

/// Resolve the org from either auth method (org key preferred for rollout).
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtPolicyOut {
    /// Union of detector pattern keys across enabled policies. The browser
    /// engine ignores any key it doesn't recognize, so this stays forward-
    /// compatible with regional packs it hasn't mirrored yet.
    pub patterns: Vec<String>,
    /// Recommended single enforcement mode (block > redact > flag wins).
    pub mode: String,
    /// False when the org has no enabled policies (extension uses its default).
    pub enabled: bool,
}

/// `GET /api/extension/policy` — the org's effective in-browser DLP config.
pub async fn policy(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ExtPolicyOut>> {
    let org_id = resolve_org(&s, &headers).await?;

    let rows = sqlx::query_as::<_, (Vec<String>, String)>(
        "SELECT patterns, action FROM policies WHERE org_id = $1 AND enabled = TRUE",
    )
    .bind(org_id)
    .fetch_all(&s.db)
    .await?;

    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut best_rank = 0u8; // flag=1, redact=2, block=3
    for (patterns, action) in &rows {
        for p in patterns {
            set.insert(p.clone());
        }
        let rank = match action.as_str() {
            "block" => 3,
            "redact" => 2,
            _ => 1,
        };
        best_rank = best_rank.max(rank);
    }

    let mode = match best_rank {
        3 => "block",
        1 => "flag",
        _ => "redact", // also the sensible default when no policies exist
    }
    .to_string();

    Ok(Json(ExtPolicyOut {
        enabled: !set.is_empty(),
        patterns: set.into_iter().collect(),
        mode,
    }))
}
