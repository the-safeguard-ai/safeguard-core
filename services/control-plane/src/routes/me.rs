//! Personal endpoints — the current user's own API keys, usage stats, and
//! activity feed. These never require `require_manage` because they only
//! return data belonging to the authenticated user.

use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use proto::plan::{self, QuotaStatus};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

// ── Personal API keys ───────────────────────────────────────────────────────

fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalKeyInfo {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub created_at: String,
    pub last_used: Option<String>,
    pub revoked: bool,
}

/// List the current user's personal API keys.
pub async fn list_keys(
    State(s): State<AppState>,
    claims: Claims,
) -> AppResult<Json<Vec<PersonalKeyInfo>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, Option<String>, bool)>(
        r#"SELECT id, name, prefix,
                  to_char(created_at, 'YYYY-MM-DD') AS created_at,
                  to_char(last_used, 'YYYY-MM-DD HH24:MI') AS last_used,
                  revoked
           FROM api_keys
           WHERE scope = 'personal' AND user_id = $1
           ORDER BY created_at DESC"#,
    )
    .bind(claims.sub)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, name, prefix, created_at, last_used, revoked)| PersonalKeyInfo {
                id,
                name,
                prefix,
                created_at,
                last_used,
                revoked,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreatePersonalKey {
    pub name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedPersonalKey {
    pub id: Uuid,
    pub name: String,
    /// Plaintext — returned ONCE, never retrievable again.
    pub key: String,
    pub prefix: String,
}

/// Create a personal API key (scoped to the current user).
pub async fn create_key(
    State(s): State<AppState>,
    claims: Claims,
    Json(body): Json<CreatePersonalKey>,
) -> AppResult<Json<CreatedPersonalKey>> {
    let name = body.name.unwrap_or_else(|| "Personal key".into());
    let key = format!("sg_{}", Uuid::new_v4().simple());
    let prefix = format!("{}…", &key[..11]);

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO api_keys (org_id, user_id, name, key_hash, prefix, scope)
           VALUES ($1, $2, $3, $4, $5, 'personal') RETURNING id"#,
    )
    .bind(claims.org)
    .bind(claims.sub)
    .bind(&name)
    .bind(hash_key(&key))
    .bind(&prefix)
    .fetch_one(&s.db)
    .await?;

    Ok(Json(CreatedPersonalKey {
        id,
        name,
        key,
        prefix,
    }))
}

/// Revoke a personal API key (only the owner can revoke it).
pub async fn revoke_key(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    let name: Option<String> = sqlx::query_scalar(
        "UPDATE api_keys SET revoked = TRUE WHERE id = $1 AND user_id = $2 AND scope = 'personal' RETURNING name",
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&s.db)
    .await?;
    let Some(_name) = name else {
        return Err(AppError::NotFound);
    };
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ── Personal usage stats ────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalStats {
    /// Total prompts sent by this user.
    pub total_prompts: i64,
    /// Total sensitive items redacted across this user's prompts.
    pub total_redactions: i64,
    /// Total prompts blocked by DLP for this user.
    pub total_blocks: i64,
    /// Org-level quota information.
    pub quota: QuotaStatus,
}

/// Personal usage stats for the current user.
pub async fn stats(
    State(s): State<AppState>,
    claims: Claims,
) -> AppResult<Json<PersonalStats>> {
    let (total_prompts, total_redactions): (i64, i64) = sqlx::query_as(
        r#"SELECT COUNT(*)::bigint, COALESCE(SUM(redactions), 0)::bigint
           FROM usage_logs WHERE org_id = $1 AND user_id = $2"#,
    )
    .bind(claims.org)
    .bind(claims.sub)
    .fetch_one(&s.db)
    .await
    .unwrap_or((0, 0));

    let total_blocks: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM usage_logs
           WHERE org_id = $1 AND user_id = $2 AND blocked = TRUE"#,
    )
    .bind(claims.org)
    .bind(claims.sub)
    .fetch_one(&s.db)
    .await
    .unwrap_or(0);

    // Org-level quota (shared across all members).
    let plan: String = sqlx::query_scalar("SELECT plan FROM orgs WHERE id = $1")
        .bind(claims.org)
        .fetch_optional(&s.db)
        .await?
        .unwrap_or_else(|| "free".into());

    let now = Utc::now();
    let day = now.format("%Y%m%d").to_string();
    let rkey = plan::quota_key(&claims.org.to_string(), &day);

    let used: i64 = match &s.redis {
        Some(conn) => conn
            .clone()
            .get::<_, Option<i64>>(&rkey)
            .await
            .ok()
            .flatten()
            .unwrap_or(0),
        None => 0,
    };

    Ok(Json(PersonalStats {
        total_prompts,
        total_redactions,
        total_blocks,
        quota: QuotaStatus::build(&plan, used, now.timestamp()),
    }))
}

// ── Personal activity feed ──────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEntry {
    pub action: String,
    pub target: String,
    pub created_at: String,
}

/// Personal activity feed — actions performed by the current user only.
/// The `actor` column stores the user's name, so we resolve it from `claims.sub`.
pub async fn activity(
    State(s): State<AppState>,
    claims: Claims,
) -> AppResult<Json<Vec<ActivityEntry>>> {
    let actor = sqlx::query_scalar::<_, String>(
        "SELECT name FROM users WHERE id = $1",
    )
    .bind(claims.sub)
    .fetch_optional(&s.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let rows = sqlx::query_as::<_, (String, String, String)>(
        r#"SELECT action, target,
                  to_char(created_at, 'YYYY-MM-DD HH24:MI') AS created_at
           FROM activity
           WHERE org_id = $1 AND actor = $2
           ORDER BY created_at DESC
           LIMIT 50"#,
    )
    .bind(claims.org)
    .bind(&actor)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(action, target, created_at)| ActivityEntry {
                action,
                target,
                created_at,
            })
            .collect(),
    ))
}
