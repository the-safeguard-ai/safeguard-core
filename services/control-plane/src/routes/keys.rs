//! Org API / enrollment keys. The same key authenticates the browser extension
//! (telemetry) and the gateway proxy. The plaintext key is shown exactly once,
//! at creation; only its SHA-256 hash is stored.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Deserialize)]
pub struct CreateKey {
    pub name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedKey {
    pub id: Uuid,
    pub name: String,
    /// Plaintext — returned ONCE, never retrievable again.
    pub key: String,
    pub prefix: String,
}

pub async fn create(
    State(s): State<AppState>,
    claims: Claims,
    Json(body): Json<CreateKey>,
) -> AppResult<Json<CreatedKey>> {
    claims.require_manage()?;
    let name = body.name.unwrap_or_else(|| "Extension key".into());
    let key = format!("sg_{}", Uuid::new_v4().simple());
    let prefix = format!("{}…", &key[..11]);

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO api_keys (org_id, user_id, name, key_hash, prefix)
           VALUES ($1, $2, $3, $4, $5) RETURNING id"#,
    )
    .bind(claims.org)
    .bind(claims.sub)
    .bind(&name)
    .bind(hash_key(&key))
    .bind(&prefix)
    .fetch_one(&s.db)
    .await?;

    crate::routes::metrics::record_activity(
        &s.db,
        claims.org,
        claims.sub,
        "created API key",
        &name,
    )
    .await;

    Ok(Json(CreatedKey {
        id,
        name,
        key,
        prefix,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub created_at: String,
    pub last_used: Option<String>,
    pub revoked: bool,
}

pub async fn list(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<KeyInfo>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, Option<String>, bool)>(
        r#"SELECT id, name, prefix,
                  to_char(created_at, 'YYYY-MM-DD') AS created_at,
                  to_char(last_used, 'YYYY-MM-DD HH24:MI') AS last_used,
                  revoked
           FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC"#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, name, prefix, created_at, last_used, revoked)| KeyInfo {
                    id,
                    name,
                    prefix,
                    created_at,
                    last_used,
                    revoked,
                },
            )
            .collect(),
    ))
}

pub async fn revoke(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_manage()?;
    let name: Option<String> = sqlx::query_scalar(
        "UPDATE api_keys SET revoked = TRUE WHERE id = $1 AND org_id = $2 RETURNING name",
    )
    .bind(id)
    .bind(claims.org)
    .fetch_optional(&s.db)
    .await?;
    let Some(name) = name else {
        return Err(AppError::NotFound);
    };
    crate::routes::metrics::record_activity(
        &s.db,
        claims.org,
        claims.sub,
        "revoked API key",
        &name,
    )
    .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
