//! Chat conversation history (Chat page sidebar). The live message streaming
//! itself goes through the gateway; these endpoints serve saved history and let
//! the chat app sync its local history to the server for cross-device access.
//!
//! Privacy: everything persisted here is redacted with the org's DLP policies
//! first — raw PII is never stored at rest (consistent with the audit trail).
//! Orgs with zero-retention store no message bodies at all.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Load the org's enabled DLP policies as engine policies (for at-rest redaction).
async fn redact_policies(s: &AppState, org_id: Uuid) -> AppResult<Vec<dlp::Policy>> {
    let rows = sqlx::query_as::<_, (String, bool, Vec<String>, String)>(
        "SELECT name, enabled, patterns, action FROM policies WHERE org_id = $1 AND enabled = TRUE",
    )
    .bind(org_id)
    .fetch_all(&s.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(name, enabled, patterns, action)| dlp::Policy {
            name,
            enabled,
            patterns,
            action: match action.as_str() {
                "block" => dlp::Action::Block,
                "flag" => dlp::Action::Flag,
                _ => dlp::Action::Redact,
            },
        })
        .collect())
}

/// True when the org has zero-retention enabled (store no bodies at rest).
async fn zero_retention(s: &AppState, org_id: Uuid) -> AppResult<bool> {
    let z: Option<bool> = sqlx::query_scalar("SELECT zero_retention FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_optional(&s.db)
        .await?;
    Ok(z.unwrap_or(false))
}

/// Redact text for at-rest storage using the org's policies. All matched spans
/// are masked regardless of the policy's action (we never store raw PII here).
async fn redact_for_store(s: &AppState, org_id: Uuid, text: &str) -> AppResult<String> {
    let mut policies = redact_policies(s, org_id).await?;
    // Force redact so a "flag"/"block" policy still masks the stored copy.
    for p in policies.iter_mut() {
        p.action = dlp::Action::Redact;
    }
    Ok(dlp::scan(text, &policies).text)
}

#[derive(Serialize)]
pub struct ConversationOut {
    pub id: String,
    pub title: String,
    pub date: String,
    pub preview: String,
}

pub async fn list(
    State(s): State<AppState>,
    claims: Claims,
) -> AppResult<Json<Vec<ConversationOut>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, Option<String>)>(
        r#"
        SELECT c.id, c.title, to_char(c.updated_at, 'YYYY-MM-DD') AS date,
               (SELECT content FROM messages m
                WHERE m.conversation_id = c.id ORDER BY m.created_at DESC LIMIT 1) AS preview
        FROM conversations c
        WHERE c.org_id = $1 AND c.user_id = $2
        ORDER BY c.updated_at DESC
        "#,
    )
    .bind(claims.org)
    .bind(claims.sub)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, title, date, preview)| ConversationOut {
                id: id.to_string(),
                title,
                date,
                preview: preview.unwrap_or_default().chars().take(80).collect(),
            })
            .collect(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageOut {
    pub id: String,
    pub role: String,
    pub content: String,
    pub timestamp: String,
    pub safe_mode: bool,
}

pub async fn messages(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<MessageOut>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, bool)>(
        r#"
        SELECT m.id, m.role, m.content, to_char(m.created_at, 'HH12:MI AM') AS ts, m.safe_mode
        FROM messages m
        JOIN conversations c ON c.id = m.conversation_id
        WHERE m.conversation_id = $1 AND c.org_id = $2
        ORDER BY m.created_at
        "#,
    )
    .bind(id)
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, role, content, timestamp, safe_mode)| MessageOut {
                id: id.to_string(),
                role,
                content,
                timestamp,
                safe_mode,
            })
            .collect(),
    ))
}

// ── Write path: sync the chat app's local history to the server ──────────────

#[derive(Deserialize)]
pub struct UpsertConversation {
    #[serde(default)]
    pub title: String,
}

/// `PUT /api/conversations/:id` — create or rename a conversation (idempotent).
/// The id is the chat app's own UUID so client and server stay aligned. Title is
/// redacted at rest; under zero-retention it's stored generically.
pub async fn upsert(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
    Json(p): Json<UpsertConversation>,
) -> AppResult<axum::http::StatusCode> {
    let title = if zero_retention(&s, claims.org).await? {
        "Conversation".to_string()
    } else {
        let t = redact_for_store(&s, claims.org, &p.title).await?;
        if t.trim().is_empty() {
            "New chat".to_string()
        } else {
            t
        }
    };

    sqlx::query(
        r#"
        INSERT INTO conversations (id, org_id, user_id, title)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO UPDATE
            SET title = EXCLUDED.title, updated_at = now()
            WHERE conversations.org_id = $2 AND conversations.user_id = $3
        "#,
    )
    .bind(id)
    .bind(claims.org)
    .bind(claims.sub)
    .bind(&title)
    .execute(&s.db)
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `DELETE /api/conversations/:id` — delete a conversation (messages cascade).
pub async fn delete(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    let res =
        sqlx::query("DELETE FROM conversations WHERE id = $1 AND org_id = $2 AND user_id = $3")
            .bind(id)
            .bind(claims.org)
            .bind(claims.sub)
            .execute(&s.db)
            .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMessage {
    pub id: Option<Uuid>,
    pub role: String,
    #[serde(default)]
    pub content: String,
}

/// `POST /api/conversations/:id/messages` — append a message (idempotent on id).
/// Content is redacted before storage; zero-retention orgs store no body (no-op).
pub async fn add_message(
    State(s): State<AppState>,
    claims: Claims,
    Path(conv_id): Path<Uuid>,
    Json(m): Json<AddMessage>,
) -> AppResult<axum::http::StatusCode> {
    let role = match m.role.as_str() {
        "user" | "assistant" | "system" => m.role.as_str(),
        _ => return Err(AppError::BadRequest("invalid role".into())),
    };

    // Zero-retention: never persist message bodies. Conversation metadata only.
    if zero_retention(&s, claims.org).await? {
        return Ok(axum::http::StatusCode::NO_CONTENT);
    }

    // Ensure the conversation exists and belongs to this user (self-healing so
    // message sync doesn't depend on the conversation PUT landing first).
    sqlx::query(
        r#"INSERT INTO conversations (id, org_id, user_id)
           VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(conv_id)
    .bind(claims.org)
    .bind(claims.sub)
    .execute(&s.db)
    .await?;

    // Guard: only write to a conversation owned by the caller.
    let owns: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM conversations WHERE id = $1 AND org_id = $2 AND user_id = $3",
    )
    .bind(conv_id)
    .bind(claims.org)
    .bind(claims.sub)
    .fetch_optional(&s.db)
    .await?;
    if owns.is_none() {
        return Err(AppError::NotFound);
    }

    let content = redact_for_store(&s, claims.org, &m.content).await?;
    let msg_id = m.id.unwrap_or_else(Uuid::new_v4);

    sqlx::query(
        r#"INSERT INTO messages (id, conversation_id, role, content, safe_mode)
           VALUES ($1, $2, $3, $4, TRUE) ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(msg_id)
    .bind(conv_id)
    .bind(role)
    .bind(&content)
    .execute(&s.db)
    .await?;

    // Touch the conversation so it sorts to the top of the history list.
    let _ = sqlx::query("UPDATE conversations SET updated_at = now() WHERE id = $1")
        .bind(conv_id)
        .execute(&s.db)
        .await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}
