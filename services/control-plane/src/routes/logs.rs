//! Usage logs (Usage Logs page) — filterable, paginated.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::error::AppResult;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LogQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Optional provider filter (openai | anthropic | ollama | vllm).
    pub provider: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogRow {
    pub id: String,
    pub timestamp: String,
    pub model: String,
    pub provider: String,
    pub route: String,
    pub prompt_tokens: i32,
    pub output_tokens: i32,
    pub latency_ms: i32,
    pub redactions: i32,
    pub blocked: bool,
}

pub async fn list(
    State(s): State<AppState>,
    claims: Claims,
    Query(q): Query<LogQuery>,
) -> AppResult<Json<Vec<LogRow>>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);

    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            String,
            i32,
            i32,
            i32,
            i32,
            bool,
        ),
    >(
        r#"
        SELECT id, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS timestamp,
               model, provider, route, prompt_tokens, output_tokens,
               latency_ms, redactions, blocked
        FROM usage_logs
        WHERE org_id = $1 AND ($2::text IS NULL OR provider = $2)
        ORDER BY created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(claims.org)
    .bind(q.provider)
    .bind(limit)
    .bind(offset)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| LogRow {
                id: r.0.to_string(),
                timestamp: r.1,
                model: r.2,
                provider: r.3,
                route: r.4,
                prompt_tokens: r.5,
                output_tokens: r.6,
                latency_ms: r.7,
                redactions: r.8,
                blocked: r.9,
            })
            .collect(),
    ))
}
