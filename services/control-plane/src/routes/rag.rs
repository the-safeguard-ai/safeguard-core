//! RAG knowledge base: ingest documents (chunk → embed → pgvector), list/delete
//! them, and a cosine-similarity search endpoint. The gateway performs retrieval
//! at request time; these routes manage the corpus and let admins test search.
//!
//! Embeddings use the shared `embed` client (OpenAI-compatible). When embeddings
//! aren't configured the routes return a clear error rather than failing opaquely.

use axum::extract::{Path, Query, State};
use axum::Json;
use embed::{chunk_text, format_vector};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// ~1000 chars (~250 tokens) per chunk with 150 chars of overlap — a reasonable
/// default for prose knowledge bases.
const CHUNK_CHARS: usize = 1000;
const CHUNK_OVERLAP: usize = 150;
const DEFAULT_TOP_K: i64 = 5;

fn embedder(s: &AppState) -> AppResult<&embed::EmbeddingClient> {
    s.embed
        .as_deref()
        .ok_or_else(|| AppError::BadRequest(
            "embeddings are not configured on this server (set OPENAI_API_KEY or EMBEDDING_BASE_URL)".into(),
        ))
}

// ── Ingest ───────────────────────────────────────────────────────────────────
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestReq {
    pub title: String,
    #[serde(default)]
    pub source: Option<String>,
    pub content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestResp {
    pub id: String,
    pub title: String,
    pub chunks: usize,
}

pub async fn ingest(
    State(s): State<AppState>,
    claims: Claims,
    Json(req): Json<IngestReq>,
) -> AppResult<Json<IngestResp>> {
    claims.require_admin()?;
    if req.title.trim().is_empty() || req.content.trim().is_empty() {
        return Err(AppError::BadRequest(
            "title and content are required".into(),
        ));
    }
    let client = embedder(&s)?;

    let chunks = chunk_text(&req.content, CHUNK_CHARS, CHUNK_OVERLAP);
    if chunks.is_empty() {
        return Err(AppError::BadRequest("content produced no chunks".into()));
    }
    let vectors = client
        .embed(&chunks)
        .await
        .map_err(|e| AppError::Internal(format!("embedding failed: {e}")))?;
    if vectors.len() != chunks.len() {
        return Err(AppError::Internal("embedding count mismatch".into()));
    }

    let mut tx = s.db.begin().await?;
    let doc_id: Uuid = sqlx::query_scalar(
        "INSERT INTO rag_documents (org_id, title, source) VALUES ($1,$2,$3) RETURNING id",
    )
    .bind(claims.org)
    .bind(req.title.trim())
    .bind(req.source.as_deref())
    .fetch_one(&mut *tx)
    .await?;

    for (i, (content, vector)) in chunks.iter().zip(vectors.iter()).enumerate() {
        sqlx::query(
            r#"INSERT INTO rag_chunks (document_id, org_id, content, embedding, chunk_index)
               VALUES ($1,$2,$3,$4::vector,$5)"#,
        )
        .bind(doc_id)
        .bind(claims.org)
        .bind(content)
        .bind(format_vector(vector))
        .bind(i as i32)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    crate::routes::metrics::record_activity(
        &s.db,
        claims.org,
        claims.sub,
        "added document",
        &req.title,
    )
    .await;

    Ok(Json(IngestResp {
        id: doc_id.to_string(),
        title: req.title,
        chunks: chunks.len(),
    }))
}

// ── List / delete ────────────────────────────────────────────────────────────
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentOut {
    pub id: String,
    pub title: String,
    pub source: Option<String>,
    pub chunks: i64,
    pub created_at: String,
}

pub async fn list(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<DocumentOut>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, i64, String)>(
        r#"SELECT d.id, d.title, d.source, COUNT(c.id) AS chunks,
                  to_char(d.created_at, 'YYYY-MM-DD HH24:MI') AS created_at
           FROM rag_documents d
           LEFT JOIN rag_chunks c ON c.document_id = d.id
           WHERE d.org_id = $1
           GROUP BY d.id
           ORDER BY d.created_at DESC"#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, title, source, chunks, created_at)| DocumentOut {
                id: id.to_string(),
                title,
                source,
                chunks,
                created_at,
            })
            .collect(),
    ))
}

pub async fn delete(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_admin()?;
    // Chunks cascade via the FK.
    let title: Option<String> = sqlx::query_scalar(
        "DELETE FROM rag_documents WHERE id = $1 AND org_id = $2 RETURNING title",
    )
    .bind(id)
    .bind(claims.org)
    .fetch_optional(&s.db)
    .await?;
    let Some(title) = title else {
        return Err(AppError::NotFound);
    };
    crate::routes::metrics::record_activity(
        &s.db,
        claims.org,
        claims.sub,
        "deleted document",
        &title,
    )
    .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ── Search (manual / debugging; the gateway does its own retrieval) ───────────
#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub k: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub document_id: String,
    pub title: String,
    pub content: String,
    pub score: f64,
}

pub async fn search(
    State(s): State<AppState>,
    claims: Claims,
    Query(q): Query<SearchQuery>,
) -> AppResult<Json<Vec<SearchHit>>> {
    if q.q.trim().is_empty() {
        return Err(AppError::BadRequest("query `q` is required".into()));
    }
    let client = embedder(&s)?;
    let k = q.k.unwrap_or(DEFAULT_TOP_K).clamp(1, 20);

    let vector = client
        .embed_one(&q.q)
        .await
        .map_err(|e| AppError::Internal(format!("embedding failed: {e}")))?;

    // `<=>` is cosine distance (vector_cosine_ops); similarity = 1 - distance.
    let rows = sqlx::query_as::<_, (Uuid, String, String, f64)>(
        r#"SELECT c.document_id, d.title, c.content,
                  1 - (c.embedding <=> $1::vector) AS score
           FROM rag_chunks c
           JOIN rag_documents d ON d.id = c.document_id
           WHERE c.org_id = $2 AND c.embedding IS NOT NULL
           ORDER BY c.embedding <=> $1::vector
           LIMIT $3"#,
    )
    .bind(format_vector(&vector))
    .bind(claims.org)
    .bind(k)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(document_id, title, content, score)| SearchHit {
                document_id: document_id.to_string(),
                title,
                content,
                score,
            })
            .collect(),
    ))
}
