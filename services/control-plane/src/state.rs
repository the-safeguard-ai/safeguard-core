//! Shared application state for the control-plane API.

use std::sync::Arc;

use embed::EmbeddingClient;
use redis::aio::ConnectionManager;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: Arc<String>,
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
    /// Optional Redis connection — used to read the same daily-quota counter the
    /// gateway increments. `None` if Redis was unreachable at startup; the quota
    /// endpoint then reports `used = 0` rather than failing.
    pub redis: Option<ConnectionManager>,
    /// Embeddings client for RAG ingest. `None` when no embedding endpoint/key is
    /// configured — the RAG routes then return a clear "not configured" error.
    pub embed: Option<Arc<EmbeddingClient>>,
}
