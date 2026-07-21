//! Shared application state for the control-plane API.

use std::sync::Arc;

use embed::EmbeddingClient;
use redis::aio::ConnectionManager;
use sqlx::PgPool;

/// How this control-plane instance authenticates and provisions users.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ControlPlaneMode {
    /// `ADMIN_EMAIL` not set — open registration creates a new org + Admin (local dev).
    Dev,
    /// `ADMIN_EMAIL` set, mode not `cloud` — bootstrap creates admin, registration
    /// is disabled. Admin must invite members.
    SelfHosted,
    /// `ADMIN_EMAIL` set, `CONTROL_PLANE_MODE=cloud` — bootstrap creates a shared org
    /// + super-admin. Open registration creates `User`-role members in that shared org.
    Cloud,
}

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
    /// Deployment mode — determines registration behaviour and bootstrap flow.
    pub mode: ControlPlaneMode,
    /// When set, the email of the initial admin account bootstrapped on first start.
    /// In SelfHosted mode this gates registration; in Cloud mode new sign-ups join
    /// the org this admin belongs to.
    pub admin_email: Option<String>,
}
