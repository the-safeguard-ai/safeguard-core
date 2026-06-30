//! Database access for the gateway: API-key authentication, per-org policy
//! resolution, and audit-log persistence. Uses runtime SQLx queries so the
//! service builds without a live database (no compile-time `query!` macros).

use dlp::{Action, Policy};
use proto::Route;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Identity + plan resolved from an API key, attached to each request.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub org_id: Uuid,
    pub user_id: Option<Uuid>,
    pub plan: String,
    pub zero_retention: bool,
}

/// SHA-256 hex of an API key. Keys are stored hashed, never in plaintext.
pub fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

/// Look up an (un-revoked) API key and return its org/plan context.
pub async fn authenticate(pool: &PgPool, presented_key: &str) -> Option<AuthContext> {
    let key_hash = hash_key(presented_key);
    let row = sqlx::query_as::<_, (Uuid, Option<Uuid>, String, bool)>(
        r#"
        SELECT k.org_id, k.user_id, o.plan, o.zero_retention
        FROM api_keys k
        JOIN orgs o ON o.id = k.org_id
        WHERE k.key_hash = $1 AND k.revoked = FALSE
        "#,
    )
    .bind(&key_hash)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()?;

    // Best-effort last-used touch; ignore failures.
    let _ = sqlx::query("UPDATE api_keys SET last_used = now() WHERE key_hash = $1")
        .bind(&key_hash)
        .execute(pool)
        .await;

    Some(AuthContext {
        org_id: row.0,
        user_id: row.1,
        plan: row.2,
        zero_retention: row.3,
    })
}

/// Resolve org plan/zero-retention for a JWT-authenticated user (end-user chat
/// app signs in with their account, then calls the gateway with that Bearer JWT
/// — no API key needed). The org/user identity comes from verified claims.
pub async fn org_context(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Option<AuthContext> {
    let row =
        sqlx::query_as::<_, (String, bool)>("SELECT plan, zero_retention FROM orgs WHERE id = $1")
            .bind(org_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()?;

    Some(AuthContext {
        org_id,
        user_id: Some(user_id),
        plan: row.0,
        zero_retention: row.1,
    })
}

/// Active DLP policies plus the routing decision for an org.
pub struct ResolvedPolicies {
    pub policies: Vec<Policy>,
    pub route: Route,
    pub deep_scan: bool,
    pub rag_enabled: bool,
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    name: String,
    enabled: bool,
    patterns: Vec<String>,
    action: String,
    deep_scan: bool,
    rag_enabled: bool,
    route: String,
}

fn parse_action(s: &str) -> Action {
    match s {
        "block" => Action::Block,
        "flag" => Action::Flag,
        _ => Action::Redact,
    }
}

/// Load enabled policies for an org. Route is taken from the first enabled
/// policy that requests `selfhosted`; otherwise cloud. Deep-scan is the OR of
/// all enabled policies.
pub async fn load_policies(pool: &PgPool, org_id: Uuid) -> ResolvedPolicies {
    let rows = sqlx::query_as::<_, PolicyRow>(
        r#"
        SELECT name, enabled, patterns, action, deep_scan, rag_enabled, route
        FROM policies
        WHERE org_id = $1 AND enabled = TRUE
        "#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let route = if rows.iter().any(|r| r.route == "selfhosted") {
        Route::SelfHosted
    } else {
        Route::Cloud
    };
    let deep_scan = rows.iter().any(|r| r.deep_scan);
    let rag_enabled = rows.iter().any(|r| r.rag_enabled);

    let policies = rows
        .into_iter()
        .map(|r| Policy {
            name: r.name,
            enabled: r.enabled,
            patterns: r.patterns,
            action: parse_action(&r.action),
        })
        .collect();

    ResolvedPolicies {
        policies,
        route,
        deep_scan,
        rag_enabled,
    }
}

/// Retrieve the top-`k` knowledge-base chunks for an org most similar to
/// `query_vector` (a pgvector text literal, e.g. `[0.1,0.2,...]`). Cosine
/// distance via the hnsw `vector_cosine_ops` index. Best-effort: returns an
/// empty list on any error so RAG never breaks the proxy path.
pub async fn retrieve_chunks(
    pool: &PgPool,
    org_id: Uuid,
    query_vector: &str,
    k: i64,
) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT content
        FROM rag_chunks
        WHERE org_id = $1 AND embedding IS NOT NULL
        ORDER BY embedding <=> $2::vector
        LIMIT $3
        "#,
    )
    .bind(org_id)
    .bind(query_vector)
    .bind(k)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Data captured for one proxied request.
pub struct UsageRecord {
    pub org_id: Uuid,
    pub user_id: Option<Uuid>,
    pub model: String,
    pub provider: String,
    pub route: Route,
    pub prompt_tokens: i32,
    pub output_tokens: i32,
    pub latency_ms: i32,
    pub redactions: i32,
    pub blocked: bool,
    /// Already NULLed by the caller when zero-retention is on.
    pub prompt_body: Option<String>,
    pub response_body: Option<String>,
}

/// Persist a usage/audit log row. Returns the new row id (for alert linkage).
pub async fn insert_usage_log(pool: &PgPool, rec: &UsageRecord) -> Option<Uuid> {
    let route = match rec.route {
        Route::Cloud => "cloud",
        Route::SelfHosted => "selfhosted",
    };
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO usage_logs
            (org_id, user_id, model, provider, route, prompt_tokens, output_tokens,
             latency_ms, redactions, blocked, prompt_body, response_body)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        RETURNING id
        "#,
    )
    .bind(rec.org_id)
    .bind(rec.user_id)
    .bind(&rec.model)
    .bind(&rec.provider)
    .bind(route)
    .bind(rec.prompt_tokens)
    .bind(rec.output_tokens)
    .bind(rec.latency_ms)
    .bind(rec.redactions)
    .bind(rec.blocked)
    .bind(&rec.prompt_body)
    .bind(&rec.response_body)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Emit a risk alert (e.g. when a request was blocked or many redactions fired).
pub async fn emit_alert(
    pool: &PgPool,
    org_id: Uuid,
    log_id: Option<Uuid>,
    severity: &str,
    message: &str,
) {
    let _ = sqlx::query(
        r#"
        INSERT INTO risk_alerts (org_id, log_id, severity, message)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(org_id)
    .bind(log_id)
    .bind(severity)
    .bind(message)
    .execute(pool)
    .await;
}
