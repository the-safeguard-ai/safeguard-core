//! SafeGuard AI — Secure AI Gateway (PRD 5.1).
//!
//! OpenAI-compatible proxy that authenticates requests, enforces quotas, scans
//! traffic with the DLP engine, routes to cloud or self-hosted LLM backends,
//! and writes audit logs. Supports streaming (SSE pass-through) and
//! non-streaming completions.

mod config;
mod db;
mod error;
mod middleware;
mod stream_dlp;
mod upstream;

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::{Extension, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use proto::{ChatCompletionRequest, ChatCompletionResponse, ChatMessage, Role};
use redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower_http::cors::{Any, CorsLayer};

use config::Config;
use db::{AuthContext, UsageRecord};
use error::GatewayError;
use upstream::Upstream;

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    upstream: Arc<Upstream>,
    db: PgPool,
    redis: ConnectionManager,
    /// Presidio deep-scan client; invoked only for `deep_scan` policies and
    /// fails open to the regex result when the sidecar is unreachable.
    presidio: Arc<dlp::PresidioClient>,
    /// Embeddings client for RAG retrieval; invoked only for `rag_enabled`
    /// policies and fails open (no context injected) on any error.
    embed: Arc<embed::EmbeddingClient>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,gateway=debug".into()),
        )
        .init();

    let cfg = Config::from_env()?;
    let bind = cfg.bind.clone();

    let db = PgPoolOptions::new()
        .max_connections(20)
        .connect_lazy(&cfg.database_url)?;
    let redis_client = redis::Client::open(cfg.redis_url.clone())?;
    let redis = ConnectionManager::new(redis_client).await?;

    let presidio = Arc::new(dlp::PresidioClient::new(cfg.presidio_url.clone()));
    let embed = Arc::new(embed::EmbeddingClient::new(
        cfg.embedding_base_url.clone(),
        cfg.openai_api_key.clone(),
        cfg.embedding_model.clone(),
    ));

    let state = AppState {
        cfg: Arc::new(cfg),
        upstream: Arc::new(Upstream::new()),
        db,
        redis,
        presidio,
        embed,
    };

    // Protected proxy routes sit behind the auth+quota gate.
    let proxy = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::gate,
        ));

    // Browser clients (chat app) call the gateway cross-origin; expose the
    // redaction-count header so the UI can show what SafeGuard stripped.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .merge(proxy)
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("gateway listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn chat_completions(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(mut req): Json<ChatCompletionRequest>,
) -> Result<Response, GatewayError> {
    let started = Instant::now();
    let resolved = db::load_policies(&state.db, ctx.org_id).await;

    // ── Inbound DLP scan: redact/flag user & system messages; block aborts. ──
    // We never persist raw PII: on block we store no body, and the prompt
    // snapshot used for audit is built AFTER redaction below.
    // Deep-scan (Presidio NER) is enabled when any active policy requests it;
    // otherwise we stay on the in-process regex hot path.
    let presidio = resolved.deep_scan.then(|| state.presidio.as_ref());

    let mut redactions = 0i32;
    for msg in req.messages.iter_mut() {
        if matches!(msg.role, Role::User | Role::System) {
            let res = dlp::scan_deep(&msg.content, &resolved.policies, presidio).await;
            if res.blocked {
                let log_id = log_usage(
                    &state,
                    &ctx,
                    &req.model,
                    resolved.route,
                    0,
                    0,
                    started.elapsed().as_millis() as i32,
                    res.redactions() as i32,
                    true,
                    None,
                    None,
                )
                .await;
                let msg = "Request blocked by DLP policy";
                db::emit_alert(&state.db, ctx.org_id, log_id, "high", msg).await;
                notify_alert(&state, ctx.org_id, "high", msg);
                return Err(GatewayError::Blocked);
            }
            redactions += res.redactions() as i32;
            msg.content = res.text;
        }
    }

    // Redacted prompt for audit (post-scan; contains no raw PII). Built before
    // RAG injection so the audit reflects the user's prompt, not our KB context.
    let prompt_snapshot = req
        .messages
        .iter()
        .map(|m| m.content.clone())
        .collect::<Vec<_>>()
        .join("\n");

    // ── RAG: inject retrieved knowledge-base context (best-effort) ──
    // For rag_enabled policies, embed the (already-redacted) latest user message,
    // cosine-search the org's chunks, and prepend the top matches as a system
    // message. Fails open: any embed/retrieval error simply injects nothing.
    if resolved.rag_enabled {
        if let Some(query) = req
            .messages
            .iter()
            .rev()
            .find(|m| matches!(m.role, Role::User))
            .map(|m| m.content.clone())
        {
            if let Ok(vector) = state.embed.embed_one(&query).await {
                let chunks =
                    db::retrieve_chunks(&state.db, ctx.org_id, &embed::format_vector(&vector), 5)
                        .await;
                if !chunks.is_empty() {
                    let mut context = String::from(
                        "Relevant context from the organization's knowledge base. \
                         Use it when it helps answer; otherwise rely on your general knowledge.\n\n",
                    );
                    for (i, c) in chunks.iter().enumerate() {
                        context.push_str(&format!("[{}] {}\n\n", i + 1, c));
                    }
                    req.messages.insert(
                        0,
                        ChatMessage {
                            role: Role::System,
                            content: context,
                        },
                    );
                }
            }
        }
    }

    // ── Streaming path: SSE pass-through (inbound redaction already applied). ──
    if req.stream {
        let upstream_resp = state
            .upstream
            .chat_stream(&state.cfg, resolved.route, &req)
            .await?;
        // Minimal audit row; token counts/body not captured for live streams.
        log_usage(
            &state,
            &ctx,
            &req.model,
            resolved.route,
            0,
            0,
            started.elapsed().as_millis() as i32,
            redactions,
            false,
            ctx_body(&ctx, &prompt_snapshot),
            None,
        )
        .await;

        // Outbound DLP: redact streamed response tokens on the fly (cross-chunk)
        // when any redact policy applies; otherwise pass the stream through.
        let body = if stream_dlp::has_outbound_redaction(&resolved.policies) {
            Body::from_stream(stream_dlp::redact_sse(
                upstream_resp.bytes_stream(),
                resolved.policies.clone(),
            ))
        } else {
            Body::from_stream(upstream_resp.bytes_stream())
        };
        return Response::builder()
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .header("x-safeguard-redactions", redactions.to_string())
            .body(body)
            .map_err(|e| GatewayError::Internal(e.to_string()));
    }

    // ── Non-streaming path: full request/response DLP + token accounting. ──
    let mut resp: ChatCompletionResponse = state
        .upstream
        .chat(&state.cfg, resolved.route, &req)
        .await?;

    let mut response_text = String::new();
    for choice in resp.choices.iter_mut() {
        let res = dlp::scan_deep(&choice.message.content, &resolved.policies, presidio).await;
        redactions += res.redactions() as i32;
        choice.message.content = res.text;
        response_text.push_str(&choice.message.content);
    }

    let usage = resp.usage.unwrap_or_default();
    log_usage(
        &state,
        &ctx,
        &resp.model,
        resolved.route,
        usage.prompt_tokens as i32,
        usage.completion_tokens as i32,
        started.elapsed().as_millis() as i32,
        redactions,
        false,
        ctx_body(&ctx, &prompt_snapshot),
        ctx_body(&ctx, &response_text),
    )
    .await;

    if redactions > 0 {
        let msg = format!("{redactions} sensitive field(s) redacted");
        db::emit_alert(&state.db, ctx.org_id, None, "medium", &msg).await;
        notify_alert(&state, ctx.org_id, "medium", &msg);
    }

    // Mirror the streaming path: tell the client how many fields were stripped.
    let mut response = Json(resp).into_response();
    response.headers_mut().insert(
        "x-safeguard-redactions",
        redactions.to_string().parse().expect("digit header value"),
    );
    Ok(response)
}

/// Fan a gateway risk alert out to the org's installed Slack/Teams/webhook
/// integrations, off the request path (best-effort, never blocks the response).
fn notify_alert(state: &AppState, org_id: uuid::Uuid, severity: &str, message: &str) {
    let ev = notify::WebhookEvent::new(
        org_id,
        "risk_alert",
        severity,
        message.to_string(),
        chrono::Utc::now().to_rfc3339(),
    );
    tokio::spawn(notify::dispatch(state.db.clone(), ev));
}

/// Returns the body only when zero-retention is off (privacy by default).
fn ctx_body<'a>(ctx: &AuthContext, body: &'a str) -> Option<&'a str> {
    if ctx.zero_retention {
        None
    } else {
        Some(body)
    }
}

#[allow(clippy::too_many_arguments)]
async fn log_usage(
    state: &AppState,
    ctx: &AuthContext,
    model: &str,
    route: proto::Route,
    prompt_tokens: i32,
    output_tokens: i32,
    latency_ms: i32,
    redactions: i32,
    blocked: bool,
    prompt_body: Option<&str>,
    response_body: Option<&str>,
) -> Option<uuid::Uuid> {
    let rec = UsageRecord {
        org_id: ctx.org_id,
        user_id: ctx.user_id,
        model: model.to_string(),
        provider: Upstream::provider_name(route).to_string(),
        route,
        prompt_tokens,
        output_tokens,
        latency_ms,
        redactions,
        blocked,
        prompt_body: prompt_body.map(|s| s.to_string()),
        response_body: response_body.map(|s| s.to_string()),
    };
    db::insert_usage_log(&state.db, &rec).await
}
