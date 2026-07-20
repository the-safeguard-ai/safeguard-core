//! SafeGuard AI — Control Plane API.
//!
//! Backs every admin-dashboard screen (replacing Admin-dash/lib/mockData.ts):
//! auth, metrics, policies, users/teams, logs, integrations, settings, chat
//! history. All `/api/*` routes are org-scoped via JWT claims.

mod auth;
mod error;
mod routes;
mod state;

use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,control_plane=debug".into()),
        )
        .init();

    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
    let database_url = env(
        "DATABASE_URL",
        "postgres://safeguard:safeguard@localhost:5432/safeguard",
    );
    let bind = env("CONTROL_PLANE_BIND", "0.0.0.0:8081");

    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect_lazy(&database_url)?;

    // Run SQLx migrations automatically on startup. Migrations are embedded at
    // compile time, so the infra/migrations/ dir must be present at build time
    // (the Dockerfile copies it in). Safe to run on every start — SQLx skips
    // already-applied migrations.
    sqlx::migrate!("../../infra/migrations")
        .run(&db)
        .await
        .expect("database migrations failed — check DATABASE_URL and that the postgres container is healthy");

    // Best-effort Redis connection for reading the shared daily-quota counter.
    // If it's down at startup we degrade gracefully (quota reports used = 0).
    let redis_url = env("REDIS_URL", "redis://localhost:6379");
    let redis = match redis::Client::open(redis_url) {
        Ok(client) => match ConnectionManager::new(client).await {
            Ok(conn) => Some(conn),
            Err(e) => {
                tracing::warn!("redis unavailable, quota usage will read 0: {e}");
                None
            }
        },
        Err(e) => {
            tracing::warn!("invalid REDIS_URL, quota usage will read 0: {e}");
            None
        }
    };

    // Embeddings for RAG ingest. Enabled when an embedding endpoint is reachable:
    // a self-hosted base URL needs no key; OpenAI needs OPENAI_API_KEY.
    let embed_base = env(
        "EMBEDDING_BASE_URL",
        &env("OPENAI_BASE_URL", "https://api.openai.com"),
    );
    let embed_model = env("EMBEDDING_MODEL", "text-embedding-3-small");
    let openai_key = std::env::var("OPENAI_API_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    let self_hosted_embed = std::env::var("EMBEDDING_BASE_URL").is_ok();
    let embed = if openai_key.is_some() || self_hosted_embed {
        Some(Arc::new(embed::EmbeddingClient::new(
            embed_base,
            openai_key,
            embed_model,
        )))
    } else {
        tracing::warn!("embeddings not configured (no OPENAI_API_KEY / EMBEDDING_BASE_URL); RAG ingest disabled");
        None
    };

    let state = AppState {
        db,
        jwt_secret: Arc::new(env("JWT_SECRET", "dev-secret")),
        access_ttl_secs: env("JWT_ACCESS_TTL_SECS", "900").parse().unwrap_or(900),
        refresh_ttl_secs: env("JWT_REFRESH_TTL_SECS", "2592000")
            .parse()
            .unwrap_or(2_592_000),
        redis,
        embed,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api = Router::new()
        // auth (public)
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        // invite acceptance (public — invitee has no session yet)
        .route("/auth/invite", get(auth::invite_preview))
        .route("/auth/accept-invite", post(auth::accept_invite))
        // metrics
        .route("/metrics/kpis", get(routes::metrics::kpis))
        .route("/metrics/usage", get(routes::metrics::usage))
        .route("/metrics/quota", get(routes::metrics::quota))
        .route("/alerts", get(routes::metrics::alerts))
        .route("/activity", get(routes::metrics::activity))
        // policies
        .route(
            "/policies",
            get(routes::policies::list).post(routes::policies::create),
        )
        .route(
            "/policies/:id",
            patch(routes::policies::update).delete(routes::policies::delete),
        )
        // regional rule-pack catalog (optional detector packs, off by default)
        .route("/rule-packs", get(routes::rule_packs::list))
        // effective in-browser DLP policy for the extension (dual-auth)
        .route("/extension/policy", get(routes::extension::policy))
        // users & teams
        .route(
            "/users",
            get(routes::users::list).post(routes::users::create),
        )
        .route(
            "/users/:id",
            patch(routes::users::update).delete(routes::users::delete),
        )
        .route("/users/:id/invite", post(routes::users::resend_invite))
        // teams
        .route(
            "/teams",
            get(routes::teams::list).post(routes::teams::create),
        )
        .route(
            "/teams/:id",
            patch(routes::teams::rename).delete(routes::teams::delete),
        )
        // logs
        .route("/logs", get(routes::logs::list))
        // integrations
        .route("/integrations", get(routes::integrations::list))
        .route(
            "/integrations/:slug/install",
            put(routes::integrations::install).delete(routes::integrations::uninstall),
        )
        .route(
            "/integrations/:slug/config",
            patch(routes::integrations::configure),
        )
        .route("/integrations/:slug/test", post(routes::integrations::test))
        // RAG knowledge base (ingest → pgvector; search for testing)
        .route(
            "/rag/documents",
            get(routes::rag::list).post(routes::rag::ingest),
        )
        .route("/rag/documents/:id", delete(routes::rag::delete))
        .route("/rag/search", get(routes::rag::search))
        // settings
        .route(
            "/org/settings",
            get(routes::settings::get).patch(routes::settings::update),
        )
        // org API / enrollment keys (for the browser extension + gateway)
        .route("/keys", get(routes::keys::list).post(routes::keys::create))
        .route("/keys/:id", delete(routes::keys::revoke))
        // conversations (read history + sync the chat app's local history)
        .route("/conversations", get(routes::conversations::list))
        .route(
            "/conversations/:id",
            put(routes::conversations::upsert).delete(routes::conversations::delete),
        )
        .route(
            "/conversations/:id/messages",
            get(routes::conversations::messages).post(routes::conversations::add_message),
        )
        // shadow AI telemetry (ingest = API-key auth; discovery = JWT)
        .route("/telemetry/events", post(routes::telemetry::ingest))
        .route("/discovery", get(routes::telemetry::discovery))
        .route("/discovery/labels", get(routes::telemetry::labels))
        .route("/discovery/events", get(routes::telemetry::events));

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest("/api", api)
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("control-plane listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
