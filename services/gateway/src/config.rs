//! Runtime configuration loaded from environment (see `.env.example`).

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub openai_api_key: Option<String>,
    pub openai_base_url: String,
    // Parsed from env and reserved for the native Anthropic adapter (a tracked
    // follow-up); not yet read by the OpenAI-compatible upstream path.
    #[allow(dead_code)]
    pub anthropic_api_key: Option<String>,
    pub ollama_base_url: String,
    pub presidio_url: String,
    // Org-level zero-retention (resolved per-request from auth claims) is what the
    // gateway enforces today; this env default is reserved for orgs without an
    // explicit setting and isn't read yet.
    #[allow(dead_code)]
    pub zero_retention_default: bool,
    /// Embeddings endpoint for RAG retrieval (OpenAI-compatible). Defaults to the
    /// OpenAI base URL; override for a self-hosted embedder.
    pub embedding_base_url: String,
    pub embedding_model: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let _ = dotenvy::dotenv();
        let get = |k: &str| std::env::var(k).ok();
        Ok(Self {
            bind: get("GATEWAY_BIND").unwrap_or_else(|| "0.0.0.0:8080".into()),
            database_url: get("DATABASE_URL").unwrap_or_else(|| {
                "postgres://safeguard:safeguard@localhost:5432/safeguard".into()
            }),
            redis_url: get("REDIS_URL").unwrap_or_else(|| "redis://localhost:6379".into()),
            jwt_secret: get("JWT_SECRET").unwrap_or_else(|| "dev-secret".into()),
            openai_api_key: get("OPENAI_API_KEY").filter(|s| !s.is_empty()),
            openai_base_url: get("OPENAI_BASE_URL")
                .unwrap_or_else(|| "https://api.openai.com".into()),
            anthropic_api_key: get("ANTHROPIC_API_KEY").filter(|s| !s.is_empty()),
            ollama_base_url: get("OLLAMA_BASE_URL")
                .unwrap_or_else(|| "http://localhost:11434".into()),
            presidio_url: get("PRESIDIO_URL").unwrap_or_else(|| "http://localhost:5001".into()),
            zero_retention_default: get("ZERO_RETENTION_DEFAULT")
                .map(|v| v == "true")
                .unwrap_or(false),
            embedding_base_url: get("EMBEDDING_BASE_URL")
                .or_else(|| get("OPENAI_BASE_URL"))
                .unwrap_or_else(|| "https://api.openai.com".into()),
            embedding_model: get("EMBEDDING_MODEL")
                .unwrap_or_else(|| "text-embedding-3-small".into()),
        })
    }
}
