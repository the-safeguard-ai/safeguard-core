//! Upstream LLM routing. Cloud providers (OpenAI/Anthropic) and self-hosted
//! backends (Ollama/vLLM) are all reached over an OpenAI-compatible HTTP API,
//! so routing is a base-URL + auth-header decision.

use proto::{ChatCompletionRequest, ChatCompletionResponse, Route};

use crate::config::Config;
use crate::error::GatewayError;

pub struct Upstream {
    http: reqwest::Client,
}

impl Upstream {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    /// Resolve the upstream URL + optional bearer auth for a route.
    fn target(cfg: &Config, route: Route) -> (String, Option<String>, &'static str) {
        match route {
            Route::Cloud => (
                format!(
                    "{}/v1/chat/completions",
                    cfg.openai_base_url.trim_end_matches('/')
                ),
                cfg.openai_api_key.clone(),
                "openai",
            ),
            Route::SelfHosted => (
                format!(
                    "{}/v1/chat/completions",
                    cfg.ollama_base_url.trim_end_matches('/')
                ),
                None,
                "ollama",
            ),
        }
    }

    pub fn provider_name(route: Route) -> &'static str {
        match route {
            Route::Cloud => "openai",
            Route::SelfHosted => "ollama",
        }
    }

    /// Open a streaming (SSE) connection to the upstream and return the raw
    /// response so the handler can pass `bytes_stream()` straight through.
    ///
    /// NOTE: outbound DLP is not applied to live-streamed tokens in Phase 1
    /// (cross-chunk redaction is deferred); inbound redaction still applies.
    pub async fn chat_stream(
        &self,
        cfg: &Config,
        route: Route,
        req: &ChatCompletionRequest,
    ) -> Result<reqwest::Response, GatewayError> {
        let (url, auth, _) = Self::target(cfg, route);
        let mut rb = self.http.post(url).json(req);
        if let Some(key) = auth {
            rb = rb.bearer_auth(key);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| GatewayError::Upstream(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::UpstreamStatus(status.as_u16(), body));
        }
        Ok(resp)
    }

    /// Forward a (already DLP-scanned) request to the resolved upstream.
    /// Non-streaming for now; SSE pass-through is the next milestone.
    pub async fn chat(
        &self,
        cfg: &Config,
        route: Route,
        req: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, GatewayError> {
        let (url, auth, _) = Self::target(cfg, route);
        let mut rb = self.http.post(url).json(req);
        if let Some(key) = auth {
            rb = rb.bearer_auth(key);
        }

        let resp = rb
            .send()
            .await
            .map_err(|e| GatewayError::Upstream(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::UpstreamStatus(status.as_u16(), body));
        }

        resp.json::<ChatCompletionResponse>()
            .await
            .map_err(|e| GatewayError::Upstream(e.to_string()))
    }
}

impl Default for Upstream {
    fn default() -> Self {
        Self::new()
    }
}
