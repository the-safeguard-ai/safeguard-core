//! Embeddings + text chunking for the RAG path.
//!
//! Shared by the control-plane (ingest: chunk → embed → pgvector) and the gateway
//! (query: embed the user's prompt → cosine-search chunks → inject context). Talks
//! the OpenAI-compatible `POST /v1/embeddings` API, so it works against OpenAI
//! (`text-embedding-3-small`, 1536 dims — matches the `vector(1536)` schema) or a
//! self-hosted embedder (Ollama/vLLM) by pointing `base_url` elsewhere.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmbedError {
    #[error("embeddings disabled: no API key / endpoint configured")]
    NotConfigured,
    #[error("embedding request failed: {0}")]
    Request(String),
    #[error("embedding response had no vectors")]
    Empty,
}

#[derive(Clone)]
pub struct EmbeddingClient {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
}

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: &'a [String],
}

#[derive(Deserialize)]
struct EmbedResponse {
    data: Vec<EmbedDatum>,
}

#[derive(Deserialize)]
struct EmbedDatum {
    embedding: Vec<f32>,
    #[serde(default)]
    index: usize,
}

impl EmbeddingClient {
    pub fn new(
        base_url: impl Into<String>,
        api_key: Option<String>,
        model: impl Into<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap_or_default();
        Self {
            http,
            base_url: base_url.into(),
            api_key,
            model: model.into(),
        }
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Embed one or more inputs, returning a vector per input (order preserved).
    pub async fn embed(&self, inputs: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let url = format!("{}/v1/embeddings", self.base_url.trim_end_matches('/'));
        let mut rb = self.http.post(url).json(&EmbedRequest {
            model: &self.model,
            input: inputs,
        });
        if let Some(key) = &self.api_key {
            rb = rb.bearer_auth(key);
        }

        let resp = rb
            .send()
            .await
            .map_err(|e| EmbedError::Request(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(EmbedError::Request(format!("{status}: {body}")));
        }

        let mut parsed: EmbedResponse = resp
            .json()
            .await
            .map_err(|e| EmbedError::Request(e.to_string()))?;
        if parsed.data.is_empty() {
            return Err(EmbedError::Empty);
        }
        // Re-order by the provider's `index` so it lines up with `inputs`.
        parsed.data.sort_by_key(|d| d.index);
        Ok(parsed.data.into_iter().map(|d| d.embedding).collect())
    }

    /// Convenience: embed a single string.
    pub async fn embed_one(&self, input: &str) -> Result<Vec<f32>, EmbedError> {
        let mut v = self.embed(&[input.to_string()]).await?;
        v.pop().ok_or(EmbedError::Empty)
    }
}

/// Format an embedding as a pgvector text literal: `[0.1,0.2,...]`. Bound as a
/// string and cast with `$n::vector` so we need no extra sqlx vector type.
pub fn format_vector(v: &[f32]) -> String {
    let mut s = String::with_capacity(v.len() * 8 + 2);
    s.push('[');
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&x.to_string());
    }
    s.push(']');
    s
}

/// Split text into overlapping chunks of roughly `max_chars`, breaking on
/// whitespace so words aren't cut. `overlap` characters of the previous chunk are
/// repeated at the start of the next for context continuity.
pub fn chunk_text(text: &str, max_chars: usize, overlap: usize) -> Vec<String> {
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let max_chars = max_chars.max(1);
    let overlap = overlap.min(max_chars / 2);

    // Work over char boundaries (not bytes) to stay UTF-8 safe.
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut start = 0;
    while start < chars.len() {
        let hard_end = (start + max_chars).min(chars.len());
        // Prefer to end on the last whitespace within the window (unless we're at
        // the very end of the text).
        let mut end = hard_end;
        if hard_end < chars.len() {
            if let Some(ws) = chars[start..hard_end]
                .iter()
                .rposition(|c| c.is_whitespace())
            {
                if ws > 0 {
                    end = start + ws;
                }
            }
        }
        let piece: String = chars[start..end].iter().collect();
        let piece = piece.trim().to_string();
        if !piece.is_empty() {
            chunks.push(piece);
        }
        if end >= chars.len() {
            break;
        }
        // Advance, leaving `overlap` chars of tail for the next window.
        start = (end.saturating_sub(overlap)).max(start + 1);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_is_one_chunk() {
        assert_eq!(chunk_text("hello world", 100, 10), vec!["hello world"]);
    }

    #[test]
    fn long_text_splits_with_progress() {
        let text = "word ".repeat(200); // 1000 chars
        let chunks = chunk_text(&text, 100, 20);
        assert!(chunks.len() > 1);
        // Every chunk is within the window bound (allowing the trim).
        assert!(chunks.iter().all(|c| c.chars().count() <= 100));
    }

    #[test]
    fn empty_text_yields_no_chunks() {
        assert!(chunk_text("   ", 100, 10).is_empty());
    }

    #[test]
    fn format_vector_shape() {
        assert_eq!(format_vector(&[1.0, 2.5]), "[1,2.5]");
        assert_eq!(format_vector(&[]), "[]");
    }
}
