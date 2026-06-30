//! Client for the Microsoft Presidio analyzer sidecar (deep-scan path).
//!
//! Used only for policies with `deep_scan = true`. The hot path stays in-process
//! (see [`crate::rules`]); Presidio adds ML-based NER (names, locations, etc.)
//! at the cost of a network round-trip.

use serde::{Deserialize, Serialize};

use crate::{DlpError, Finding};

#[derive(Clone)]
pub struct PresidioClient {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct AnalyzeRequest<'a> {
    text: &'a str,
    language: &'a str,
}

#[derive(Deserialize)]
struct AnalyzeResult {
    entity_type: String,
    start: usize,
    end: usize,
    score: f32,
}

impl PresidioClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        // Bound the deep-scan round-trip so a slow/down sidecar can't hang the
        // gateway hot path — `scan_deep` fails open to the regex result on error.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .unwrap_or_default();
        Self {
            base_url: base_url.into(),
            http,
        }
    }

    /// Calls the analyzer `/analyze` endpoint and maps results to [`Finding`]s.
    pub async fn analyze(&self, text: &str) -> Result<Vec<Finding>, DlpError> {
        let url = format!("{}/analyze", self.base_url.trim_end_matches('/'));
        let results: Vec<AnalyzeResult> = self
            .http
            .post(url)
            .json(&AnalyzeRequest {
                text,
                language: "en",
            })
            .send()
            .await
            .map_err(|e| DlpError::Presidio(e.to_string()))?
            .error_for_status()
            .map_err(|e| DlpError::Presidio(e.to_string()))?
            .json()
            .await
            .map_err(|e| DlpError::Presidio(e.to_string()))?;

        Ok(results
            .into_iter()
            .filter(|r| r.score >= 0.5)
            .map(|r| Finding {
                label: r.entity_type,
                start: r.start,
                end: r.end,
            })
            .collect())
    }
}
