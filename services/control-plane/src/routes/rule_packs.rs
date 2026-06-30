//! Regional rule-pack catalog. Exposes the optional, country-specific detector
//! packs (UK NINO, India Aadhaar/PAN, Brazil CPF, …) so the policy editor can
//! let admins enable them. All packs are off by default; selecting one appends
//! its `pattern` keys to a policy's `patterns[]`. The catalog itself is static
//! (compiled into the DLP engine) but JWT-scoped for consistency.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::auth::Claims;
use crate::error::AppResult;
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleOut {
    pub pattern: &'static str,
    pub label: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackOut {
    pub id: &'static str,
    pub name: &'static str,
    pub region: &'static str,
    pub description: &'static str,
    pub rules: Vec<RuleOut>,
}

/// `GET /api/rule-packs` — the catalog of available regional rule packs.
pub async fn list(State(_s): State<AppState>, _claims: Claims) -> AppResult<Json<Vec<PackOut>>> {
    let packs = dlp::packs::packs()
        .into_iter()
        .map(|p| PackOut {
            id: p.id,
            name: p.name,
            region: p.region,
            description: p.description,
            rules: p
                .rules
                .into_iter()
                .map(|r| RuleOut {
                    pattern: r.pattern,
                    label: r.label,
                })
                .collect(),
        })
        .collect();
    Ok(Json(packs))
}
