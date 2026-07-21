//! Integrations (Extensions page). A fixed catalog merged with the org's
//! install state + delivery config from the `integrations` table. Slack, Teams,
//! and Webhooks accept a delivery URL and can be sent a live test event.

use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Integration {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    /// Whether this integration delivers events to a URL (slack/teams/webhooks).
    pub configurable: bool,
    pub installed: bool,
    /// Configured delivery URL (if any). Never fabricated.
    pub webhook_url: Option<String>,
}

/// (slug, name, description, icon, configurable)
const CATALOG: &[(&str, &str, &str, &str, bool)] = &[
    (
        "slack",
        "Slack",
        "Post risk alerts to a Slack channel via an incoming webhook",
        "💬",
        true,
    ),
    (
        "teams",
        "Microsoft Teams",
        "Post risk alerts to a Teams channel via an incoming webhook",
        "👥",
        true,
    ),
    (
        "webhooks",
        "Webhooks",
        "Send a structured JSON event to your own endpoint on every alert",
        "🔗",
        true,
    ),
    (
        "google-sheets",
        "Google Sheets",
        "Export logs and reports to Google Sheets",
        "📊",
        false,
    ),
];

fn is_configurable(slug: &str) -> bool {
    CATALOG.iter().any(|(c, .., cfg)| *c == slug && *cfg)
}

pub async fn list(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<Integration>>> {
    // Map slug → (installed, url) from the org's rows.
    let rows = sqlx::query_as::<_, (String, bool, Option<String>)>(
        "SELECT slug, installed, config->>'url' FROM integrations WHERE org_id=$1",
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;
    let state: HashMap<String, (bool, Option<String>)> = rows
        .into_iter()
        .map(|(slug, installed, url)| (slug, (installed, url)))
        .collect();

    Ok(Json(
        CATALOG
            .iter()
            .map(|(slug, name, desc, icon, configurable)| {
                let (installed, url) = state.get(*slug).cloned().unwrap_or((false, None));
                Integration {
                    id: slug.to_string(),
                    name: name.to_string(),
                    description: desc.to_string(),
                    icon: icon.to_string(),
                    configurable: *configurable,
                    installed,
                    webhook_url: url,
                }
            })
            .collect(),
    ))
}

fn ensure_in_catalog(slug: &str) -> AppResult<()> {
    if CATALOG.iter().any(|(c, ..)| *c == slug) {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// Mark an integration installed.
pub async fn install(
    State(s): State<AppState>,
    claims: Claims,
    Path(slug): Path<String>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_admin()?;
    ensure_in_catalog(&slug)?;
    sqlx::query(
        r#"INSERT INTO integrations (org_id, slug, installed) VALUES ($1,$2,TRUE)
           ON CONFLICT (org_id, slug) DO UPDATE SET installed=TRUE"#,
    )
    .bind(claims.org)
    .bind(&slug)
    .execute(&s.db)
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn uninstall(
    State(s): State<AppState>,
    claims: Claims,
    Path(slug): Path<String>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_admin()?;
    sqlx::query("UPDATE integrations SET installed=FALSE WHERE org_id=$1 AND slug=$2")
        .bind(claims.org)
        .bind(&slug)
        .execute(&s.db)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ConfigBody {
    /// Delivery URL (Slack/Teams incoming webhook, or your own endpoint).
    pub url: String,
}

/// Set the delivery URL for a configurable integration (and install it).
pub async fn configure(
    State(s): State<AppState>,
    claims: Claims,
    Path(slug): Path<String>,
    Json(body): Json<ConfigBody>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_admin()?;
    ensure_in_catalog(&slug)?;
    if !is_configurable(&slug) {
        return Err(AppError::BadRequest(
            "this integration has no delivery URL".into(),
        ));
    }
    let url = body.url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(AppError::BadRequest("url must be http(s)".into()));
    }
    sqlx::query(
        r#"INSERT INTO integrations (org_id, slug, installed, config)
           VALUES ($1, $2, TRUE, jsonb_build_object('url', $3::text))
           ON CONFLICT (org_id, slug)
           DO UPDATE SET installed = TRUE,
                         config = integrations.config || jsonb_build_object('url', $3::text)"#,
    )
    .bind(claims.org)
    .bind(&slug)
    .bind(url)
    .execute(&s.db)
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Send a live test event to the integration's configured URL so the admin can
/// confirm delivery works. Surfaces the endpoint's failure as a 400.
pub async fn test(
    State(s): State<AppState>,
    claims: Claims,
    Path(slug): Path<String>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_admin()?;
    ensure_in_catalog(&slug)?;
    let url: Option<String> =
        sqlx::query_scalar("SELECT config->>'url' FROM integrations WHERE org_id=$1 AND slug=$2")
            .bind(claims.org)
            .bind(&slug)
            .fetch_optional(&s.db)
            .await?
            .flatten();
    let url = url.ok_or_else(|| AppError::BadRequest("configure a delivery URL first".into()))?;

    let ev = notify::WebhookEvent::new(
        claims.org,
        "test",
        "info",
        "SafeGuard test notification — your integration is connected.",
        Utc::now().to_rfc3339(),
    );
    notify::deliver(&slug, &url, &ev)
        .await
        .map_err(|e| AppError::BadRequest(format!("delivery failed: {e}")))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
