//! Policy CRUD. Shape mirrors mockData.ts policyRules plus the routing/action
//! extensions stored in the `policies` table.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub action: String,
    pub deep_scan: bool,
    pub route: String,
    pub rag_enabled: bool,
}

const SELECT_COLS: &str =
    "id, name, description, enabled, patterns, action, deep_scan, route, rag_enabled";

pub async fn list(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<Policy>>> {
    let rows = sqlx::query_as::<_, Policy>(&format!(
        "SELECT {SELECT_COLS} FROM policies WHERE org_id=$1 ORDER BY created_at"
    ))
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePolicy {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub deep_scan: bool,
    #[serde(default = "default_route")]
    pub route: String,
    #[serde(default)]
    pub rag_enabled: bool,
}

fn default_true() -> bool {
    true
}
fn default_action() -> String {
    "redact".into()
}
fn default_route() -> String {
    "cloud".into()
}

pub async fn create(
    State(s): State<AppState>,
    claims: Claims,
    Json(p): Json<CreatePolicy>,
) -> AppResult<Json<Policy>> {
    claims.require_manage()?;
    let row = sqlx::query_as::<_, Policy>(&format!(
        r#"INSERT INTO policies
            (org_id, name, description, enabled, patterns, action, deep_scan, route, rag_enabled)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           RETURNING {SELECT_COLS}"#
    ))
    .bind(claims.org)
    .bind(&p.name)
    .bind(&p.description)
    .bind(p.enabled)
    .bind(&p.patterns)
    .bind(&p.action)
    .bind(p.deep_scan)
    .bind(&p.route)
    .bind(p.rag_enabled)
    .fetch_one(&s.db)
    .await?;
    crate::routes::metrics::record_activity(
        &s.db,
        claims.org,
        claims.sub,
        "created policy",
        &row.name,
    )
    .await;
    Ok(Json(row))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicy {
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub patterns: Option<Vec<String>>,
    pub action: Option<String>,
    pub deep_scan: Option<bool>,
    pub route: Option<String>,
    pub rag_enabled: Option<bool>,
}

pub async fn update(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
    Json(p): Json<UpdatePolicy>,
) -> AppResult<Json<Policy>> {
    claims.require_manage()?;
    // COALESCE keeps existing values for fields not supplied.
    let row = sqlx::query_as::<_, Policy>(&format!(
        r#"UPDATE policies SET
              name = COALESCE($3, name),
              description = COALESCE($4, description),
              enabled = COALESCE($5, enabled),
              patterns = COALESCE($6, patterns),
              action = COALESCE($7, action),
              deep_scan = COALESCE($8, deep_scan),
              route = COALESCE($9, route),
              rag_enabled = COALESCE($10, rag_enabled),
              updated_at = now()
           WHERE id=$1 AND org_id=$2
           RETURNING {SELECT_COLS}"#
    ))
    .bind(id)
    .bind(claims.org)
    .bind(p.name)
    .bind(p.description)
    .bind(p.enabled)
    .bind(p.patterns)
    .bind(p.action)
    .bind(p.deep_scan)
    .bind(p.route)
    .bind(p.rag_enabled)
    .fetch_optional(&s.db)
    .await?
    .ok_or(AppError::NotFound)?;
    crate::routes::metrics::record_activity(
        &s.db,
        claims.org,
        claims.sub,
        "updated policy",
        &row.name,
    )
    .await;
    Ok(Json(row))
}

pub async fn delete(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_manage()?;
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM policies WHERE id=$1 AND org_id=$2 RETURNING name")
            .bind(id)
            .bind(claims.org)
            .fetch_optional(&s.db)
            .await?;
    let Some(name) = name else {
        return Err(AppError::NotFound);
    };
    crate::routes::metrics::record_activity(&s.db, claims.org, claims.sub, "deleted policy", &name)
        .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
