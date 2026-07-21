//! Org settings (Settings page): plan, zero-retention, free-form settings JSON.
//! Provider API keys live in the gateway's environment, not here, and are never
//! returned by this endpoint.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgSettings {
    pub org_name: String,
    pub plan: String,
    pub zero_retention: bool,
    pub settings: serde_json::Value,
}

pub async fn get(State(s): State<AppState>, claims: Claims) -> AppResult<Json<OrgSettings>> {
    let row = sqlx::query_as::<_, (String, String, bool, serde_json::Value)>(
        "SELECT name, plan, zero_retention, settings FROM orgs WHERE id=$1",
    )
    .bind(claims.org)
    .fetch_optional(&s.db)
    .await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(OrgSettings {
        org_name: row.0,
        plan: row.1,
        zero_retention: row.2,
        settings: row.3,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettings {
    pub org_name: Option<String>,
    pub zero_retention: Option<bool>,
    pub settings: Option<serde_json::Value>,
}

pub async fn update(
    State(s): State<AppState>,
    claims: Claims,
    Json(u): Json<UpdateSettings>,
) -> AppResult<Json<OrgSettings>> {
    claims.require_admin()?;
    sqlx::query(
        r#"UPDATE orgs SET
              name = COALESCE($2, name),
              zero_retention = COALESCE($3, zero_retention),
              settings = COALESCE($4, settings)
           WHERE id=$1"#,
    )
    .bind(claims.org)
    .bind(u.org_name)
    .bind(u.zero_retention)
    .bind(u.settings)
    .execute(&s.db)
    .await?;

    crate::routes::metrics::record_activity(
        &s.db,
        claims.org,
        claims.sub,
        "updated org settings",
        "Organization",
    )
    .await;

    get(State(s), claims).await
}
