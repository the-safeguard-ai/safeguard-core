//! Teams — first-class org management. Teams group users; deleting a team
//! detaches its members (users.team_id → NULL via the FK) rather than deleting
//! them. Read is open to any org member; mutations require manage rights.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamOut {
    pub id: String,
    pub name: String,
    pub member_count: i64,
}

/// List teams with their member counts.
pub async fn list(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<TeamOut>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, i64)>(
        r#"SELECT t.id, t.name, COUNT(u.id) AS member_count
           FROM teams t LEFT JOIN users u ON u.team_id = t.id
           WHERE t.org_id = $1
           GROUP BY t.id, t.name
           ORDER BY t.name"#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, name, member_count)| TeamOut {
                id: id.to_string(),
                name,
                member_count,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct TeamBody {
    pub name: String,
}

pub async fn create(
    State(s): State<AppState>,
    claims: Claims,
    Json(body): Json<TeamBody>,
) -> AppResult<Json<TeamOut>> {
    claims.require_manage()?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("team name is required".into()));
    }
    let id: Uuid =
        sqlx::query_scalar(r#"INSERT INTO teams (org_id, name) VALUES ($1, $2) RETURNING id"#)
            .bind(claims.org)
            .bind(name)
            .fetch_one(&s.db)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    AppError::Conflict("a team with that name already exists".into())
                }
                other => AppError::Db(other),
            })?;

    crate::routes::metrics::record_activity(&s.db, claims.org, claims.sub, "created team", name)
        .await;

    Ok(Json(TeamOut {
        id: id.to_string(),
        name: name.to_string(),
        member_count: 0,
    }))
}

pub async fn rename(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
    Json(body): Json<TeamBody>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_manage()?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("team name is required".into()));
    }
    let res = sqlx::query("UPDATE teams SET name = $3 WHERE id = $1 AND org_id = $2")
        .bind(id)
        .bind(claims.org)
        .bind(name)
        .execute(&s.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AppError::Conflict("a team with that name already exists".into())
            }
            other => AppError::Db(other),
        })?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    crate::routes::metrics::record_activity(&s.db, claims.org, claims.sub, "renamed team", name)
        .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_manage()?;
    // Members are detached (team_id → NULL) by the ON DELETE SET NULL FK.
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM teams WHERE id = $1 AND org_id = $2 RETURNING name")
            .bind(id)
            .bind(claims.org)
            .fetch_optional(&s.db)
            .await?;
    let Some(name) = name else {
        return Err(AppError::NotFound);
    };
    crate::routes::metrics::record_activity(&s.db, claims.org, claims.sub, "deleted team", &name)
        .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
