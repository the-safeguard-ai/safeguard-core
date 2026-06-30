//! Users & teams. User shape mirrors mockData.ts users
//! ({ id, name, email, role, team, status }); `team` is the team name.

use axum::extract::{Path, State};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{hash_token, Claims};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// How long a fresh invite link stays valid.
const INVITE_TTL_DAYS: i64 = 7;

/// Issue (or replace) a pending invite for `user_id`, returning the raw token
/// (shown once) and its expiry. The caller builds a shareable accept link from
/// the raw token; only the SHA-256 hash is persisted.
async fn issue_invite(s: &AppState, org: Uuid, user_id: Uuid) -> AppResult<(String, String)> {
    let token = format!("inv_{}", Uuid::new_v4().simple());
    let expires_at = Utc::now() + Duration::days(INVITE_TTL_DAYS);

    let mut tx = s.db.begin().await?;
    // Replace any prior pending invite (the partial unique index allows one).
    sqlx::query("DELETE FROM invites WHERE user_id = $1 AND accepted_at IS NULL")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"INSERT INTO invites (org_id, user_id, token_hash, expires_at)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(org)
    .bind(user_id)
    .bind(hash_token(&token))
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok((token, expires_at.to_rfc3339()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteOut {
    /// Raw invite token — returned ONCE; the admin shares an accept link with it.
    pub invite_token: String,
    pub expires_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOut {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub team: String,
    pub status: String,
}

pub async fn list(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<UserOut>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, Option<String>, String)>(
        r#"SELECT u.id, u.name, u.email, u.role, t.name AS team, u.status
           FROM users u LEFT JOIN teams t ON t.id = u.team_id
           WHERE u.org_id=$1 ORDER BY u.created_at"#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, name, email, role, team, status)| UserOut {
                id: id.to_string(),
                name,
                email,
                role,
                team: team.unwrap_or_default(),
                status,
            })
            .collect(),
    ))
}

/// Resolve a team by name within the org, creating it if necessary.
async fn upsert_team(s: &AppState, org: Uuid, name: &str) -> AppResult<Option<Uuid>> {
    if name.trim().is_empty() {
        return Ok(None);
    }
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO teams (org_id, name) VALUES ($1,$2)
           ON CONFLICT (org_id, name) DO UPDATE SET name = EXCLUDED.name
           RETURNING id"#,
    )
    .bind(org)
    .bind(name)
    .fetch_one(&s.db)
    .await?;
    Ok(Some(id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUser {
    pub name: String,
    pub email: String,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default)]
    pub team: String,
}
fn default_role() -> String {
    "User".into()
}

/// Response to creating a member: the user (status `invited`) plus a one-time
/// invite token the admin shares so the invitee can set a password and log in.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedMember {
    #[serde(flatten)]
    pub user: UserOut,
    pub invite_token: String,
    pub invite_expires_at: String,
}

pub async fn create(
    State(s): State<AppState>,
    claims: Claims,
    Json(u): Json<CreateUser>,
) -> AppResult<Json<CreatedMember>> {
    claims.require_manage()?;
    let team_id = upsert_team(&s, claims.org, &u.team).await?;
    // New members start as `invited` (no password yet); accepting the invite
    // sets their password and flips them to `active`.
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO users (org_id, team_id, name, email, role, status)
           VALUES ($1,$2,$3,$4,$5,'invited') RETURNING id"#,
    )
    .bind(claims.org)
    .bind(team_id)
    .bind(&u.name)
    .bind(&u.email)
    .bind(&u.role)
    .fetch_one(&s.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::Conflict("email already exists in org".into())
        }
        other => AppError::Db(other),
    })?;

    let (invite_token, invite_expires_at) = issue_invite(&s, claims.org, id).await?;
    crate::routes::metrics::record_activity(
        &s.db,
        claims.org,
        claims.sub,
        "invited member",
        &u.email,
    )
    .await;

    Ok(Json(CreatedMember {
        user: UserOut {
            id: id.to_string(),
            name: u.name,
            email: u.email,
            role: u.role,
            team: u.team,
            status: "invited".into(),
        },
        invite_token,
        invite_expires_at,
    }))
}

/// Re-issue an invite link for a member who hasn't accepted yet (status
/// `invited`). Returns a fresh one-time token, invalidating the previous one.
pub async fn resend_invite(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<Json<InviteOut>> {
    claims.require_manage()?;
    // Only members who haven't set a password can be (re)invited.
    let row = sqlx::query_as::<_, (String,)>(
        "SELECT status FROM users WHERE id = $1 AND org_id = $2 AND password_hash IS NULL",
    )
    .bind(id)
    .bind(claims.org)
    .fetch_optional(&s.db)
    .await?;
    if row.is_none() {
        return Err(AppError::NotFound);
    }

    let (invite_token, expires_at) = issue_invite(&s, claims.org, id).await?;
    Ok(Json(InviteOut {
        invite_token,
        expires_at,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUser {
    pub name: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    pub team: Option<String>,
}

pub async fn update(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
    Json(u): Json<UpdateUser>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_manage()?;
    let team_id = match &u.team {
        Some(name) => upsert_team(&s, claims.org, name).await?,
        None => None,
    };
    let name: Option<String> = sqlx::query_scalar(
        r#"UPDATE users SET
              name = COALESCE($3, name),
              role = COALESCE($4, role),
              status = COALESCE($5, status),
              team_id = COALESCE($6, team_id)
           WHERE id=$1 AND org_id=$2
           RETURNING name"#,
    )
    .bind(id)
    .bind(claims.org)
    .bind(u.name)
    .bind(u.role)
    .bind(u.status)
    .bind(team_id)
    .fetch_optional(&s.db)
    .await?;
    let Some(name) = name else {
        return Err(AppError::NotFound);
    };
    crate::routes::metrics::record_activity(&s.db, claims.org, claims.sub, "updated member", &name)
        .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(s): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    claims.require_manage()?;
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM users WHERE id=$1 AND org_id=$2 RETURNING name")
            .bind(id)
            .bind(claims.org)
            .fetch_optional(&s.db)
            .await?;
    let Some(name) = name else {
        return Err(AppError::NotFound);
    };
    crate::routes::metrics::record_activity(&s.db, claims.org, claims.sub, "removed member", &name)
        .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
