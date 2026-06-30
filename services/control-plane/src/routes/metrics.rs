//! Dashboard metrics: KPIs, usage chart, risk alerts, activity feed.
//! Shapes mirror Admin-dash/lib/mockData.ts (dashboardKPIs, usageChartData,
//! riskAlerts, recentActivity).

use axum::extract::State;
use axum::Json;
use chrono::Utc;
use proto::plan::{self, QuotaStatus};
use redis::AsyncCommands;
use serde::Serialize;

use crate::auth::Claims;
use crate::error::AppResult;
use crate::state::AppState;

/// Current daily quota for the caller's org. Reads the **same** Redis counter the
/// gateway increments (so the number matches enforcement); if Redis is
/// unavailable it reports `used = 0` rather than erroring. Limits/reset come from
/// the shared `proto::plan` source of truth.
pub async fn quota(State(s): State<AppState>, claims: Claims) -> AppResult<Json<QuotaStatus>> {
    let plan: String = sqlx::query_scalar("SELECT plan FROM orgs WHERE id = $1")
        .bind(claims.org)
        .fetch_optional(&s.db)
        .await?
        .unwrap_or_else(|| "free".into());

    let now = Utc::now();
    let day = now.format("%Y%m%d").to_string();
    let rkey = plan::quota_key(&claims.org.to_string(), &day);

    let used: i64 = match &s.redis {
        Some(conn) => conn
            .clone()
            .get::<_, Option<i64>>(&rkey)
            .await
            .ok()
            .flatten()
            .unwrap_or(0),
        None => 0,
    };

    Ok(Json(QuotaStatus::build(&plan, used, now.timestamp())))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kpis {
    pub active_users: i64,
    pub queries_today: i64,
    pub risk_incidents: i64,
    pub compliance_score: i64,
}

pub async fn kpis(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Kpis>> {
    let active_users: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE org_id=$1 AND status='active'")
            .bind(claims.org)
            .fetch_one(&s.db)
            .await?;
    let queries_today: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM usage_logs WHERE org_id=$1 AND created_at::date = current_date",
    )
    .bind(claims.org)
    .fetch_one(&s.db)
    .await?;
    let risk_incidents: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM risk_alerts WHERE org_id=$1 AND status IN ('open','investigating')",
    )
    .bind(claims.org)
    .fetch_one(&s.db)
    .await?;
    // Compliance score: % of (last-7-day) requests that were not blocked.
    let compliance_score: i64 = sqlx::query_scalar(
        r#"SELECT COALESCE(
              round(100.0 * (1 - (count(*) FILTER (WHERE blocked))::numeric
                                 / NULLIF(count(*),0))), 100)::bigint
           FROM usage_logs
           WHERE org_id=$1 AND created_at > now() - interval '7 days'"#,
    )
    .bind(claims.org)
    .fetch_one(&s.db)
    .await?;

    Ok(Json(Kpis {
        active_users,
        queries_today,
        risk_incidents,
        compliance_score,
    }))
}

#[derive(Serialize)]
pub struct UsagePoint {
    pub date: String,
    pub queries: i64,
    pub incidents: i64,
}

pub async fn usage(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<UsagePoint>>> {
    let rows = sqlx::query_as::<_, (String, i64, i64)>(
        r#"
        SELECT to_char(d.day, 'Mon DD') AS date,
               COALESCE(q.cnt, 0) AS queries,
               COALESCE(a.cnt, 0) AS incidents
        FROM generate_series(current_date - interval '9 days', current_date, interval '1 day') AS d(day)
        LEFT JOIN (
            SELECT created_at::date AS day, count(*) cnt
            FROM usage_logs WHERE org_id=$1 GROUP BY 1
        ) q ON q.day = d.day::date
        LEFT JOIN (
            SELECT created_at::date AS day, count(*) cnt
            FROM risk_alerts WHERE org_id=$1 GROUP BY 1
        ) a ON a.day = d.day::date
        ORDER BY d.day
        "#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(date, queries, incidents)| UsagePoint {
                date,
                queries,
                incidents,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: String,
    pub team: String,
    pub severity: String,
    pub message: String,
    pub status: String,
}

pub async fn alerts(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<Alert>>> {
    let rows = sqlx::query_as::<_, (uuid::Uuid, String, String, String, String, String)>(
        r#"
        SELECT r.id,
               to_char(r.created_at, 'HH12:MI AM') AS timestamp,
               COALESCE(t.name, 'Org-wide') AS team,
               r.severity, r.message, r.status
        FROM risk_alerts r
        LEFT JOIN teams t ON t.id = r.team_id
        WHERE r.org_id = $1
        ORDER BY r.created_at DESC
        LIMIT 50
        "#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, timestamp, team, severity, message, status)| Alert {
                id: id.to_string(),
                timestamp,
                team,
                severity,
                message,
                status,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct Activity {
    pub id: String,
    pub timestamp: String,
    pub user: String,
    pub action: String,
    pub target: String,
}

pub async fn activity(State(s): State<AppState>, claims: Claims) -> AppResult<Json<Vec<Activity>>> {
    let rows = sqlx::query_as::<_, (uuid::Uuid, String, String, String, String)>(
        r#"
        SELECT id, to_char(created_at, 'HH12:MI AM') AS timestamp, actor, action, target
        FROM activity WHERE org_id=$1 ORDER BY created_at DESC LIMIT 20
        "#,
    )
    .bind(claims.org)
    .fetch_all(&s.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, timestamp, user, action, target)| Activity {
                id: id.to_string(),
                timestamp,
                user,
                action,
                target,
            })
            .collect(),
    ))
}

/// Best-effort write to the activity feed shown on the dashboard. Resolves the
/// actor's display name from their user id in-query, and **never** propagates an
/// error — a logging miss must not fail the mutation that triggered it. Call it
/// with `let _ = record_activity(...).await;` (or just `.await;`) after a
/// successful change.
pub async fn record_activity(
    db: &sqlx::PgPool,
    org: uuid::Uuid,
    actor_id: uuid::Uuid,
    action: &str,
    target: &str,
) {
    let res = sqlx::query(
        r#"INSERT INTO activity (org_id, actor, action, target)
           SELECT $1, COALESCE((SELECT name FROM users WHERE id = $2), 'Someone'), $3, $4"#,
    )
    .bind(org)
    .bind(actor_id)
    .bind(action)
    .bind(target)
    .execute(db)
    .await;
    if let Err(e) = res {
        tracing::warn!("failed to record activity: {e}");
    }
}
