//! Request gate: API-key authentication + Redis quota enforcement, run as one
//! Axum middleware so ordering is unambiguous. On success it injects
//! [`AuthContext`] into request extensions for the handler.

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use jsonwebtoken::{decode, DecodingKey, Validation};
use proto::plan::{self, QuotaStatus};
use proto::ApiError;
use redis::AsyncCommands;
use serde::Deserialize;
use uuid::Uuid;

use crate::db::{self, AuthContext};
use crate::error::GatewayError;
use crate::AppState;

/// Subset of the control-plane JWT claims the gateway needs. Extra claims
/// (role/iat/exp) are ignored by serde; `exp` is still validated by the decoder.
#[derive(Deserialize)]
struct GwClaims {
    sub: Uuid,
    org: Uuid,
}

fn decode_jwt(secret: &str, token: &str) -> Option<GwClaims> {
    decode::<GwClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|d| d.claims)
}

/// Attach `x-safeguard-quota-*` headers describing the org's daily window so
/// clients (chat app, SDK, IDE) can show remaining budget. Skipped for
/// unlimited (enterprise) plans, which have no meaningful limit/remaining.
fn add_quota_headers(resp: &mut Response, q: &QuotaStatus) {
    let h = resp.headers_mut();
    h.insert("x-safeguard-quota-used", header_val(q.used));
    h.insert("x-safeguard-quota-reset", header_val(q.resets_at));
    if let Some(limit) = q.limit {
        h.insert("x-safeguard-quota-limit", header_val(limit));
    }
    if let Some(remaining) = q.remaining {
        h.insert("x-safeguard-quota-remaining", header_val(remaining));
    }
}

fn header_val(n: i64) -> HeaderValue {
    HeaderValue::from_str(&n.to_string()).unwrap_or(HeaderValue::from_static("0"))
}

fn bearer(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

pub async fn gate(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    // ── Authenticate: user JWT (chat app / IDE) OR org API key (extension/SDK) ──
    let token = bearer(&req).ok_or(GatewayError::Unauthorized)?;
    let ctx: AuthContext = match decode_jwt(&state.cfg.jwt_secret, &token) {
        Some(claims) => db::org_context(&state.db, claims.org, claims.sub).await,
        None => db::authenticate(&state.db, &token).await,
    }
    .ok_or(GatewayError::Unauthorized)?;

    // ── Quota (fixed daily window in Redis, shared key with the control-plane) ──
    let now = Utc::now();
    let day = now.format("%Y%m%d").to_string();
    let rkey = plan::quota_key(&ctx.org_id.to_string(), &day);
    let mut redis = state.redis.clone();
    // INCR then set 25h expiry on first use of the window.
    let count: i64 = redis.incr(&rkey, 1).await.unwrap_or(0);
    if count == 1 {
        let _: Result<(), _> = redis.expire(&rkey, 90_000).await;
    }
    let quota = QuotaStatus::build(&ctx.plan, count, now.timestamp());

    if let Some(limit) = quota.limit {
        if count > limit {
            // Roll back the over-limit increment so the counter reflects the
            // window cap rather than drifting upward on every rejected attempt.
            let _: Result<i64, _> = redis.decr(&rkey, 1).await;
            let capped = QuotaStatus::build(&ctx.plan, limit, now.timestamp());
            let body = ApiError::new(
                format!(
                    "daily request quota exceeded for the {} plan ({} req/day); resets at next UTC midnight",
                    capped.plan, limit
                ),
                "quota_exceeded",
            );
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            add_quota_headers(&mut resp, &capped);
            return Ok(resp);
        }
    }

    req.extensions_mut().insert(ctx);
    let mut resp = next.run(req).await;
    add_quota_headers(&mut resp, &quota);
    Ok(resp)
}
