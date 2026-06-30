//! Plan tiers and their quota limits — the single source of truth shared by the
//! gateway (which *enforces* the daily request quota) and the control-plane
//! (which *reports* current usage to the dashboard). Keeping the numbers and the
//! Redis key format here guarantees the two services never drift.

use serde::{Deserialize, Serialize};

/// Per-plan daily request quota. `None` == unlimited.
///
/// `free` and `team` are capped; `enterprise` (and any unknown plan) is
/// unlimited. Counts are per-org, per UTC day.
pub fn daily_request_limit(plan: &str) -> Option<i64> {
    match plan {
        "free" => Some(200),
        "team" => Some(20_000),
        _ => None, // enterprise / unknown → unlimited
    }
}

/// Redis key holding an org's request count for a given UTC day (`yyyymmdd`).
/// Both services build the key through this fn so they read/write the same slot.
pub fn quota_key(org_id: &str, yyyymmdd: &str) -> String {
    format!("quota:{org_id}:{yyyymmdd}")
}

/// UNIX seconds of the next UTC midnight strictly after `now_secs` — when the
/// fixed daily window rolls over. Pure arithmetic (no tz/chrono dependency).
pub fn next_utc_midnight(now_secs: i64) -> i64 {
    const DAY: i64 = 86_400;
    (now_secs / DAY + 1) * DAY
}

/// A point-in-time view of an org's daily quota, returned by the control-plane
/// and mirrored in the gateway's `x-safeguard-quota-*` response headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaStatus {
    pub plan: String,
    /// Daily request limit; `null` = unlimited.
    pub limit: Option<i64>,
    /// Requests counted in the current UTC day.
    pub used: i64,
    /// Requests left before the cap; `null` = unlimited.
    pub remaining: Option<i64>,
    /// UNIX seconds when the window resets (next UTC midnight).
    pub resets_at: i64,
}

impl QuotaStatus {
    /// Build a status from the plan, the current count, and the current time.
    pub fn build(plan: &str, used: i64, now_secs: i64) -> Self {
        let limit = daily_request_limit(plan);
        let remaining = limit.map(|l| (l - used).max(0));
        Self {
            plan: plan.to_string(),
            limit,
            used,
            remaining,
            resets_at: next_utc_midnight(now_secs),
        }
    }
}
