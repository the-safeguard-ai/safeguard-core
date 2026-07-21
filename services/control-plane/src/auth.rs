//! Authentication: Argon2 password hashing, JWT issuance/verification, the
//! `Claims` request extractor, and register/login handlers.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::extract::{FromRequestParts, State};
use axum::http::header;
use axum::http::request::Parts;
use axum::Json;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::state::{AppState, ControlPlaneMode};

/// JWT claims. `sub` = user id, `org` = org id, `role` = RBAC role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub org: Uuid,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
}

impl Claims {
    pub fn is_admin(&self) -> bool {
        self.role == "Admin"
    }
    /// Admin or Manager may mutate org resources.
    pub fn can_manage(&self) -> bool {
        self.role == "Admin" || self.role == "Manager"
    }
    pub fn require_manage(&self) -> AppResult<()> {
        if self.can_manage() {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
    /// Only Admin may mutate sensitive org resources.
    pub fn require_admin(&self) -> AppResult<()> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

/// SHA-256 hex of an invite token. Tokens are stored hashed, never in plaintext
/// (mirrors the API-key handling). Shared by invite issuance and acceptance.
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(format!("hash: {e}")))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .and_then(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed))
        .is_ok()
}

pub fn issue_token(
    state: &AppState,
    sub: Uuid,
    org: Uuid,
    role: &str,
    ttl_secs: i64,
) -> AppResult<String> {
    let now = Utc::now();
    let claims = Claims {
        sub,
        org,
        role: role.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ttl_secs)).timestamp(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("jwt: {e}")))
}

/// Decode + validate a JWT (used by extractors and the telemetry dual-auth path).
pub fn decode_token(state: &AppState, token: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|d| d.claims)
}

// ── Claims extractor ────────────────────────────────────────────────────────
#[async_trait::async_trait]
impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized)?;

        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Unauthorized)?;
        Ok(data.claims)
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterReq {
    pub org_name: String,
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: AuthUser,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthUser {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: String,
    pub org_id: Uuid,
}

/// Create a new org with its first (Admin) user.
/// Default DLP policies seeded for every new org (redact, enabled, cloud route).
/// International/built-in detectors only — regional packs remain opt-in.
const DEFAULT_POLICIES: &[(&str, &str, &[&str])] = &[
    (
        "Personal Data (PII)",
        "Emails, phone numbers, and IP addresses.",
        &["email", "phone", "intl_phone", "ip_address"],
    ),
    (
        "Secrets & API Keys",
        "API keys, tokens, and other credentials.",
        &["api_key"],
    ),
    (
        "Financial & ID Numbers",
        "Payment cards, SSNs, IBANs, and passport numbers.",
        &["credit_card", "ssn", "iban", "passport"],
    ),
];

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> AppResult<Json<AuthResponse>> {
    if req.password.len() < 8 {
        return Err(AppError::BadRequest(
            "password must be at least 8 chars".into(),
        ));
    }
    let pw_hash = hash_password(&req.password)?;

    // ── Mode dispatch ─────────────────────────────────────────────────────────
    match state.mode {
        // ── Dev mode: create a new org + Admin user (current behaviour). ──────
        ControlPlaneMode::Dev => {
            let mut tx = state.db.begin().await?;
            let org_id: Uuid =
                sqlx::query_scalar("INSERT INTO orgs (name) VALUES ($1) RETURNING id")
                    .bind(&req.org_name)
                    .fetch_one(&mut *tx)
                    .await?;

            let user_id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO users (org_id, name, email, role, status, password_hash)
                   VALUES ($1, $2, $3, 'Admin', 'active', $4) RETURNING id"#,
            )
            .bind(org_id)
            .bind(&req.name)
            .bind(&req.email)
            .bind(&pw_hash)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    AppError::Conflict("email already registered".into())
                }
                other => AppError::Db(other),
            })?;

            // Seed default DLP policies so the org is protected from day one.
            for (name, description, patterns) in DEFAULT_POLICIES {
                let pats: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
                sqlx::query(
                    r#"INSERT INTO policies (org_id, name, description, enabled, patterns, action, route)
                       VALUES ($1, $2, $3, TRUE, $4, 'redact', 'cloud')"#,
                )
                .bind(org_id)
                .bind(name)
                .bind(description)
                .bind(&pats)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;

            crate::routes::metrics::record_activity(
                &state.db,
                org_id,
                user_id,
                "created organization",
                &req.org_name,
            )
            .await;

            issue_auth(&state, user_id, org_id, "Admin", &req.name, &req.email)
        }

        // ── Self-hosted: registration is disabled; admin must invite members. ─
        ControlPlaneMode::SelfHosted => {
            tracing::warn!("registration blocked — self-hosted mode (admin: {})",
                state.admin_email.as_deref().unwrap_or("unknown"));
            Err(AppError::Forbidden)
        }

        // ── Cloud: join the shared bootstrap org as a User. ───────────────────
        ControlPlaneMode::Cloud => {
            let admin_email = state.admin_email.as_deref().ok_or_else(|| {
                AppError::Internal("cloud mode requires admin_email".into())
            })?;

            let org_id: Uuid = sqlx::query_scalar(
                "SELECT org_id FROM users WHERE email = $1 AND role = 'Admin'",
            )
            .bind(admin_email)
            .fetch_optional(&state.db)
            .await?
            .ok_or(AppError::Internal(
                "bootstrap admin not found — run with ADMIN_EMAIL set first".into(),
            ))?;

            let user_id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO users (org_id, name, email, role, status, password_hash)
                   VALUES ($1, $2, $3, 'User', 'active', $4) RETURNING id"#,
            )
            .bind(org_id)
            .bind(&req.name)
            .bind(&req.email)
            .bind(&pw_hash)
            .fetch_one(&state.db)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    AppError::Conflict("email already registered".into())
                }
                other => AppError::Db(other),
            })?;

            crate::routes::metrics::record_activity(
                &state.db,
                org_id,
                user_id,
                "joined organization",
                &req.email,
            )
            .await;

            issue_auth(&state, user_id, org_id, "User", &req.name, &req.email)
        }
    }
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginReq>,
) -> AppResult<Json<AuthResponse>> {
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, Option<String>)>(
        r#"SELECT id, org_id, name, email, role, password_hash
           FROM users WHERE email = $1"#,
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Unauthorized)?;

    let (id, org_id, name, email, role, pw_hash) = row;
    let pw_hash = pw_hash.ok_or(AppError::Unauthorized)?;
    if !verify_password(&req.password, &pw_hash) {
        return Err(AppError::Unauthorized);
    }
    crate::routes::metrics::record_activity(&state.db, org_id, id, "signed in", &name).await;
    issue_auth(&state, id, org_id, &role, &name, &email)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshReq {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshResp {
    // snake_case to match the login/register token fields and the extension client.
    pub access_token: String,
}

/// Exchange a valid refresh token for a fresh access token.
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshReq>,
) -> AppResult<Json<RefreshResp>> {
    let claims = decode_token(&state, &req.refresh_token).ok_or(AppError::Unauthorized)?;
    let access_token = issue_token(
        &state,
        claims.sub,
        claims.org,
        &claims.role,
        state.access_ttl_secs,
    )?;
    Ok(Json(RefreshResp { access_token }))
}

// ── Change password (authenticated) ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct ChangePasswordReq {
    pub old_password: String,
    pub new_password: String,
}

/// Change the current user's password. Requires the old password for verification.
pub async fn change_password(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<ChangePasswordReq>,
) -> AppResult<axum::http::StatusCode> {
    if req.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "new password must be at least 8 chars".into(),
        ));
    }

    let row = sqlx::query_scalar::<_, Option<String>>(
        "SELECT password_hash FROM users WHERE id = $1 AND org_id = $2",
    )
    .bind(claims.sub)
    .bind(claims.org)
    .fetch_optional(&state.db)
    .await?;

    let pw_hash = row.flatten().ok_or(AppError::Unauthorized)?;

    if !verify_password(&req.old_password, &pw_hash) {
        return Err(AppError::Unauthorized);
    }

    let new_hash = hash_password(&req.new_password)?;
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(claims.sub)
        .execute(&state.db)
        .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ── Invite acceptance (public) ───────────────────────────────────────────────
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePreview {
    pub name: String,
    pub email: String,
    pub org_name: String,
}

/// Resolve a pending, unexpired invite by its raw token. Returns the target
/// user + org for both preview and acceptance.
async fn resolve_invite(
    state: &AppState,
    token: &str,
) -> AppResult<(
    Uuid,   /*user*/
    Uuid,   /*org*/
    String, /*name*/
    String, /*email*/
    String, /*role*/
    String, /*org_name*/
)> {
    let token_hash = hash_token(token);
    sqlx::query_as::<_, (Uuid, Uuid, String, String, String, String)>(
        r#"SELECT u.id, u.org_id, u.name, u.email, u.role, o.name AS org_name
           FROM invites i
           JOIN users u ON u.id = i.user_id
           JOIN orgs  o ON o.id = i.org_id
           WHERE i.token_hash = $1
             AND i.accepted_at IS NULL
             AND i.expires_at > now()"#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

#[derive(Deserialize)]
pub struct InviteQuery {
    pub token: String,
}

/// Preview an invite (who/where) so the accept page can show context.
pub async fn invite_preview(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<InviteQuery>,
) -> AppResult<Json<InvitePreview>> {
    let (_, _, name, email, _role, org_name) = resolve_invite(&state, &q.token).await?;
    Ok(Json(InvitePreview {
        name,
        email,
        org_name,
    }))
}

#[derive(Deserialize)]
pub struct AcceptInviteReq {
    pub token: String,
    pub password: String,
}

/// Accept an invite: set the password, activate the account, and log in.
pub async fn accept_invite(
    State(state): State<AppState>,
    Json(req): Json<AcceptInviteReq>,
) -> AppResult<Json<AuthResponse>> {
    if req.password.len() < 8 {
        return Err(AppError::BadRequest(
            "password must be at least 8 chars".into(),
        ));
    }
    let (user_id, org_id, name, email, role, _org_name) =
        resolve_invite(&state, &req.token).await?;
    let pw_hash = hash_password(&req.password)?;
    let token_hash = hash_token(&req.token);

    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $2, status = 'active' WHERE id = $1")
        .bind(user_id)
        .bind(&pw_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE invites SET accepted_at = now() WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    crate::routes::metrics::record_activity(
        &state.db,
        org_id,
        user_id,
        "joined the organization",
        &name,
    )
    .await;

    issue_auth(&state, user_id, org_id, &role, &name, &email)
}

/// Bootstrap the first admin account from environment variables.
///
/// Called once at startup when `ADMIN_EMAIL` is set. Idempotent: if the admin
/// user already exists (detected by email + `Admin` role) it's a no-op.
///
/// In both SelfHosted and Cloud modes this creates the shared org and the first
/// admin user. The generated (or configured) initial password is logged — the
/// admin **must** change it after first login.
pub async fn bootstrap_admin(
    db: &sqlx::PgPool,
    admin_email: &str,
    admin_password: Option<&str>,
) {
    // Idempotency check — already bootstrapped?
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND role = 'Admin')",
    )
    .bind(admin_email)
    .fetch_one(db)
    .await
    .unwrap_or(false);

    if exists {
        tracing::info!("admin account already exists for {admin_email}");
        return;
    }

    let org_name = admin_email
        .split('@')
        .next()
        .unwrap_or("admin")
        .to_string();

    // Create the shared org.
    let org_id: Uuid = sqlx::query_scalar("INSERT INTO orgs (name) VALUES ($1) RETURNING id")
        .bind(&org_name)
        .fetch_one(db)
        .await
        .expect("failed to create bootstrap org");

    // Create the admin user with a password.
    let password = match admin_password {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => {
            // Generate a random password (UUID string — unique, no special deps).
            Uuid::new_v4().to_string()
        }
    };

    let pw_hash = hash_password(&password).expect("failed to hash admin password");

    sqlx::query(
        r#"INSERT INTO users (org_id, name, email, role, status, password_hash)
           VALUES ($1, $2, $3, 'Admin', 'active', $4)"#,
    )
    .bind(org_id)
    .bind(&org_name)
    .bind(admin_email)
    .bind(&pw_hash)
    .execute(db)
    .await
    .expect("failed to create admin user");

    // Seed the same default DLP policies as the register handler.
    for (name, description, patterns) in DEFAULT_POLICIES {
        let pats: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        sqlx::query(
            r#"INSERT INTO policies (org_id, name, description, enabled, patterns, action, route)
               VALUES ($1, $2, $3, TRUE, $4, 'redact', 'cloud')"#,
        )
        .bind(org_id)
        .bind(name)
        .bind(description)
        .bind(&pats)
        .execute(db)
        .await
        .expect("failed to seed default policies for bootstrap org");
    }

    tracing::warn!(
        "⚠️  ADMIN ACCOUNT CREATED — email: {admin_email}  password: {password}  — CHANGE IMMEDIATELY AFTER LOGIN"
    );
}

fn issue_auth(
    state: &AppState,
    user_id: Uuid,
    org_id: Uuid,
    role: &str,
    name: &str,
    email: &str,
) -> AppResult<Json<AuthResponse>> {
    let access_token = issue_token(state, user_id, org_id, role, state.access_ttl_secs)?;
    let refresh_token = issue_token(state, user_id, org_id, role, state.refresh_ttl_secs)?;
    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        user: AuthUser {
            id: user_id,
            name: name.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            org_id,
        },
    }))
}
