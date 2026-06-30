//! Gateway error type that renders as an OpenAI-compatible error envelope.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use proto::ApiError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("request blocked by DLP policy")]
    Blocked,
    #[error("unauthorized")]
    Unauthorized,
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("upstream returned {0}")]
    UpstreamStatus(u16, String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, kind) = match &self {
            GatewayError::Blocked => (StatusCode::UNPROCESSABLE_ENTITY, "dlp_blocked"),
            GatewayError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            GatewayError::Upstream(_) | GatewayError::UpstreamStatus(..) => {
                (StatusCode::BAD_GATEWAY, "upstream_error")
            }
            GatewayError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (status, Json(ApiError::new(self.to_string(), kind))).into_response()
    }
}
