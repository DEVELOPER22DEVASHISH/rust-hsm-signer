//src/error.rs
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Failures from the crypto backend.
///
/// `Internal` carries a diagnostic string that is **logged server-side** but
/// never serialised into the HTTP response body, so implementation details
/// never leak to callers.
#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    #[error("key not found")]
    KeyNotFound,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("hsm session pool saturated")]
    PoolSaturated,
    #[error("timed out waiting for an hsm session")]
    PoolTimeout,
    #[error("hsm unavailable")]
    Unavailable,
    #[error("hsm internal error: {0}")]
    Internal(String),
}

impl HsmError {
    /// Low-cardinality label used in Prometheus metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::KeyNotFound => "key_not_found",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::InvalidInput(_) => "invalid_input",
            Self::DecryptionFailed => "decryption_failed",
            Self::PoolSaturated => "pool_saturated",
            Self::PoolTimeout => "pool_timeout",
            Self::Unavailable => "unavailable",
            Self::Internal(_) => "internal",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error(transparent)]
    Hsm(#[from] HsmError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Log internal detail before discarding it.
        if let ApiError::Hsm(HsmError::Internal(ref detail)) = self {
            tracing::error!(detail = %detail, "internal hsm error");
        }

        let (status, code, message, retry_after) = match &self {
            ApiError::BadRequest(m) => {
                (StatusCode::BAD_REQUEST, "bad_request", m.clone(), None)
            }
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required".into(),
                None,
            ),
            ApiError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "not permitted for this key".into(),
                None,
            ),
            ApiError::Hsm(e) => match e {
                HsmError::KeyNotFound => {
                    (StatusCode::NOT_FOUND, "key_not_found", "key not found".into(), None)
                }
                HsmError::UnsupportedAlgorithm => (
                    StatusCode::BAD_REQUEST,
                    "unsupported_algorithm",
                    "unsupported algorithm".into(),
                    None,
                ),
                HsmError::InvalidInput(m) => {
                    (StatusCode::BAD_REQUEST, "invalid_input", (*m).into(), None)
                }
                HsmError::DecryptionFailed => (
                    StatusCode::BAD_REQUEST,
                    "decryption_failed",
                    "decryption failed".into(),
                    None,
                ),
                HsmError::PoolSaturated | HsmError::PoolTimeout => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "hsm_busy",
                    "signing capacity exhausted, retry".into(),
                    Some("1"),
                ),
                HsmError::Unavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "hsm_unavailable",
                    "hsm unavailable".into(),
                    Some("2"),
                ),
                HsmError::Internal(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error".into(),
                    None,
                ),
            },
        };

        let mut resp =
            (status, Json(json!({ "error": { "code": code, "message": message } }))).into_response();

        if let Some(s) = retry_after {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static(s));
        }
        if matches!(self, ApiError::Unauthorized) {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}
