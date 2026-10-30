//src/api/mod.rs
use crate::{
    auth::{self, Auth, Principal},
    config::valid_key_id,
    error::{ApiError, HsmError},
    hsm::{CryptoBackend, SigAlgorithm},
    metrics::Metrics,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

// ---- application state ----

#[derive(Clone)]
pub struct AppState {
    pub backend: Arc<dyn CryptoBackend>,
    pub metrics: Arc<Metrics>,
    pub auth: Arc<Auth>,
}

pub struct RouterConfig {
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
}

// ---- router construction ----

pub fn build_router(state: AppState, cfg: &RouterConfig) -> Router {
    // All /v1/* routes require authentication.
    let v1 = Router::new()
        .route("/sign", post(sign))
        .route("/encrypt", post(encrypt))
        .route("/decrypt", post(decrypt))
        .route("/keys/:key_id/public", get(public_key))
        .layer(middleware::from_fn_with_state(
            state.auth.clone(),
            auth::require_auth,
        ));

    Router::new()
        .nest("/v1", v1)
        // Health/readiness probes are unauthenticated so load balancers can reach them.
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .layer(DefaultBodyLimit::max(cfg.max_body_bytes))
        .layer(TimeoutLayer::new(cfg.request_timeout))
        // Logs method / path / status / latency.  Never logs bodies or headers.
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Separate router for Prometheus metrics (binds to a different port).
pub fn metrics_router(metrics: Arc<Metrics>) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            let m = metrics.clone();
            async move { m.render() }
        }),
    )
}

// ---- DTOs ----

#[derive(Deserialize)]
struct SignRequest {
    key_id: String,
    algorithm: String,
    /// Base64-encoded bytes to sign.
    payload: String,
}

#[derive(Serialize)]
struct SignResponse {
    key_id: String,
    algorithm: &'static str,
    /// Base64-encoded raw r‖s signature.
    signature: String,
    duration_ms: u64,
}

#[derive(Deserialize)]
struct EncryptRequest {
    key_id: String,
    /// Base64-encoded plaintext.
    plaintext: String,
    /// Optional base64-encoded additional authenticated data.
    #[serde(default)]
    aad: Option<String>,
}

#[derive(Serialize)]
struct EncryptResponse {
    key_id: String,
    /// Base64-encoded IV(12) ‖ ciphertext ‖ tag(16).
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptRequest {
    key_id: String,
    /// Base64-encoded IV(12) ‖ ciphertext ‖ tag(16).
    ciphertext: String,
    #[serde(default)]
    aad: Option<String>,
}

#[derive(Serialize)]
struct DecryptResponse {
    key_id: String,
    /// Base64-encoded recovered plaintext.
    plaintext: String,
}

#[derive(Serialize)]
struct PublicKeyResponse {
    key_id: String,
    algorithm: &'static str,
    /// Base64-encoded uncompressed SEC1 point (04 ‖ X ‖ Y, 65 bytes for P-256).
    public_key_sec1: String,
}

// ---- helpers ----

/// Validate key ID format and check caller authorisation.
fn check_key(p: &Principal, key_id: &str) -> Result<(), ApiError> {
    if !valid_key_id(key_id) {
        return Err(ApiError::BadRequest("invalid key_id".into()));
    }
    if !p.allows(key_id) {
        tracing::warn!(
            target: "audit",
            principal = %p.name,
            key_id,
            outcome = "forbidden",
            "access denied"
        );
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn b64(field: &str, v: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(v)
        .map_err(|_| ApiError::BadRequest(format!("{field} is not valid base64")))
}

fn opt_b64(field: &str, v: &Option<String>) -> Result<Vec<u8>, ApiError> {
    v.as_deref()
        .map(|s| b64(field, s))
        .transpose()
        .map(|o| o.unwrap_or_default())
}

fn record<T>(m: &Metrics, op: &str, res: &Result<T, HsmError>, d: Duration) {
    let outcome = match res {
        Ok(_) => "ok",
        Err(e) => e.label(),
    };
    m.requests.with_label_values(&[op, outcome]).inc();
    m.op_latency.with_label_values(&[op]).observe(d.as_secs_f64());
}

// ---- handlers ----

/// Sign a base64-encoded payload with the named key.
#[tracing::instrument(
    skip_all,
    fields(principal = %p.name, key_id = %req.key_id)
)]
async fn sign(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    check_key(&p, &req.key_id)?;
    let alg = SigAlgorithm::parse(&req.algorithm).ok_or(HsmError::UnsupportedAlgorithm)?;
    let payload = b64("payload", &req.payload)?;

    let start = Instant::now();
    let res = st.backend.sign(&req.key_id, alg, &payload).await;
    let elapsed = start.elapsed();
    record(&st.metrics, "sign", &res, elapsed);

    // Audit log: structured fields only; never the signature bytes or payload content.
    tracing::info!(
        target: "audit",
        principal = %p.name,
        key_id = %req.key_id,
        op = "sign",
        outcome = res.as_ref().map(|_| "ok").unwrap_or_else(|e| e.label()),
        payload_len = payload.len(),
        duration_us = elapsed.as_micros() as u64,
    );

    let sig = res?;
    Ok(Json(SignResponse {
        key_id: req.key_id,
        algorithm: alg.as_str(),
        signature: B64.encode(sig),
        duration_ms: elapsed.as_millis() as u64,
    }))
}

async fn encrypt(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Json(req): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, ApiError> {
    check_key(&p, &req.key_id)?;
    let (pt, aad) = (b64("plaintext", &req.plaintext)?, opt_b64("aad", &req.aad)?);
    let start = Instant::now();
    let res = st.backend.encrypt(&req.key_id, &aad, &pt).await;
    record(&st.metrics, "encrypt", &res, start.elapsed());
    Ok(Json(EncryptResponse { key_id: req.key_id, ciphertext: B64.encode(res?) }))
}

async fn decrypt(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Json(req): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, ApiError> {
    check_key(&p, &req.key_id)?;
    let (ct, aad) = (b64("ciphertext", &req.ciphertext)?, opt_b64("aad", &req.aad)?);
    let start = Instant::now();
    let res = st.backend.decrypt(&req.key_id, &aad, &ct).await;
    record(&st.metrics, "decrypt", &res, start.elapsed());
    Ok(Json(DecryptResponse { key_id: req.key_id, plaintext: B64.encode(res?) }))
}

async fn public_key(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(key_id): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    check_key(&p, &key_id)?;
    let pk = st.backend.public_key(&key_id).await?;
    Ok(Json(PublicKeyResponse {
        key_id,
        algorithm: SigAlgorithm::EcdsaP256Sha256.as_str(),
        public_key_sec1: B64.encode(pk),
    }))
}

async fn readyz(State(st): State<AppState>) -> impl IntoResponse {
    match st.backend.health().await {
        Ok(()) => (StatusCode::OK, "ready"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "not ready"),
    }
}
