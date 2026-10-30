// tests/api_mock.rs
//! Integration tests for the HTTP API using the in-memory MockBackend.
//! No HSM or SoftHSM2 is required to run these.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hsm_signer::{
    api::{build_router, AppState, RouterConfig},
    auth::{Auth, TokenRecord},
    hsm::mock::MockBackend,
    metrics::Metrics,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

/// A token with enough entropy for a real bearer token.
const TOKEN: &str = "test-token-with-plenty-of-entropy-abc123";

fn app() -> Router {
    let backend = Arc::new(MockBackend::new(
        &["sign-key".into(), "other-key".into()],
        &["aes-key".into()],
    ));
    let auth = Auth::with_records(vec![TokenRecord::from_plain(
        "t1",
        TOKEN,
        &["sign-key", "aes-key"],
    )]);
    let state = AppState {
        backend,
        metrics: Arc::new(Metrics::new()),
        auth: Arc::new(auth),
    };
    build_router(
        state,
        &RouterConfig { request_timeout: Duration::from_secs(2), max_body_bytes: 1 << 20 },
    )
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut rb = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        rb = rb.header("authorization", format!("Bearer {t}"));
    }
    let req = rb
        .body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn sign_body(key: &str, alg: &str, payload: &[u8]) -> Value {
    json!({
        "key_id": key,
        "algorithm": alg,
        "payload": B64.encode(payload)
    })
}

// ---- tests ----

#[tokio::test]
async fn sign_and_verify_with_public_key() {
    let app = app();
    let payload = b"tbs-certificate-bytes";

    let (st, body) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(TOKEN),
        Some(sign_body("sign-key", "ECDSA_P256_SHA256", payload)),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["algorithm"].as_str().unwrap(), "ECDSA_P256_SHA256");

    let sig_bytes = B64.decode(body["signature"].as_str().unwrap()).unwrap();
    let sig = Signature::from_slice(&sig_bytes).unwrap();

    let (st, pk_body) = call(&app, "GET", "/v1/keys/sign-key/public", Some(TOKEN), None).await;
    assert_eq!(st, StatusCode::OK);
    let pk_bytes = B64.decode(pk_body["public_key_sec1"].as_str().unwrap()).unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();

    vk.verify(payload, &sig).expect("signature must verify against the payload");
    assert!(vk.verify(b"tampered-payload", &sig).is_err(), "tampered payload must not verify");
}

#[tokio::test]
async fn rejects_bad_input() {
    let app = app();

    // Unknown algorithm.
    let (st, body) =
        call(&app, "POST", "/v1/sign", Some(TOKEN), Some(sign_body("sign-key", "RSA_PSS", b"x")))
            .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"].as_str().unwrap(), "unsupported_algorithm");

    // Invalid base64 payload.
    let (st, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(TOKEN),
        Some(json!({"key_id":"sign-key","algorithm":"ECDSA_P256_SHA256","payload":"!!!not-base64"})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Path-traversal key ID.
    let (st, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(TOKEN),
        Some(sign_body("../etc/passwd", "ECDSA_P256_SHA256", b"x")),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Empty key ID.
    let (st, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(TOKEN),
        Some(sign_body("", "ECDSA_P256_SHA256", b"x")),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_and_authorization() {
    let app = app();
    let b = sign_body("sign-key", "ECDSA_P256_SHA256", b"x");

    // No token → 401.
    assert_eq!(
        call(&app, "POST", "/v1/sign", None, Some(b.clone())).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Wrong token → 401.
    assert_eq!(
        call(&app, "POST", "/v1/sign", Some("wrong-token"), Some(b.clone())).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Valid token but key not in its scope → 403 (key existence must not be revealed).
    let (st, body) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(TOKEN),
        Some(sign_body("other-key", "ECDSA_P256_SHA256", b"x")),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"].as_str().unwrap(), "forbidden");

    // Valid token, key in scope but nonexistent → 403 (same error, no key enumeration).
    let (st, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(TOKEN),
        Some(sign_body("nonexistent-key", "ECDSA_P256_SHA256", b"x")),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn aes_gcm_roundtrip_and_tamper() {
    let app = app();
    let plaintext = b"very secret data";
    let aad_bytes = b"binding-context";

    let (st, enc) = call(
        &app,
        "POST",
        "/v1/encrypt",
        Some(TOKEN),
        Some(json!({
            "key_id": "aes-key",
            "plaintext": B64.encode(plaintext),
            "aad": B64.encode(aad_bytes)
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let ct = enc["ciphertext"].as_str().unwrap().to_string();

    // Correct roundtrip.
    let (st, dec) = call(
        &app,
        "POST",
        "/v1/decrypt",
        Some(TOKEN),
        Some(json!({
            "key_id": "aes-key",
            "ciphertext": ct,
            "aad": B64.encode(aad_bytes)
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        B64.decode(dec["plaintext"].as_str().unwrap()).unwrap(),
        plaintext
    );

    // Wrong AAD must fail authentication.
    let (st, _) = call(
        &app,
        "POST",
        "/v1/decrypt",
        Some(TOKEN),
        Some(json!({
            "key_id": "aes-key",
            "ciphertext": ct,
            "aad": B64.encode(b"wrong-aad")
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Bit flip in last byte (tag corruption) must fail authentication.
    let mut raw = B64.decode(&ct).unwrap();
    *raw.last_mut().unwrap() ^= 0xFF;
    let (st, _) = call(
        &app,
        "POST",
        "/v1/decrypt",
        Some(TOKEN),
        Some(json!({
            "key_id": "aes-key",
            "ciphertext": B64.encode(raw),
            "aad": B64.encode(aad_bytes)
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn health_endpoints_need_no_auth() {
    let app = app();
    assert_eq!(call(&app, "GET", "/healthz", None, None).await.0, StatusCode::OK);
    assert_eq!(call(&app, "GET", "/readyz", None, None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn duration_ms_is_non_negative() {
    let app = app();
    let (st, body) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(TOKEN),
        Some(sign_body("sign-key", "ECDSA_P256_SHA256", b"payload")),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // duration_ms must be present and non-negative.
    assert!(body["duration_ms"].as_u64().is_some());
}
