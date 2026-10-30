// tests/pkcs11_integration.rs
//! End-to-end integration test against a real SoftHSM2 token.
//!
//! Requires: `softhsm2-util` on PATH and `libsofthsm2.so` at the path in
//! `PKCS11_MODULE` (default `/usr/lib/softhsm/libsofthsm2.so`).
//! The test skips itself gracefully when either is absent.
//!
//! **Only one test function** — `C_Initialize`/`C_Finalize` are process-global in PKCS#11
//! and cannot safely be called more than once per process.
use base64::Engine as _;
use hsm_signer::{
    error::HsmError,
    hsm::{
        pkcs11::{Pkcs11Backend, Pkcs11Params},
        pool::PoolConfig,
        CryptoBackend, SigAlgorithm,
    },
    metrics::Metrics,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use std::{path::Path, process::Command, sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn softhsm_end_to_end() {
    // ---- locate the PKCS#11 module ----
    let module =
        std::env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".into());
    if !Path::new(&module).exists() {
        eprintln!("SKIP: PKCS#11 module not found at {module}");
        return;
    }

    // ---- spin up a throwaway SoftHSM2 token in a temp directory ----
    let dir = tempfile::tempdir().unwrap();
    let tokens_dir = dir.path().join("tokens");
    std::fs::create_dir_all(&tokens_dir).unwrap();
    let conf_path = dir.path().join("softhsm2.conf");
    std::fs::write(
        &conf_path,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens_dir.display()
        ),
    )
    .unwrap();
    // Make the SoftHSM2 library pick up the temp config.
    std::env::set_var("SOFTHSM2_CONF", &conf_path);

    // Throwaway PINs — the token is deleted with the tempdir.
    let status = Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", &conf_path)
        .args([
            "--init-token", "--free",
            "--label", "itest",
            "--so-pin", "0000so",
            "--pin", "1234pin",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("SKIP: softhsm2-util unavailable or failed");
            return;
        }
    }

    // ---- connect the backend ----
    let metrics = Arc::new(Metrics::new());
    let params = Pkcs11Params {
        module: module.into(),
        token_label: "itest".into(),
        pin: cryptoki::types::AuthPin::new("1234pin".into()),
        pool: PoolConfig {
            size: 2,
            max_waiters: 8,
            acquire_timeout: Duration::from_millis(500),
        },
        signing_key_ids: vec!["itest-ec".into()],
        aes_key_ids: vec!["itest-aes".into()],
        provision: true,
    };
    let m = metrics.clone();
    let backend = Arc::new(
        tokio::task::spawn_blocking(move || Pkcs11Backend::connect(params, m))
            .await
            .unwrap()
            .expect("PKCS#11 backend connect"),
    );

    // ---- 1) ECDSA sign in HSM, verify in software ----
    let payload = b"hello softhsm integration test";
    let sig_bytes = backend.sign("itest-ec", SigAlgorithm::EcdsaP256Sha256, payload).await.unwrap();
    assert_eq!(sig_bytes.len(), 64, "expected raw r||s (64 bytes for P-256)");

    let pk_bytes = backend.public_key("itest-ec").await.unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();
    let sig = Signature::from_slice(&sig_bytes).unwrap();
    vk.verify(payload, &sig).expect("HSM signature must verify against the public key");
    assert!(vk.verify(b"different-payload", &sig).is_err());

    // ---- 2) AES-256-GCM inside the HSM ----
    let ct = backend.encrypt("itest-aes", b"aad-context", b"plaintext-secret").await.unwrap();
    // Correct roundtrip.
    let pt = backend.decrypt("itest-aes", b"aad-context", &ct).await.unwrap();
    assert_eq!(pt, b"plaintext-secret");

    // Wrong AAD → decryption failure.
    assert!(matches!(
        backend.decrypt("itest-aes", b"wrong-aad", &ct).await,
        Err(HsmError::DecryptionFailed)
    ));

    // Bit-flip in last byte (tag corruption) → decryption failure.
    let mut tampered = ct.clone();
    *tampered.last_mut().unwrap() ^= 0xFF;
    assert!(matches!(
        backend.decrypt("itest-aes", b"aad-context", &tampered).await,
        Err(HsmError::DecryptionFailed)
    ));

    // ---- 3) Unknown key IDs ----
    assert!(matches!(
        backend.sign("unknown-key", SigAlgorithm::EcdsaP256Sha256, b"x").await,
        Err(HsmError::KeyNotFound)
    ));
    assert!(matches!(
        backend.encrypt("unknown-key", b"", b"x").await,
        Err(HsmError::KeyNotFound)
    ));

    // ---- 4) Concurrency over a 2-session pool ----
    // Fire 40 concurrent signing requests; with pool_size=2 and pool_max_waiters=8
    // some will succeed, the rest will receive backpressure errors.
    let mut set = tokio::task::JoinSet::new();
    for i in 0u8..40 {
        let b = backend.clone();
        set.spawn(async move { b.sign("itest-ec", SigAlgorithm::EcdsaP256Sha256, &[i; 32]).await });
    }
    let mut ok_count = 0usize;
    while let Some(r) = set.join_next().await {
        match r.unwrap() {
            Ok(_) => ok_count += 1,
            Err(HsmError::PoolSaturated) | Err(HsmError::PoolTimeout) => {}
            Err(e) => panic!("unexpected error from pool: {e}"),
        }
    }
    assert!(ok_count > 0, "at least some requests should have succeeded");

    // ---- 5) Graceful shutdown ----
    backend.shutdown(Duration::from_secs(2)).await;
    assert!(
        matches!(
            backend.sign("itest-ec", SigAlgorithm::EcdsaP256Sha256, b"x").await,
            Err(HsmError::Unavailable)
        ),
        "pool should refuse new work after shutdown"
    );

    // Silence an unused-import warning that some toolchain versions emit.
    let _ = base64::engine::general_purpose::STANDARD;
}
