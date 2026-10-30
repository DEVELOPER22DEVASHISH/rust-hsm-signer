//src/hsm/mod.rs
pub mod mock;
pub mod pkcs11;
pub mod pool;

use crate::error::HsmError;
use async_trait::async_trait;

/// Signing algorithm discriminant.  Only ECDSA P-256 / SHA-256 is implemented;
/// RSA-PSS and Ed25519 are listed in README as known limitations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlgorithm {
    EcdsaP256Sha256,
}

impl SigAlgorithm {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ECDSA_P256_SHA256" => Some(Self::EcdsaP256Sha256),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ECDSA_P256_SHA256",
        }
    }
}

/// The seam between the HTTP layer and key material.
///
/// Implemented by `Pkcs11Backend` (real HSM) and `MockBackend` (in-process software keys
/// for tests and local load tests).  Nothing in this trait can return private or symmetric
/// key bytes — handles / object references stay inside the implementation.
#[async_trait]
pub trait CryptoBackend: Send + Sync + 'static {
    /// Returns raw **r‖s** (64 bytes for P-256).
    async fn sign(
        &self,
        key_id: &str,
        alg: SigAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    /// Returns the uncompressed SEC1 public point (65 bytes for P-256: `04 || X || Y`).
    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HsmError>;

    /// AES-256-GCM encrypt.  Output layout: `IV(12) ‖ ciphertext ‖ tag(16)`.
    async fn encrypt(
        &self,
        key_id: &str,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    /// AES-256-GCM decrypt.  Expects blob in the layout produced by `encrypt`.
    async fn decrypt(
        &self,
        key_id: &str,
        aad: &[u8],
        blob: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    /// Liveness check: returns `Ok(())` when the HSM is reachable.
    async fn health(&self) -> Result<(), HsmError>;

    /// Graceful shutdown: stop accepting work, wait for in-flight ops (bounded by `grace`),
    /// then log out and close sessions.
    async fn shutdown(&self, grace: std::time::Duration);
}
