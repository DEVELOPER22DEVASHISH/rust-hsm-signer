//src/hsm/mock.rs
//! In-memory software crypto backend.
//!
//! **NOT SECURE** — private and symmetric keys live in process memory.
//! Use only for unit tests, CI, and local load tests.
use super::{CryptoBackend, SigAlgorithm};
use crate::error::HsmError;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use async_trait::async_trait;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
#[allow(unused_imports)]
use p256::elliptic_curve::sec1::ToEncodedPoint; // trait in scope for .to_encoded_point()
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;

pub struct MockBackend {
    ec: HashMap<String, SigningKey>,
    aes: HashMap<String, Aes256Gcm>,
}

impl MockBackend {
    pub fn new(ec_ids: &[String], aes_ids: &[String]) -> Self {
        let ec = ec_ids
            .iter()
            .map(|id| (id.clone(), SigningKey::random(&mut OsRng)))
            .collect();
        let aes = aes_ids
            .iter()
            .map(|id| {
                let mut k = [0u8; 32];
                OsRng.fill_bytes(&mut k);
                (id.clone(), Aes256Gcm::new_from_slice(&k).expect("32-byte AES key"))
            })
            .collect();
        Self { ec, aes }
    }
}

#[async_trait]
impl CryptoBackend for MockBackend {
    async fn sign(
        &self,
        key_id: &str,
        _alg: SigAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let k = self.ec.get(key_id).ok_or(HsmError::KeyNotFound)?;
        let sig: Signature = k.sign(payload);
        Ok(sig.to_bytes().to_vec())
    }

    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HsmError> {
        let k = self.ec.get(key_id).ok_or(HsmError::KeyNotFound)?;
        Ok(k.verifying_key().to_encoded_point(false).as_bytes().to_vec())
    }

    async fn encrypt(
        &self,
        key_id: &str,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let c = self.aes.get(key_id).ok_or(HsmError::KeyNotFound)?;
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);
        let nonce = Nonce::from(iv);
        let ct = c
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|_| HsmError::Internal("mock encrypt failed".into()))?;
        let mut out = iv.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    async fn decrypt(
        &self,
        key_id: &str,
        aad: &[u8],
        blob: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let c = self.aes.get(key_id).ok_or(HsmError::KeyNotFound)?;
        // IV(12) + min ciphertext(0) + tag(16) = 28 bytes minimum.
        if blob.len() < 28 {
            return Err(HsmError::InvalidInput("ciphertext too short"));
        }
        let nonce = Nonce::from(<[u8; 12]>::try_from(&blob[..12]).unwrap());
        c.decrypt(&nonce, Payload { msg: &blob[12..], aad })
            .map_err(|_| HsmError::DecryptionFailed)
    }

    async fn health(&self) -> Result<(), HsmError> {
        Ok(())
    }

    async fn shutdown(&self, _grace: std::time::Duration) {
        // Nothing to close.
    }
}
