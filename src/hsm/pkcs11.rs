//src/hsm/pkcs11.rs

//! PKCS#11 backend — wraps a SoftHSM2 (or real HSM) token via the `cryptoki` crate.
//!
//! # Potential compile errors
//! The PKCS#11 calls are written against **cryptoki 0.7**.  If the crate changes its API
//! in a point release, errors will appear here.  Run `cargo build` first and paste any
//! errors from this file.
use super::{
    pool::{PoolConfig, SessionPool},
    CryptoBackend, SigAlgorithm,
};
use crate::{error::HsmError, metrics::Metrics};
use async_trait::async_trait;
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    error::{Error as CkError, RvError},
    mechanism::{aead::GcmParams, Mechanism},
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

// P-256 curve OID in DER: OID 1.2.840.10045.3.1.7
const P256_OID_DER: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

// ---- public parameters ----

pub struct Pkcs11Params {
    pub module: PathBuf,
    pub token_label: String,
    pub pin: AuthPin,
    pub pool: PoolConfig,
    pub signing_key_ids: Vec<String>,
    pub aes_key_ids: Vec<String>,
    pub provision: bool,
}

// ---- private key bundle ----

struct EcKey {
    private: ObjectHandle,
    /// Cached uncompressed SEC1 public point (65 bytes).  Never a private key.
    sec1_public: Vec<u8>,
}

// ---- backend ----

pub struct Pkcs11Backend {
    pool: SessionPool,
    /// Keyed by the key-id string from config / requests.
    ec: HashMap<String, EcKey>,
    aes: HashMap<String, ObjectHandle>,
}

// ---- error classification ----

fn classify(e: CkError) -> HsmError {
    match e {
        CkError::Pkcs11(rv, _) => match rv {
            RvError::SessionHandleInvalid
            | RvError::SessionClosed
            | RvError::DeviceError
            | RvError::DeviceRemoved
            | RvError::TokenNotPresent
            | RvError::UserNotLoggedIn => HsmError::Unavailable,
            other => HsmError::Internal(format!("pkcs11 rv={other:?}")),
        },
        other => HsmError::Internal(other.to_string()),
    }
}

// ---- object helpers ----

/// Find exactly zero or one object matching class + key-type + CKA_LABEL.
/// Finding two or more is a startup failure (fail closed).
fn find_one(
    s: &Session,
    class: ObjectClass,
    kt: KeyType,
    label: &str,
) -> Result<Option<ObjectHandle>, HsmError> {
    let template = [
        Attribute::Class(class),
        Attribute::KeyType(kt),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let objs = s.find_objects(&template).map_err(classify)?;
    match objs.len() {
        0 => Ok(None),
        1 => Ok(Some(objs[0])),
        _ => Err(HsmError::Internal(format!(
            "duplicate PKCS#11 objects for label {label:?} — refusing to continue"
        ))),
    }
}

/// Locate or provision an EC P-256 key pair.
fn ensure_ec(
    s: &Session,
    label: &str,
    provision: bool,
) -> Result<(ObjectHandle, ObjectHandle), HsmError> {
    let private = find_one(s, ObjectClass::PRIVATE_KEY, KeyType::EC, label)?;
    let public = find_one(s, ObjectClass::PUBLIC_KEY, KeyType::EC, label)?;

    match (private, public) {
        (Some(pr), Some(pu)) => Ok((pr, pu)),
        (None, None) if provision => {
            let id = label.as_bytes().to_vec();
            let pub_template = vec![
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Verify(true),
                Attribute::EcParams(P256_OID_DER.to_vec()),
                Attribute::Label(id.clone()),
                Attribute::Id(id.clone()),
            ];
            let priv_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Label(id.clone()),
                Attribute::Id(id),
            ];
            let (pu, pr) = s
                .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
                .map_err(classify)?;
            tracing::info!(key_id = label, "provisioned EC P-256 key pair (non-extractable)");
            Ok((pr, pu))
        }
        _ => Err(HsmError::Internal(format!(
            "EC key {label:?} missing/inconsistent and provisioning is off (or only one half exists)"
        ))),
    }
}

/// Locate or provision an AES-256 key.
fn ensure_aes(s: &Session, label: &str, provision: bool) -> Result<ObjectHandle, HsmError> {
    if let Some(h) = find_one(s, ObjectClass::SECRET_KEY, KeyType::AES, label)? {
        return Ok(h);
    }
    if !provision {
        return Err(HsmError::Internal(format!(
            "AES key {label:?} not found and provisioning is off"
        )));
    }
    let id = label.as_bytes().to_vec();
    let template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::ValueLen(32u64.into()),
        Attribute::Label(id.clone()),
        Attribute::Id(id),
    ];
    let h = s.generate_key(&Mechanism::AesKeyGen, &template).map_err(classify)?;
    tracing::info!(key_id = label, "provisioned AES-256 key (non-extractable)");
    Ok(h)
}

/// Fail closed: abort startup if any key is extractable or non-sensitive.
fn verify_policy(s: &Session, h: ObjectHandle, label: &str) -> Result<(), HsmError> {
    let attrs = s
        .get_attributes(h, &[AttributeType::Extractable, AttributeType::Sensitive])
        .map_err(classify)?;
    let (mut extractable, mut sensitive) = (None, None);
    for a in attrs {
        match a {
            Attribute::Extractable(v) => extractable = Some(v),
            Attribute::Sensitive(v) => sensitive = Some(v),
            _ => {}
        }
    }
    if extractable != Some(false) || sensitive != Some(true) {
        return Err(HsmError::Internal(format!(
            "key policy violation for {label:?}: \
             CKA_EXTRACTABLE must be false and CKA_SENSITIVE must be true"
        )));
    }
    Ok(())
}

/// `CKA_EC_POINT` is typically a DER OCTET STRING wrapping the SEC1 point.
/// Some tokens return the raw 65-byte point directly.
fn ec_point_to_sec1(v: &[u8]) -> Result<Vec<u8>, HsmError> {
    // Raw uncompressed point: 0x04 || X(32) || Y(32) = 65 bytes.
    if v.len() == 65 && v[0] == 0x04 {
        return Ok(v.to_vec());
    }
    // DER OCTET STRING: 0x04 (tag) || 0x41 (len=65) || 0x04 (point) ... = 67 bytes.
    if v.len() == 67 && v[0] == 0x04 && v[1] == 0x41 && v[2] == 0x04 {
        return Ok(v[2..].to_vec());
    }
    Err(HsmError::Internal(format!(
        "unexpected CKA_EC_POINT encoding: {} bytes starting with {:02x?}",
        v.len(),
        &v[..v.len().min(4)]
    )))
}

fn public_sec1(s: &Session, pu: ObjectHandle) -> Result<Vec<u8>, HsmError> {
    let attrs = s
        .get_attributes(pu, &[AttributeType::EcPoint])
        .map_err(classify)?;
    for a in attrs {
        if let Attribute::EcPoint(v) = a {
            return ec_point_to_sec1(&v);
        }
    }
    Err(HsmError::Internal("CKA_EC_POINT attribute not returned".into()))
}

/// Hash the payload in software (not secret), send the 32-byte digest into the HSM.
/// Using `CKM_ECDSA` (raw) instead of `CKM_ECDSA_SHA256` broadens token compatibility.
fn raw_sign(s: &Session, h: ObjectHandle, payload: &[u8]) -> Result<Vec<u8>, HsmError> {
    let digest = Sha256::digest(payload);
    let sig = s.sign(&Mechanism::Ecdsa, h, &digest).map_err(classify)?;
    if sig.len() != 64 {
        return Err(HsmError::Internal(format!(
            "expected 64-byte raw ECDSA signature, got {} bytes",
            sig.len()
        )));
    }
    Ok(sig)
}

// ---- backend implementation ----

impl Pkcs11Backend {
    /// **Blocking** — must be called from `spawn_blocking` or a non-async context.
    pub fn connect(p: Pkcs11Params, metrics: Arc<Metrics>) -> Result<Self, HsmError> {
        let pkcs11 =
            Pkcs11::new(&p.module).map_err(|e| HsmError::Internal(format!("load module: {e}")))?;

        match pkcs11.initialize(CInitializeArgs::OsThreads) {
            Ok(()) => {}
            // Another process already initialized the library — fine.
            Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(HsmError::Internal(format!("C_Initialize: {e}"))),
        }

        // Select token by label; slot IDs are not stable across reboots/re-inserts.
        let slots = pkcs11.get_slots_with_token().map_err(classify)?;
        let mut chosen = None;
        for slot in slots {
            let info = pkcs11.get_token_info(slot).map_err(classify)?;
            if info.label() == p.token_label {
                chosen = Some(slot);
                break;
            }
        }
        let slot = chosen.ok_or_else(|| {
            HsmError::Internal(format!("token label {:?} not found", p.token_label))
        })?;

        // Open the first session and log in (login is token-wide).
        let first = pkcs11.open_rw_session(slot).map_err(classify)?;
        match first.login(UserType::User, Some(&p.pin)) {
            Ok(()) => {}
            Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            // Deliberately do not format the PIN into the error message.
            Err(e) => return Err(HsmError::Internal(format!("token login failed: {e}"))),
        }

        // ---- EC keys ----
        let mut ec = HashMap::new();
        for id in &p.signing_key_ids {
            let (pr, pu) = ensure_ec(&first, id, p.provision)?;
            verify_policy(&first, pr, id)?;
            let sec1 = public_sec1(&first, pu)?;

            // Startup self-test: sign a fixed message inside the HSM, verify in software.
            let test_msg = b"hsm-signer startup self-test";
            let raw = raw_sign(&first, pr, test_msg)?;
            let vk = VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| HsmError::Internal(format!("bad public key for {id}: {e}")))?;
            let sig = Signature::from_slice(&raw)
                .map_err(|e| HsmError::Internal(format!("bad signature for {id}: {e}")))?;
            vk.verify(test_msg, &sig)
                .map_err(|_| HsmError::Internal(format!("self-test failed for {id}")))?;

            tracing::info!(key_id = id, "EC key ready (self-test passed)");
            ec.insert(id.clone(), EcKey { private: pr, sec1_public: sec1 });
        }

        // ---- AES keys ----
        let mut aes = HashMap::new();
        for id in &p.aes_key_ids {
            let h = ensure_aes(&first, id, p.provision)?;
            verify_policy(&first, h, id)?;
            tracing::info!(key_id = id, "AES-256 key ready");
            aes.insert(id.clone(), h);
        }

        // Open the remaining pool sessions (they share the login from `first`).
        let mut sessions = vec![first];
        for _ in 1..p.pool.size {
            sessions.push(pkcs11.open_rw_session(slot).map_err(classify)?);
        }

        tracing::info!(
            pool = p.pool.size,
            ec_keys = ec.len(),
            aes_keys = aes.len(),
            "PKCS#11 backend ready"
        );

        let pool = SessionPool::new(pkcs11, slot, sessions, p.pool, metrics);
        Ok(Self { pool, ec, aes })
    }

    /// Run a blocking PKCS#11 closure on a pooled session via `spawn_blocking`.
    ///
    /// If the *outer* async task is cancelled (e.g. by a request timeout), the
    /// `spawn_blocking` task still runs to completion and returns its session,
    /// keeping pool accounting correct.
    async fn run<T, F>(&self, f: F) -> Result<T, HsmError>
    where
        T: Send + 'static,
        F: FnOnce(&Session) -> Result<T, HsmError> + Send + 'static,
    {
        let mut guard = self.pool.acquire().await?;
        tokio::task::spawn_blocking(move || {
            let res = f(guard.session());
            if matches!(res, Err(HsmError::Unavailable)) {
                guard.mark_broken();
            }
            res
        })
        .await
        .map_err(|e| HsmError::Internal(format!("spawn_blocking task panicked: {e}")))?
    }
}

#[async_trait]
impl CryptoBackend for Pkcs11Backend {
    async fn sign(
        &self,
        key_id: &str,
        alg: SigAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        match alg {
            SigAlgorithm::EcdsaP256Sha256 => {} // only supported algorithm
        }
        let handle = self.ec.get(key_id).ok_or(HsmError::KeyNotFound)?.private;
        let payload = payload.to_vec();
        self.run(move |s| raw_sign(s, handle, &payload)).await
    }

    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HsmError> {
        Ok(self.ec.get(key_id).ok_or(HsmError::KeyNotFound)?.sec1_public.clone())
    }

    async fn encrypt(
        &self,
        key_id: &str,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let handle = *self.aes.get(key_id).ok_or(HsmError::KeyNotFound)?;
        let (aad, pt) = (aad.to_vec(), plaintext.to_vec());
        self.run(move |s| {
            // Use the HSM's TRNG for the IV; random 96-bit IVs are safe for up to
            // ~2^32 messages under the same key (rotate the key before reaching that limit).
            let mut iv = s
                .generate_random_vec(GCM_IV_LEN as u32)
                .map_err(classify)?;
            let iv_copy = iv.clone();
            let params = GcmParams::new(&mut iv, &aad, 128u64.into());
            let ct = s
                .encrypt(&Mechanism::AesGcm(params), handle, &pt)
                .map_err(classify)?;
            // Output: IV(12) || ciphertext || tag(16)
            let mut out = iv_copy;
            out.extend_from_slice(&ct);
            Ok(out)
        })
        .await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        aad: &[u8],
        blob: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let handle = *self.aes.get(key_id).ok_or(HsmError::KeyNotFound)?;
        if blob.len() < GCM_IV_LEN + GCM_TAG_LEN {
            return Err(HsmError::InvalidInput("ciphertext too short"));
        }
        let (aad, blob) = (aad.to_vec(), blob.to_vec());
        self.run(move |s| {
            let mut iv = blob[..GCM_IV_LEN].to_vec();
            let params = GcmParams::new(&mut iv, &aad, 128u64.into());
            s.decrypt(&Mechanism::AesGcm(params), handle, &blob[GCM_IV_LEN..])
                .map_err(|e| {
                    // Auth-tag failures surface as many different RV codes depending on the
                    // token; collapse them all to one uniform, uninformative error.
                    match classify(e) {
                        HsmError::Internal(detail) => {
                            tracing::debug!(detail = %detail, "decrypt auth-tag failure");
                            HsmError::DecryptionFailed
                        }
                        other => other,
                    }
                })
        })
        .await
    }

    async fn health(&self) -> Result<(), HsmError> {
        self.run(|s| s.get_session_info().map(|_| ()).map_err(classify)).await
    }

    async fn shutdown(&self, grace: Duration) {
        self.pool.shutdown(grace).await;
    }
}
