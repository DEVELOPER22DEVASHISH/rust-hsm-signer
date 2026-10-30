//src/auth.rs
use crate::error::ApiError;
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, path::Path, sync::Arc};
use subtle::ConstantTimeEq;

// ---- token file schema ----

#[derive(Deserialize)]
struct TokenFileEntry {
    name: String,
    /// Hex-encoded SHA-256 digest of the bearer token. Plain tokens are never stored.
    token_sha256: String,
    /// Keys this principal may access. Use `["*"]` to grant all keys.
    key_ids: Vec<String>,
}

// ---- internal record ----

#[derive(Clone)]
pub struct TokenRecord {
    name: Arc<str>,
    hash: [u8; 32],
    key_ids: Arc<HashSet<String>>,
}

impl TokenRecord {
    /// Convenience constructor for tests and tooling: builds a record from a plaintext token.
    pub fn from_plain(name: &str, token: &str, key_ids: &[&str]) -> Self {
        Self {
            name: name.into(),
            hash: Sha256::digest(token.as_bytes()).into(),
            key_ids: Arc::new(key_ids.iter().map(|s| s.to_string()).collect()),
        }
    }
}

// ---- authenticated caller ----

/// An authenticated caller with a scoped key allowlist.
/// `"*"` in `key_ids` grants access to every key.
#[derive(Clone)]
pub struct Principal {
    pub name: Arc<str>,
    key_ids: Arc<HashSet<String>>,
}

impl Principal {
    pub fn allows(&self, key_id: &str) -> bool {
        self.key_ids.contains("*") || self.key_ids.contains(key_id)
    }
}

// ---- auth store ----

pub struct Auth {
    /// `None` means auth is disabled (local dev only).
    records: Option<Vec<TokenRecord>>,
}

impl Auth {
    pub fn disabled() -> Self {
        tracing::warn!("AUTHENTICATION DISABLED — local development only");
        Self { records: None }
    }

    pub fn with_records(records: Vec<TokenRecord>) -> Self {
        Self { records: Some(records) }
    }

    /// Load from a JSON file with schema:
    /// `[{"name":"…","token_sha256":"<64 hex chars>","key_ids":["…"]}]`
    ///
    /// Only SHA-256 digests of high-entropy tokens are stored; plain tokens are
    /// never written to disk.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let entries: Vec<TokenFileEntry> = serde_json::from_str(&raw)?;
        anyhow::ensure!(!entries.is_empty(), "token file is empty");
        let mut records = Vec::new();
        for e in entries {
            let bytes = hex::decode(&e.token_sha256)?;
            let hash: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("token_sha256 must be exactly 32 bytes (64 hex)"))?;
            records.push(TokenRecord {
                name: e.name.into(),
                hash,
                key_ids: Arc::new(e.key_ids.into_iter().collect()),
            });
        }
        Ok(Self { records: Some(records) })
    }

    /// Constant-time comparison against every record to prevent timing side-channels.
    /// No early exit on match.
    fn authenticate(&self, header_val: Option<&HeaderValue>) -> Result<Principal, ApiError> {
        let Some(records) = &self.records else {
            // Auth disabled: anonymous principal with full access.
            return Ok(Principal {
                name: "anonymous".into(),
                key_ids: Arc::new(["*".to_string()].into()),
            });
        };

        let token = header_val
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();

        // Scan every record; no early exit on match (constant-time enumeration).
        let mut found: Option<&TokenRecord> = None;
        for r in records {
            if bool::from(r.hash.ct_eq(&digest)) {
                found = Some(r);
            }
        }

        found
            .map(|r| Principal { name: r.name.clone(), key_ids: r.key_ids.clone() })
            .ok_or(ApiError::Unauthorized)
    }
}

// ---- axum middleware ----

pub async fn require_auth(
    State(auth): State<Arc<Auth>>,
    mut req: Request,
    next: Next,
) -> Response {
    match auth.authenticate(req.headers().get(header::AUTHORIZATION)) {
        Ok(p) => {
            req.extensions_mut().insert(p);
            next.run(req).await
        }
        Err(e) => {
            tracing::warn!(target: "audit", outcome = "unauthenticated", "rejected request");
            e.into_response()
        }
    }
}
