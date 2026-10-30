//src/config.rs
use anyhow::{bail, Context, Result};
use cryptoki::types::AuthPin;
use std::{net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Pkcs11,
    Mock,
}

/// Runtime configuration. Deliberately contains no secrets — the HSM PIN is read
/// separately and never stored here.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    pub backend: BackendKind,
    pub pkcs11_module: PathBuf,
    pub token_label: String,
    pub pool_size: usize,
    pub pool_max_waiters: usize,
    pub pool_acquire_timeout: Duration,
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
    pub signing_key_ids: Vec<String>,
    pub aes_key_ids: Vec<String>,
    pub provision: bool,
    pub api_tokens_file: Option<PathBuf>,
    pub allow_unauthenticated: bool,
    pub shutdown_grace: Duration,
    pub log_json: bool,
}

/// Accepts alphanumeric, hyphens, underscores, and dots. Max 128 chars.
pub fn valid_key_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn env_str(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T: FromStr>(k: &str, default: T) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match std::env::var(k) {
        Ok(v) => v.parse::<T>().map_err(|e| anyhow::anyhow!("invalid {k}: {e}")),
        Err(_) => Ok(default),
    }
}

fn env_bool(k: &str, default: bool) -> bool {
    std::env::var(k)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(default)
}

fn env_list(k: &str, default: &str) -> Vec<String> {
    env_str(k, default)
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let backend = match env_str("BACKEND", "pkcs11").as_str() {
            "pkcs11" => BackendKind::Pkcs11,
            "mock" => BackendKind::Mock,
            other => bail!("BACKEND must be pkcs11|mock, got {other}"),
        };
        let cfg = Config {
            bind_addr: env_parse("BIND_ADDR", "0.0.0.0:8080".parse().unwrap())?,
            metrics_addr: env_parse("METRICS_ADDR", "127.0.0.1:9100".parse().unwrap())?,
            backend,
            pkcs11_module: env_str("PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so").into(),
            token_label: env_str("HSM_TOKEN_LABEL", "arkion"),
            pool_size: env_parse("POOL_SIZE", 8usize)?,
            pool_max_waiters: env_parse("POOL_MAX_WAITERS", 256usize)?,
            pool_acquire_timeout: Duration::from_millis(
                env_parse("POOL_ACQUIRE_TIMEOUT_MS", 500u64)?,
            ),
            request_timeout: Duration::from_millis(env_parse("REQUEST_TIMEOUT_MS", 2000u64)?),
            max_body_bytes: env_parse("MAX_BODY_BYTES", 1024 * 1024usize)?,
            signing_key_ids: env_list("SIGNING_KEY_IDS", "arkion-intermediate-prod"),
            aes_key_ids: env_list("AES_KEY_IDS", "arkion-data-key"),
            provision: env_bool("HSM_PROVISION", true),
            api_tokens_file: std::env::var("API_TOKENS_FILE").ok().map(PathBuf::from),
            allow_unauthenticated: env_bool("ALLOW_UNAUTHENTICATED", false),
            shutdown_grace: Duration::from_secs(env_parse("SHUTDOWN_GRACE_SECS", 20u64)?),
            log_json: env_str("LOG_FORMAT", "json") == "json",
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if !(1..=256).contains(&self.pool_size) {
            bail!("POOL_SIZE must be 1..=256");
        }
        for id in self.signing_key_ids.iter().chain(&self.aes_key_ids) {
            if !valid_key_id(id) {
                bail!("invalid key id in config: {id:?}");
            }
        }
        if self.api_tokens_file.is_none() && !self.allow_unauthenticated {
            bail!(
                "refusing to start: set API_TOKENS_FILE \
                 (or ALLOW_UNAUTHENTICATED=true for local dev only)"
            );
        }
        Ok(())
    }
}

/// PIN comes from a file (preferred — e.g. a Docker/K8s secret mount) or, as a
/// fallback, an environment variable that is cleared after reading.
/// Wrapped in `AuthPin` whose Debug output is redacted.
pub fn read_pin() -> Result<AuthPin> {
    if let Ok(path) = std::env::var("HSM_PIN_FILE") {
        let s = std::fs::read_to_string(&path)
            .with_context(|| format!("reading HSM_PIN_FILE {path}"))?;
        return Ok(AuthPin::new(s.trim().to_string()));
    }
    if let Ok(p) = std::env::var("HSM_PIN") {
        tracing::warn!("HSM_PIN taken from environment; prefer HSM_PIN_FILE");
        // Clear from the environment immediately so it does not appear in /proc/*/environ.
        std::env::remove_var("HSM_PIN");
        return Ok(AuthPin::new(p));
    }
    bail!("no HSM PIN: set HSM_PIN_FILE (or HSM_PIN for local dev only)")
}
