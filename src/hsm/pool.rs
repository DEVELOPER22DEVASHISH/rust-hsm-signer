//src/hsm/pool.rs
use crate::{error::HsmError, metrics::Metrics};
use cryptoki::{context::Pkcs11, session::Session, slot::Slot};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Configuration for the session pool.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Maximum simultaneous HSM operations.
    pub size: usize,
    /// Maximum number of callers that may be *queued* waiting for a session.
    /// Beyond `size + max_waiters` total, requests are rejected immediately.
    pub max_waiters: usize,
    /// How long a caller waits for a session permit before receiving 503.
    pub acquire_timeout: Duration,
}

// ---- internals ----

struct Inner {
    pkcs11: Pkcs11,
    slot: Slot,
    /// Idle (returned) sessions ready for checkout.
    idle: Mutex<Vec<Session>>,
    /// Bounds concurrent HSM work to `size`.
    permits: Arc<Semaphore>,
    /// Bounds total in-flight + queued callers to `size + max_waiters`.
    admission: Arc<Semaphore>,
    size: usize,
    acquire_timeout: Duration,
    closed: AtomicBool,
    metrics: Arc<Metrics>,
}

/// Fixed-size pool of logged-in PKCS#11 sessions.
///
/// # Backpressure layers
/// 1. **Admission control**: if more than `size + max_waiters` callers are already
///    in-flight or queued, new callers receive an immediate `PoolSaturated` error.
/// 2. **Bounded wait**: callers wait at most `acquire_timeout` for a permit.
///    Exceeding it yields `PoolTimeout`.
/// 3. **Concurrency cap**: at most `size` blocking PKCS#11 calls run simultaneously.
///
/// A request that is cancelled (e.g. by a higher-level timeout) does **not** lose its
/// session — the `spawn_blocking` task always returns the session before exiting, so
/// pool accounting stays correct.
#[derive(Clone)]
pub struct SessionPool {
    inner: Arc<Inner>,
}

impl SessionPool {
    pub fn new(
        pkcs11: Pkcs11,
        slot: Slot,
        sessions: Vec<Session>,
        cfg: PoolConfig,
        metrics: Arc<Metrics>,
    ) -> Self {
        metrics.pool_capacity.set(cfg.size as i64);
        Self {
            inner: Arc::new(Inner {
                pkcs11,
                slot,
                idle: Mutex::new(sessions),
                permits: Arc::new(Semaphore::new(cfg.size)),
                admission: Arc::new(Semaphore::new(cfg.size + cfg.max_waiters)),
                size: cfg.size,
                acquire_timeout: cfg.acquire_timeout,
                closed: AtomicBool::new(false),
                metrics,
            }),
        }
    }

    /// Check out a session, respecting all backpressure layers.
    pub async fn acquire(&self) -> Result<PooledSession, HsmError> {
        let i = &self.inner;

        if i.closed.load(Ordering::Acquire) {
            return Err(HsmError::Unavailable);
        }

        // Layer 1: admission control — fail fast if the queue is full.
        let admit = i.admission.clone().try_acquire_owned().map_err(|_| {
            i.metrics.pool_rejected.inc();
            HsmError::PoolSaturated
        })?;

        // Layer 2: bounded wait for a concurrency permit.
        let permit =
            match tokio::time::timeout(i.acquire_timeout, i.permits.clone().acquire_owned()).await
            {
                Ok(Ok(p)) => p,
                Ok(Err(_)) => return Err(HsmError::Unavailable), // semaphore closed
                Err(_elapsed) => {
                    i.metrics.pool_timeouts.inc();
                    return Err(HsmError::PoolTimeout);
                }
            };

        // Re-check closed after acquiring the permit (shutdown may have raced us).
        if i.closed.load(Ordering::Acquire) {
            return Err(HsmError::Unavailable);
        }

        let popped = i.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
        let session = match popped {
            Some(s) => s,
            // A broken session was discarded earlier; open a replacement.
            // Login state is token-wide, so the new session is already authenticated.
            None => i
                .pkcs11
                .open_rw_session(i.slot)
                .map_err(|e| HsmError::Internal(format!("open replacement session: {e}")))?,
        };

        i.metrics.pool_in_use.inc();
        Ok(PooledSession {
            session: Some(session),
            inner: self.inner.clone(),
            broken: false,
            _permit: permit,
            _admit: admit,
        })
    }

    /// Graceful shutdown:
    /// 1. Mark the pool closed so no new acquires succeed.
    /// 2. Drain in-flight operations (wait for all permits — bounded by `grace`).
    /// 3. Log out and drop all idle sessions.
    pub async fn shutdown(&self, grace: Duration) {
        self.inner.closed.store(true, Ordering::Release);

        // Acquire all permits to know every in-flight op has finished.
        let all = self
            .inner
            .permits
            .clone()
            .acquire_many_owned(self.inner.size as u32);

        match tokio::time::timeout(grace, all).await {
            Ok(Ok(_held)) => tracing::info!("all HSM sessions returned to pool"),
            _ => tracing::warn!("grace period elapsed; some HSM sessions may still be in use"),
        }

        let inner = self.inner.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let mut idle = inner.idle.lock().unwrap_or_else(|e| e.into_inner());
            // Log out using the first available session (login is token-wide).
            if let Some(s) = idle.first() {
                let _ = s.logout();
            }
            idle.clear(); // Drop each Session, which closes the PKCS#11 handle.
        })
        .await;

        tracing::info!("HSM sessions closed");
    }
}

// ---- pooled session guard ----

/// An RAII guard that returns a session to the pool on drop (or discards it if broken).
pub struct PooledSession {
    session: Option<Session>,
    inner: Arc<Inner>,
    broken: bool,
    _permit: OwnedSemaphorePermit,
    _admit: OwnedSemaphorePermit,
}

impl PooledSession {
    pub fn session(&self) -> &Session {
        self.session.as_ref().expect("session present until drop")
    }

    /// Mark the session as broken so it is not returned to the pool.
    /// A replacement is opened lazily on the next `acquire`.
    pub fn mark_broken(&mut self) {
        self.broken = true;
    }
}

impl Drop for PooledSession {
    fn drop(&mut self) {
        self.inner.metrics.pool_in_use.dec();
        if let Some(s) = self.session.take() {
            if !self.broken {
                self.inner
                    .idle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(s);
            }
            // If broken: dropping `s` closes the PKCS#11 session.
        }
        // Semaphore permits are released here, *after* the session is back in the pool.
    }
}
