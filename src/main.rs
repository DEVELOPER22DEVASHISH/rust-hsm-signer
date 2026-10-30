//src/main.rs
use anyhow::Context;
use hsm_signer::{
    api::{build_router, metrics_router, AppState, RouterConfig},
    auth::Auth,
    config::{read_pin, BackendKind, Config},
    hsm::{
        mock::MockBackend,
        pkcs11::{Pkcs11Backend, Pkcs11Params},
        pool::PoolConfig,
        CryptoBackend,
    },
    metrics::Metrics,
};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, signal};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if json {
        tracing_subscriber::fmt().json().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

/// Resolves on SIGINT or SIGTERM (what Docker/K8s send).
async fn wait_for_signal() {
    let ctrl_c = async { signal::ctrl_c().await.expect("install SIGINT handler") };
    #[cfg(unix)]
    let term = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::from_env().context("configuration")?;
    init_tracing(cfg.log_json);
    tracing::info!(
        backend = ?cfg.backend,
        bind = %cfg.bind_addr,
        pool = cfg.pool_size,
        "starting hsm-signer"
    );

    let metrics = Arc::new(Metrics::new());

    let backend: Arc<dyn CryptoBackend> = match cfg.backend {
        BackendKind::Mock => {
            tracing::warn!("MOCK BACKEND: software keys in process memory - NOT FOR PRODUCTION");
            Arc::new(MockBackend::new(&cfg.signing_key_ids, &cfg.aes_key_ids))
        }
        BackendKind::Pkcs11 => {
            let params = Pkcs11Params {
                module: cfg.pkcs11_module.clone(),
                token_label: cfg.token_label.clone(),
                pin: read_pin()?,
                pool: PoolConfig {
                    size: cfg.pool_size,
                    max_waiters: cfg.pool_max_waiters,
                    acquire_timeout: cfg.pool_acquire_timeout,
                },
                signing_key_ids: cfg.signing_key_ids.clone(),
                aes_key_ids: cfg.aes_key_ids.clone(),
                provision: cfg.provision,
            };
            let m = metrics.clone();
            // PKCS#11 init/provisioning is blocking; keep it off the async workers.
            let b = tokio::task::spawn_blocking(move || Pkcs11Backend::connect(params, m))
                .await?
                .map_err(|e| anyhow::anyhow!("HSM init failed: {e}"))?;
            Arc::new(b)
        }
    };

    let auth = Arc::new(match &cfg.api_tokens_file {
        Some(p) => Auth::load(p).context("loading API tokens")?,
        // config validation only allows this path when ALLOW_UNAUTHENTICATED=true
        None => Auth::disabled(),
    });

    let state = AppState {
        backend: backend.clone(),
        metrics: metrics.clone(),
        auth,
    };
    let app = build_router(
        state,
        &RouterConfig {
            request_timeout: cfg.request_timeout,
            max_body_bytes: cfg.max_body_bytes,
        },
    );

    let api_listener = TcpListener::bind(cfg.bind_addr).await.context("bind api")?;
    let metrics_listener = TcpListener::bind(cfg.metrics_addr).await.context("bind metrics")?;

    // ---- shutdown orchestration ----
    // CancellationToken is shared with axum serve tasks so they stop accepting new connections.
    let token = CancellationToken::new();
    {
        let token = token.clone();
        tokio::spawn(async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received: draining in-flight requests");
            token.cancel();
            // A second signal forces immediate exit (useful if drain is hung).
            wait_for_signal().await;
            tracing::warn!("second signal received: forcing exit");
            std::process::exit(130);
        });
    }

    let api_task = {
        let t = token.clone();
        tokio::spawn(async move {
            axum::serve(api_listener, app)
                .with_graceful_shutdown(t.cancelled_owned())
                .await
        })
    };
    let metrics_task = {
        let t = token.clone();
        let r = metrics_router(metrics);
        tokio::spawn(async move {
            axum::serve(metrics_listener, r)
                .with_graceful_shutdown(t.cancelled_owned())
                .await
        })
    };

    // Wait until the signal handler cancels the token.
    token.cancelled().await;

    // Phase 1: stop accepting; let in-flight HTTP requests finish (bounded by grace period).
    let drain = async {
        let _ = api_task.await;
        let _ = metrics_task.await;
    };
    if tokio::time::timeout(cfg.shutdown_grace, drain).await.is_err() {
        tracing::warn!("HTTP drain exceeded grace period; proceeding to HSM shutdown");
    }

    // Phase 2: wait for any in-flight HSM blocking tasks, log out, close sessions.
    // Give HSM shutdown at most 5 s or the remaining grace budget, whichever is smaller.
    backend
        .shutdown(Duration::from_secs(5).min(cfg.shutdown_grace))
        .await;

    tracing::info!("shutdown complete");
    Ok(())
}
