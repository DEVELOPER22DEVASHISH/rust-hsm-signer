// src/bin/loadtest.rs
//! Concurrent load test binary.
//!
//! Build: `cargo build --release --features loadtest --bin loadtest`
//! Run:   `cargo run --release --features loadtest --bin loadtest`
//!
//! Environment variables:
//!   LT_URL      Base URL of the signing service (default: http://127.0.0.1:8080)
//!   LT_TOKEN    Bearer token (default: empty — use only with ALLOW_UNAUTHENTICATED=true)
//!   LT_KEY_ID   Key ID to sign with (default: arkion-intermediate-prod)
//!   LT_LEVELS   Comma-separated concurrency levels (default: 1,10,100,500)
//!   LT_SECS     Duration per level in seconds (default: 15)
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn pct(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize] as f64 / 1000.0
}

#[tokio::main]
async fn main() {
    let url = format!("{}/v1/sign", env("LT_URL", "http://127.0.0.1:8080"));
    let token = env("LT_TOKEN", "");
    let key_id = env("LT_KEY_ID", "arkion-intermediate-prod");
    let secs: u64 = env("LT_SECS", "15").parse().unwrap_or(15);
    let levels: Vec<usize> = env("LT_LEVELS", "1,10,100,500")
        .split(',')
        .map(|s| s.trim().parse().unwrap_or(1))
        .collect();

    // 256 bytes of fixed payload (content doesn't matter for a load test).
    let body = serde_json::json!({
        "key_id": key_id,
        "algorithm": "ECDSA_P256_SHA256",
        "payload": B64.encode([0x07u8; 256])
    })
    .to_string();

    println!(
        "| concurrency | requests | req/s | p50 ms | p95 ms | p99 ms | error % | status breakdown |"
    );
    println!("|---|---|---|---|---|---|---|---|");

    for n in levels {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(n)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(secs);
        let wall_start = Instant::now();

        let mut set = JoinSet::new();
        for _ in 0..n {
            let (c, u, t, b) = (client.clone(), url.clone(), token.clone(), body.clone());
            set.spawn(async move {
                let mut results: Vec<(u64, u16)> = Vec::new();
                while Instant::now() < deadline {
                    let t0 = Instant::now();
                    let mut rb = c
                        .post(&u)
                        .header("content-type", "application/json")
                        .body(b.clone());
                    if !t.is_empty() {
                        rb = rb.bearer_auth(&t);
                    }
                    let code = match rb.send().await {
                        Ok(r) => {
                            let status = r.status().as_u16();
                            // Drain the body so the connection is returned to the pool.
                            let _ = r.bytes().await;
                            status
                        }
                        Err(_) => 0,
                    };
                    results.push((t0.elapsed().as_micros() as u64, code));
                }
                results
            });
        }

        let mut all: Vec<(u64, u16)> = Vec::new();
        while let Some(r) = set.join_next().await {
            if let Ok(v) = r {
                all.extend(v);
            }
        }

        let wall = wall_start.elapsed().as_secs_f64();
        let mut lat: Vec<u64> = all.iter().map(|(l, _)| *l).collect();
        lat.sort_unstable();

        let errs = all.iter().filter(|(_, c)| *c != 200).count();
        let mut codes = std::collections::BTreeMap::<u16, usize>::new();
        for (_, c) in &all {
            *codes.entry(*c).or_insert(0) += 1;
        }

        println!(
            "| {} | {} | {:.0} | {:.2} | {:.2} | {:.2} | {:.2} | {:?} |",
            n,
            all.len(),
            all.len() as f64 / wall,
            pct(&lat, 0.50),
            pct(&lat, 0.95),
            pct(&lat, 0.99),
            100.0 * errs as f64 / all.len().max(1) as f64,
            codes,
        );
    }
}
