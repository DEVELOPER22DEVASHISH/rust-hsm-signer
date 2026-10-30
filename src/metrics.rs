// src/metrics.rs
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

pub struct Metrics {
    pub registry: Registry,
    /// Labelled by (op, outcome).
    pub requests: IntCounterVec,
    /// End-to-end latency including pool wait time.
    pub op_latency: HistogramVec,
    pub pool_capacity: IntGauge,
    pub pool_in_use: IntGauge,
    pub pool_rejected: IntCounter,
    pub pool_timeouts: IntCounter,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let requests = IntCounterVec::new(
            Opts::new("signer_requests_total", "Requests by op and outcome"),
            &["op", "outcome"],
        )
        .unwrap();

        let op_latency = HistogramVec::new(
            HistogramOpts::new(
                "signer_op_duration_seconds",
                "End-to-end backend op latency incl. pool wait",
            )
            .buckets(vec![
                0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0,
            ]),
            &["op"],
        )
        .unwrap();

        let pool_capacity =
            IntGauge::new("hsm_pool_capacity", "Total session slots in the pool").unwrap();
        let pool_in_use =
            IntGauge::new("hsm_pool_in_use", "Sessions currently checked out").unwrap();
        let pool_rejected = IntCounter::new(
            "hsm_pool_rejected_total",
            "Requests rejected by admission control (queue full)",
        )
        .unwrap();
        let pool_timeouts = IntCounter::new(
            "hsm_pool_acquire_timeouts_total",
            "Requests that timed out waiting for a session",
        )
        .unwrap();

        for c in [
            Box::new(requests.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(op_latency.clone()),
            Box::new(pool_capacity.clone()),
            Box::new(pool_in_use.clone()),
            Box::new(pool_rejected.clone()),
            Box::new(pool_timeouts.clone()),
        ] {
            registry.register(c).unwrap();
        }

        Self {
            registry,
            requests,
            op_latency,
            pool_capacity,
            pool_in_use,
            pool_rejected,
            pool_timeouts,
        }
    }

    /// Render all registered metrics in Prometheus text format.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut buf).ok();
        String::from_utf8(buf).unwrap_or_default()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
