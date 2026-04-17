//! Prometheus metrics exposed on `/metrics`.
//!
//! The registry is a process-wide singleton. Every HTTP handler and the HSM
//! layer bumps metrics directly via the [`Metrics`] struct held in the axum
//! application state.

use std::sync::Arc;

use anyhow::Result;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    registry: Registry,
    pub signs_total: IntCounterVec,
    pub sign_duration_seconds: HistogramVec,
    pub policy_denials_total: IntCounterVec,
    pub replay_hits_total: IntCounter,
    pub inflight: IntGauge,
    pub hsm_up: IntGauge,
    pub signer_errors_total: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let signs_total = IntCounterVec::new(
            Opts::new(
                "openkms_signs_total",
                "Total successful sign operations per chain / key / outcome.",
            ),
            &["chain", "key", "decision"],
        )?;
        registry.register(Box::new(signs_total.clone()))?;

        let sign_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "openkms_sign_duration_seconds",
                "End-to-end sign latency in seconds, including policy eval + HSM.",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["chain", "key"],
        )?;
        registry.register(Box::new(sign_duration_seconds.clone()))?;

        let policy_denials_total = IntCounterVec::new(
            Opts::new(
                "openkms_policy_denials_total",
                "Total policy denials, labelled by reason code.",
            ),
            &["chain", "key", "reason"],
        )?;
        registry.register(Box::new(policy_denials_total.clone()))?;

        let replay_hits_total = IntCounter::with_opts(Opts::new(
            "openkms_replay_hits_total",
            "Incremented when a /sign request is served from the replay cache.",
        ))?;
        registry.register(Box::new(replay_hits_total.clone()))?;

        let inflight = IntGauge::with_opts(Opts::new(
            "openkms_inflight",
            "Current in-flight sign requests.",
        ))?;
        registry.register(Box::new(inflight.clone()))?;

        let hsm_up = IntGauge::with_opts(Opts::new(
            "openkms_hsm_up",
            "1 when the HSM responded to its last ping, 0 otherwise.",
        ))?;
        registry.register(Box::new(hsm_up.clone()))?;

        let signer_errors_total = IntCounterVec::new(
            Opts::new(
                "openkms_signer_errors_total",
                "Sign-path failures broken down by chain / kind (decode, hsm, validation).",
            ),
            &["chain", "kind"],
        )?;
        registry.register(Box::new(signer_errors_total.clone()))?;

        Ok(Self {
            inner: Arc::new(MetricsInner {
                registry,
                signs_total,
                sign_duration_seconds,
                policy_denials_total,
                replay_hits_total,
                inflight,
                hsm_up,
                signer_errors_total,
            }),
        })
    }

    pub fn signs_total(&self) -> &IntCounterVec {
        &self.inner.signs_total
    }
    pub fn sign_duration_seconds(&self) -> &HistogramVec {
        &self.inner.sign_duration_seconds
    }
    pub fn policy_denials_total(&self) -> &IntCounterVec {
        &self.inner.policy_denials_total
    }
    pub fn replay_hits_total(&self) -> &IntCounter {
        &self.inner.replay_hits_total
    }
    pub fn inflight(&self) -> &IntGauge {
        &self.inner.inflight
    }
    pub fn hsm_up(&self) -> &IntGauge {
        &self.inner.hsm_up
    }
    pub fn signer_errors_total(&self) -> &IntCounterVec {
        &self.inner.signer_errors_total
    }

    /// Render the current registry as a Prometheus text-exposition payload.
    pub fn render(&self) -> Result<(String, &'static str)> {
        let encoder = TextEncoder::new();
        let metric_families = self.inner.registry.gather();
        let mut buf = Vec::new();
        encoder.encode(&metric_families, &mut buf)?;
        Ok((String::from_utf8(buf)?, "text/plain; version=0.0.4"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_render_contains_expected_metric_names() {
        let m = Metrics::new().unwrap();
        m.signs_total()
            .with_label_values(&["solana", "k1", "allow"])
            .inc();
        m.sign_duration_seconds()
            .with_label_values(&["solana", "k1"])
            .observe(0.012);
        m.policy_denials_total()
            .with_label_values(&["cosmos", "k2", "rate_limited"])
            .inc();
        m.inflight().inc();
        m.hsm_up().set(1);
        m.replay_hits_total().inc();

        let (text, ct) = m.render().unwrap();
        assert!(ct.starts_with("text/plain"));
        for needle in [
            "openkms_signs_total",
            "openkms_sign_duration_seconds",
            "openkms_policy_denials_total",
            "openkms_inflight",
            "openkms_hsm_up",
            "openkms_replay_hits_total",
        ] {
            assert!(text.contains(needle), "missing metric {needle} in:\n{text}");
        }
    }
}
