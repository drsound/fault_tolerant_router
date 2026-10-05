//! The status snapshot of `GET /v1/status` (SPEC.md FR-API-2): published by
//! the State task after its changes, read by the API without touching the
//! routing state (FR-API-4, IMPL-4). It holds operational fields only, never
//! configuration contents or diagnostics.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Status {
    pub version: &'static str,
    pub instance: String,
    /// When the daemon started (RFC 3339, UTC); the API adds the uptime.
    pub started: String,
    pub config_digest: String,
    pub generation: Generations,
    /// `ok` or `degraded`.
    pub status: &'static str,
    pub reasons: Vec<&'static str>,
    pub uplinks: Vec<UplinkStatus>,
    pub paths: Vec<PathStatus>,
    /// The active set of each managed family, by uplink name.
    pub active: BTreeMap<&'static str, Vec<String>>,
}

impl Status {
    /// The one-line summary that systemd shows (IMPL-10, `STATUS=`): the
    /// overall status with its reasons and the active set of each family,
    /// worded as `polywan status` words them.
    pub fn summary(&self) -> String {
        let mut s = format!("status {}", self.status);
        if !self.reasons.is_empty() {
            s += &format!(" ({})", self.reasons.join(", "));
        }
        for (family, set) in &self.active {
            let names = if set.is_empty() { "none".into() } else { set.join(", ") };
            s += &format!("; active {family}: {names}");
        }
        s
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Generations {
    pub desired: u64,
    pub applied: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UplinkStatus {
    pub name: String,
    pub id: u8,
    pub interface: String,
    pub drained: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PathStatus {
    pub uplink: String,
    pub family: &'static str,
    /// `up` or `down`.
    pub state: &'static str,
    pub ready: bool,
    pub reason: &'static str,
    /// Since when the path is in its state (RFC 3339, UTC).
    pub since: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    pub addresses: Vec<IpAddr>,
    /// Of the samples of the quality window (FR-PROBE-5); `None` without
    /// the inputs a statistic needs.
    pub statistics: Statistics,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct Statistics {
    pub samples: usize,
    pub loss: Option<f64>,
    pub rtt_seconds: Option<f64>,
    pub jitter_seconds: Option<f64>,
}

impl From<&crate::quality::Stats> for Statistics {
    fn from(s: &crate::quality::Stats) -> Statistics {
        Statistics {
            samples: s.samples,
            loss: s.loss,
            rtt_seconds: s.rtt.map(|d| d.as_secs_f64()),
            jitter_seconds: s.jitter.map(|d| d.as_secs_f64()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_name_the_status_its_reasons_and_the_active_sets() {
        let mut s = Status {
            status: "ok",
            ..Status::default()
        };
        s.active.insert("ipv4", vec!["a".into(), "b".into()]);
        s.active.insert("ipv6", Vec::new());
        assert_eq!(s.summary(), "status ok; active ipv4: a, b; active ipv6: none");
        s.status = "degraded";
        s.reasons = vec!["apply_failed", "nftables_missing"];
        assert_eq!(
            s.summary(),
            "status degraded (apply_failed, nftables_missing); active ipv4: a, b; active ipv6: none"
        );
    }
}
