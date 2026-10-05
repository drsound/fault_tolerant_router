//! Metrics (SPEC.md §10, FR-MET-2) in the Prometheus text format, rendered
//! from the published status and its counters, and from the notifiers'
//! failure counts; served by the API's listener manager on
//! `metrics.listen` (FR-MET-1).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::status::Status;

/// Failed notifications by channel, counted by the notifiers on the I/O
/// runtime: each failed sendmail submission (retries included) and each
/// hook run that did not exit with 0. Notification tests are not counted.
#[derive(Debug, Default)]
pub struct Failures {
    pub email: AtomicU64,
    pub hook: AtomicU64,
}

impl Failures {
    pub fn add(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// A label value, escaped for the text format.
fn label(v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            c => s.push(c),
        }
    }
    s
}

/// The text of `GET /metrics`.
pub fn render(status: &Status, failures: &Failures) -> String {
    let mut out = String::new();
    let mut family = |name: &str, kind: &str, help: &str, samples: Vec<(String, String)>| {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
        for (labels, value) in samples {
            if labels.is_empty() {
                let _ = writeln!(out, "{name} {value}");
            } else {
                let _ = writeln!(out, "{name}{{{labels}}} {value}");
            }
        }
    };
    let flag = |b: bool| if b { "1" } else { "0" }.to_owned();
    let path = |uplink: &str, family: &str| format!("uplink=\"{}\",family=\"{}\"", label(uplink), family);
    family(
        "polywan_build_info",
        "gauge",
        "The running PolyWAN version.",
        vec![(format!("version=\"{}\"", label(status.version)), "1".into())],
    );
    family(
        "polywan_status_degraded",
        "gauge",
        "1 while the overall status is degraded.",
        vec![(String::new(), flag(status.status == "degraded"))],
    );
    let per_path = |f: &dyn Fn(&crate::status::PathStatus) -> Option<String>| {
        status
            .paths
            .iter()
            .filter_map(|p| Some((path(&p.uplink, p.family), f(p)?)))
            .collect::<Vec<_>>()
    };
    family(
        "polywan_path_up",
        "gauge",
        "1 while the path's health is up.",
        per_path(&|p| Some(flag(p.state == "up"))),
    );
    family(
        "polywan_path_ready",
        "gauge",
        "1 while the path is ready (carrier, address, gateway).",
        per_path(&|p| Some(flag(p.ready))),
    );
    family(
        "polywan_path_active",
        "gauge",
        "1 while the path is in its family's active set.",
        per_path(&|p| {
            Some(flag(
                status.active.get(p.family).is_some_and(|set| set.contains(&p.uplink)),
            ))
        }),
    );
    family(
        "polywan_uplink_drained",
        "gauge",
        "1 while the uplink is drained.",
        status
            .uplinks
            .iter()
            .map(|u| (format!("uplink=\"{}\"", label(&u.name)), flag(u.drained)))
            .collect(),
    );
    family(
        "polywan_path_rtt_seconds",
        "gauge",
        "Median probe round-trip time over the quality window.",
        per_path(&|p| p.statistics.rtt_seconds.map(|v| v.to_string())),
    );
    family(
        "polywan_path_jitter_seconds",
        "gauge",
        "Median absolute difference of consecutive round-trip times over the quality window.",
        per_path(&|p| p.statistics.jitter_seconds.map(|v| v.to_string())),
    );
    family(
        "polywan_path_loss_ratio",
        "gauge",
        "Lost probe samples over the quality window.",
        per_path(&|p| p.statistics.loss.map(|v| v.to_string())),
    );
    let c = &status.counters;
    family(
        "polywan_path_transitions_total",
        "counter",
        "Health transitions of the path, by new state.",
        c.transitions
            .iter()
            .map(|((u, f, to), n)| (format!("{},to=\"{to}\"", path(u, f)), n.to_string()))
            .collect(),
    );
    family(
        "polywan_probe_samples_total",
        "counter",
        "Probe samples of the path, by target and result.",
        c.probe_samples
            .iter()
            .map(|((u, f, target, result), n)| {
                (
                    format!("{},target=\"{}\",result=\"{result}\"", path(u, f), label(target)),
                    n.to_string(),
                )
            })
            .collect(),
    );
    let by = |key: &str, list: &[(&'static str, u64)]| -> Vec<(String, String)> {
        list.iter()
            .map(|(k, n)| (format!("{key}=\"{k}\""), n.to_string()))
            .collect()
    };
    family(
        "polywan_artifact_repairs_total",
        "counter",
        "Artifacts re-created after a removal by a third party, by kind.",
        by("kind", &c.repairs),
    );
    family(
        "polywan_apply_failures_total",
        "counter",
        "Failed operations of the reconciler, by kind.",
        by("kind", &c.apply_failures),
    );
    family(
        "polywan_events_dropped_total",
        "counter",
        "Events dropped because a notifier's queue was full.",
        by("notifier", &c.events_dropped),
    );
    family(
        "polywan_notifications_failed_total",
        "counter",
        "Failed notifications: sendmail submissions and hook runs.",
        by(
            "channel",
            &[
                ("email", failures.email.load(Ordering::Relaxed)),
                ("hook", failures.hook.load(Ordering::Relaxed)),
            ],
        ),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{Counters, PathStatus, Statistics, UplinkStatus};

    fn status() -> Status {
        let path = |uplink: &str, state: &'static str, rtt: Option<f64>| PathStatus {
            uplink: uplink.into(),
            family: "ipv4",
            state,
            ready: true,
            reason: "probe",
            since: String::new(),
            source: None,
            gateway: None,
            addresses: Vec::new(),
            statistics: Statistics {
                samples: 4,
                loss: Some(0.25),
                rtt_seconds: rtt,
                jitter_seconds: None,
            },
        };
        let mut c = Counters::default();
        c.transitions.insert(("a".into(), "ipv4", "down"), 2);
        c.probe_samples
            .insert(("a".into(), "ipv4", "icmp:192.0.2.1".into(), "lost"), 3);
        c.apply_failures = vec![("route", 1), ("rule", 0)];
        c.events_dropped = vec![("hooks", 0), ("email", 5)];
        Status {
            version: "2.0.0",
            status: "degraded",
            uplinks: vec![
                UplinkStatus {
                    name: "a".into(),
                    id: 1,
                    interface: "wana".into(),
                    drained: true,
                },
                UplinkStatus {
                    name: "b\"x".into(),
                    id: 2,
                    interface: "wanb".into(),
                    drained: false,
                },
            ],
            paths: vec![path("a", "down", None), path("b\"x", "up", Some(0.02))],
            active: [("ipv4", vec!["b\"x".to_owned()])].into_iter().collect(),
            counters: c,
            ..Status::default()
        }
    }

    #[test]
    fn the_families_of_fr_met_2_are_rendered() {
        let f = Failures::default();
        Failures::add(&f.email);
        let text = render(&status(), &f);
        for line in [
            "polywan_build_info{version=\"2.0.0\"} 1",
            "polywan_status_degraded 1",
            "polywan_path_up{uplink=\"a\",family=\"ipv4\"} 0",
            "polywan_path_up{uplink=\"b\\\"x\",family=\"ipv4\"} 1",
            "polywan_path_ready{uplink=\"a\",family=\"ipv4\"} 1",
            "polywan_path_active{uplink=\"a\",family=\"ipv4\"} 0",
            "polywan_path_active{uplink=\"b\\\"x\",family=\"ipv4\"} 1",
            "polywan_uplink_drained{uplink=\"a\"} 1",
            "polywan_path_rtt_seconds{uplink=\"b\\\"x\",family=\"ipv4\"} 0.02",
            "polywan_path_loss_ratio{uplink=\"a\",family=\"ipv4\"} 0.25",
            "polywan_path_transitions_total{uplink=\"a\",family=\"ipv4\",to=\"down\"} 2",
            "polywan_probe_samples_total{uplink=\"a\",family=\"ipv4\",target=\"icmp:192.0.2.1\",result=\"lost\"} 3",
            "polywan_apply_failures_total{kind=\"route\"} 1",
            "polywan_events_dropped_total{notifier=\"email\"} 5",
            "polywan_notifications_failed_total{channel=\"email\"} 1",
            "polywan_notifications_failed_total{channel=\"hook\"} 0",
            "# TYPE polywan_path_transitions_total counter",
            "# TYPE polywan_path_jitter_seconds gauge",
            "# TYPE polywan_artifact_repairs_total counter",
        ] {
            assert!(text.lines().any(|l| l == line), "{line}\n{text}");
        }
        // A statistic without its inputs is absent, not zero.
        assert!(!text.contains("polywan_path_rtt_seconds{uplink=\"a\""));
        assert!(!text.contains("polywan_path_jitter_seconds{"));
    }
}
