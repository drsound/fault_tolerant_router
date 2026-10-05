//! Network namespace test harness for PolyWAN 2.0.
//!
//! Builds the reference topology of SPEC.md §14.2 out of network namespaces
//! and veth pairs (an "internet" node, three providers, the router under test
//! and a LAN client), and offers the helpers that acceptance tests need:
//! command execution inside a namespace, failure injection, traffic
//! generation with per-connection uplink attribution, and leak detection.
//!
//! Everything a run creates is named after a random run identifier
//! (`tb-<run>-<node>`), so several runs can share a host, and is removed when
//! the [`Topology`] is dropped or by `polywan-testbed down`.

#![forbid(unsafe_code)]

pub mod agent;
pub mod dhcpv6;
pub mod inject;
pub mod netns;
pub mod plan;
pub mod polywan;
pub mod sendmail;
pub mod topology;
pub mod traffic;

pub use netns::Ns;
pub use plan::{Family, Node, Uplink};
pub use topology::{Options, Topology};
pub use traffic::{ConnResult, FlowReport, Outcome, PingOutcome};

/// Whether the current process runs with effective user id 0.
pub fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).map(|euid| euid == "0"))
        })
        .unwrap_or(false)
}
