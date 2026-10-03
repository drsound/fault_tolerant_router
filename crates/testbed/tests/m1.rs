//! M1 acceptance scenarios (SPEC.md §14.3, §17), IPv4, with the daemon
//! under test (`FTR_DAEMON_BIN`) in the router namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use testbed::ftr::{self, HealthSpec, UplinkSpec};
use testbed::plan::{Family, Node, Uplink};
use testbed::traffic::tally;
use testbed::{Options, Outcome, Topology};

fn build() -> Topology {
    assert!(testbed::is_root(), "these tests need root: tests/vm/run-suite.sh");
    let bin = std::env::var_os("FTR_TESTBED_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_ftr-testbed")));
    Topology::build(Options {
        agent_bin: bin,
        ..Options::default()
    })
    .unwrap_or_else(|e| panic!("{e:#}"))
}

fn ab() -> Vec<UplinkSpec> {
    vec![UplinkSpec::new(Uplink::A, 1), UplinkSpec::new(Uplink::B, 2)]
}

fn abc() -> Vec<UplinkSpec> {
    vec![
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3),
    ]
}

/// The members of the IPv4 balancing route (table 1000), by interface name.
fn balancing_members(t: &Topology) -> Result<Vec<String>> {
    let text = t.router().run("ip", ["-4", "route", "show", "table", "1000"])?;
    let mut v: Vec<String> = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .filter(|w| w[0] == "dev")
        .map(|w| w[1].to_owned())
        .collect();
    v.sort();
    v.dedup();
    Ok(v)
}

fn share(results: &[testbed::ConnResult], u: Uplink) -> f64 {
    let n = tally(results).get(&Some(u)).copied().unwrap_or(0);
    n as f64 / results.len() as f64
}

/// AS-01: two healthy uplinks with equal weights; each gets 45–55% of new
/// connections (1,000 connections to 50 destinations, 5 runs).
#[test]
#[ignore = "needs root and network namespaces"]
fn as01_equal_weights_split_connections_evenly() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t)?, ["wana", "wanb"]);
    t.reset_counters()?;
    for run in 0..5 {
        let r = t.connect_many(Node::Client, Family::V4, 50, 1000, false)?;
        let failed = r.iter().filter(|c| c.outcome != Outcome::Ok).count();
        assert_eq!(failed, 0, "run {run}: {:?}", tally(&r));
        let a = share(&r, Uplink::A);
        assert!((0.45..=0.55).contains(&a), "run {run}: A got {a:.3} ({:?})", tally(&r));
    }
    assert_eq!(t.ipv4_leaks()?, 0, "INV-3");
    Ok(())
}

/// AS-04: carrier lost on A; A leaves the active set within 1 s and new
/// connections use B (FR-HEALTH-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as04_carrier_loss_withdraws_the_uplink_within_a_second() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t)?, ["wana", "wanb"]);
    let start = Instant::now();
    t.carrier_down(Uplink::A)?;
    t.wait_for("A out of the balancing route", Duration::from_secs(3), || {
        Ok(balancing_members(&t)? == ["wanb"])
    })?;
    let took = start.elapsed();
    assert!(took <= Duration::from_secs(1), "withdrawn after {took:?}");
    let r = t.connect_many(Node::Client, Family::V4, 20, 100, false)?;
    assert_eq!(tally(&r).get(&Some(Uplink::B)), Some(&100), "{:?}", tally(&r));
    t.carrier_up(Uplink::A)?;
    Ok(())
}

/// AS-14: every uplink loses carrier; new connections are rejected and no
/// packet leaves through a route that FTR did not install (INV-3).
#[test]
#[ignore = "needs root and network namespaces"]
fn as14_no_uplink_rejects_without_leaking() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&abc(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    for u in [Uplink::A, Uplink::B, Uplink::C] {
        t.carrier_down(u)?;
    }
    t.wait_for("an empty balancing route", Duration::from_secs(5), || {
        Ok(balancing_members(&t)?.is_empty())
    })?;
    t.reset_counters()?;
    let r = t.connect_many(Node::Client, Family::V4, 10, 30, false)?;
    assert!(r.iter().all(|c| c.outcome != Outcome::Ok), "{:?}", tally(&r));
    assert_eq!(t.ipv4_leaks()?, 0, "INV-3");
    for u in [Uplink::A, Uplink::B] {
        assert_eq!(t.egress_packets(u, Family::V4)?, 0, "no packet leaves through {u}");
    }
    Ok(())
}

/// AS-45(a): an IPv4-only configuration installs no IPv6 routing or
/// nftables artifact and changes no IPv6 setting.
#[test]
#[ignore = "needs root and network namespaces"]
fn as45a_ipv4_only_leaves_ipv6_alone() -> Result<()> {
    let t = build();
    let keys = [
        "net/ipv6/conf/all/forwarding",
        "net/ipv6/fib_multipath_hash_policy",
        "net/ipv6/conf/wana/ignore_routes_with_linkdown",
        "net/ipv6/conf/wanb/ignore_routes_with_linkdown",
        "net/ipv6/conf/wana/forwarding",
    ];
    let read = |k: &str| {
        t.router()
            .run("cat", [format!("/proc/sys/{k}")])
            .map(|s| s.trim().to_owned())
    };
    let before: Vec<String> = keys.iter().map(|k| read(k)).collect::<Result<_>>()?;
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let rules = t.router().run("ip", ["-6", "rule", "show"])?;
    assert!(!rules.contains("proto 249"), "{rules}");
    let routes = t
        .router()
        .run("ip", ["-6", "route", "show", "table", "all", "proto", "249"])?;
    assert_eq!(routes.trim(), "", "{routes}");
    let table = t
        .router()
        .run("nft", ["list", "table", "inet", "fault_tolerant_router"])?;
    assert!(!table.contains("meta nfproto ipv6 "), "{table}");
    let after: Vec<String> = keys.iter().map(|k| read(k)).collect::<Result<_>>()?;
    assert_eq!(before, after, "IPv6 settings of {keys:?}");
    Ok(())
}
