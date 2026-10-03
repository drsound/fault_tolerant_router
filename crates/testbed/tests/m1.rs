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
    // A table without routes does not exist: an empty set.
    let out = t.router().output("ip", ["-4", "route", "show", "table", "1000"])?;
    let text = String::from_utf8_lossy(&out.stdout);
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

// ------------------------------------------------------------------ helpers

fn wait_members(t: &Topology, expected: &[&str], timeout: Duration) -> Result<Duration> {
    t.wait_for(&format!("balancing members {expected:?}"), timeout, || {
        Ok(balancing_members(t)? == expected)
    })
}

fn gateway(t: &Topology, u: Uplink) -> Result<String> {
    Ok(t.os_default_route(u, Family::V4)?
        .flatten()
        .map(|g| g.to_string())
        .unwrap_or_default())
}

fn address(t: &Topology, u: Uplink) -> Result<String> {
    Ok(t.uplink_address(u, Family::V4)?
        .map(|a| a.to_string())
        .unwrap_or_default())
}

/// TCP destinations `ip:port` on test servers `first..first+count`.
fn servers(first: u8, count: u8) -> Vec<String> {
    (first..first + count)
        .map(|n| format!("{}:{}", testbed::plan::server(Family::V4, n), testbed::plan::TCP_PORT))
        .collect()
}

/// A counter in the router namespace (table `inet t_<name>`, postrouting
/// priority 300) counting packets that match `selector`.
fn counter(t: &Topology, name: &str, selector: &str) -> Result<()> {
    t.router().nft(&format!(
        "table inet t_{name} {{\n  counter c {{}}\n  chain post {{\n    type filter hook postrouting priority 300; policy accept;\n    {selector} counter name c\n  }}\n}}\n"
    ))
}

fn counter_value(t: &Topology, name: &str) -> Result<u64> {
    let out = t
        .router()
        .run("nft", ["-j", "list", "counter", "inet", &format!("t_{name}"), "c"])?;
    let v: serde_json::Value = serde_json::from_str(&out)?;
    Ok(v["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|o| o["counter"]["packets"].as_u64())
        .unwrap_or(0))
}

// ---------------------------------------------------------------- scenarios

/// AS-02: weights 3:1; the first uplink gets 70–80% of new connections.
#[test]
#[ignore = "needs root and network namespaces"]
fn as02_weights_three_to_one() -> Result<()> {
    let t = build();
    let ups = [UplinkSpec::new(Uplink::A, 1).weight(3), UplinkSpec::new(Uplink::B, 2)];
    let f = t.start_ftr(&ftr::ipv4_config(&ups, &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    for run in 0..5 {
        let r = t.connect_many(Node::Client, Family::V4, 50, 1000, false)?;
        let a = share(&r, Uplink::A);
        assert!((0.70..=0.80).contains(&a), "run {run}: A got {a:.3} ({:?})", tally(&r));
    }
    Ok(())
}

/// AS-03: long-lived connections on A are never interrupted while B fails
/// and recovers (INV-2).
#[test]
#[ignore = "needs root and network namespaces"]
fn as03_connections_on_a_survive_failure_and_recovery_of_b() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let flows: Vec<_> = (1..=8)
        .map(|n| {
            t.start_flow(
                Node::Client,
                testbed::plan::server(Family::V4, n),
                Duration::from_millis(50),
            )
        })
        .collect::<Result<_>>()?;
    std::thread::sleep(Duration::from_secs(1));
    t.carrier_down(Uplink::B)?;
    wait_members(&t, &["wana"], Duration::from_secs(3))?;
    std::thread::sleep(Duration::from_secs(2));
    t.carrier_up(Uplink::B)?;
    wait_members(&t, &["wana", "wanb"], Duration::from_secs(15))?;
    std::thread::sleep(Duration::from_secs(1));
    let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    let on_a: Vec<_> = reports.iter().filter(|r| r.uplink() == Some(Uplink::A)).collect();
    assert!(!on_a.is_empty(), "no flow was hashed to A: {reports:?}");
    for r in on_a {
        assert!(
            r.continuous(Duration::from_millis(1000)),
            "flow on A interrupted: {r:?}"
        );
    }
    Ok(())
}

/// AS-05: provider A disconnected upstream with the link up; A leaves the
/// active set within (fall + 1) × interval + timeout × attempts = 17 s with
/// the default health settings (FR-HEALTH-5), reason `probe_failed`.
#[test]
#[ignore = "needs root and network namespaces"]
fn as05_silent_upstream_failure_within_the_detection_bound() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::defaults(), "", ""))?;
    f.wait_installed(&t)?;
    // Past the cold start: the first rounds have completed.
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(balancing_members(&t)?, ["wana", "wanb"]);
    let start = Instant::now();
    t.upstream_down(Uplink::A)?;
    wait_members(&t, &["wanb"], Duration::from_secs(25))?;
    let took = start.elapsed();
    assert!(took <= Duration::from_millis(17_500), "removed after {took:?}");
    assert!(
        f.log()
            .contains("uplink=1 family=ipv4 from=Up to=Down reason=probe_failed"),
        "{}",
        f.log()
    );
    t.upstream_up(Uplink::A)?;
    Ok(())
}

/// AS-08: priority groups; group 2 takes over when all of group 1 fails and
/// hands back after recovery.
#[test]
#[ignore = "needs root and network namespaces"]
fn as08_priority_groups_fail_over_and_back() -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3).priority(Some(2)),
    ];
    let f = t.start_ftr(&ftr::ipv4_config(&ups, &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    wait_members(&t, &["wana", "wanb"], Duration::from_secs(5))?;
    t.upstream_down(Uplink::A)?;
    t.upstream_down(Uplink::B)?;
    wait_members(&t, &["ppp0"], Duration::from_secs(10))?;
    let r = t.connect_many(Node::Client, Family::V4, 10, 50, false)?;
    assert_eq!(tally(&r).get(&Some(Uplink::C)), Some(&50), "{:?}", tally(&r));
    t.upstream_up(Uplink::A)?;
    t.upstream_up(Uplink::B)?;
    wait_members(&t, &["wana", "wanb"], Duration::from_secs(15))?;
    Ok(())
}

/// AS-13: every path fails its probes but stays ready; with
/// `all_down_policy = "ready"` group 1 stays active, and recovers.
#[test]
#[ignore = "needs root and network namespaces"]
fn as13_all_probes_failing_keeps_the_best_group() -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3).priority(Some(2)),
    ];
    let f = t.start_ftr(&ftr::ipv4_config(
        &ups,
        &HealthSpec::fast(),
        "all_down_policy = \"ready\"",
        "",
    ))?;
    f.wait_installed(&t)?;
    for u in [Uplink::A, Uplink::B, Uplink::C] {
        t.upstream_down(u)?;
    }
    f.wait_log(&t, "to=Down reason=probe_failed", 3, Duration::from_secs(15))?;
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        balancing_members(&t)?,
        ["wana", "wanb"],
        "group 1 candidates regardless of health"
    );
    for u in [Uplink::A, Uplink::B, Uplink::C] {
        t.upstream_up(u)?;
    }
    f.wait_log(&t, "reason=probes_recovered", 3, Duration::from_secs(20))?;
    assert_eq!(balancing_members(&t)?, ["wana", "wanb"]);
    Ok(())
}

/// AS-20: an invalid configuration on reload keeps the running one.
#[test]
#[ignore = "needs root and network namespaces"]
fn as20_invalid_reload_keeps_the_running_configuration() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    f.write_config("version = 2\n[[bogus]]\n")?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert_eq!(balancing_members(&t)?, ["wana", "wanb"]);
    let r = t.connect_many(Node::Client, Family::V4, 10, 20, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    Ok(())
}

/// AS-24: mark bits outside `fwmark_mask` written by another table are
/// preserved end to end (INV-7).
#[test]
#[ignore = "needs root and network namespaces"]
fn as24_foreign_mark_bits_are_preserved() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    t.router().nft(
        "table inet admin {\n  chain pre {\n    type filter hook prerouting priority -300; policy accept;\n    iifname \"lan\" meta mark set meta mark | 0x00000001\n  }\n  chain ctmark {\n    type filter hook prerouting priority -190; policy accept;\n    iifname \"lan\" ct state new ct mark set ct mark | 0x01000000\n  }\n}\n",
    )?;
    counter(&t, "all", "oifname { \"wana\", \"wanb\" } ip daddr 198.18.100.0/24")?;
    counter(
        &t,
        "kept",
        "oifname { \"wana\", \"wanb\" } ip daddr 198.18.100.0/24 meta mark & 0xff00ffff == 0x00000001 meta mark & 0x00ff0000 != 0 ct mark & 0x01000000 == 0x01000000 ct mark & 0x00ff0000 != 0",
    )?;
    let r = t.connect_many(Node::Client, Family::V4, 20, 100, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    let (all, kept) = (counter_value(&t, "all")?, counter_value(&t, "kept")?);
    assert!(all >= 300, "{all} packets");
    assert_eq!(kept, all, "every packet keeps the foreign bits and carries its path");
    Ok(())
}

/// AS-26: more-specific routes in main are followed (main bypass, INV-1).
#[test]
#[ignore = "needs root and network namespaces"]
fn as26_more_specific_main_routes_take_precedence() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let (gwa, gwb) = (gateway(&t, Uplink::A)?, gateway(&t, Uplink::B)?);
    t.router()
        .ip(&format!("route add 198.18.100.128/25 via {gwb} dev wanb"))?;
    let r = t.connect_to(Node::Client, &servers(200, 50), 100, false, Duration::from_secs(2))?;
    assert_eq!(
        tally(&r).get(&Some(Uplink::B)),
        Some(&100),
        "static route via B: {:?}",
        tally(&r)
    );
    let r = t.connect_to(Node::Client, &servers(1, 50), 200, false, Duration::from_secs(2))?;
    let counts = tally(&r);
    assert!(
        counts.contains_key(&Some(Uplink::A)) && counts.contains_key(&Some(Uplink::B)),
        "others balanced: {counts:?}"
    );
    // A VPN-style pair of /1 routes overrides FTR for everything (by design).
    t.router().ip(&format!("route add 0.0.0.0/1 via {gwa} dev wana"))?;
    t.router().ip(&format!("route add 128.0.0.0/1 via {gwa} dev wana"))?;
    let r = t.connect_to(Node::Client, &servers(1, 50), 100, false, Duration::from_secs(2))?;
    assert_eq!(
        tally(&r).get(&Some(Uplink::A)),
        Some(&100),
        "/1 routes via A: {:?}",
        tally(&r)
    );
    Ok(())
}

/// AS-29: probes of a path outside the active set, and of a target covered
/// by a main route through another uplink, leave through the path (INV-6).
#[test]
#[ignore = "needs root and network namespaces"]
fn as29_probes_leave_through_their_path() -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1).priority(None),
        UplinkSpec::new(Uplink::B, 2),
    ];
    let f = t.start_ftr(&ftr::ipv4_config(&ups, &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t)?, ["wanb"]);
    let (gwb, a) = (gateway(&t, Uplink::B)?, address(&t, Uplink::A)?);
    t.router().ip(&format!("route add 1.1.1.1/32 via {gwb} dev wanb"))?;
    counter(&t, "wrong", &format!("oifname != \"wana\" ip saddr {a}"))?;
    counter(&t, "probes", "oifname \"wana\" ip daddr 1.1.1.1 icmp type echo-request")?;
    std::thread::sleep(Duration::from_secs(4));
    assert!(counter_value(&t, "probes")? >= 3, "probes to 1.1.1.1 leave through A");
    assert_eq!(
        counter_value(&t, "wrong")?,
        0,
        "nothing with A's address leaves elsewhere"
    );
    assert!(
        !f.log().contains("uplink=1 family=ipv4 from=Up to=Down"),
        "A stays healthy:\n{}",
        f.log()
    );
    Ok(())
}

/// AS-33: startup refused with a colliding foreign rule and with flowtables
/// on an uplink or a downlink; a flowtable created at runtime degrades the
/// status until removed; a reload whose proposed configuration matches a
/// flowtable is refused without degrading the running one (FR-CT-2).
#[test]
#[ignore = "needs root and network namespaces"]
fn as33_collisions_and_flowtables() -> Result<()> {
    let t = build();
    let only_a = ftr::ipv4_config(
        &[UplinkSpec::new(Uplink::A, 1)],
        &HealthSpec::fast(),
        "reconcile_interval = \"10s\"",
        "",
    );
    let refused = |setup: &str, undo: &str, needle: &str| -> Result<()> {
        t.router().run("sh", ["-c", setup])?;
        let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
        f.wait_exit(&t, Duration::from_secs(10))?;
        assert!(f.log().contains(needle), "expected {needle:?} in:\n{}", f.log());
        drop(f);
        t.router().run("sh", ["-c", undo])?;
        Ok(())
    };
    refused(
        "ip rule add pref 1650 lookup 5",
        "ip rule del pref 1650",
        "collides with FTR",
    )?;
    let ft = |devs: &str| {
        format!(
            r"nft add table inet ft && nft add flowtable inet ft f {{ hook ingress priority 0 \; devices = {{ {devs} }} \; }}"
        )
    };
    refused(&ft("wana"), "nft delete table inet ft", "matches the uplink wana")?;
    refused(&ft("lan"), "nft delete table inet ft", "matches the downlink lan")?;

    // Runtime detection and recovery.
    let mut f = t.start_ftr(&only_a)?;
    f.wait_installed(&t)?;
    t.router().run("sh", ["-c", &ft("wana")])?;
    f.wait_log(&t, "status_degraded", 1, Duration::from_secs(15))?;
    assert!(f.log().contains("flowtable inet ft f"), "{}", f.log());
    t.router().run("sh", ["-c", "nft delete table inet ft"])?;
    f.wait_log(&t, "status_recovered", 1, Duration::from_secs(15))?;
    // A flowtable on wanb matches only the proposed configuration.
    t.router().run("sh", ["-c", &ft("wanb")])?;
    f.write_config(&ftr::ipv4_config(
        &ab(),
        &HealthSpec::fast(),
        "reconcile_interval = \"10s\"",
        "",
    ))?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert_eq!(
        f.log().matches("status_degraded").count(),
        1,
        "the running configuration is not degraded"
    );
    assert_eq!(balancing_members(&t)?, ["wana"]);
    f.stop()?;
    Ok(())
}

/// AS-40: a foreign rule below `rule_priority_base` is listed in a warning;
/// a missing local rule refuses startup (FR-ROUTE-6).
#[test]
#[ignore = "needs root and network namespaces"]
fn as40_foreign_earlier_rule_and_missing_local_rule() -> Result<()> {
    let t = build();
    t.router().ip("rule add pref 500 lookup 5")?;
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    assert!(
        f.log().contains("the rule at priority 500 precedes FTR's rules"),
        "{}",
        f.log()
    );
    drop(f);
    t.router().ip("rule del pref 500")?;
    t.router().ip("rule del pref 0")?;
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_exit(&t, Duration::from_secs(10))?;
    assert!(
        f.log().contains("local-table rule at priority 0 is missing"),
        "{}",
        f.log()
    );
    t.router().ip("rule add pref 0 lookup local")?;
    Ok(())
}

/// Starts the test servers in another node (ports 7000/tcp and 7001/udp).
fn serve_in(t: &Topology, node: Node) -> Result<std::process::Child> {
    let log = t.dir().join(format!("server-{}.log", node.short()));
    t.ns(node)
        .spawn(&t.agent_bin().to_string_lossy(), ["agent", "serve"], &log)
}

/// Rules of FTR (protocol 249) in the router, as `ip rule` lines.
fn ftr_rules(t: &Topology) -> Result<Vec<String>> {
    Ok(t.router()
        .run("ip", ["-4", "rule", "show"])?
        .lines()
        .filter(|l| l.contains("proto 249"))
        .map(str::to_owned)
        .collect())
}

/// AS-09: inbound connections through port forwarding on each uplink,
/// including one outside the active set, are answered through the uplink
/// they arrived on (INV-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as09_inbound_replies_leave_through_the_arrival_uplink() -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3).priority(Some(2)),
    ];
    let f = t.start_ftr(&ftr::ipv4_config(&ups, &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let _server = serve_in(&t, Node::Client)?;
    t.router().nft(&format!(
        "table ip admin {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname {{ \"wana\", \"wanb\", \"ppp0\" }} tcp dport 8007 dnat to {}:{}\n  }}\n}}\n",
        testbed::plan::LAN_CLIENT_V4,
        testbed::plan::TCP_PORT
    ))?;
    // Provider B (CGNAT) forwards its public port 8007 to the router.
    let b = address(&t, Uplink::B)?;
    t.ns(Node::IspB).nft(&format!(
        "table ip tb_in {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"core\" tcp dport 8007 dnat to {b}\n  }}\n}}\n"
    ))?;
    for (u, iface) in [(Uplink::A, "wana"), (Uplink::B, "wanb"), (Uplink::C, "ppp0")] {
        let public = if u == Uplink::B {
            "198.18.0.6".to_owned()
        } else {
            address(&t, u)?
        };
        counter(
            &t,
            &format!("in{iface}"),
            &format!("oifname \"{iface}\" tcp sport 8007"),
        )?;
        counter(
            &t,
            &format!("out{iface}"),
            &format!("oifname != \"{iface}\" oifname != \"lan\" tcp sport 8007"),
        )?;
        let r = t.connect_to(
            Node::Inet,
            &[format!("{public}:8007")],
            10,
            false,
            Duration::from_secs(2),
        )?;
        assert!(
            r.iter().all(|c| c.outcome == Outcome::Ok),
            "{u}: {:?}",
            r.iter().map(|c| c.outcome).collect::<Vec<_>>()
        );
        assert!(
            counter_value(&t, &format!("in{iface}"))? >= 20,
            "{u}: replies leave through {iface}"
        );
        assert_eq!(
            counter_value(&t, &format!("out{iface}"))?,
            0,
            "{u}: no reply through another uplink"
        );
    }
    Ok(())
}

/// AS-17: rules and routes deleted by a third party come back within 1 s,
/// the nftables table at the next full reconciliation; repeated deletions
/// lead to `ownership_conflict` and later recovery (FR-COEX-3, FR-COEX-4).
#[test]
#[ignore = "needs root and network namespaces"]
fn as17_third_party_deletions_are_repaired() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(
        &ab(),
        &HealthSpec::fast(),
        "reconcile_interval = \"10s\"",
        "",
    ))?;
    f.wait_installed(&t)?;
    let rules = ftr_rules(&t)?;
    let r = t.router();
    let start = Instant::now();
    r.ip("rule del pref 1600")?;
    t.wait_for("the balancing rule back", Duration::from_secs(2), || {
        Ok(ftr_rules(&t)? == rules)
    })?;
    assert!(
        start.elapsed() <= Duration::from_secs(1),
        "rule repaired after {:?}",
        start.elapsed()
    );
    let path = r.run("ip", ["route", "show", "table", "1001"])?;
    let start = Instant::now();
    r.ip("route del default table 1001")?;
    t.wait_for("the path route back", Duration::from_secs(2), || {
        Ok(r.run("ip", ["route", "show", "table", "1001"])? == path)
    })?;
    assert!(
        start.elapsed() <= Duration::from_secs(1),
        "route repaired after {:?}",
        start.elapsed()
    );
    r.run("nft", ["delete", "table", "inet", "fault_tolerant_router"])?;
    t.wait_for("the nftables table back", Duration::from_secs(13), || {
        Ok(r.output("nft", ["list", "table", "inet", "fault_tolerant_router"])?
            .status
            .success())
    })?;
    // Repeated deletions: after the fourth rule removal in five minutes (the
    // balancing rule above counts) immediate repairs stop until a full
    // reconciliation.
    for n in 1..=3 {
        r.ip("rule del pref 1699")?;
        if n < 3 {
            t.wait_for("the final guard back", Duration::from_secs(2), || {
                Ok(ftr_rules(&t)? == rules)
            })?;
        }
    }
    f.wait_log(&t, "ownership_conflict", 1, Duration::from_secs(3))?;
    std::thread::sleep(Duration::from_millis(1500));
    assert_ne!(ftr_rules(&t)?, rules, "no immediate repair during the conflict");
    t.wait_for(
        "the final guard back at a full reconciliation",
        Duration::from_secs(12),
        || Ok(ftr_rules(&t)? == rules),
    )?;
    f.wait_log(&t, "ownership conflict cleared", 1, Duration::from_secs(25))?;
    f.wait_log(&t, "status_recovered", 1, Duration::from_secs(2))?;
    Ok(())
}

/// AS-18: `kill -9` while a long-lived connection runs on healthy B and A
/// is probe-unhealthy: the connection continues, A stays out of the active
/// set after the restart, no duplicate artifacts.
#[test]
#[ignore = "needs root and network namespaces"]
fn as18_crash_and_restart_keep_state_and_connections() -> Result<()> {
    let t = build();
    let mut f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    t.upstream_down(Uplink::A)?;
    wait_members(&t, &["wanb"], Duration::from_secs(10))?;
    let flow = t.start_flow(
        Node::Client,
        testbed::plan::server(Family::V4, 9),
        Duration::from_millis(50),
    )?;
    std::thread::sleep(Duration::from_millis(500));
    let rules = ftr_rules(&t)?;
    f.kill()?;
    f.start(&t)?;
    f.wait_log(&t, "warm=true", 2, Duration::from_secs(10))?;
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        assert_eq!(balancing_members(&t)?, ["wanb"], "A never re-enters the active set");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(ftr_rules(&t)?, rules, "no duplicate or missing rule");
    let report = flow.stop()?;
    assert_eq!(report.uplink(), Some(Uplink::B));
    assert!(report.continuous(Duration::from_millis(1000)), "{report:?}");
    t.upstream_up(Uplink::A)?;
    Ok(())
}

/// AS-19: a reload adding, removing and reordering uplinks leaves the
/// connections of unchanged uplinks alone; reusing the id of a removed
/// uplink is refused until `forget-uplink`.
#[test]
#[ignore = "needs root and network namespaces"]
fn as19_reload_adds_removes_reorders_and_protects_ids() -> Result<()> {
    let t = build();
    let mut f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let flows: Vec<_> = (20..26)
        .map(|n| {
            t.start_flow(
                Node::Client,
                testbed::plan::server(Family::V4, n),
                Duration::from_millis(50),
            )
        })
        .collect::<Result<_>>()?;
    std::thread::sleep(Duration::from_millis(500));
    // C added first in the file, A removed, B unchanged.
    f.write_config(&ftr::ipv4_config(
        &[UplinkSpec::new(Uplink::C, 3), UplinkSpec::new(Uplink::B, 2)],
        &HealthSpec::fast(),
        "",
        "",
    ))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    wait_members(&t, &["ppp0", "wanb"], Duration::from_secs(10))?;
    std::thread::sleep(Duration::from_secs(1));
    let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    for r in reports.iter().filter(|r| r.uplink() == Some(Uplink::B)) {
        assert!(
            r.continuous(Duration::from_millis(1000)),
            "flow on B interrupted: {r:?}"
        );
    }
    // Id 1 belonged to A: reusing it for another name is refused.
    let reuse = [UplinkSpec::new(Uplink::A, 1), UplinkSpec::new(Uplink::B, 2)];
    let text = ftr::ipv4_config(&reuse, &HealthSpec::fast(), "", "").replace("name = \"a\"", "name = \"fiber\"");
    f.write_config(&text)?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains("forget-uplink a"), "{}", f.log());
    f.stop()?;
    let out = f.cli(&["forget-uplink", "a", "--config", &f.config.display().to_string()])?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, &["wana", "wanb"], Duration::from_secs(10))?;
    Ok(())
}

/// AS-32: a conntrack flush during a long-lived connection leaves the
/// daemon unaffected (FR-CT-3).
#[test]
#[ignore = "needs root and network namespaces"]
fn as32_conntrack_flush() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let rules = ftr_rules(&t)?;
    let flow = t.start_flow(
        Node::Client,
        testbed::plan::server(Family::V4, 30),
        Duration::from_millis(50),
    )?;
    std::thread::sleep(Duration::from_millis(500));
    t.router().run("conntrack", ["-F"])?;
    std::thread::sleep(Duration::from_secs(2));
    let _ = flow.stop()?;
    assert_eq!(ftr_rules(&t)?, rules);
    assert_eq!(balancing_members(&t)?, ["wana", "wanb"]);
    let r = t.connect_many(Node::Client, Family::V4, 10, 50, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    Ok(())
}

/// AS-41: a downlink prefix missing from main is warned about; a static
/// off-subnet gateway makes the path ready only with `gateway_onlink`.
#[test]
#[ignore = "needs root and network namespaces"]
fn as41_downlink_prefix_and_off_subnet_gateway() -> Result<()> {
    let t = build();
    t.router().ip("route del 198.51.100.0/24 dev lan")?;
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    assert!(
        f.log().contains("the prefix 198.51.100.0/24 is not in the main table"),
        "{}",
        f.log()
    );
    drop(f);
    t.router()
        .ip("route add 198.51.100.0/24 dev lan proto kernel scope link src 198.51.100.1")?;
    // Provider A answers on an address outside the customer subnet.
    t.ns(Node::IspA).ip("addr add 10.99.0.1/32 dev wan")?;
    let off = |onlink: bool| {
        let extra = if onlink { "gateway_onlink = true\n" } else { "" };
        ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", "").replacen(
            "[uplink.ipv4]\n",
            &format!("[uplink.ipv4]\ngateway = \"10.99.0.1\"\n{extra}"),
            1,
        )
    };
    let f = t.start_ftr(&off(false))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t)?, ["wanb"], "A not ready without gateway_onlink");
    drop(f);
    let f = t.start_ftr(&off(true))?;
    f.wait_installed(&t)?;
    wait_members(&t, &["wana", "wanb"], Duration::from_secs(5))?;
    let route = t.router().run("ip", ["route", "show", "table", "1001"])?;
    assert!(route.contains("via 10.99.0.1") && route.contains("onlink"), "{route}");
    Ok(())
}

/// AS-42: a router service answers from a secondary address of A through A
/// while the active set is empty (INV-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as42_router_reply_from_a_secondary_address() -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1).priority(None),
        UplinkSpec::new(Uplink::B, 2).priority(None),
    ];
    t.router().ip("addr add 192.0.2.250/24 dev wana")?;
    let f = t.start_ftr(&ftr::ipv4_config(&ups, &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    assert!(balancing_members(&t)?.is_empty(), "empty active set");
    let _server = serve_in(&t, Node::Router)?;
    counter(&t, "a", "oifname \"wana\" ip saddr 192.0.2.250 tcp sport 7000")?;
    counter(&t, "other", "oifname != \"wana\" ip saddr 192.0.2.250")?;
    let r = t.connect_to(
        Node::Inet,
        &["192.0.2.250:7000".to_owned()],
        10,
        false,
        Duration::from_secs(2),
    )?;
    assert!(
        r.iter().all(|c| c.outcome == Outcome::Ok),
        "{:?}",
        r.iter().map(|c| c.outcome).collect::<Vec<_>>()
    );
    assert!(counter_value(&t, "a")? >= 20);
    assert_eq!(counter_value(&t, "other")?, 0);
    Ok(())
}
