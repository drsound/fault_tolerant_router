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
        &format!(
            "table inet admin {{\n  chain pre {{\n    type filter hook prerouting priority -300; policy accept;\n    iifname \"lan\" meta mark set meta mark | {p:#010x}\n  }}\n  chain ctmark {{\n    type filter hook prerouting priority -190; policy accept;\n    iifname \"lan\" ct state new ct mark set ct mark | {c:#010x}\n  }}\n}}\n",
            p = ftr::foreign_bit(0),
            c = ftr::foreign_bit(8)
        ),
    )?;
    counter(&t, "all", "oifname { \"wana\", \"wanb\" } ip daddr 198.18.100.0/24")?;
    counter(
        &t,
        "kept",
        &format!(
            "oifname {{ \"wana\", \"wanb\" }} ip daddr 198.18.100.0/24 meta mark & {nm:#010x} == {p:#010x} meta mark & {m:#010x} != 0 ct mark & {c:#010x} == {c:#010x} ct mark & {m:#010x} != 0",
            nm = !ftr::mask(),
            m = ftr::mask(),
            p = ftr::foreign_bit(0),
            c = ftr::foreign_bit(8)
        ),
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
    // Real interfaces only: traffic of the router to itself goes through `lo`.
    counter(
        &t,
        "wrong",
        &format!("oifname {{ \"wanb\", \"ppp0\", \"lan\" }} ip saddr {a}"),
    )?;
    counter(&t, "probes", "oifname \"wana\" ip daddr 1.1.1.1 icmp type echo-request")?;
    t.router().nft(&format!(
        "table inet t_diag {{\n  set seen {{ type ifname . ipv4_addr; flags dynamic; }}\n  chain post {{\n    type filter hook postrouting priority 300; policy accept;\n    oifname != \"wana\" ip saddr {a} add @seen {{ oifname . ip daddr }}\n  }}\n}}\n"
    ))?;
    std::thread::sleep(Duration::from_secs(4));
    let seen = t.router().run("nft", ["list", "set", "inet", "t_diag", "seen"])?;
    assert!(counter_value(&t, "probes")? >= 3, "probes to 1.1.1.1 leave through A");
    assert_eq!(
        counter_value(&t, "wrong")?,
        0,
        "nothing with A's address leaves elsewhere: {seen}"
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
    // A path added by reload starts down and needs `rise` passed rounds.
    wait_members(&t, &["ppp0", "wanb"], Duration::from_secs(20))?;
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

/// The IPv4 path route of table `table`, as `ip route` prints it.
fn path_route(t: &Topology, table: u32) -> Result<String> {
    let out = t
        .router()
        .output("ip", ["-4", "route", "show", "table", &table.to_string()])?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// AS-10: the DHCP lease of A changes address and gateway; FTR's artifacts
/// follow within 1 s; connections on B are unaffected.
#[test]
#[ignore = "needs root and network namespaces"]
fn as10_lease_change_updates_artifacts_within_a_second() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let flows: Vec<_> = (40..46)
        .map(|n| {
            t.start_flow(
                Node::Client,
                testbed::plan::server(Family::V4, n),
                Duration::from_millis(50),
            )
        })
        .collect::<Result<_>>()?;
    std::thread::sleep(Duration::from_millis(500));
    let old = address(&t, Uplink::A)?;
    t.ns(Node::IspA).ip("addr add 192.0.2.254/24 dev wan")?;
    // What a DHCP client does on a new lease (the default route keeps the
    // harness realm that marks operating-system routes).
    let r = t.router();
    let realm = r.run("ip", ["-4", "route", "show", "default", "dev", "wana"])?;
    let realm = realm
        .split_whitespace()
        .skip_while(|w| *w != "realm")
        .nth(1)
        .unwrap_or("99")
        .to_owned();
    let start = Instant::now();
    r.ip(&format!("addr del {old}/24 dev wana"))?;
    r.ip("addr add 192.0.2.77/24 dev wana")?;
    r.ip(&format!(
        "route replace default via 192.0.2.254 dev wana metric 100 realm {realm}"
    ))?;
    t.wait_for(
        "A's path route with the new gateway and source",
        Duration::from_secs(3),
        || {
            let p = path_route(&t, 1001)?;
            Ok(p.contains("via 192.0.2.254") && p.contains("src 192.0.2.77"))
        },
    )?;
    let took = start.elapsed();
    assert!(took <= Duration::from_secs(1), "updated after {took:?}");
    let rules = ftr_rules(&t)?.join("\n");
    assert!(
        rules.contains("from 192.0.2.77") && !rules.contains(&format!("from {old} ")),
        "{rules}"
    );
    assert!(f.log().contains("path discovery changed uplink=1"), "{}", f.log());
    std::thread::sleep(Duration::from_secs(1));
    let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    for r in reports.iter().filter(|r| r.uplink() == Some(Uplink::B)) {
        assert!(
            r.continuous(Duration::from_millis(1000)),
            "flow on B interrupted: {r:?}"
        );
    }
    Ok(())
}

/// AS-11: the PPP uplink reconnects with a new interface index; artifacts
/// follow and the per-interface settings are applied again.
#[test]
#[ignore = "needs root and network namespaces"]
fn as11_ppp_reconnection_with_a_new_ifindex() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&abc(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let ifindex = || -> Result<Option<u64>> {
        Ok(t.router()
            .ip_json("link show dev ppp0")
            .ok()
            .and_then(|v| v[0]["ifindex"].as_u64()))
    };
    let before = ifindex()?.expect("ppp0");
    assert!(path_route(&t, 1003)?.contains("dev ppp0"));
    t.pppoe_reset()?;
    t.wait_for("ppp0 to come back with a new index", Duration::from_secs(30), || {
        Ok(ifindex()?.is_some_and(|i| i != before))
    })?;
    let back = Instant::now();
    t.wait_for("C's path route on the new ppp0", Duration::from_secs(10), || {
        Ok(path_route(&t, 1003)?.contains("dev ppp0")
            && t.router()
                .run("ip", ["-4", "addr", "show", "dev", "ppp0"])?
                .contains("inet "))
    })?;
    // The address may arrive after the link: the bound applies to the last event.
    let _ = back;
    let svm = t.router().run("cat", ["/proc/sys/net/ipv4/conf/ppp0/src_valid_mark"])?;
    assert_eq!(svm.trim(), "1", "per-interface settings re-applied");
    let route = path_route(&t, 1003)?;
    let addr = address(&t, Uplink::C)?;
    assert!(route.contains(&format!("src {addr}")), "{route}");
    Ok(())
}

/// AS-22: retransmitted SYNs without answer and one-way UDP flows while the
/// active set changes: every packet of each flow leaves through one uplink.
#[test]
#[ignore = "needs root and network namespaces"]
fn as22_unanswered_and_one_way_flows_stay_on_their_uplink() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    t.inet().nft("table inet blackhole {\n  chain in {\n    type filter hook prerouting priority 0; policy accept;\n    tcp dport 9999 drop\n  }\n}\n")?;
    // The UDP flows are told apart by their (pre-NAT) source port.
    t.router().nft("table inet t_flows {\n  set flows_tcp { type ipv4_addr . inet_service . ifname; flags dynamic; size 4096; }\n  set flows_udp { type inet_service . ifname; flags dynamic; size 4096; }\n  chain post {\n    type filter hook postrouting priority 300; policy accept;\n    oifname { \"wana\", \"wanb\" } tcp dport 9999 add @flows_tcp { ip daddr . ct original proto-src . oifname }\n    oifname { \"wana\", \"wanb\" } udp dport 7002 add @flows_udp { ct original proto-src . oifname }\n  }\n}\n")?;
    let dsts: Vec<String> = (60..70)
        .map(|n| format!("{}:9999", testbed::plan::server(Family::V4, n)))
        .collect();
    std::thread::scope(|s| -> Result<()> {
        let syn = s.spawn(|| t.connect_to(Node::Client, &dsts, 10, false, Duration::from_secs(7)));
        let udp: Vec<_> = (0..5u16)
            .map(|i| {
                let t = &t;
                s.spawn(move || {
                    t.udp_send(
                        Node::Client,
                        testbed::plan::server(Family::V4, 70 + i as u8),
                        43000 + i,
                        60,
                        Duration::from_millis(100),
                    )
                })
            })
            .collect();
        for _ in 0..2 {
            std::thread::sleep(Duration::from_millis(1200));
            t.upstream_down(Uplink::B)?;
            wait_members(&t, &["wana"], Duration::from_secs(5))?;
            t.upstream_up(Uplink::B)?;
            wait_members(&t, &["wana", "wanb"], Duration::from_secs(8))?;
        }
        syn.join().expect("syn thread")?;
        for u in udp {
            u.join().expect("udp thread")?;
        }
        Ok(())
    })?;
    let listing = t.router().run("nft", ["-j", "list", "table", "inet", "t_flows"])?;
    let v: serde_json::Value = serde_json::from_str(&listing)?;
    let mut flows: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> = Default::default();
    for o in v["nftables"].as_array().into_iter().flatten() {
        let Some(set) = o.get("set") else { continue };
        for e in set["elem"].as_array().into_iter().flatten() {
            let parts = e["concat"]
                .as_array()
                .or_else(|| e["elem"]["val"]["concat"].as_array())
                .cloned()
                .unwrap_or_default();
            let parts: Vec<String> = parts.iter().map(|p| p.to_string()).collect();
            if let Some((ifname, key)) = parts.split_last() {
                flows
                    .entry(format!("{} {}", set["name"], key.join(" ")))
                    .or_default()
                    .insert(ifname.clone());
            }
        }
    }
    assert!(flows.len() >= 12, "flows seen: {flows:?}");
    let split: Vec<_> = flows.iter().filter(|(_, ifs)| ifs.len() > 1).collect();
    assert!(split.is_empty(), "flows that changed uplink: {split:?}");
    Ok(())
}

/// AS-30: with an empty active set and no operating-system default route,
/// inbound DNAT traffic, connections to router listeners and ICMP and TCP
/// probe replies are accepted; without the source rule of the probe source,
/// ICMP probe replies fail the IPv4 reverse-path check (negative control).
#[test]
#[ignore = "needs root and network namespaces"]
fn as30_replies_with_an_empty_active_set() -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1).priority(None),
        UplinkSpec::new(Uplink::B, 2).priority(None),
    ];
    let health = HealthSpec {
        text: "interval = \"1s\"\ntimeout = \"300ms\"\nattempts = 2\n[health.ipv4]\ntargets = [\"icmp:1.1.1.1\", \"icmp:8.8.8.8\", \"tcp:9.9.9.9:443\", \"tcp:208.67.222.222:443\"]\n".into(),
    };
    // Static gateways: the operating-system default routes go away.
    let (gwa, gwb) = (gateway(&t, Uplink::A)?, gateway(&t, Uplink::B)?);
    let config = ftr::ipv4_config(&ups, &health, "", "")
        .replacen("[uplink.ipv4]\n", &format!("[uplink.ipv4]\ngateway = \"{gwa}\"\n"), 1)
        .replacen(
            "[uplink.ipv4]\n[health]",
            &format!("[uplink.ipv4]\ngateway = \"{gwb}\"\n[health]"),
            1,
        );
    for _ in 0..3 {
        let _ = t.router().output("ip", ["-4", "route", "del", "default"])?;
    }
    let mut f = t.start_ftr(&config)?;
    f.wait_installed(&t)?;
    assert!(balancing_members(&t)?.is_empty());
    std::thread::sleep(Duration::from_secs(4));
    assert!(
        !f.log().contains("to=Down"),
        "ICMP and TCP probe replies accepted:\n{}",
        f.log()
    );
    let _client = serve_in(&t, Node::Client)?;
    let _router = serve_in(&t, Node::Router)?;
    t.router().nft(&format!(
        "table ip admin {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"wana\" tcp dport 8007 dnat to {}:{}\n  }}\n}}\n",
        testbed::plan::LAN_CLIENT_V4,
        testbed::plan::TCP_PORT
    ))?;
    let a = address(&t, Uplink::A)?;
    for dst in [format!("{a}:8007"), format!("{a}:7000")] {
        let r = t.connect_to(Node::Inet, std::slice::from_ref(&dst), 5, false, Duration::from_secs(2))?;
        assert!(
            r.iter().all(|c| c.outcome == Outcome::Ok),
            "{dst}: {:?}",
            r.iter().map(|c| c.outcome).collect::<Vec<_>>()
        );
    }
    // Negative control: freeze the daemon, remove the source rule of A's
    // address, and watch ICMP probe replies fail the reverse-path check.
    f.signal("STOP")?;
    t.router().ip(&format!("rule del from {a} pref 1501"))?;
    let drops = || -> Result<u64> {
        let out = t.router().run("nstat", ["-az", "TcpExtIPReversePathFilter"])?;
        Ok(out
            .lines()
            .find_map(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
            .unwrap_or(0))
    };
    let before = drops()?;
    let ping = t.router().output(
        "ping",
        [
            "-n",
            "-c",
            "3",
            "-W",
            "1",
            "-I",
            "wana",
            "-m",
            &ftr::encode(0x41).to_string(),
            "1.1.1.1",
        ],
    )?;
    assert!(
        !ping.status.success(),
        "replies must be dropped without the source rule"
    );
    assert!(drops()? > before, "reverse-path drops counted");
    f.signal("CONT")?;
    f.stop()?;
    Ok(())
}

/// AS-37: an uplink removed by reload with a live connection: its packets
/// are rejected by the path guard, never balanced; router traffic bound to
/// its interface never leaves through another interface (INV-2, INV-3).
#[test]
#[ignore = "needs root and network namespaces"]
fn as37_removed_uplink_connections_are_rejected_not_moved() -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::C, 3),
        UplinkSpec::new(Uplink::A, 1).priority(Some(2)),
        UplinkSpec::new(Uplink::B, 2).priority(Some(2)),
    ];
    let f = t.start_ftr(&ftr::ipv4_config(&ups, &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t)?, ["ppp0"]);
    t.reset_counters()?;
    let flow = t.start_flow(
        Node::Client,
        testbed::plan::server(Family::V4, 77),
        Duration::from_millis(50),
    )?;
    std::thread::sleep(Duration::from_millis(700));
    counter(
        &t,
        "moved",
        "oifname { \"wana\", \"wanb\" } ip daddr { 198.18.100.77, 198.18.100.78 }",
    )?;
    f.write_config(&ftr::ipv4_config(&[ups[1], ups[2]], &HealthSpec::fast(), "", ""))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    wait_members(&t, &["wana", "wanb"], Duration::from_secs(5))?;
    std::thread::sleep(Duration::from_secs(2));
    let report = flow.stop()?;
    assert_eq!(report.uplink(), Some(Uplink::C));
    assert_eq!(t.ipv4_leaks()?, 0, "INV-3 for the connection of the removed uplink");
    // Router traffic bound to C's interface: outside INV-3 (§4.1.1), it
    // may leave on-link through C but never through another interface.
    let _ = t
        .router()
        .output("ping", ["-n", "-c", "2", "-W", "1", "-I", "ppp0", "198.18.100.78"])?;
    assert_eq!(
        counter_value(&t, "moved")?,
        0,
        "no packet of the connection or of the bound traffic left through A or B"
    );
    Ok(())
}

/// AS-38: the checkpoint stays fresh without transitions, so a restart keeps
/// a down path down (warm start); after a reboot (another boot id) the start
/// is cold.
#[test]
#[ignore = "needs root and network namespaces"]
fn as38_warm_restart_and_cold_start_after_reboot() -> Result<()> {
    let t = build();
    let mut f = t.start_ftr(&ftr::ipv4_config(
        &ab(),
        &HealthSpec::fast(),
        "all_down_policy = \"keep\"",
        "",
    ))?;
    f.wait_installed(&t)?;
    t.upstream_down(Uplink::A)?;
    wait_members(&t, &["wanb"], Duration::from_secs(10))?;
    let checkpoint = f.dir.join("state/health.json");
    let stamp = |p: &std::path::Path| -> Result<u64> {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p)?)?;
        Ok(v["boottime_ms"].as_u64().unwrap_or(0))
    };
    let first = stamp(&checkpoint)?;
    std::thread::sleep(Duration::from_secs(32));
    assert!(
        stamp(&checkpoint)? > first,
        "rewritten at least every 30 s without transitions"
    );
    f.stop()?;
    f.start(&t)?;
    f.wait_log(
        &t,
        "initial path state uplink=1 family=ipv4 state=Down warm=true",
        1,
        Duration::from_secs(10),
    )?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t)?, ["wanb"]);
    f.stop()?;
    // Reboot: another boot identifier.
    let text = std::fs::read_to_string(&checkpoint)?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let boot = v["boot_id"].as_str().unwrap_or_default().to_owned();
    std::fs::write(&checkpoint, text.replace(&boot, "00000000-0000-0000-0000-000000000000"))?;
    f.start(&t)?;
    f.wait_log(
        &t,
        "initial path state uplink=1 family=ipv4 state=Up warm=false",
        1,
        Duration::from_secs(10),
    )?;
    f.wait_log(
        &t,
        "uplink=1 family=ipv4 from=Up to=Down reason=probe_failed",
        1,
        Duration::from_secs(10),
    )?;
    t.upstream_up(Uplink::A)?;
    Ok(())
}

/// AS-50: a connection from a host behind an interface FTR does not manage
/// to a LAN host, whose replies follow the balancing route: the replies are
/// never assigned a path and continue through the other uplink when theirs
/// loses readiness.
#[test]
#[ignore = "needs root and network namespaces"]
fn as50_unmanaged_interface_replies_are_not_pinned() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let _client = serve_in(&t, Node::Client)?;
    // An unmanaged link between the router and the internet node; the
    // internet node reaches the LAN through it from 198.18.100.50, which the
    // router reaches only through its uplinks.
    testbed::netns::host(
        "ip",
        [
            "link",
            "add",
            "wanx",
            "netns",
            t.router().name(),
            "type",
            "veth",
            "peer",
            "name",
            "rx",
            "netns",
            t.inet().name(),
        ],
    )?;
    t.router().ip("addr add 10.250.0.1/30 dev wanx")?;
    t.router().ip("link set wanx up")?;
    let i = t.inet();
    i.ip("addr add 10.250.0.2/30 dev rx")?;
    i.ip("link set rx up")?;
    i.ip("addr add 198.18.100.50/32 dev lo")?;
    i.ip("route add 198.51.100.0/24 via 10.250.0.1 src 198.18.100.50")?;
    for k in ["all", "default", "rx"] {
        i.run("sysctl", ["-qw", &format!("net.ipv4.conf.{k}.rp_filter=0")])?;
    }
    for name in i.run("ls", ["/proc/sys/net/ipv4/conf"])?.split_whitespace() {
        let _ = i.output("sysctl", ["-qw", &format!("net.ipv4.conf.{name}.rp_filter=0")]);
    }
    counter(&t, "a", "oifname \"wana\" ip daddr 198.18.100.50")?;
    counter(&t, "b", "oifname \"wanb\" ip daddr 198.18.100.50")?;
    let flow = t.start_flow(
        Node::Inet,
        testbed::plan::LAN_CLIENT_V4.into(),
        Duration::from_millis(50),
    )?;
    std::thread::sleep(Duration::from_secs(1));
    let ct = t.router().run(
        "conntrack",
        [
            "-L",
            "-s",
            "198.18.100.50",
            "-d",
            &testbed::plan::LAN_CLIENT_V4.to_string(),
        ],
    )?;
    let marks: Vec<&str> = ct.split_whitespace().filter(|w| w.starts_with("mark=")).collect();
    assert!(
        !marks.is_empty()
            && marks
                .iter()
                .all(|m| m.trim_start_matches("mark=").parse::<u32>().unwrap_or(1) & ftr::mask() == 0),
        "{ct}"
    );
    let (a, b) = (counter_value(&t, "a")?, counter_value(&t, "b")?);
    let used = if a > b { Uplink::A } else { Uplink::B };
    assert!(a.min(b) == 0 && a.max(b) > 0, "replies through one uplink: a={a} b={b}");
    t.carrier_down(used)?;
    std::thread::sleep(Duration::from_secs(3));
    let report = flow.stop()?;
    assert!(report.continuous(Duration::from_millis(2500)), "{report:?}");
    let other = if used == Uplink::A {
        counter_value(&t, "b")?
    } else {
        counter_value(&t, "a")?
    };
    assert!(other > 0, "replies continued through the other uplink");
    t.carrier_up(used)?;
    Ok(())
}

/// AS-21: router-originated traffic. Unbound connections are balanced;
/// connections bound to A's address use A, also outside the active set;
/// connections bound to A's interface never leave through another interface
/// and behave as §4.1.1 describes, for TCP and UDP, on the Ethernet and the
/// point-to-point uplink, with the path in and outside the active set and
/// with its path route withdrawn.
#[test]
#[ignore = "needs root and network namespaces"]
fn as21_router_originated_traffic() -> Result<()> {
    use testbed::agent::Binding;
    let t = build();
    let f = t.start_ftr(&ftr::ipv4_config(&abc(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    let ok = |r: &[testbed::ConnResult]| r.iter().all(|c| c.outcome == Outcome::Ok);
    // Unbound: balanced over A and B.
    let r = t.connect_to(Node::Router, &servers(1, 50), 200, false, Duration::from_secs(2))?;
    let counts = tally(&r);
    assert!(
        ok(&r) && counts.contains_key(&Some(Uplink::A)) && counts.contains_key(&Some(Uplink::B)),
        "{counts:?}"
    );
    let a: std::net::IpAddr = address(&t, Uplink::A)?.parse()?;
    let by_addr = Binding {
        source: Some(a),
        device: None,
    };
    let by_dev = |d: &str| Binding {
        source: None,
        device: Some(d.to_owned()),
    };
    let check = |what: &str, b: &Binding, udp: bool, expect: Option<Uplink>| -> Result<()> {
        let port = if udp {
            testbed::plan::UDP_PORT
        } else {
            testbed::plan::TCP_PORT
        };
        let dsts: Vec<String> = servers(120, 10)
            .iter()
            .map(|d| d.replace(":7000", &format!(":{port}")))
            .collect();
        let r = t.connect_bound(Node::Router, &dsts, 20, udp, Duration::from_secs(2), b)?;
        match expect {
            Some(u) => assert!(
                ok(&r) && tally(&r).get(&Some(u)) == Some(&20),
                "{what}: {:?} {:?}",
                tally(&r),
                r.iter()
                    .map(|c| (c.outcome, c.errno, c.local, c.observed))
                    .take(4)
                    .collect::<Vec<_>>()
            ),
            None => assert!(r.iter().all(|c| c.outcome != Outcome::Ok), "{what}: {:?}", tally(&r)),
        }
        Ok(())
    };
    check("bound to A's address", &by_addr, false, Some(Uplink::A))?;
    for udp in [false, true] {
        check("bound to wana", &by_dev("wana"), udp, Some(Uplink::A))?;
        check("bound to ppp0", &by_dev("ppp0"), udp, Some(Uplink::C))?;
    }
    // A outside the active set (probes fail, path still ready).
    t.upstream_down(Uplink::A)?;
    wait_members(&t, &["ppp0", "wanb"], Duration::from_secs(10))?;
    t.upstream_up(Uplink::A)?;
    // While A recovers (rise rounds), it is still outside the active set.
    check(
        "bound to A's address outside the active set",
        &by_addr,
        false,
        Some(Uplink::A),
    )?;
    check(
        "bound to wana outside the active set",
        &by_dev("wana"),
        false,
        Some(Uplink::A),
    )?;
    // A's path route withdrawn: the gateway disappears from main.
    counter(
        &t,
        "elsewhere",
        "oifname != \"wana\" oifname != \"lo\" ip daddr 198.18.100.120-198.18.100.129",
    )?;
    t.router().ip("route del default dev wana")?;
    t.wait_for("A's path route withdrawn", Duration::from_secs(3), || {
        Ok(path_route(&t, 1001)?.is_empty())
    })?;
    for udp in [false, true] {
        // IPv4 sends on-link through the bound interface (§4.1.1): nothing
        // answers on Ethernet.
        check("bound to wana, path withdrawn", &by_dev("wana"), udp, None)?;
    }
    assert_eq!(counter_value(&t, "elsewhere")?, 0, "never through another interface");
    // The point-to-point uplink with its path route withdrawn: the
    // datagrams go to the peer, through ppp0 only.
    counter(
        &t,
        "c_elsewhere",
        "oifname != \"ppp0\" oifname != \"lo\" ip daddr 198.18.100.120-198.18.100.129",
    )?;
    let c = address(&t, Uplink::C)?;
    t.router()
        .ip(&format!("addr del {c}/32 dev ppp0"))
        .or_else(|_| t.router().ip("addr flush dev ppp0"))?;
    let udp_dsts: Vec<String> = servers(120, 10).iter().map(|d| d.replace(":7000", ":7001")).collect();
    let _ = t.connect_bound(
        Node::Router,
        &udp_dsts,
        10,
        true,
        Duration::from_secs(1),
        &by_dev("ppp0"),
    )?;
    assert_eq!(counter_value(&t, "c_elsewhere")?, 0, "never through another interface");
    Ok(())
}

/// AS-23: external firewall mode; the administrator loads the exported
/// ruleset by hand; the results of AS-01, AS-03 and AS-09 hold.
#[test]
#[ignore = "needs root and network namespaces"]
fn as23_external_firewall_mode() -> Result<()> {
    let t = build();
    let config = ftr::ipv4_config(
        &ab(),
        &HealthSpec::fast(),
        "reconcile_interval = \"10s\"",
        "[firewall]\nmode = \"external\"\n",
    );
    let f = t.start_ftr(&config)?;
    f.wait_installed(&t)?;
    assert!(
        f.log()
            .contains("marking and NAT are the administrator's responsibility"),
        "{}",
        f.log()
    );
    f.wait_log(
        &t,
        "reason=\"external_ruleset_missing\" status_degraded",
        1,
        Duration::from_secs(2),
    )
    .or_else(|_| f.wait_log(&t, "external_ruleset_missing", 1, Duration::from_secs(2)))?;
    assert!(
        !t.router()
            .output("nft", ["list", "table", "inet", "fault_tolerant_router"])?
            .status
            .success(),
        "FTR performs no nftables mutation"
    );
    let out = f.cli(&["export-nft", "--config", &f.config.display().to_string()])?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    t.router().nft(&String::from_utf8_lossy(&out.stdout))?;
    f.wait_log(&t, "status_recovered", 1, Duration::from_secs(13))?;
    // AS-01 (one run).
    let r = t.connect_many(Node::Client, Family::V4, 50, 1000, false)?;
    let a = share(&r, Uplink::A);
    assert!(
        r.iter().all(|c| c.outcome == Outcome::Ok) && (0.45..=0.55).contains(&a),
        "A got {a:.3} ({:?})",
        tally(&r)
    );
    // AS-03: connections on A survive a failure of B.
    let flows: Vec<_> = (1..=6)
        .map(|n| {
            t.start_flow(
                Node::Client,
                testbed::plan::server(Family::V4, n),
                Duration::from_millis(50),
            )
        })
        .collect::<Result<_>>()?;
    std::thread::sleep(Duration::from_millis(500));
    t.carrier_down(Uplink::B)?;
    wait_members(&t, &["wana"], Duration::from_secs(3))?;
    std::thread::sleep(Duration::from_secs(1));
    t.carrier_up(Uplink::B)?;
    let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    for r in reports.iter().filter(|r| r.uplink() == Some(Uplink::A)) {
        assert!(
            r.continuous(Duration::from_millis(1000)),
            "flow on A interrupted: {r:?}"
        );
    }
    // AS-09 on A.
    let _server = serve_in(&t, Node::Client)?;
    t.router().nft(&format!(
        "table ip admin {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"wana\" tcp dport 8007 dnat to {}:{}\n  }}\n}}\n",
        testbed::plan::LAN_CLIENT_V4,
        testbed::plan::TCP_PORT
    ))?;
    counter(&t, "in_a", "oifname \"wana\" tcp sport 8007")?;
    let r = t.connect_to(
        Node::Inet,
        &[format!("{}:8007", address(&t, Uplink::A)?)],
        10,
        false,
        Duration::from_secs(2),
    )?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok));
    assert!(counter_value(&t, "in_a")? >= 20);
    Ok(())
}

/// AS-47: startup with intact artifacts and an expired checkpoint (adoption,
/// cold start); with partial artifacts, live marks and a recent checkpoint
/// (repair, connections routed again once repaired); in external mode with
/// the administrator's ruleset already loaded (no degradation).
#[test]
#[ignore = "needs root and network namespaces"]
fn as47_startup_with_existing_artifacts() -> Result<()> {
    let t = build();
    let mut f = t.start_ftr(&ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    t.upstream_down(Uplink::A)?;
    wait_members(&t, &["wanb"], Duration::from_secs(10))?;
    let rules = ftr_rules(&t)?;
    let flow = t.start_flow(
        Node::Client,
        testbed::plan::server(Family::V4, 90),
        Duration::from_millis(50),
    )?;
    std::thread::sleep(Duration::from_millis(500));

    // (1) Intact artifacts, checkpoint older than 10 minutes: adopted, cold start.
    f.kill()?;
    let checkpoint = f.dir.join("state/health.json");
    let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&checkpoint)?)?;
    let ms = v["boottime_ms"].as_u64().unwrap_or(0);
    v["boottime_ms"] = serde_json::json!(ms.saturating_sub(11 * 60 * 1000));
    std::fs::write(&checkpoint, serde_json::to_string(&v)?)?;
    f.start(&t)?;
    f.wait_log(
        &t,
        "initial path state uplink=1 family=ipv4 state=Up warm=false",
        1,
        Duration::from_secs(10),
    )?;
    f.wait_installed(&t)?;
    assert_eq!(ftr_rules(&t)?, rules, "adopted without duplicates");
    wait_members(&t, &["wanb"], Duration::from_secs(5))?;

    // (2) Partial artifacts with live marks and a recent checkpoint.
    f.kill()?;
    t.router().ip("rule del pref 1202")?;
    t.router().ip("route del default table 1000")?;
    std::thread::sleep(Duration::from_secs(1));
    f.start(&t)?;
    f.wait_log(
        &t,
        "initial path state uplink=2 family=ipv4 state=Up warm=true",
        1,
        Duration::from_secs(10),
    )?;
    f.wait_installed(&t)?;
    t.wait_for("the layout repaired", Duration::from_secs(3), || {
        Ok(ftr_rules(&t)? == rules)
    })?;
    wait_members(&t, &["wanb"], Duration::from_secs(3))?;
    std::thread::sleep(Duration::from_secs(1));
    let report = flow.stop()?;
    assert_eq!(report.uplink(), Some(Uplink::B));
    assert!(
        report.error.is_none(),
        "the connection on the damaged path recovers once repaired: {report:?}"
    );
    f.stop()?;
    t.upstream_up(Uplink::A)?;

    // (3) External mode with the administrator's ruleset already loaded.
    let config = ftr::ipv4_config(&ab(), &HealthSpec::fast(), "", "[firewall]\nmode = \"external\"\n");
    let out = f.cli(&["cleanup", "--config", &f.config.display().to_string()])?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    f.write_config(&config)?;
    let out = f.cli(&["export-nft", "--config", &f.config.display().to_string()])?;
    t.router().nft(&String::from_utf8_lossy(&out.stdout))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    std::thread::sleep(Duration::from_secs(1));
    assert!(!f.log().contains("external_ruleset_missing"), "{}", f.log());
    Ok(())
}

/// AS-31: RELATED ICMP errors and path MTU discovery through the PPPoE
/// uplink (MTU 1492) and through a bottleneck inside provider A while the
/// server advertises a full-size MSS: large transfers succeed (INV-2).
#[test]
#[ignore = "needs root and network namespaces"]
fn as31_path_mtu_discovery_through_pppoe_and_a_provider_bottleneck() -> Result<()> {
    let t = build();
    let c_first = [
        UplinkSpec::new(Uplink::C, 3),
        UplinkSpec::new(Uplink::A, 1).priority(Some(2)),
        UplinkSpec::new(Uplink::B, 2).priority(Some(2)),
    ];
    let f = t.start_ftr(&ftr::ipv4_config(&c_first, &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t)?, ["ppp0"]);
    let r = t.bulk(
        Node::Client,
        testbed::plan::server(Family::V4, 95),
        300_000,
        Duration::from_secs(10),
    )?;
    assert!(r.error.is_none() && r.received == 300_000, "through PPPoE: {r:?}");
    assert_eq!(r.uplink(), Some(Uplink::C));

    // A 1300-byte link inside provider A; the server's route towards A's
    // customers advertises a full-size MSS, so the client's segments are too
    // big and provider A answers with "fragmentation needed".
    let a_first = [
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2).priority(Some(2)),
        UplinkSpec::new(Uplink::C, 3).priority(Some(2)),
    ];
    f.write_config(&ftr::ipv4_config(&a_first, &HealthSpec::fast(), "", ""))?;
    f.reload()?;
    wait_members(&t, &["wana"], Duration::from_secs(10))?;
    t.ns(Node::IspA).ip("link set core mtu 1300")?;
    t.inet().ip("link set isp-a mtu 1300")?;
    let route = t.inet().run("ip", ["-4", "route", "show", "192.0.2.0/24"])?;
    let route = route.lines().next().unwrap_or_default().trim().to_owned();
    t.inet().ip(&format!("route change {route} advmss 1460"))?;
    let r = t.bulk(
        Node::Client,
        testbed::plan::server(Family::V4, 96),
        300_000,
        Duration::from_secs(10),
    )?;
    assert!(
        r.error.is_none() && r.received == 300_000,
        "through the provider bottleneck: {r:?}"
    );
    assert_eq!(r.uplink(), Some(Uplink::A));
    Ok(())
}
