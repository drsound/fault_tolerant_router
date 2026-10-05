//! M1 acceptance scenarios (SPEC.md §14.3, §17), IPv4, with the daemon
//! under test (`POLYWAN_DAEMON_BIN`) in the router namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use testbed::plan::{Family, Node, TCP_PORT, Uplink};
use testbed::polywan::{self, HealthSpec, UplinkSpec};
use testbed::traffic::tally;
use testbed::{Options, Outcome, Topology};

#[macro_use]
mod common;
use common::*;

per_family!(as01_equal_weights_split_connections_evenly);

/// AS-01: two healthy uplinks with equal weights; each gets 45–55% of new
/// connections (§14.3).
fn as01_equal_weights_split_connections_evenly(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t, fam)?, ["wana", "wanb"]);
    t.reset_counters()?;
    split(&t, fam, 500, 50)?;
    assert_eq!(t.leaks(fam)?, 0, "INV-3");
    Ok(())
}

per_family!(as04_carrier_loss_withdraws_the_uplink_within_a_second);

/// AS-04: carrier lost on A; A leaves the active set within 1 s and new
/// connections use B (FR-HEALTH-5).
fn as04_carrier_loss_withdraws_the_uplink_within_a_second(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t, fam)?, ["wana", "wanb"]);
    let start = Instant::now();
    t.carrier_down(Uplink::A)?;
    t.wait_for("A out of the balancing route", Duration::from_secs(3), || {
        Ok(balancing_members(&t, fam)? == ["wanb"])
    })?;
    let took = start.elapsed();
    assert!(took <= Duration::from_secs(1), "withdrawn after {took:?}");
    let r = t.connect_many(Node::Client, fam, 20, 100, false)?;
    assert_eq!(tally(&r).get(&Some(Uplink::B)), Some(&100), "{:?}", tally(&r));
    t.carrier_up(Uplink::A)?;
    Ok(())
}

per_family!(as14_no_uplink_rejects_without_leaking);

/// AS-14: every uplink loses carrier; new connections are rejected and no
/// packet leaves through a route that PolyWAN did not install (INV-3), although
/// an operating-system default route through an unmanaged interface stays
/// usable; without PolyWAN's final guard, that route carries them (control).
fn as14_no_uplink_rejects_without_leaking(fam: Family) -> Result<()> {
    let t = build();
    let mut f = t.start_polywan(&polywan::family(&abc(), fam))?;
    f.wait_installed(&t)?;
    // An escape: a default route of main through an interface PolyWAN does not
    // manage, with the realm of operating-system routes (IPv4); for IPv6,
    // the harness's `leak6` route is one.
    let r = t.router();
    if fam == Family::V4 {
        r.ip("link add esc0 type dummy")?;
        r.ip("link set esc0 up")?;
        r.ip(&format!(
            "route add default dev esc0 metric 900 realm {}",
            testbed::plan::OS_ROUTE_REALM
        ))?;
    }
    for u in Uplink::ALL {
        t.carrier_down(u)?;
    }
    t.wait_for("an empty balancing route", Duration::from_secs(5), || {
        Ok(balancing_members(&t, fam)?.is_empty())
    })?;
    t.reset_counters()?;
    let c = t.connect_many(Node::Client, fam, 10, 30, false)?;
    assert!(c.iter().all(|c| c.outcome != Outcome::Ok), "{:?}", tally(&c));
    assert_eq!(t.leaks(fam)?, 0, "INV-3");
    for u in [Uplink::A, Uplink::B] {
        assert_eq!(t.egress_packets(u, fam)?, 0, "no packet leaves through {u}");
    }
    // Control: the escape is real once the final guard is gone.
    f.kill()?;
    r.ip(&format!("{} rule del pref 1699", fam.flag()))?;
    t.connect_many(Node::Client, fam, 10, 10, false)?;
    assert!(t.leaks(fam)? > 0, "without the final guard the escape route is used");
    Ok(())
}

/// AS-45(a): an IPv4-only configuration installs no IPv6 routing or
/// nftables artifact and changes no IPv6 setting.
#[test]
#[ignore = "needs root and network namespaces"]
fn as45a_ipv4_only_leaves_ipv6_alone() -> Result<()> {
    let t = build();
    let mut keys = IPV6_SETTINGS.to_vec();
    keys.push("net/ipv6/conf/wana/forwarding");
    let before = sysctl_values(&t, &keys)?;
    let f = t.start_polywan(&polywan::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    let left = ipv6_artifacts(&t)?;
    assert!(left.is_empty(), "IPv6 artifacts: {left:#?}");
    assert_eq!(before, sysctl_values(&t, &keys)?, "IPv6 settings of {keys:?}");
    Ok(())
}

// ---------------------------------------------------------------- scenarios

per_family!(as02_weights_three_to_one);

/// AS-02: weights 3:1; the first uplink gets 70–80% of new connections.
fn as02_weights_three_to_one(fam: Family) -> Result<()> {
    let t = build();
    let ups = [UplinkSpec::new(Uplink::A, 1).weight(3), UplinkSpec::new(Uplink::B, 2)];
    let f = t.start_polywan(&polywan::family(&ups, fam))?;
    f.wait_installed(&t)?;
    split(&t, fam, 750, 50)
}

per_family!(as03_connections_on_a_survive_failure_and_recovery_of_b);

/// AS-03: long-lived connections on A are never interrupted while B fails
/// and recovers (INV-2).
fn as03_connections_on_a_survive_failure_and_recovery_of_b(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    let flows = start_flows(&t, fam, 1, 20)?;
    std::thread::sleep(Duration::from_secs(1));
    t.carrier_down(Uplink::B)?;
    wait_members(&t, fam, &["wana"], Duration::from_secs(3))?;
    std::thread::sleep(Duration::from_secs(2));
    t.carrier_up(Uplink::B)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(15))?;
    std::thread::sleep(Duration::from_secs(1));
    flows_on_continuous(flows, &[Uplink::A])
}

per_family!(as05_silent_upstream_failure_within_the_detection_bound);

/// AS-05: provider A disconnected upstream with the link up; A leaves the
/// active set within (fall + 1) × interval + timeout × attempts = 17 s with
/// the default health settings (FR-HEALTH-5), reason `probe_failed`.
fn as05_silent_upstream_failure_within_the_detection_bound(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::config(&ab(), &[fam], &HealthSpec::defaults(), "", ""))?;
    f.wait_installed(&t)?;
    // Past the cold start: the first rounds have completed.
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(balancing_members(&t, fam)?, ["wana", "wanb"]);
    let start = Instant::now();
    t.upstream_down(Uplink::A)?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(25))?;
    let took = start.elapsed();
    assert!(took <= Duration::from_millis(17_500), "removed after {took:?}");
    assert!(
        f.log()
            .contains(&format!("uplink=1 family={fam} from=Up to=Down reason=probe_failed")),
        "{}",
        f.log()
    );
    t.upstream_up(Uplink::A)?;
    Ok(())
}

per_family!(as08_priority_groups_fail_over_and_back);

/// AS-08: priority groups; group 2 takes over when all of group 1 fails and
/// hands back after recovery.
fn as08_priority_groups_fail_over_and_back(fam: Family) -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3).priority(Some(2)),
    ];
    let f = t.start_polywan(&polywan::family(&ups, fam))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(5))?;
    t.upstream_down(Uplink::A)?;
    t.upstream_down(Uplink::B)?;
    wait_members(&t, fam, &["ppp0"], Duration::from_secs(10))?;
    let r = t.connect_many(Node::Client, fam, 10, 50, false)?;
    assert_eq!(tally(&r).get(&Some(Uplink::C)), Some(&50), "{:?}", tally(&r));
    t.upstream_up(Uplink::A)?;
    t.upstream_up(Uplink::B)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(15))?;
    Ok(())
}

per_family!(as13_all_probes_failing_keeps_the_best_group);

/// AS-13: every path fails its probes but stays ready; with
/// `all_down_policy = "ready"` group 1 stays active, and recovers.
fn as13_all_probes_failing_keeps_the_best_group(fam: Family) -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3).priority(Some(2)),
    ];
    let f = t.start_polywan(&polywan::config(
        &ups,
        &[fam],
        &HealthSpec::fast(),
        "all_down_policy = \"ready\"",
        "",
    ))?;
    f.wait_installed(&t)?;
    for u in Uplink::ALL {
        t.upstream_down(u)?;
    }
    f.wait_log(&t, "to=Down reason=probe_failed", 3, Duration::from_secs(15))?;
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        balancing_members(&t, fam)?,
        ["wana", "wanb"],
        "group 1 candidates regardless of health"
    );
    for u in Uplink::ALL {
        t.upstream_up(u)?;
    }
    f.wait_log(&t, "reason=probes_recovered", 3, Duration::from_secs(20))?;
    assert_eq!(balancing_members(&t, fam)?, ["wana", "wanb"]);
    Ok(())
}

per_family!(as20_invalid_reload_keeps_the_running_configuration);

/// AS-20: an invalid configuration on reload keeps the running one.
fn as20_invalid_reload_keeps_the_running_configuration(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&stack(fam, &ab()))?;
    f.wait_installed(&t)?;
    // For IPv6, an IPv6 section without its required `nat` (FR-NAT-1).
    let (invalid, reason) = match fam {
        Family::V4 => ("version = 2\n[[bogus]]\n".to_owned(), "bogus"),
        Family::V6 => (
            stack(
                fam,
                &[
                    UplinkSpec::new(Uplink::A, 1).ipv6_nat(None),
                    UplinkSpec::new(Uplink::B, 2),
                ],
            ),
            "must be set explicitly for IPv6",
        ),
    };
    f.write_config(&invalid)?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains(reason), "{}", f.log());
    for g in stack_families(fam) {
        wait_members(&t, *g, &["wana", "wanb"], Duration::from_secs(5))?;
    }
    let r = t.connect_many(Node::Client, fam, 10, 20, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    Ok(())
}

/// AS-20 and AS-23, `firewall.nft_path` (FR-CFG-5): an `nft` reached
/// through a symbolic link whose target directory is writable by others is
/// refused by online `check-config`, at startup and on reload, in both
/// firewall modes, and never runs; the rejected reload keeps the running
/// configuration.
#[test]
#[ignore = "needs root and network namespaces"]
fn as20_an_untrusted_nft_path_never_runs() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    let open = f.dir.join("open");
    std::fs::create_dir(&open)?;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))?;
    let ran = f.dir.join("ran");
    let nft = open.join("nft");
    std::fs::write(&nft, format!("#!/bin/sh\ntouch {}\nexec nft \"$@\"\n", ran.display()))?;
    std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755))?;
    let link = f.dir.join("nft");
    std::os::unix::fs::symlink(&nft, &link)?;
    let untrusted = |mode: &str| {
        let firewall = format!("[firewall]\nmode = \"{mode}\"\nnft_path = \"{}\"\n", link.display());
        polywan::config(&ab(), &[Family::V4], &HealthSpec::fast(), "", &firewall)
    };
    let refusal = format!("{} is writable by group or others", open.display());
    for mode in ["managed", "external"] {
        f.write_config(&untrusted(mode))?;
        let out = f.cli_config(&["check-config"])?;
        let text = polywan::output_text(&out);
        assert!(!out.status.success() && text.contains(&refusal), "{mode}: {text}");
        f.start(&t)?;
        f.wait_exit(&t, Duration::from_secs(5))?;
        assert!(f.log().contains(&refusal), "{mode}: {}", f.log());
    }
    f.write_config(&polywan::ipv4(&ab()))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    f.write_config(&untrusted("managed"))?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains(&refusal), "{}", f.log());
    let r = t.connect_many(Node::Client, Family::V4, 10, 20, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    assert!(!ran.exists(), "the untrusted nft never ran");
    f.stop()?;
    Ok(())
}

per_family!(as24_foreign_mark_bits_are_preserved);

/// AS-24: mark bits outside `fwmark_mask` written by another table are
/// preserved end to end (INV-7).
fn as24_foreign_mark_bits_are_preserved(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    t.router().nft(
        &format!(
            "table inet admin {{\n  chain pre {{\n    type filter hook prerouting priority -300; policy accept;\n    iifname \"lan\" meta mark set meta mark | {p:#010x}\n  }}\n  chain ctmark {{\n    type filter hook prerouting priority -190; policy accept;\n    iifname \"lan\" ct state new ct mark set ct mark | {c:#010x}\n  }}\n}}\n",
            p = polywan::foreign_bit(0),
            c = polywan::foreign_bit(8)
        ),
    )?;
    // Packets to the test servers: with the foreign bits and a path in
    // both marks; or invalid ones, which PolyWAN leaves alone (§4.7): foreign
    // bit kept, no path. Nothing else.
    let (nm, m) = (!polywan::mask(), polywan::mask());
    let (p, c) = (polywan::foreign_bit(0), polywan::foreign_bit(8));
    let (ipk, srv) = (ip(fam), servers_prefix(fam));
    t.router().nft(&format!(
        "table inet t_as24 {{\n  counter total {{}}\n  counter kept {{}}\n  counter skipped {{}}\n  counter other {{}}\n  chain post {{\n    type filter hook postrouting priority 300; policy accept;\n    oifname {{ \"wana\", \"wanb\" }} {ipk} daddr {srv} jump count\n  }}\n  chain count {{\n    counter name total\n    meta mark & {nm:#010x} == {p:#010x} meta mark & {m:#010x} != 0 ct mark & {c:#010x} == {c:#010x} ct mark & {m:#010x} != 0 counter name kept return\n    ct state invalid meta mark & {nm:#010x} == {p:#010x} meta mark & {m:#010x} == 0 counter name skipped return\n    counter name other\n  }}\n}}\n"
    ))?;
    let r = t.connect_many(Node::Client, fam, 20, 100, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    std::thread::sleep(Duration::from_millis(500));
    let value = |name: &str| t.router().counter("inet", "t_as24", name);
    let table = t.router().run("nft", ["list", "table", "inet", "t_as24"])?;
    let (kept, skipped, other) = (value("kept")?, value("skipped")?, value("other")?);
    assert!(kept >= 300, "{table}");
    assert_eq!(
        other, 0,
        "every packet keeps the foreign bits and carries its path:\n{table}"
    );
    assert!(skipped * 100 <= kept, "invalid packets are rare:\n{table}");
    Ok(())
}

per_family!(as26_more_specific_main_routes_take_precedence);

/// AS-26: more-specific routes in main are followed (main bypass, INV-1).
fn as26_more_specific_main_routes_take_precedence(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    let (gwa, gwb) = (gateway(&t, fam, Uplink::A)?, gateway(&t, fam, Uplink::B)?);
    // Servers 128-255, and the two halves of the address space.
    let (upper, halves) = match fam {
        Family::V4 => ("198.18.100.128/25", ["0.0.0.0/1", "128.0.0.0/1"]),
        Family::V6 => ("2001:db8:ff00::80/121", ["::/1", "8000::/1"]),
    };
    let flag = fam.flag();
    t.router().ip(&format!("{flag} route add {upper} via {gwb} dev wanb"))?;
    let r = t.connect_to(
        Node::Client,
        &servers(fam, 200, 50, TCP_PORT),
        100,
        false,
        Duration::from_secs(2),
    )?;
    assert_eq!(
        tally(&r).get(&Some(Uplink::B)),
        Some(&100),
        "static route via B: {:?}",
        tally(&r)
    );
    let r = t.connect_to(
        Node::Client,
        &servers(fam, 1, 50, TCP_PORT),
        200,
        false,
        Duration::from_secs(2),
    )?;
    let counts = tally(&r);
    assert!(
        counts.contains_key(&Some(Uplink::A)) && counts.contains_key(&Some(Uplink::B)),
        "others balanced: {counts:?}"
    );
    // A VPN-style pair of /1 routes overrides PolyWAN for everything (by design).
    for half in halves {
        t.router().ip(&format!("{flag} route add {half} via {gwa} dev wana"))?;
    }
    let r = t.connect_to(
        Node::Client,
        &servers(fam, 1, 50, TCP_PORT),
        100,
        false,
        Duration::from_secs(2),
    )?;
    assert_eq!(
        tally(&r).get(&Some(Uplink::A)),
        Some(&100),
        "/1 routes via A: {:?}",
        tally(&r)
    );
    Ok(())
}

per_family!(as29_probes_leave_through_their_path);

/// AS-29: probes of a path outside the active set, and of a target covered
/// by a main route through another uplink, leave through the path (INV-6).
fn as29_probes_leave_through_their_path(fam: Family) -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1).priority(None),
        UplinkSpec::new(Uplink::B, 2),
    ];
    let f = t.start_polywan(&polywan::family(&ups, fam))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t, fam)?, ["wanb"]);
    let (gwb, a) = (gateway(&t, fam, Uplink::B)?, address(&t, fam, Uplink::A)?);
    let target = testbed::plan::probe_targets(fam)[0];
    let (flag, ipk, icmpk, ty) = (fam.flag(), ip(fam), icmp(fam), addr_type(fam));
    t.router()
        .ip(&format!("{flag} route add {target} via {gwb} dev wanb"))?;
    // Real interfaces only: traffic of the router to itself goes through `lo`.
    counter(
        &t,
        "wrong",
        &format!("oifname {{ \"wanb\", \"ppp0\", \"lan\" }} {ipk} saddr {a}"),
    )?;
    counter(
        &t,
        "probes",
        &format!("oifname \"wana\" {ipk} daddr {target} {icmpk} type echo-request"),
    )?;
    t.router().nft(&format!(
        "table inet t_diag {{\n  set seen {{ type ifname . {ty}; flags dynamic; }}\n  chain post {{\n    type filter hook postrouting priority 300; policy accept;\n    oifname != \"wana\" {ipk} saddr {a} add @seen {{ oifname . {ipk} daddr }}\n  }}\n}}\n"
    ))?;
    std::thread::sleep(Duration::from_secs(4));
    let seen = t.router().run("nft", ["list", "set", "inet", "t_diag", "seen"])?;
    assert!(counter_value(&t, "probes")? >= 3, "probes to {target} leave through A");
    assert_eq!(
        counter_value(&t, "wrong")?,
        0,
        "nothing with A's address leaves elsewhere: {seen}"
    );
    assert!(
        !f.log().contains(&format!("uplink=1 family={fam} from=Up to=Down")),
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
    let only_a = polywan::config(
        &[UplinkSpec::new(Uplink::A, 1)],
        &[Family::V4],
        &HealthSpec::fast(),
        "reconcile_interval = \"10s\"",
        "",
    );
    let refused = |setup: &str, undo: &str, needle: &str| -> Result<()> {
        t.router().run("sh", ["-c", setup])?;
        let before = foreign_objects(&t)?;
        assert_refused(&t, &polywan::ipv4(&ab()), needle)?;
        assert_eq!(foreign_objects(&t)?, before, "foreign objects unchanged");
        t.router().run("sh", ["-c", undo])?;
        Ok(())
    };
    refused(
        "ip rule add pref 1650 lookup 5",
        "ip rule del pref 1650",
        "collides with PolyWAN",
    )?;
    let ft = |devs: &str| flowtable("ft", devs);
    refused(&ft("wana"), "nft delete table inet ft", "matches the uplink wana")?;
    refused(&ft("lan"), "nft delete table inet ft", "matches the downlink lan")?;

    // Runtime detection and recovery.
    let mut f = t.start_polywan(&only_a)?;
    f.wait_installed(&t)?;
    t.router().run("sh", ["-c", &ft("wana")])?;
    f.wait_log(&t, "status_degraded", 1, Duration::from_secs(15))?;
    assert!(f.log().contains("flowtable inet ft f"), "{}", f.log());
    t.router().run("sh", ["-c", "nft delete table inet ft"])?;
    f.wait_log(&t, "status_recovered", 1, Duration::from_secs(15))?;
    // A flowtable on wanb matches only the proposed configuration.
    t.router().run("sh", ["-c", &ft("wanb")])?;
    f.write_config(&polywan::config(
        &ab(),
        &[Family::V4],
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
    assert_eq!(balancing_members(&t, Family::V4)?, ["wana"]);
    f.stop()?;
    Ok(())
}

/// A shell command creating table `inet <table>` with flowtable `f` on `devs`.
fn flowtable(table: &str, devs: &str) -> String {
    format!(
        r"nft add table inet {table} && nft add flowtable inet {table} f {{ hook ingress priority 0 \; devices = {{ {devs} }} \; }}"
    )
}

/// The router's rules and its nftables ruleset without PolyWAN's table and the
/// harness's counters, for checks that foreign objects stay unchanged.
fn foreign_objects(t: &Topology) -> Result<String> {
    let rules = t.router().run("ip", ["-4", "rule", "show"])?;
    let rules: Vec<&str> = rules.lines().filter(|l| !l.contains("proto 249")).collect();
    let nft = t.router().run("nft", ["list", "ruleset"])?;
    let mut tables = String::new();
    let mut keep = false;
    for l in nft.lines() {
        if l.starts_with("table ") {
            keep = !l.contains("polywan") && !l.contains(" tb_");
        }
        if keep {
            tables.push_str(l);
            tables.push('\n');
        }
    }
    Ok(format!("{}\n{tables}", rules.join("\n")))
}

/// AS-33, systemd-networkd (FR-COEX-1): a networkd in the router's namespace
/// with foreign-rule or foreign-route management enabled (both default to
/// yes) makes online `check-config` fail and startup be refused, naming each
/// setting; a networkd in another namespace is not considered; a drop-in
/// disabling both lets PolyWAN start. The networkd process is a stand-in with its
/// name, and the configuration is the router namespace's `/etc/systemd`
/// (`ip netns exec` mounts it): the check is by process and configuration.
#[test]
#[ignore = "needs root and network namespaces"]
fn as33_networkd_foreign_management() -> Result<()> {
    let t = build();
    // A script's process name is its file name. (A copy of `sleep` is not
    // enough: uutils' multicall binary picks the utility by its own name.)
    let fake = t.dir().join("systemd-networkd");
    std::fs::write(&fake, "#!/bin/sh\nwhile :; do sleep 1; done\n")?;
    std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    let fake = fake.display().to_string();
    let dropins = t.netns_etc(Node::Router).join("systemd/networkd.conf.d");
    std::fs::create_dir_all(&dropins)?;
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    let check = |f: &polywan::Polywan| -> Result<(bool, String)> {
        let out = f.cli_config(&["check-config"])?;
        let text = polywan::output_text(&out);
        Ok((out.status.success(), text))
    };
    let enabled = |key: &str| format!("systemd-networkd is active with {key} enabled");

    // A networkd in another namespace manages other interfaces.
    // `ip netns exec` runs first under its own name: wait for the stand-in.
    let started = |ns: &testbed::netns::Ns| {
        t.wait_for("the networkd stand-in", Duration::from_secs(5), || {
            Ok(ns.pids()?.into_iter().any(|p| {
                std::fs::read_to_string(format!("/proc/{p}/comm")).is_ok_and(|c| c.trim() == "systemd-network")
            }))
        })
    };
    let mut other = t.client().spawn(&fake, [""; 0], &t.dir().join("networkd-client.log"))?;
    started(&t.client())?;
    let (ok, text) = check(&f)?;
    assert!(ok, "{text}");
    f.start(&t)?;
    f.wait_installed(&t)?;
    f.stop()?;
    other.kill()?;
    other.wait()?;

    let mut networkd = t.router().spawn(&fake, [""; 0], &t.dir().join("networkd-router.log"))?;
    started(&t.router())?;
    // Defaults: both enabled.
    let (ok, text) = check(&f)?;
    assert!(!ok, "{text}");
    for key in ["ManageForeignRoutingPolicyRules", "ManageForeignRoutes"] {
        assert!(text.contains(&enabled(key)), "{key}: {text}");
    }
    f.start(&t)?;
    f.wait_exit(&t, Duration::from_secs(10))?;
    for key in ["ManageForeignRoutingPolicyRules", "ManageForeignRoutes"] {
        assert!(f.log().contains(&enabled(key)), "{key}: {}", f.log());
    }
    // Rules disabled, routes still enabled.
    std::fs::write(
        dropins.join("50-polywan.conf"),
        "[Network]\nManageForeignRoutingPolicyRules=no\n",
    )?;
    f.start(&t)?;
    f.wait_exit(&t, Duration::from_secs(10))?;
    assert!(f.log().contains(&enabled("ManageForeignRoutes")), "{}", f.log());
    assert!(
        !f.log().contains(&enabled("ManageForeignRoutingPolicyRules")),
        "{}",
        f.log()
    );
    // Both disabled.
    std::fs::write(
        dropins.join("50-polywan.conf"),
        "[Network]\nManageForeignRoutingPolicyRules=no\nManageForeignRoutes=no\n",
    )?;
    let (ok, text) = check(&f)?;
    assert!(ok, "{text}");
    f.start(&t)?;
    f.wait_installed(&t)?;
    f.stop()?;
    networkd.kill()?;
    networkd.wait()?;
    Ok(())
}

/// AS-33, during active operation and in external firewall mode (FR-CT-2):
/// an unrelated flowtable alone refuses nothing; a matching flowtable with
/// several devices degrades the status, and a failed inspection keeps
/// `flow_offload` after the flowtable is gone, until an inspection succeeds;
/// in external mode a matching flowtable refuses startup and `check-config`,
/// and while `external_ruleset_missing` remains, clearing `flow_offload`
/// emits no `status_recovered`.
#[test]
#[ignore = "needs root and network namespaces"]
fn as33_flowtable_inspection_and_external_mode() -> Result<()> {
    let t = build();
    let r = t.router();
    r.ip("link add ftx type dummy")?;
    r.ip("link set ftx up")?;
    r.sh(&flowtable("unrelated", "ftx"))?;
    let only_a = |extra: &str| {
        polywan::config(
            &[UplinkSpec::new(Uplink::A, 1)],
            &[Family::V4],
            &HealthSpec::fast(),
            "reconcile_interval = \"10s\"",
            extra,
        )
    };
    let mut f = t.prepare_polywan(&only_a(""))?;
    let (wrapper, flag) = nft_wrapper(&t, &f, &["list ruleset", "list flowtables"], NFT_FAILS)?;
    let managed = only_a(&format!("[firewall]\nnft_path = \"{}\"\n", wrapper.display()));
    f.write_config(&managed)?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    std::thread::sleep(Duration::from_secs(1));
    assert!(!f.log().contains("status_degraded"), "{}", f.log());

    // A matching flowtable with several devices, then a failed inspection.
    r.sh(&flowtable("ftm", "ftx, wana"))?;
    f.wait_log(&t, "status_degraded", 1, Duration::from_secs(15))?;
    assert!(f.log().contains("flowtable inet ftm f"), "{}", f.log());
    std::fs::write(&flag, "")?;
    r.sh("nft delete table inet ftm")?;
    f.wait_log(&t, "flowtable inspection failed", 2, Duration::from_secs(25))?;
    assert!(
        !f.log().contains("status_recovered"),
        "a failed inspection keeps flow_offload"
    );
    std::fs::remove_file(&flag)?;
    f.wait_log(&t, "status_recovered", 1, Duration::from_secs(15))?;
    f.stop()?;
    r.run("nft", ["list", "table", "inet", "unrelated"])?;
    let out = f.cli_config(&["cleanup"])?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    // External mode: a matching flowtable refuses startup and check-config.
    let external = only_a("[firewall]\nmode = \"external\"\n");
    f.write_config(&external)?;
    r.sh(&flowtable("ftm", "lan"))?;
    let out = f.cli_config(&["check-config"])?;
    let text = polywan::output_text(&out);
    assert!(
        !out.status.success() && text.contains("matches the downlink lan"),
        "{text}"
    );
    f.start(&t)?;
    f.wait_exit(&t, Duration::from_secs(10))?;
    assert!(f.log().contains("matches the downlink lan"), "{}", f.log());
    r.sh("nft delete table inet ftm")?;

    // External mode without the administrator's ruleset, then a flowtable:
    // two reasons. A reload inspects at once (and is refused while the
    // flowtable matches).
    f.start(&t)?;
    f.wait_log(&t, "status_degraded", 1, Duration::from_secs(15))?;
    assert!(f.log().contains("external_ruleset_missing"), "{}", f.log());
    r.sh(&flowtable("ftm", "wana"))?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains("flowtable inet ftm f"), "{}", f.log());
    r.sh("nft delete table inet ftm")?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !f.log().contains("status_recovered"),
        "external_ruleset_missing remains: {}",
        f.log()
    );
    let out = f.cli_config(&["export-nft"])?;
    r.nft(&String::from_utf8_lossy(&out.stdout))?;
    f.wait_log(&t, "status_recovered", 1, Duration::from_secs(15))?;
    assert_eq!(f.log().matches("status_degraded").count(), 1, "{}", f.log());
    f.stop()?;
    Ok(())
}

per_family!(as40_foreign_earlier_rule_and_missing_local_rule);

/// AS-40: a foreign rule below `rule_priority_base` is listed in a warning;
/// a missing local rule refuses startup (FR-ROUTE-6).
fn as40_foreign_earlier_rule_and_missing_local_rule(fam: Family) -> Result<()> {
    let t = build();
    let flag = fam.flag();
    t.router().ip(&format!("{flag} rule add pref 500 lookup 5"))?;
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    assert!(
        f.log().contains("the rule at priority 500 precedes PolyWAN's rules"),
        "{}",
        f.log()
    );
    drop(f);
    t.router().ip(&format!("{flag} rule del pref 500"))?;
    t.router().ip(&format!("{flag} rule del pref 0"))?;
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_exit(&t, Duration::from_secs(10))?;
    assert!(
        f.log().contains("local-table rule at priority 0 is missing"),
        "{}",
        f.log()
    );
    t.router().ip(&format!("{flag} rule add pref 0 lookup local"))?;
    Ok(())
}

per_family!(as09_inbound_replies_leave_through_the_arrival_uplink);

/// AS-09: inbound connections through port forwarding on each uplink,
/// including one outside the active set, are answered through the uplink
/// they arrived on (INV-5).
fn as09_inbound_replies_leave_through_the_arrival_uplink(fam: Family) -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3).priority(Some(2)),
    ];
    let f = t.start_polywan(&polywan::family(&ups, fam))?;
    f.wait_installed(&t)?;
    inbound_via_each_uplink(&t, fam, &[Uplink::A, Uplink::B, Uplink::C])?;
    Ok(())
}

/// Port forwarding on every uplink of `uplinks` (provider B forwards its
/// public port to the router, CGNAT): inbound connections from the internet
/// succeed and their replies leave through the uplink they arrived on, never
/// another (INV-5).
fn inbound_via_each_uplink(t: &Topology, fam: Family, uplinks: &[Uplink]) -> Result<()> {
    let _server = serve_in(t, Node::Client)?;
    t.router().nft(&format!(
        "table {} admin {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname {{ \"wana\", \"wanb\", \"ppp0\" }} tcp dport 8007 dnat to {}\n  }}\n}}\n",
        ip(fam),
        endpoint(&lan_client(fam).to_string(), testbed::plan::TCP_PORT)
    ))?;
    // Provider B (CGNAT) forwards its public IPv4 port 8007 to the router;
    // its IPv6 addresses are public.
    if fam == Family::V4 {
        let b = address(t, Family::V4, Uplink::B)?;
        t.ns(Node::IspB).nft(&format!(
            "table ip tb_in {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"core\" tcp dport 8007 dnat to {b}\n  }}\n}}\n"
        ))?;
    }
    for &u in uplinks {
        let iface = u.l3_iface();
        let public = if u == Uplink::B && fam == Family::V4 {
            "198.18.0.6".to_owned()
        } else {
            address(t, fam, u)?
        };
        counter(t, &format!("in{iface}"), &format!("oifname \"{iface}\" tcp sport 8007"))?;
        counter(
            t,
            &format!("out{iface}"),
            &format!("oifname != \"{iface}\" oifname != \"lan\" tcp sport 8007"),
        )?;
        let r = t.connect_to(
            Node::Inet,
            &[endpoint(&public, 8007)],
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
            counter_value(t, &format!("in{iface}"))? >= 20,
            "{u}: replies leave through {iface}"
        );
        assert_eq!(
            counter_value(t, &format!("out{iface}"))?,
            0,
            "{u}: no reply through another uplink"
        );
    }
    Ok(())
}

per_family!(as17_third_party_deletions_are_repaired);

/// AS-17: rules and routes deleted by a third party come back within 1 s,
/// the nftables table at the next full reconciliation; repeated deletions
/// lead to `ownership_conflict` and later recovery (FR-COEX-3, FR-COEX-4).
fn as17_third_party_deletions_are_repaired(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::config(
        &ab(),
        stack_families(fam),
        &HealthSpec::fast(),
        "reconcile_interval = \"10s\"",
        "",
    ))?;
    f.wait_installed(&t)?;
    let rules = polywan_rules(&t, fam)?;
    // In the dual-stack variant, IPv4's rules are left alone.
    let rules4 = polywan_rules(&t, Family::V4)?;
    let r = t.router();
    let flag = fam.flag();
    let start = Instant::now();
    r.ip(&format!("{flag} rule del pref 1600"))?;
    t.wait_for("the balancing rule back", Duration::from_secs(2), || {
        Ok(polywan_rules(&t, fam)? == rules)
    })?;
    assert!(
        start.elapsed() <= Duration::from_secs(1),
        "rule repaired after {:?}",
        start.elapsed()
    );
    let path = path_route(&t, fam, 1001)?;
    let start = Instant::now();
    r.ip(&format!("{flag} route del default table 1001"))?;
    t.wait_for("the path route back", Duration::from_secs(2), || {
        Ok(path_route(&t, fam, 1001)? == path)
    })?;
    assert!(
        start.elapsed() <= Duration::from_secs(1),
        "route repaired after {:?}",
        start.elapsed()
    );
    let table = || -> Result<String> {
        let out = r.output("nft", ["list", "table", "inet", "polywan"])?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let installed = table()?;
    assert!(installed.contains("chain"), "{installed}");
    r.run("nft", ["delete", "table", "inet", "polywan"])?;
    t.wait_for("the same nftables table back", Duration::from_secs(13), || {
        Ok(table()? == installed)
    })?;
    // Repeated deletions: after the fourth rule removal in five minutes (the
    // balancing rule above counts) immediate repairs stop until a full
    // reconciliation.
    for n in 1..=3 {
        r.ip(&format!("{flag} rule del pref 1699"))?;
        if n < 3 {
            t.wait_for("the final guard back", Duration::from_secs(2), || {
                Ok(polywan_rules(&t, fam)? == rules)
            })?;
        }
    }
    f.wait_log(&t, "ownership_conflict", 1, Duration::from_secs(3))?;
    std::thread::sleep(Duration::from_millis(1500));
    assert_ne!(
        polywan_rules(&t, fam)?,
        rules,
        "no immediate repair during the conflict"
    );
    t.wait_for(
        "the final guard back at a full reconciliation",
        Duration::from_secs(12),
        || Ok(polywan_rules(&t, fam)? == rules),
    )?;
    f.wait_log(&t, "ownership conflict cleared", 1, Duration::from_secs(25))?;
    f.wait_log(&t, "status_recovered", 1, Duration::from_secs(2))?;
    // The invariants hold again: new connections are balanced without
    // leaks, a pinned connection runs uninterrupted, inbound replies leave
    // through their arrival uplink.
    t.reset_counters()?;
    let c = t.connect_many(Node::Client, fam, 20, 100, false)?;
    assert!(c.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&c));
    let flows = start_flows(&t, fam, 30, 20)?;
    std::thread::sleep(Duration::from_secs(2));
    flows_on_continuous(flows, &[Uplink::A])?;
    assert_eq!(t.leaks(fam)?, 0, "INV-3");
    inbound_via_each_uplink(&t, fam, &[Uplink::A, Uplink::B])?;
    assert_eq!(polywan_rules(&t, Family::V4)?, rules4);
    Ok(())
}

per_family!(as18_crash_and_restart_keep_state_and_connections);

/// AS-18: `kill -9` while a long-lived connection runs on healthy B and A
/// is probe-unhealthy: the connection continues, A stays out of the active
/// set after the restart, no duplicate artifacts.
fn as18_crash_and_restart_keep_state_and_connections(fam: Family) -> Result<()> {
    let t = build();
    let mut f = t.start_polywan(&stack(fam, &ab()))?;
    f.wait_installed(&t)?;
    t.upstream_down(Uplink::A)?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(10))?;
    let flow = t.start_flow(Node::Client, testbed::plan::server(fam, 9), Duration::from_millis(50))?;
    std::thread::sleep(Duration::from_millis(500));
    let all_rules = || -> Result<Vec<String>> {
        let mut v = Vec::new();
        for g in stack_families(fam) {
            v.extend(polywan_rules(&t, *g)?);
        }
        Ok(v)
    };
    let rules = all_rules()?;
    f.kill()?;
    f.start(&t)?;
    f.wait_log(&t, "warm=true", 2 * stack_families(fam).len(), Duration::from_secs(10))?;
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        assert_eq!(
            balancing_members(&t, fam)?,
            ["wanb"],
            "A never re-enters the active set"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(all_rules()?, rules, "no duplicate or missing rule");
    let report = flow.stop()?;
    assert_eq!(report.uplink(), Some(Uplink::B));
    assert!(report.continuous(Duration::from_millis(1000)), "{report:?}");
    t.upstream_up(Uplink::A)?;
    Ok(())
}

/// AS-20 and AS-18, the state directory: a reload that moves it is
/// rejected and changes nothing; moved while the daemon is stopped with its
/// artifacts kept, it carries the bindings, a valid checkpoint and the
/// sysctl baselines to the restart: warm start, A still out, the
/// connection on B uninterrupted, the same rules, and `cleanup` restores
/// the settings (FR-CFG-4, IMPL-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as20_state_dir_moves_only_while_stopped() -> Result<()> {
    let t = build();
    let svm = || t.router().sysctl_get("net.ipv4.conf.wana.src_valid_mark");
    let before = svm()?;
    let mut f = t.start_polywan(&polywan::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    assert_eq!(svm()?, "1");
    t.upstream_down(Uplink::A)?;
    wait_members(&t, Family::V4, &["wanb"], Duration::from_secs(10))?;
    let flow = t.start_flow(
        Node::Client,
        testbed::plan::server(Family::V4, 9),
        Duration::from_millis(50),
    )?;
    std::thread::sleep(Duration::from_millis(500));
    let rules = polywan_rules(&t, Family::V4)?;
    let old = f.state.clone();
    let new = f.dir.join("moved-state");
    f.state = new.clone();
    f.write_config(&polywan::ipv4(&ab()))?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains("state_dir cannot change on reload"), "{}", f.log());
    assert!(!new.exists(), "the rejected directory is not created");
    f.stop()?;
    std::fs::rename(&old, &new)?;
    f.start(&t)?;
    f.wait_log(&t, "warm=true", 2, Duration::from_secs(10))?;
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        assert_eq!(
            balancing_members(&t, Family::V4)?,
            ["wanb"],
            "A never re-enters the active set"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(polywan_rules(&t, Family::V4)?, rules, "no duplicate or missing rule");
    assert!(!old.exists(), "nothing is written to the old directory");
    let report = flow.stop()?;
    assert_eq!(report.uplink(), Some(Uplink::B));
    assert!(report.continuous(Duration::from_millis(1000)), "{report:?}");
    f.stop()?;
    let out = f.cli_config(&["cleanup"])?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(svm()?, before, "the baselines moved with the directory");
    t.upstream_up(Uplink::A)?;
    Ok(())
}

per_family!(as19_reload_adds_removes_reorders_and_protects_ids);

/// AS-19: a reload adding, removing and reordering uplinks leaves the
/// connections of unchanged uplinks alone; reusing the id of a removed
/// uplink is refused until `forget-uplink`.
fn as19_reload_adds_removes_reorders_and_protects_ids(fam: Family) -> Result<()> {
    let t = build();
    let mut f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    let flows = start_flows(&t, fam, 20, 20)?;
    std::thread::sleep(Duration::from_millis(500));
    // C added first in the file, A removed, B unchanged.
    f.write_config(&polywan::family(
        &[UplinkSpec::new(Uplink::C, 3), UplinkSpec::new(Uplink::B, 2)],
        fam,
    ))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    // A path added by reload starts down and needs `rise` passed rounds.
    wait_members(&t, fam, &["ppp0", "wanb"], Duration::from_secs(20))?;
    std::thread::sleep(Duration::from_secs(1));
    flows_on_continuous(flows, &[Uplink::B])?;
    // Id 1 belonged to A: reusing it for another name is refused.
    let reuse = [UplinkSpec::new(Uplink::A, 1), UplinkSpec::new(Uplink::B, 2)];
    let text = polywan::family(&reuse, fam).replace("name = \"a\"", "name = \"fiber\"");
    f.write_config(&text)?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains("forget-uplink a"), "{}", f.log());
    f.stop()?;
    let out = f.cli_config(&["forget-uplink", "a"])?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    Ok(())
}

per_family!(as32_conntrack_flush);

/// AS-32: a conntrack flush during a long-lived connection leaves the
/// daemon unaffected (FR-CT-3).
fn as32_conntrack_flush(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    let rules = polywan_rules(&t, fam)?;
    let flow = t.start_flow(Node::Client, testbed::plan::server(fam, 30), Duration::from_millis(50))?;
    std::thread::sleep(Duration::from_millis(500));
    t.router().run("conntrack", ["-F"])?;
    std::thread::sleep(Duration::from_secs(2));
    let _ = flow.stop()?;
    assert_eq!(polywan_rules(&t, fam)?, rules);
    assert_eq!(balancing_members(&t, fam)?, ["wana", "wanb"]);
    let r = t.connect_many(Node::Client, fam, 10, 50, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    Ok(())
}

per_family!(as41_downlink_prefix_and_off_subnet_gateway);

/// AS-41: a downlink prefix missing from main is warned about; a static
/// off-subnet gateway makes the path ready only with `gateway_onlink`.
fn as41_downlink_prefix_and_off_subnet_gateway(fam: Family) -> Result<()> {
    let t = build();
    let (lan, restore, gw) = match fam {
        Family::V4 => (
            "198.51.100.0/24",
            "route add 198.51.100.0/24 dev lan proto kernel scope link src 198.51.100.1",
            "10.99.0.1",
        ),
        Family::V6 => (
            "2001:db8:1::/64",
            "-6 route add 2001:db8:1::/64 dev lan proto kernel metric 256",
            "2001:db8:99::1",
        ),
    };
    t.router().ip(&format!("{} route del {lan} dev lan", fam.flag()))?;
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    assert!(
        f.log().contains(&format!("the prefix {lan} is not in the main table")),
        "{}",
        f.log()
    );
    drop(f);
    t.router().ip(restore)?;
    // Provider A answers on an address outside the customer subnet.
    let host = if fam == Family::V4 { "32" } else { "128 nodad" };
    t.ns(Node::IspA).ip(&format!("addr add {gw}/{host} dev wan"))?;
    let off = |onlink: bool| {
        let extra = if onlink { "gateway_onlink = true\n" } else { "" };
        let a = UplinkSpec::new(Uplink::A, 1).path(fam, &format!("gateway = \"{gw}\"\n{extra}"));
        polywan::family(&[a, UplinkSpec::new(Uplink::B, 2)], fam)
    };
    let f = t.start_polywan(&off(false))?;
    f.wait_installed(&t)?;
    assert_eq!(
        balancing_members(&t, fam)?,
        ["wanb"],
        "A not ready without gateway_onlink"
    );
    drop(f);
    let f = t.start_polywan(&off(true))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(5))?;
    let route = path_route(&t, fam, 1001)?;
    assert!(
        route.contains(&format!("via {gw}")) && route.contains("onlink"),
        "{route}"
    );
    Ok(())
}

per_family!(as42_router_reply_from_a_secondary_address);

/// AS-42: a router service answers from a secondary address of A through A
/// while the active set is empty (INV-5).
fn as42_router_reply_from_a_secondary_address(fam: Family) -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::A, 1).priority(None),
        UplinkSpec::new(Uplink::B, 2).priority(None),
    ];
    let (secondary, len) = match fam {
        Family::V4 => ("192.0.2.250", 24),
        Family::V6 => ("2001:db8:a:ffff::250", 64),
    };
    let nodad = if fam == Family::V6 { " nodad" } else { "" };
    t.router().ip(&format!("addr add {secondary}/{len} dev wana{nodad}"))?;
    let f = t.start_polywan(&polywan::family(&ups, fam))?;
    f.wait_installed(&t)?;
    assert!(balancing_members(&t, fam)?.is_empty(), "empty active set");
    let _server = serve_in(&t, Node::Router)?;
    let ipk = ip(fam);
    counter(
        &t,
        "a",
        &format!("oifname \"wana\" {ipk} saddr {secondary} tcp sport 7000"),
    )?;
    counter(&t, "other", &format!("oifname != \"wana\" {ipk} saddr {secondary}"))?;
    let r = t.connect_to(
        Node::Inet,
        &[endpoint(secondary, 7000)],
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

/// AS-10: the DHCP lease of A changes address and gateway; PolyWAN's artifacts
/// follow within 1 s; connections on B are unaffected.
#[test]
#[ignore = "needs root and network namespaces"]
fn as10_lease_change_updates_artifacts_within_a_second() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let flows = start_flows(&t, Family::V4, 40, 20)?;
    std::thread::sleep(Duration::from_millis(500));
    let old = address(&t, Family::V4, Uplink::A)?;
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
            let p = path_route(&t, Family::V4, 1001)?;
            Ok(p.contains("via 192.0.2.254") && p.contains("src 192.0.2.77"))
        },
    )?;
    let took = start.elapsed();
    assert!(took <= Duration::from_secs(1), "updated after {took:?}");
    let rules = polywan_rules(&t, Family::V4)?.join("\n");
    assert!(
        rules.contains("from 192.0.2.77") && !rules.contains(&format!("from {old} ")),
        "{rules}"
    );
    assert!(f.log().contains("path discovery changed uplink=1"), "{}", f.log());
    std::thread::sleep(Duration::from_secs(1));
    flows_on_continuous(flows, &[Uplink::B])?;
    Ok(())
}

/// AS-10, IPv6: A is renumbered (a new address, the old one removed) and a
/// better router appears on its link; PolyWAN's artifacts follow within 1 s,
/// connections on B are unaffected. Like the IPv4 variant's DHCP client,
/// the harness does what SLAAC and a second router's advertisements would,
/// with SLAAC off on A so that the old address does not come back.
#[test]
#[ignore = "needs root and network namespaces"]
fn as10_lease_change_updates_artifacts_within_a_second_ipv6() -> Result<()> {
    let t = build();
    let r = t.router();
    r.sysctl(&["net.ipv6.conf.wana.autoconf=0"])?;
    let f = t.start_polywan(&polywan::family(&ab(), Family::V6))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(10))?;
    let flows = start_flows(&t, Family::V6, 40, 20)?;
    std::thread::sleep(Duration::from_millis(500));
    let old = address(&t, Family::V6, Uplink::A)?;
    t.ns(Node::IspA).ip("addr add fe80::99/64 dev wan nodad")?;
    let start = Instant::now();
    r.ip("addr add 2001:db8:a:ffff::77/64 dev wana nodad")?;
    r.ip(&format!("addr del {old}/64 dev wana"))?;
    r.ip("-6 route add default via fe80::99 dev wana metric 512 proto ra")?;
    t.wait_for(
        "A's path route with the new gateway and source",
        Duration::from_secs(3),
        || {
            let p = path_route(&t, Family::V6, 1001)?;
            Ok(p.contains("via fe80::99") && p.contains("src 2001:db8:a:ffff::77"))
        },
    )?;
    let took = start.elapsed();
    assert!(took <= Duration::from_secs(1), "updated after {took:?}");
    let rules = polywan_rules(&t, Family::V6)?.join("\n");
    assert!(
        rules.contains("from 2001:db8:a:ffff::77") && !rules.contains(&format!("from {old} ")),
        "{rules}"
    );
    assert!(f.log().contains("path discovery changed uplink=1"), "{}", f.log());
    std::thread::sleep(Duration::from_secs(1));
    flows_on_continuous(flows, &[Uplink::B])?;
    Ok(())
}

/// AS-11: the PPP uplink reconnects with a new interface index and a new
/// address; as in AS-10, artifacts follow within 1 s of the new address and
/// connections on B are unaffected; per-interface settings are applied
/// again.
#[test]
#[ignore = "needs root and network namespaces"]
fn as11_ppp_reconnection_with_a_new_ifindex() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::ipv4(&abc()))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["ppp0", "wana", "wanb"], Duration::from_secs(10))?;
    let before = t.ifindex("ppp0").expect("ppp0");
    let old = address(&t, Family::V4, Uplink::C)?;
    assert!(path_route(&t, Family::V4, 1003)?.contains("dev ppp0"));
    // Over three uplinks: 24 flows leave B without one once in 17,000 runs
    // (12 did once in 130).
    let flows = start_flows(&t, Family::V4, 50, 24)?;
    std::thread::sleep(Duration::from_millis(500));
    t.pppoe_renumber("203.0.113.20")?;
    t.wait_for(
        "ppp0 back with a new index and address",
        Duration::from_secs(30),
        || Ok(t.ifindex("ppp0").is_some_and(|i| i != before) && !address(&t, Family::V4, Uplink::C)?.is_empty()),
    )?;
    let start = Instant::now();
    let addr = address(&t, Family::V4, Uplink::C)?;
    assert_ne!(addr, old, "a new address");
    t.wait_for("C's path route on the new ppp0", Duration::from_secs(3), || {
        let route = path_route(&t, Family::V4, 1003)?;
        Ok(route.contains("dev ppp0") && route.contains(&format!("src {addr}")))
    })?;
    let took = start.elapsed();
    assert!(took <= Duration::from_secs(1), "updated after {took:?}");
    t.wait_for("the source rules of the new address", Duration::from_secs(1), || {
        let rules = polywan_rules(&t, Family::V4)?.join("\n");
        Ok(rules.contains(&format!("from {addr} ")) && !rules.contains(&format!("from {old} ")))
    })?;
    let svm = t.router().sysctl_get("net.ipv4.conf.ppp0.src_valid_mark")?;
    assert_eq!(svm, "1", "per-interface settings re-applied");
    std::thread::sleep(Duration::from_secs(1));
    flows_on_continuous(flows, &[Uplink::B])?;
    Ok(())
}

per_family!(as22_unanswered_and_one_way_flows_stay_on_their_uplink);

/// AS-22: retransmitted SYNs without answer and one-way UDP flows while the
/// active set changes: every packet of each flow leaves through one uplink.
fn as22_unanswered_and_one_way_flows_stay_on_their_uplink(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    t.inet().nft("table inet blackhole {\n  chain in {\n    type filter hook prerouting priority 0; policy accept;\n    tcp dport 9999 drop\n  }\n}\n")?;
    // The UDP flows are told apart by their (pre-NAT) source port.
    let (ty, ipk) = (addr_type(fam), ip(fam));
    t.router().nft(&format!("table inet t_flows {{\n  set flows_tcp {{ type {ty} . inet_service . ifname; flags dynamic; size 4096; }}\n  set flows_udp {{ type inet_service . ifname; flags dynamic; size 4096; }}\n  chain post {{\n    type filter hook postrouting priority 300; policy accept;\n    oifname {{ \"wana\", \"wanb\" }} tcp dport 9999 add @flows_tcp {{ {ipk} daddr . ct original proto-src . oifname }}\n    oifname {{ \"wana\", \"wanb\" }} udp dport 7002 add @flows_udp {{ ct original proto-src . oifname }}\n  }}\n}}\n"))?;
    let dsts: Vec<String> = (60..70)
        .map(|n| std::net::SocketAddr::new(testbed::plan::server(fam, n), 9999).to_string())
        .collect();
    std::thread::scope(|s| -> Result<()> {
        let syn = s.spawn(|| t.connect_to(Node::Client, &dsts, 10, false, Duration::from_secs(7)));
        let udp: Vec<_> = (0..5u16)
            .map(|i| {
                let t = &t;
                s.spawn(move || {
                    t.udp_send(
                        Node::Client,
                        testbed::plan::server(fam, 70 + i as u8),
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
            wait_members(&t, fam, &["wana"], Duration::from_secs(5))?;
            t.upstream_up(Uplink::B)?;
            wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(8))?;
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

per_family!(as30_replies_with_an_empty_active_set);

/// AS-30: with an empty active set and no operating-system default route,
/// inbound DNAT traffic, connections to router listeners and ICMP and TCP
/// probe replies are accepted; without the source rule of the probe source,
/// ICMP probe replies fail the IPv4 reverse-path check (negative control).
fn as30_replies_with_an_empty_active_set(fam: Family) -> Result<()> {
    let t = build();
    // Static gateways: the operating-system default routes go away (for
    // IPv6 also those of later Router Advertisements; the harness's leak6
    // route stays: it drops what it carries, so it masks no error).
    let (gwa, gwb) = (gateway(&t, fam, Uplink::A)?, gateway(&t, fam, Uplink::B)?);
    let ups = [
        UplinkSpec::new(Uplink::A, 1)
            .priority(None)
            .path(fam, &format!("gateway = \"{gwa}\"")),
        UplinkSpec::new(Uplink::B, 2)
            .priority(None)
            .path(fam, &format!("gateway = \"{gwb}\"")),
    ];
    let config = |targets: &str| {
        let health = HealthSpec {
            text: format!(
                "interval = \"1s\"\ntimeout = \"300ms\"\nattempts = 2\nrequired_reachable = 2\n[health.{fam}]\ntargets = [{targets}]\n"
            ),
        };
        polywan::config(&ups, &[fam], &health, "", "")
    };
    if fam == Family::V6 {
        t.router().sysctl(&[
            "net.ipv6.conf.wana.accept_ra_defrtr=0",
            "net.ipv6.conf.wanb.accept_ra_defrtr=0",
        ])?;
    }
    for u in ["wana", "wanb"] {
        let _ = t
            .router()
            .output("ip", [fam.flag(), "route", "del", "default", "dev", u])?;
    }
    // Each kind of probe separately, both of its targets required.
    let (icmp, tcp) = match fam {
        Family::V4 => (
            "\"icmp:1.1.1.1\", \"icmp:8.8.8.8\"",
            "\"tcp:9.9.9.9:443\", \"tcp:208.67.222.222:443\"",
        ),
        Family::V6 => (
            "\"icmp:2606:4700:4700::1111\", \"icmp:2001:4860:4860::8888\"",
            "\"tcp:[2620:fe::fe]:443\", \"tcp:[2001:4860:4860::8888]:443\"",
        ),
    };
    // TCP first; the ICMP configuration stays for the rest.
    let mut running: Option<polywan::Polywan> = None;
    for (kind, targets) in [("TCP", tcp), ("ICMP", icmp)] {
        if let Some(mut f) = running.take() {
            f.stop()?;
        }
        let f = t.start_polywan(&config(targets))?;
        f.wait_installed(&t)?;
        assert!(balancing_members(&t, fam)?.is_empty());
        std::thread::sleep(Duration::from_secs(5));
        assert!(
            !f.log().contains("to=Down"),
            "{kind} probe replies accepted:\n{}",
            f.log()
        );
        assert_eq!(gateway(&t, fam, Uplink::A)?, "", "no operating-system default route");
        running = Some(f);
    }
    let mut f = running.expect("started");
    let _client = serve_in(&t, Node::Client)?;
    let _router = serve_in(&t, Node::Router)?;
    t.router().nft(&format!(
        "table {} admin {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"wana\" tcp dport 8007 dnat to {}\n  }}\n}}\n",
        ip(fam),
        endpoint(&lan_client(fam).to_string(), testbed::plan::TCP_PORT)
    ))?;
    let a = address(&t, fam, Uplink::A)?;
    for dst in [endpoint(&a, 8007), endpoint(&a, 7000)] {
        let r = t.connect_to(Node::Inet, std::slice::from_ref(&dst), 5, false, Duration::from_secs(2))?;
        assert!(
            r.iter().all(|c| c.outcome == Outcome::Ok),
            "{dst}: {:?}",
            r.iter().map(|c| c.outcome).collect::<Vec<_>>()
        );
    }
    if fam == Family::V6 {
        // The negative control is IPv4-only (§14.3, AS-30): IPv6 has no
        // reverse-path filter.
        f.stop()?;
        return Ok(());
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
            &polywan::encode(0x41).to_string(),
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

per_family!(as37_removed_uplink_connections_are_rejected_not_moved);

/// AS-37: an uplink removed by reload with a live connection: its packets
/// are rejected by the path guard, never balanced; router traffic bound to
/// its interface never leaves through another interface (INV-2, INV-3).
fn as37_removed_uplink_connections_are_rejected_not_moved(fam: Family) -> Result<()> {
    let t = build();
    let ups = [
        UplinkSpec::new(Uplink::C, 3),
        UplinkSpec::new(Uplink::A, 1).priority(Some(2)),
        UplinkSpec::new(Uplink::B, 2).priority(Some(2)),
    ];
    let f = t.start_polywan(&polywan::family(&ups, fam))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t, fam)?, ["ppp0"]);
    t.reset_counters()?;
    let flow = t.start_flow(Node::Client, testbed::plan::server(fam, 77), Duration::from_millis(50))?;
    std::thread::sleep(Duration::from_millis(700));
    let (ipk, s77, s78) = (ip(fam), testbed::plan::server(fam, 77), testbed::plan::server(fam, 78));
    counter(
        &t,
        "moved",
        &format!("oifname {{ \"wana\", \"wanb\" }} {ipk} daddr {{ {s77}, {s78} }}"),
    )?;
    f.write_config(&polywan::family(&ups[1..], fam))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(5))?;
    t.wait_for("C's path route withdrawn", Duration::from_secs(5), || {
        Ok(path_route(&t, fam, 1003)?.is_empty())
    })?;
    // The connection keeps trying (retransmissions arrive from the LAN), and
    // none of its packets leaves, not even through C.
    counter(&t, "via_c", &format!("oifname \"ppp0\" {ipk} daddr {s77}"))?;
    t.router().nft(&format!(
        "table inet t_tries {{\n  counter c {{}}\n  chain pre {{\n    type filter hook prerouting priority -300; policy accept;\n    iifname \"lan\" {ipk} daddr {s77} counter name c\n  }}\n}}\n",
    ))?;
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        t.router().counter("inet", "t_tries", "c")? > 0,
        "the connection keeps sending"
    );
    assert_eq!(
        counter_value(&t, "via_c")?,
        0,
        "rejected by the path guard, not sent through C"
    );
    let report = flow.stop()?;
    assert_eq!(report.uplink(), Some(Uplink::C));
    assert_eq!(t.leaks(fam)?, 0, "INV-3 for the connection of the removed uplink");
    // Router traffic bound to C's interface: outside INV-3 (§4.1.1), it
    // may leave on-link through C but never through another interface.
    let _ = t
        .router()
        .output("ping", ["-n", "-c", "2", "-W", "1", "-I", "ppp0", &s78.to_string()])?;
    assert_eq!(
        counter_value(&t, "moved")?,
        0,
        "no packet of the connection or of the bound traffic left through A or B"
    );
    Ok(())
}

per_family!(as38_warm_restart_and_cold_start_after_reboot);

/// AS-38: the checkpoint stays fresh without transitions, so a restart keeps
/// a down path down (warm start); after a reboot (another boot id) the start
/// is cold.
fn as38_warm_restart_and_cold_start_after_reboot(fam: Family) -> Result<()> {
    let t = build();
    let mut f = t.start_polywan(&polywan::config(
        &ab(),
        &[fam],
        &HealthSpec::fast(),
        "all_down_policy = \"keep\"",
        "",
    ))?;
    f.wait_installed(&t)?;
    t.upstream_down(Uplink::A)?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(10))?;
    let checkpoint = f.dir.join("state/health.json");
    let stamp = |p: &std::path::Path| -> Result<u64> {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p)?)?;
        Ok(v["boottime_ms"].as_u64().unwrap_or(0))
    };
    let first = stamp(&checkpoint)?;
    // Rewritten at least every 30 s without transitions.
    t.wait_for("the checkpoint rewritten", Duration::from_secs(32), || {
        Ok(stamp(&checkpoint).unwrap_or(0) > first)
    })?;
    f.stop()?;
    f.start(&t)?;
    f.wait_log(
        &t,
        &format!("initial path state uplink=1 family={fam} state=Down warm=true"),
        1,
        Duration::from_secs(10),
    )?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t, fam)?, ["wanb"]);
    f.stop()?;
    // Reboot: another boot identifier.
    let text = std::fs::read_to_string(&checkpoint)?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let boot = v["boot_id"].as_str().unwrap_or_default().to_owned();
    std::fs::write(&checkpoint, text.replace(&boot, "00000000-0000-0000-0000-000000000000"))?;
    f.start(&t)?;
    f.wait_log(
        &t,
        &format!("initial path state uplink=1 family={fam} state=Up warm=false"),
        1,
        Duration::from_secs(10),
    )?;
    f.wait_log(
        &t,
        &format!("uplink=1 family={fam} from=Up to=Down reason=probe_failed"),
        1,
        Duration::from_secs(10),
    )?;
    t.upstream_up(Uplink::A)?;
    Ok(())
}

per_family!(as50_unmanaged_interface_replies_are_not_pinned);

/// AS-50: a connection from a host behind an interface PolyWAN does not manage
/// to a LAN host, whose replies follow the balancing route: the replies are
/// never assigned a path and continue through the other uplink when theirs
/// loses readiness.
fn as50_unmanaged_interface_replies_are_not_pinned(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    let _client = serve_in(&t, Node::Client)?;
    let remote = unmanaged_link(&t, fam)?;
    let ipk = ip(fam);
    counter(&t, "a", &format!("oifname \"wana\" {ipk} daddr {remote}"))?;
    counter(&t, "b", &format!("oifname \"wanb\" {ipk} daddr {remote}"))?;
    let flow = t.start_flow(Node::Inet, lan_client(fam), Duration::from_millis(50))?;
    std::thread::sleep(Duration::from_secs(1));
    let ct = t.router().run(
        "conntrack",
        [
            "-L",
            "-f",
            &fam.to_string(),
            "-s",
            &remote.to_string(),
            "-d",
            &lan_client(fam).to_string(),
        ],
    )?;
    let marks: Vec<&str> = ct.split_whitespace().filter(|w| w.starts_with("mark=")).collect();
    assert!(
        !marks.is_empty()
            && marks
                .iter()
                .all(|m| m.trim_start_matches("mark=").parse::<u32>().unwrap_or(1) & polywan::mask() == 0),
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

per_family!(as21_router_originated_traffic);

/// AS-21: router-originated traffic. Unbound connections are balanced;
/// connections bound to A's address use A, also outside the active set;
/// connections bound to A's interface never leave through another interface
/// and behave as §4.1.1 describes, for TCP and UDP, on the Ethernet and the
/// point-to-point uplink, with the path in and outside the active set and
/// with its path route withdrawn.
fn as21_router_originated_traffic(fam: Family) -> Result<()> {
    use testbed::agent::Binding;
    let t = build();
    let f = t.start_polywan(&polywan::family(&abc(), fam))?;
    f.wait_installed(&t)?;
    let ok = |r: &[testbed::ConnResult]| r.iter().all(|c| c.outcome == Outcome::Ok);
    // Unbound: balanced over A and B.
    let r = t.connect_to(
        Node::Router,
        &servers(fam, 1, 50, TCP_PORT),
        200,
        false,
        Duration::from_secs(2),
    )?;
    let counts = tally(&r);
    assert!(
        ok(&r) && counts.contains_key(&Some(Uplink::A)) && counts.contains_key(&Some(Uplink::B)),
        "{counts:?}"
    );
    let a: std::net::IpAddr = address(&t, fam, Uplink::A)?.parse()?;
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
        let dsts = servers(fam, 120, 10, port);
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
    // Bound to an interface whose path is outside the active set. IPv4:
    // the on-link fallback's source selects the path (§4.1.1). IPv6: the
    // failed first lookup has no device, so the kernel picks the source
    // among all interfaces (`ip6_dst_lookup_tail`) before the second
    // lookup; the connection goes through the path when that source is the
    // interface's own address, and is rejected otherwise. In both families
    // nothing leaves through another interface.
    let bound_outside = |what: &str, iface: &str, udp: bool, u: Uplink| -> Result<()> {
        if fam == Family::V4 {
            return check(what, &by_dev(iface), udp, Some(u));
        }
        let name = format!("not_{}{}", iface, u8::from(udp));
        counter(
            &t,
            &name,
            &format!(
                "oifname != \"{iface}\" oifname != \"lo\" ip6 daddr {}-{}",
                testbed::plan::server(fam, 120),
                testbed::plan::server(fam, 129)
            ),
        )?;
        let port = if udp {
            testbed::plan::UDP_PORT
        } else {
            testbed::plan::TCP_PORT
        };
        let dsts = servers(fam, 120, 10, port);
        let r = t.connect_bound(Node::Router, &dsts, 20, udp, Duration::from_secs(2), &by_dev(iface))?;
        assert!(
            r.iter().all(|c| c.outcome != Outcome::Ok || c.uplink() == Some(u)),
            "{what}: {:?}",
            tally(&r)
        );
        assert_eq!(counter_value(&t, &name)?, 0, "{what}: never through another interface");
        Ok(())
    };
    check("bound to A's address", &by_addr, false, Some(Uplink::A))?;
    for udp in [false, true] {
        check("bound to wana", &by_dev("wana"), udp, Some(Uplink::A))?;
        check("bound to ppp0", &by_dev("ppp0"), udp, Some(Uplink::C))?;
    }
    // A outside the active set (probes fail, path still ready).
    t.upstream_down(Uplink::A)?;
    wait_members(&t, fam, &["ppp0", "wanb"], Duration::from_secs(10))?;
    t.upstream_up(Uplink::A)?;
    // While A recovers (rise rounds), it is still outside the active set.
    check(
        "bound to A's address outside the active set",
        &by_addr,
        false,
        Some(Uplink::A),
    )?;
    bound_outside("bound to wana outside the active set", "wana", false, Uplink::A)?;
    // A's path route withdrawn: the gateway disappears from main (for
    // IPv6, Router Advertisements no longer install it).
    let dsts = format!(
        "{} daddr {}-{}",
        ip(fam),
        testbed::plan::server(fam, 120),
        testbed::plan::server(fam, 129)
    );
    counter(
        &t,
        "elsewhere",
        &format!("oifname != \"wana\" oifname != \"lo\" {dsts}"),
    )?;
    counter(&t, "a_out", &format!("oifname \"wana\" {dsts}"))?;
    if fam == Family::V6 {
        t.router().sysctl(&["net.ipv6.conf.wana.accept_ra_defrtr=0"])?;
    }
    t.router().ip(&format!("{} route del default dev wana", fam.flag()))?;
    t.wait_for("A's path route withdrawn", Duration::from_secs(3), || {
        Ok(path_route(&t, fam, 1001)?.is_empty())
    })?;
    let a_out = counter_value(&t, "a_out")?;
    for udp in [false, true] {
        // IPv4 sends on-link through the bound interface (§4.1.1): nothing
        // answers on Ethernet. IPv6 selects the interface's source address
        // and its source guard rejects the packets.
        check("bound to wana, path withdrawn", &by_dev("wana"), udp, None)?;
    }
    assert_eq!(counter_value(&t, "elsewhere")?, 0, "never through another interface");
    if fam == Family::V6 {
        assert_eq!(counter_value(&t, "a_out")?, a_out, "IPv6: nothing leaves at all");
    }
    // The point-to-point uplink outside the active set (its probes fail):
    // bound traffic still uses it.
    t.drop_probe_echoes(Uplink::C, 1)?;
    t.wait_for("C outside the active set", Duration::from_secs(10), || {
        Ok(!balancing_members(&t, fam)?.contains(&"ppp0".to_owned()))
    })?;
    for udp in [false, true] {
        bound_outside("bound to ppp0 outside the active set", "ppp0", udp, Uplink::C)?;
    }
    t.clear_provider_rules(Uplink::C)?;
    // Its path route withdrawn: an IPv4 point-to-point path needs only its
    // address, so the address goes, and traffic bound to ppp0 still goes to
    // the peer, through ppp0 only (§4.1.1). An IPv6 path needs a gateway
    // (Q12): the Router Advertisement route goes, and the source guard of
    // ppp0's address rejects the bound traffic.
    if fam == Family::V4 {
        let c = address(&t, fam, Uplink::C)?;
        t.router()
            .ip(&format!("addr del {c}/32 dev ppp0"))
            .or_else(|_| t.router().ip("addr flush dev ppp0"))?;
    } else {
        t.router().sysctl(&["net.ipv6.conf.ppp0.accept_ra_defrtr=0"])?;
        t.router().ip("-6 route del default dev ppp0")?;
    }
    t.wait_for("C's path route withdrawn", Duration::from_secs(3), || {
        Ok(path_route(&t, fam, 1003)?.is_empty())
    })?;
    counter(&t, "c_out", &format!("oifname \"ppp0\" {dsts}"))?;
    counter(
        &t,
        "c_elsewhere",
        &format!("oifname != \"ppp0\" oifname != \"lo\" {dsts}"),
    )?;
    for udp in [false, true] {
        let port = if udp {
            testbed::plan::UDP_PORT
        } else {
            testbed::plan::TCP_PORT
        };
        let dsts = servers(fam, 120, 10, port);
        let before = counter_value(&t, "c_out")?;
        let r = t.connect_bound(Node::Router, &dsts, 10, udp, Duration::from_secs(1), &by_dev("ppp0"))?;
        if fam == Family::V4 {
            assert!(counter_value(&t, "c_out")? > before, "sent through ppp0 (udp: {udp})");
        } else {
            assert!(r.iter().all(|c| c.outcome != Outcome::Ok), "rejected (udp: {udp})");
            assert_eq!(counter_value(&t, "c_out")?, before, "nothing leaves (udp: {udp})");
        }
    }
    assert_eq!(counter_value(&t, "c_elsewhere")?, 0, "never through another interface");
    Ok(())
}

per_family!(as23_external_firewall_mode);

/// AS-23: external firewall mode; the administrator loads the exported
/// ruleset by hand; the results of AS-01, AS-03 and AS-09 hold.
fn as23_external_firewall_mode(fam: Family) -> Result<()> {
    let t = build();
    // C in a second priority group: inbound connections also arrive on an
    // uplink outside the active set (AS-09).
    let ups = [
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3).priority(Some(2)),
    ];
    let config = polywan::config(
        &ups,
        stack_families(fam),
        &HealthSpec::fast(),
        "reconcile_interval = \"10s\"",
        "[firewall]\nmode = \"external\"\n",
    );
    let f = t.start_polywan(&config)?;
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
            .output("nft", ["list", "table", "inet", "polywan"])?
            .status
            .success(),
        "PolyWAN performs no nftables mutation"
    );
    let out = f.cli_config(&["export-nft"])?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    t.router().nft(&String::from_utf8_lossy(&out.stdout))?;
    f.wait_log(&t, "status_recovered", 1, Duration::from_secs(13))?;
    // AS-01.
    split(&t, fam, 500, 50)?;
    // AS-03: connections on A survive a failure and the recovery of B.
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    let flows = start_flows(&t, fam, 1, 20)?;
    std::thread::sleep(Duration::from_millis(500));
    t.carrier_down(Uplink::B)?;
    wait_members(&t, fam, &["wana"], Duration::from_secs(3))?;
    std::thread::sleep(Duration::from_secs(1));
    t.carrier_up(Uplink::B)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(15))?;
    std::thread::sleep(Duration::from_secs(1));
    flows_on_continuous(flows, &[Uplink::A])?;
    // AS-09 on every uplink, C outside the active set.
    inbound_via_each_uplink(&t, fam, &[Uplink::A, Uplink::B, Uplink::C])?;
    Ok(())
}

per_family!(as47_startup_with_existing_artifacts);

/// AS-47: startup with intact artifacts and an expired checkpoint (adoption,
/// cold start); with partial artifacts, live marks and a recent checkpoint
/// (repair, connections routed again once repaired); in external mode with
/// the administrator's ruleset already loaded (no degradation).
fn as47_startup_with_existing_artifacts(fam: Family) -> Result<()> {
    let t = build();
    let mut f = t.start_polywan(&stack(fam, &ab()))?;
    f.wait_installed(&t)?;
    t.upstream_down(Uplink::A)?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(10))?;
    let rules = polywan_rules(&t, fam)?;
    let flow = |n| t.start_flow(Node::Client, testbed::plan::server(fam, n), Duration::from_millis(50));
    let intact = flow(90)?;
    std::thread::sleep(Duration::from_millis(500));

    // (1) Intact artifacts, checkpoint older than 10 minutes: adopted, cold
    // start. The daemon's boot-time clock moves 11 minutes ahead (a test
    // hook): the host may have booted less than 10 minutes ago.
    f.kill()?;
    f.set_env("POLYWAN_TEST_BOOTTIME_SHIFT_MS", &(11 * 60 * 1000).to_string());
    f.start(&t)?;
    f.wait_log(
        &t,
        &format!("initial path state uplink=1 family={fam} state=Up warm=false"),
        1,
        Duration::from_secs(10),
    )?;
    f.wait_installed(&t)?;
    assert_eq!(polywan_rules(&t, fam)?, rules, "adopted without duplicates");
    wait_members(&t, fam, &["wanb"], Duration::from_secs(5))?;
    let report = intact.stop()?;
    assert_eq!(report.uplink(), Some(Uplink::B));
    assert!(
        report.continuous(Duration::from_secs(1)),
        "a connection whose artifacts stayed intact is uninterrupted: {report:?}"
    );
    let damaged = flow(91)?;
    std::thread::sleep(Duration::from_millis(500));

    // (2) Partial artifacts with live marks and a recent checkpoint.
    f.kill()?;
    t.router().ip(&format!("{} rule del pref 1202", fam.flag()))?;
    t.router().ip(&format!("{} route del default table 1000", fam.flag()))?;
    std::thread::sleep(Duration::from_secs(1));
    f.start(&t)?;
    f.wait_log(
        &t,
        &format!("initial path state uplink=2 family={fam} state=Up warm=true"),
        1,
        Duration::from_secs(10),
    )?;
    f.wait_installed(&t)?;
    t.wait_for("the layout repaired", Duration::from_secs(3), || {
        Ok(polywan_rules(&t, fam)? == rules)
    })?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(3))?;
    std::thread::sleep(Duration::from_secs(1));
    let report = damaged.stop()?;
    assert_eq!(report.uplink(), Some(Uplink::B));
    assert!(
        report.error.is_none(),
        "the connection on the damaged path recovers once repaired: {report:?}"
    );
    f.stop()?;
    t.upstream_up(Uplink::A)?;

    // (3) External mode with the administrator's ruleset already loaded.
    let config = polywan::config(
        &ab(),
        stack_families(fam),
        &HealthSpec::fast(),
        "",
        "[firewall]\nmode = \"external\"\n",
    );
    let out = f.cli_config(&["cleanup"])?;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    f.write_config(&config)?;
    let out = f.cli_config(&["export-nft"])?;
    t.router().nft(&String::from_utf8_lossy(&out.stdout))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    std::thread::sleep(Duration::from_secs(1));
    assert!(!f.log().contains("external_ruleset_missing"), "{}", f.log());
    Ok(())
}

per_family!(as47_warm_restart_adding_an_uplink);

/// AS-47, an uplink added while PolyWAN was stopped: at the warm restart, its
/// assignments are not in the adopted table yet, so it joins the balancing
/// route only after the replacement installs them, also while that
/// replacement fails (FR-REC-8, FR-REC-3).
fn as47_warm_restart_adding_an_uplink(fam: Family) -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&stack(fam, &ab()))?;
    let (wrapper, flag) = nft_wrapper(&t, &f, &["-f"], NFT_FAILS)?;
    let firewall = format!("[firewall]\nnft_path = \"{}\"\n", wrapper.display());
    f.write_config(&polywan::config(
        &ab(),
        stack_families(fam),
        &HealthSpec::fast(),
        "",
        &firewall,
    ))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    f.stop()?;
    f.write_config(&polywan::config(
        &abc(),
        stack_families(fam),
        &HealthSpec::fast(),
        "",
        &firewall,
    ))?;
    std::fs::write(&flag, "")?;
    f.start(&t)?;
    f.wait_log(&t, "apply_failed", 1, Duration::from_secs(15))?;
    for _ in 0..3 {
        assert_eq!(
            balancing_members(&t, fam)?,
            ["wana", "wanb"],
            "C stays out while its assignments are missing"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    std::fs::remove_file(&flag)?;
    f.wait_log(&t, "desired state fully applied", 1, Duration::from_secs(70))?;
    wait_members(&t, fam, &["ppp0", "wana", "wanb"], Duration::from_secs(10))?;
    f.stop()?;
    Ok(())
}

per_family!(as31_path_mtu_discovery_through_pppoe_and_a_provider_bottleneck);

/// AS-31: RELATED ICMP errors and path MTU discovery through the PPPoE
/// uplink (MTU 1492) and through a bottleneck inside provider A while the
/// server advertises a full-size MSS: large transfers succeed (INV-2).
fn as31_path_mtu_discovery_through_pppoe_and_a_provider_bottleneck(fam: Family) -> Result<()> {
    let t = build();
    let c_first = [
        UplinkSpec::new(Uplink::C, 3),
        UplinkSpec::new(Uplink::A, 1).priority(Some(2)),
        UplinkSpec::new(Uplink::B, 2).priority(Some(2)),
    ];
    let f = t.start_polywan(&polywan::family(&c_first, fam))?;
    f.wait_installed(&t)?;
    assert_eq!(balancing_members(&t, fam)?, ["ppp0"]);
    let r = t.bulk(
        Node::Client,
        testbed::plan::server(fam, 95),
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
    f.write_config(&polywan::family(&a_first, fam))?;
    f.reload()?;
    wait_members(&t, fam, &["wana"], Duration::from_secs(10))?;
    t.ns(Node::IspA).ip("link set core mtu 1300")?;
    t.inet().ip("link set isp-a mtu 1300")?;
    // A full-size MSS: 1500 bytes less the IP and TCP headers.
    let (customers, mss) = match fam {
        Family::V4 => ("192.0.2.0/24", 1460),
        Family::V6 => ("2001:db8:a::/48", 1440),
    };
    let route = t.inet().run("ip", [fam.flag(), "route", "show", customers])?;
    let route = route.lines().next().unwrap_or_default().trim().to_owned();
    t.inet()
        .ip(&format!("{} route change {route} advmss {mss}", fam.flag()))?;
    let r = t.bulk(
        Node::Client,
        testbed::plan::server(fam, 96),
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

/// Valid lifetime in seconds of the IPv4 address of an uplink.
fn valid_lft(t: &Topology, u: Uplink) -> Result<Option<u64>> {
    Ok(t.addresses(u.l3_iface(), Family::V4, "global")?
        .into_iter()
        .find_map(|a| a.valid_lft))
}

/// AS-44 (IPv4 parts): the router boots with PolyWAN installed before any uplink
/// is configured (no lease, no global address, no default route, empty
/// active set); then DHCPv4 acquisition (A, B) and PPPoE negotiation (C)
/// succeed, the unicast renewal to the on-link server succeeds (A), and with
/// unicast renewals dropped by the provider the broadcast rebinding succeeds
/// (B), all before the 2-minute leases expire (FR-CT-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as44_boot_before_any_uplink_is_configured() -> Result<()> {
    let t = build_with(Options {
        uplink_clients: false,
        ..Options::default()
    });
    for u in Uplink::ALL {
        assert_eq!(t.uplink_address(u, Family::V4)?, None, "{u} has no address yet");
        assert_eq!(t.os_default_route(u, Family::V4)?, None, "{u} has no default route yet");
    }
    let f = t.start_polywan(&polywan::ipv4(&abc()))?;
    f.wait_installed(&t)?;
    assert!(balancing_members(&t, Family::V4)?.is_empty(), "empty active set");
    assert!(
        !polywan_rules(&t, Family::V4)?.is_empty(),
        "PolyWAN's rules are installed"
    );
    // Requests to the DHCP servers, by destination: unicast (renewals) and
    // broadcast (discovery, selection, rebinding). Provider B drops unicast
    // renewals, so its client must rebind.
    for (node, server, drop) in [(Node::IspA, "192.0.2.1", ""), (Node::IspB, "100.64.0.1", " drop")] {
        t.ns(node).nft(&format!(
            "table ip t44 {{\n  counter uni {{}}\n  counter bc {{}}\n  chain in {{\n    type filter hook input priority -10; policy accept;\n    udp dport 67 ip daddr {server} counter name uni{drop}\n    udp dport 67 ip daddr 255.255.255.255 counter name bc\n  }}\n}}\n"
        ))?;
    }

    t.start_uplink_clients()?;
    t.wait_ready()?;
    let acquired = Instant::now();
    let leased: Vec<String> = [Uplink::A, Uplink::B]
        .into_iter()
        .map(|u| address(&t, Family::V4, u))
        .collect::<Result<_>>()?;
    let bc_a = provider_counter(&t, Node::IspA, "ip", "t44", "bc")?;
    let bc_b = provider_counter(&t, Node::IspB, "ip", "t44", "bc")?;
    wait_members(&t, Family::V4, &["ppp0", "wana", "wanb"], Duration::from_secs(15))?;
    assert!(path_route(&t, Family::V4, 1003)?.contains("dev ppp0"), "C's path route");
    t.reset_counters()?;
    let r = t.connect_many(Node::Client, Family::V4, 20, 60, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    assert_eq!(t.ipv4_leaks()?, 0, "INV-3");

    // Renewal at T1 (half of the 2-minute lease); rebinding once the
    // renewal goes unanswered, before the lease expires.
    let lease = Duration::from_secs(120);
    let renewed = |u: Uplink| -> Result<bool> { Ok(valid_lft(&t, u)?.is_some_and(|l| l >= 100)) };
    t.wait_for("A's unicast renewal", lease, || {
        Ok(provider_counter(&t, Node::IspA, "ip", "t44", "uni")? > 0)
    })?;
    // A client retransmits an unanswered renewal (the CI runner once took
    // longer than 5 s); still by unicast, well before rebinding at T2.
    t.wait_for("A's renewed lease", Duration::from_secs(30), || renewed(Uplink::A))
        .with_context(|| format!("A's valid lifetime {:?}\n{}", valid_lft(&t, Uplink::A), t.diagnostics()))?;
    assert_eq!(
        provider_counter(&t, Node::IspA, "ip", "t44", "bc")?,
        bc_a,
        "A renewed by unicast, without rebinding"
    );
    let left = lease.saturating_sub(acquired.elapsed());
    t.wait_for("B's broadcast rebinding", left, || {
        Ok(provider_counter(&t, Node::IspB, "ip", "t44", "bc")? > bc_b)
    })?;
    t.wait_for("B's rebound lease", Duration::from_secs(5), || renewed(Uplink::B))?;
    assert!(
        provider_counter(&t, Node::IspB, "ip", "t44", "uni")? > 0,
        "B tried a unicast renewal first"
    );
    for (u, a) in [Uplink::A, Uplink::B].into_iter().zip(&leased) {
        assert_eq!(&address(&t, Family::V4, u)?, a, "{u} kept its lease");
    }
    assert_eq!(balancing_members(&t, Family::V4)?, ["ppp0", "wana", "wanb"]);
    Ok(())
}

/// The daemon's failure-injection control file (`POLYWAN_TEST_FAULTS`, a test
/// hook of the `test-hooks` build): armed with n, the next n steps of the
/// reconciler or of cleanup succeed and the following ones fail until it is
/// disarmed; the steps are listed in `<file>.steps`.
struct Faults {
    path: PathBuf,
}

impl Faults {
    fn new(f: &mut polywan::Polywan) -> Faults {
        let path = f.dir.join("faults");
        f.set_env("POLYWAN_TEST_FAULTS", &path.display().to_string());
        Faults { path }
    }

    fn steps_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".steps");
        PathBuf::from(p)
    }

    fn arm(&self, n: usize) -> Result<()> {
        let _ = std::fs::remove_file(self.steps_path());
        std::fs::write(&self.path, n.to_string())?;
        Ok(())
    }

    /// Fails every step whose name contains `text`, until disarmed.
    fn arm_matching(&self, text: &str) -> Result<()> {
        let _ = std::fs::remove_file(self.steps_path());
        std::fs::write(&self.path, format!("match:{text}"))?;
        Ok(())
    }

    /// Like [`Faults::arm_matching`], and a failing route replacement also
    /// removes the route: the empty-table outcome of an IPv6 multipath
    /// replacement that fails after the first insertion (FR-ROUTE-2).
    fn arm_empty(&self, text: &str) -> Result<()> {
        let _ = std::fs::remove_file(self.steps_path());
        std::fs::write(&self.path, format!("empty:{text}"))?;
        Ok(())
    }

    fn disarm(&self) -> Result<()> {
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }

    fn steps(&self) -> Vec<String> {
        std::fs::read_to_string(self.steps_path())
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn injected(&self) -> bool {
        self.steps().iter().any(|l| l.ends_with(" failed"))
    }
}

/// Counts, in table `inet t_wrong`, packets of connections assigned to a
/// path that leave through another uplink (INV-2, INV-5).
fn wrong_uplink_counter(t: &Topology) -> Result<()> {
    let mut rules = String::new();
    for (u, id) in [(Uplink::A, 1), (Uplink::B, 2), (Uplink::C, 3)] {
        let others: Vec<String> = Uplink::ALL
            .into_iter()
            .filter(|o| *o != u)
            .map(|o| format!("\"{}\"", o.l3_iface()))
            .collect();
        rules += &format!(
            "    ct mark & {:#x} == {:#x} oifname {{ {} }} counter name c\n",
            polywan::mask(),
            polywan::encode(id),
            others.join(", ")
        );
    }
    t.router().nft(&format!(
        "table inet t_wrong {{\n  counter c {{}}\n  chain post {{\n    type filter hook postrouting priority 300; policy accept;\n{rules}  }}\n}}\n"
    ))
}

/// State for an AS-27 failure message.
fn diagnose(t: &Topology, f: &polywan::Polywan, faults: &Faults, k: usize) -> String {
    let log = f.log();
    let tail: Vec<&str> = log.lines().rev().take(40).collect();
    format!(
        "after {k} steps\nsteps: {:#?}\nmembers: {:?}\nC's path route: {:?}\nrules:\n{}\ndaemon log (tail):\n{}",
        faults.steps(),
        balancing_members(t, Family::V4),
        path_route(t, Family::V4, 1003),
        polywan_rules(t, Family::V4).map(|r| r.join("\n")).unwrap_or_default(),
        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
    )
}

/// A change of AS-27: an uplink order of FR-REC-3 or a runtime update.
#[derive(Clone, Copy, Debug)]
enum Change {
    /// Reload removing C.
    RemoveC,
    /// Reload adding C back.
    AddC,
    /// A leaves the active set (its provider stops forwarding).
    AOut,
    /// A secondary address on C: a new source rule and guard.
    AddressOnC,
    /// C's PPP session reconnects: a new interface, whose sysctls, path
    /// route and source rules are applied again.
    ReconnectC,
}

per_family!(as27_failure_after_each_step);

/// AS-27: a failure injected after each step of the uplink addition and
/// removal orders (FR-REC-3) and of runtime updates (an active-set change,
/// a new source address, a recreated interface), with continuous traffic: pinned client
/// connections, a router-originated connection, an inbound connection, and
/// connections matching a balance policy to C and a block policy to A (the
/// policy variants, whose tables and rules are steps of these orders). While
/// the failed generation is held and after its retry, no packet is routed by
/// an operating-system route (INV-3) and no packet of a pinned or inbound
/// connection leaves through another uplink; connections on B, which no
/// change touches, are uninterrupted.
fn as27_failure_after_each_step(fam: Family) -> Result<()> {
    let t = build();
    let health = HealthSpec::fast();
    // A path whose route failed is not ready until a discovery change or the
    // next full reconciliation (FR-DISC-7).
    let routing = "reconcile_interval = \"10s\"";
    // Test server 64 by a balance policy to C, 65 by a block policy to A.
    let policy = |name: &str, server: u8, uplink: &str, fallback: &str| {
        format!(
            "[[policy]]\nname = \"{name}\"\nfamily = \"{fam}\"\ndestination = \"{}\"\nuplink = \"{uplink}\"\nfallback = \"{fallback}\"\n",
            testbed::plan::server(fam, server)
        )
    };
    let on_c = policy("to-c", 64, "c", "balance");
    let on_a = policy("to-a", 65, "a", "block");
    let with_c = polywan::config(&abc(), stack_families(fam), &health, routing, &format!("{on_c}{on_a}"));
    let without_c = polywan::config(&ab(), stack_families(fam), &health, routing, &on_a);
    // Leaks of every managed family (the IPv6 variant is dual-stack).
    let leaks = || -> Result<u64> {
        let mut n = 0;
        for g in stack_families(fam) {
            n += t.leaks(*g)?;
        }
        Ok(n)
    };
    let mut f = t.prepare_polywan(&with_c)?;
    let faults = Faults::new(&mut f);
    f.start(&t)?;
    f.wait_installed(&t)?;
    let all = ["ppp0", "wana", "wanb"];
    wait_members(&t, fam, &all, Duration::from_secs(15))?;
    wrong_uplink_counter(&t)?;

    // Continuous traffic.
    let _server = serve_in(&t, Node::Client)?;
    let a = address(&t, fam, Uplink::A)?;
    t.router().nft(&format!(
        "table {ipk} admin {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"wana\" {ipk} daddr {a} tcp dport {} dnat to {}\n  }}\n}}\n",
        testbed::plan::TCP_PORT,
        lan_client(fam),
        ipk = ip(fam),
    ))?;
    // Pinned client connections, a router-originated one and an inbound one,
    // started again for each failure position: a change may legitimately end
    // those of the uplink it affects.
    let a_addr: std::net::IpAddr = a.parse()?;
    let start_traffic = || -> Result<Vec<testbed::traffic::Flow>> {
        // Servers 60 to 71: 64 and 65 are those of the policies.
        let mut flows = start_flows(&t, fam, 60, 12)?;
        flows.push(t.start_flow(Node::Router, testbed::plan::server(fam, 75), Duration::from_millis(50))?);
        flows.push(t.start_flow(Node::Inet, a_addr, Duration::from_millis(50))?);
        std::thread::sleep(Duration::from_secs(1));
        Ok(flows)
    };
    t.reset_counters()?;

    let reload = |config: &str| -> Result<()> {
        f.write_config(config)?;
        f.reload()
    };
    let c_gone = || -> Result<bool> {
        Ok(path_route(&t, fam, 1003)?.is_empty() && !polywan_rules(&t, fam)?.iter().any(|r| r.contains("lookup 1003")))
    };
    // A secondary address on C.
    let (secondary, len) = match fam {
        Family::V4 => ("203.0.113.77", "32"),
        Family::V6 => ("2001:db8:c:ffff::77", "64 nodad"),
    };
    let has_source = || -> Result<bool> {
        Ok(polywan_rules(&t, fam)?
            .iter()
            .any(|r| r.contains(&format!("from {secondary} "))))
    };
    let settings = match fam {
        Family::V4 => "net.ipv4.conf.ppp0.src_valid_mark",
        Family::V6 => "net.ipv6.conf.ppp0.ignore_routes_with_linkdown",
    };
    let timeout = Duration::from_secs(20);
    let ppp_ready = |before: Option<u64>| -> Result<bool> {
        let now = t.ifindex("ppp0");
        Ok(now.is_some()
            && now != before
            && t.router().sysctl_get(settings).is_ok_and(|v| v == "1")
            && path_route(&t, fam, 1003)?.contains("dev ppp0")
            && balancing_members(&t, fam)? == all)
    };
    for change in [
        Change::RemoveC,
        Change::AddC,
        Change::AOut,
        Change::AddressOnC,
        Change::ReconnectC,
    ] {
        let mut on_b = 0;
        for k in 0.. {
            if let Change::AddC = change {
                reload(&without_c)?;
                t.wait_for("C removed", timeout, &c_gone)?;
            }
            let flows = start_traffic()?;
            let recovered = f.log().matches("desired state fully applied").count();
            let index = t.ifindex("ppp0");
            faults.arm(k)?;
            match change {
                Change::RemoveC => reload(&without_c)?,
                Change::AddC => reload(&with_c)?,
                Change::AOut => t.upstream_down(Uplink::A)?,
                Change::AddressOnC => {
                    t.router().ip(&format!("addr add {secondary}/{len} dev ppp0"))?;
                }
                Change::ReconnectC => t.pppoe_reset()?,
            }
            let done = || -> Result<bool> {
                match change {
                    Change::RemoveC => c_gone(),
                    Change::AddC => Ok(balancing_members(&t, fam)? == all),
                    Change::AOut => Ok(balancing_members(&t, fam)? == ["ppp0", "wanb"]),
                    Change::AddressOnC => has_source(),
                    Change::ReconnectC => ppp_ready(index),
                }
            };
            let timeout = if let Change::ReconnectC = change {
                Duration::from_secs(40)
            } else {
                timeout
            };
            t.wait_for(
                &format!("{change:?} applied or failed after {k} steps"),
                timeout,
                || Ok(faults.injected() || done()?),
            )
            .with_context(|| diagnose(&t, &f, &faults, k))?;
            let injected = faults.injected();
            if injected {
                // Hold the partial generation under new connections (with A
                // out but still in the unchanged active set, some time out).
                t.connect_many(Node::Client, fam, 20, 40, false)?;
                assert_eq!(leaks()?, 0, "INV-3, {change:?} after {k} steps");
                assert_eq!(counter_value(&t, "wrong")?, 0, "INV-2, {change:?} after {k} steps");
                faults.disarm()?;
                f.wait_log(
                    &t,
                    "desired state fully applied",
                    recovered + 1,
                    Duration::from_secs(70),
                )?;
                t.wait_for(
                    &format!("{change:?} applied after the retry"),
                    Duration::from_secs(30),
                    &done,
                )
                .with_context(|| diagnose(&t, &f, &faults, k))?;
            }
            faults.disarm()?;
            assert_eq!(leaks()?, 0, "INV-3, {change:?} after {k} steps");
            assert_eq!(counter_value(&t, "wrong")?, 0, "INV-2, {change:?} after {k} steps");
            // Back to the base state.
            match change {
                Change::RemoveC => reload(&with_c)?,
                Change::AddC => {}
                Change::AOut => t.upstream_up(Uplink::A)?,
                Change::AddressOnC => {
                    let len = len.split(' ').next().unwrap_or(len);
                    t.router().ip(&format!("addr del {secondary}/{len} dev ppp0"))?;
                    t.wait_for("the source rule removed", timeout, || Ok(!has_source()?))?;
                }
                Change::ReconnectC => {}
            }
            wait_members(&t, fam, &all, timeout)?;
            // Every kind of traffic was exchanging data at this position.
            let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
            for r in &reports {
                assert!(
                    r.received > 0,
                    "{change:?} after {k} steps: traffic not exchanged: {r:?}"
                );
            }
            // Connections on B, which no change touches, are uninterrupted.
            for r in reports.iter().filter(|r| r.uplink() == Some(Uplink::B)) {
                on_b += 1;
                assert!(
                    r.continuous(Duration::from_secs(1)),
                    "{change:?} after {k} steps: flow on B interrupted: {r:?}"
                );
            }
            if !injected {
                eprintln!("{change:?}: {k} steps");
                break;
            }
        }
        assert!(on_b > 0, "{change:?}: no flow ran on B");
    }
    assert_eq!(counter_value(&t, "wrong")?, 0, "INV-2");
    f.stop()?;
    Ok(())
}

/// AS-27, a runtime update failing for one uplink does not hold back
/// another: while the settings of C's new interface keep failing, C is not
/// ready, and A still leaves the active set within the detection bound when
/// its provider fails (FR-REC-5, FR-HEALTH-5); C comes back once its
/// settings apply.
#[test]
#[ignore = "needs root and network namespaces"]
fn as27_a_failing_interface_setting_does_not_hold_back_failover() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&abc()))?;
    let faults = Faults::new(&mut f);
    f.start(&t)?;
    f.wait_installed(&t)?;
    let all = ["ppp0", "wana", "wanb"];
    wait_members(&t, Family::V4, &all, Duration::from_secs(15))?;
    faults.arm_matching("set sysctls")?;
    let before = t.ifindex("ppp0");
    t.pppoe_reset()?;
    t.wait_for(
        "C's settings failing",
        Duration::from_secs(30),
        || Ok(faults.injected()),
    )?;
    t.wait_for("C not ready", Duration::from_secs(5), || {
        Ok(t.ifindex("ppp0") != before && balancing_members(&t, Family::V4)? == ["wana", "wanb"])
    })?;
    t.upstream_down(Uplink::A)?;
    wait_members(&t, Family::V4, &["wanb"], Duration::from_secs(10))?;
    faults.disarm()?;
    t.upstream_up(Uplink::A)?;
    wait_members(&t, Family::V4, &all, Duration::from_secs(70))?;
    f.wait_log(&t, "desired state fully applied", 1, Duration::from_secs(5))?;
    f.stop()?;
    Ok(())
}

/// AS-27, an uplink added while another interface's settings keep
/// failing gets its own settings before it carries traffic: the backoff of
/// C's settings does not hold back B's (FR-REC-3, FR-REC-5); C removed
/// while its settings fail leaves nothing to retry (FR-DISC-7).
#[test]
#[ignore = "needs root and network namespaces"]
fn as27_an_added_uplink_gets_its_settings_during_another_backoff() -> Result<()> {
    let t = build();
    let (a, b, c) = (
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3),
    );
    let mut f = t.prepare_polywan(&polywan::ipv4(&[a.clone(), c.clone()]))?;
    let faults = Faults::new(&mut f);
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["ppp0", "wana"], Duration::from_secs(15))?;
    faults.arm_matching("sysctls (ppp0)")?;
    t.pppoe_reset()?;
    // Five failures: C's next retry is about 16 s away.
    t.wait_for("C's settings failing repeatedly", Duration::from_secs(40), || {
        Ok(faults.steps().iter().filter(|s| s.ends_with(" failed")).count() >= 5)
    })?;
    assert_eq!(balancing_members(&t, Family::V4)?, ["wana"], "C is not ready");
    let svm = || t.router().sysctl_get("net.ipv4.conf.wanb.src_valid_mark");
    assert_eq!(svm()?, "0", "B is not PolyWAN's yet");
    f.write_config(&polywan::ipv4(&[a.clone(), b.clone(), c]))?;
    f.reload()?;
    // Well before C's retry: a shared backoff would hold B back.
    t.wait_for("B's settings", Duration::from_secs(4), || Ok(svm()? == "1"))?;
    t.wait_for("B in the balancing route", Duration::from_secs(15), || {
        let joined = balancing_members(&t, Family::V4)?.contains(&"wanb".to_owned());
        assert!(!joined || svm()? == "1", "B carries traffic without its settings");
        Ok(joined)
    })?;
    // Before C's next retry: a kept retry would wait for it.
    f.write_config(&polywan::ipv4(&[a, b]))?;
    f.reload()?;
    f.wait_log(&t, "desired state fully applied", 1, Duration::from_secs(4))?;
    faults.disarm()?;
    f.stop()?;
    Ok(())
}

/// AS-27, management switched off by a reload while C's settings and the
/// global ones wait for long backoffs: both backoffs go, the settings are
/// only checked, and the pass completes at once (FR-DISC-7, §4.6).
#[test]
#[ignore = "needs root and network namespaces"]
fn as27_disabling_sysctl_management_drops_the_backoffs() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&abc()))?;
    let faults = Faults::new(&mut f);
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["ppp0", "wana", "wanb"], Duration::from_secs(15))?;
    faults.arm_matching("set sysctls")?;
    t.pppoe_reset()?;
    let failures = |scope: &str| {
        let step = format!("set sysctls ({scope}) failed");
        faults.steps().iter().filter(|s| **s == step).count()
    };
    // Five failures: C's next retry is about 16 s away.
    t.wait_for("C's settings failing repeatedly", Duration::from_secs(40), || {
        Ok(failures("ppp0") >= 5)
    })?;
    // A global setting changed behind PolyWAN's back, then a reload: four
    // failures put its next retry about 8 s away, and hold back the pass.
    t.router()
        .run("sh", ["-c", "echo 0 > /proc/sys/net/ipv4/fib_multipath_hash_policy"])?;
    f.reload()?;
    t.wait_for(
        "the global settings failing repeatedly",
        Duration::from_secs(20),
        || Ok(failures("global") >= 4),
    )?;
    let text = polywan::config(&abc(), &[Family::V4], &HealthSpec::fast(), "manage_sysctls = false", "");
    f.write_config(&text)?;
    f.reload()?;
    f.wait_log(&t, "desired state fully applied", 1, Duration::from_secs(4))?;
    assert!(
        f.log().contains("fib_multipath_hash_policy is 0, PolyWAN needs"),
        "only checked: {}",
        f.log()
    );
    wait_members(&t, Family::V4, &["ppp0", "wana", "wanb"], Duration::from_secs(15))?;
    faults.disarm()?;
    f.stop()?;
    Ok(())
}

/// AS-27, startup: B's settings fail from the start. The daemon starts,
/// installs A and C, and keeps B out, not probed, until its settings apply
/// (FR-DISC-7, FR-PROBE-1, FR-REC-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as27_startup_with_an_interface_setting_failing() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&abc()))?;
    let faults = Faults::new(&mut f);
    faults.arm_matching("sysctls (wanb)")?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["ppp0", "wana"], Duration::from_secs(15))?;
    f.wait_log(&t, "apply_failed", 1, Duration::from_secs(5))?;
    // Probes of a path that is ready send several packets a second; a DHCP
    // renewal (2-minute leases) may fall in the window.
    let probed = |what: &str| -> Result<u64> {
        t.reset_counters()?;
        std::thread::sleep(Duration::from_secs(3));
        let n = t.egress_packets(Uplink::B, Family::V4)?;
        eprintln!("{what}: {n} packets through B in 3 s");
        Ok(n)
    };
    assert!(probed("B not ready")? <= 2, "B is not probed while not ready");
    assert_eq!(balancing_members(&t, Family::V4)?, ["ppp0", "wana"]);
    faults.disarm()?;
    wait_members(&t, Family::V4, &["ppp0", "wana", "wanb"], Duration::from_secs(70))?;
    f.wait_log(&t, "desired state fully applied", 1, Duration::from_secs(5))?;
    assert!(probed("B ready")? > 2, "control: probes of a ready B are counted");
    f.stop()?;
    Ok(())
}

/// AS-27, startup: the global settings fail from the start. The daemon
/// starts, changes no route or rule until they apply, then installs
/// everything (FR-REC-3, FR-REC-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as27_startup_with_a_global_setting_failing() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    let faults = Faults::new(&mut f);
    faults.arm_matching("sysctls (global)")?;
    f.start(&t)?;
    f.wait_log(&t, "apply_failed", 2, Duration::from_secs(10))?;
    assert!(
        polywan_rules(&t, Family::V4)?.is_empty(),
        "no rule before the global settings"
    );
    assert!(
        balancing_members(&t, Family::V4)?.is_empty(),
        "no route before the global settings"
    );
    faults.disarm()?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(70))?;
    f.wait_log(&t, "desired state fully applied", 1, Duration::from_secs(5))?;
    f.stop()?;
    Ok(())
}

/// AS-27, an interface recreated while its settings wait for a long
/// backoff gets them at once: the backoff belonged to the old interface.
#[test]
#[ignore = "needs root and network namespaces"]
fn as27_a_recreated_interface_gets_its_settings_at_once() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&abc()))?;
    let faults = Faults::new(&mut f);
    f.start(&t)?;
    f.wait_installed(&t)?;
    let all = ["ppp0", "wana", "wanb"];
    wait_members(&t, Family::V4, &all, Duration::from_secs(15))?;
    faults.arm_matching("sysctls (ppp0)")?;
    t.pppoe_reset()?;
    // Six failures: C's next retry is about 32 s away.
    t.wait_for("C's settings failing repeatedly", Duration::from_secs(60), || {
        Ok(faults.steps().iter().filter(|s| s.ends_with(" failed")).count() >= 6)
    })?;
    faults.disarm()?;
    let before = t.ifindex("ppp0");
    t.pppoe_reset()?;
    t.wait_for("a new ppp0", Duration::from_secs(20), || {
        Ok(t.ifindex("ppp0").is_some_and(|i| Some(i) != before))
    })?;
    t.wait_for("C's settings on the new ppp0", Duration::from_secs(4), || {
        Ok(t.router().sysctl_get("net.ipv4.conf.ppp0.src_valid_mark")? == "1")
    })?;
    wait_members(&t, Family::V4, &all, Duration::from_secs(15))?;
    f.stop()?;
    Ok(())
}

/// AS-27, cleanup step by step: a failure injected after each step of
/// `cleanup` leaves the artifacts not yet removed in place, a second
/// `cleanup` completes, and foreign objects are untouched; the steps follow
/// FR-REC-4: nftables table, final guard, lookup rules by increasing
/// precedence (each source guard before its source rule), class guards,
/// routes, sysctls, state files and manifest.
#[test]
#[ignore = "needs root and network namespaces"]
fn as27_cleanup_step_by_step() -> Result<()> {
    let t = build();
    t.router().ip("rule add pref 950 lookup 5")?;
    t.router().sh(&flowtable("unrelated", "lo"))?;
    let foreign = foreign_objects(&t)?;
    let config = polywan::ipv4(&abc());
    let mut f = t.prepare_polywan(&config)?;
    let faults = Faults::new(&mut f);
    let mut order = Vec::new();
    for k in 0.. {
        f.start(&t)?;
        f.wait_installed(&t)?;
        f.stop()?;
        let installed = polywan_rules(&t, Family::V4)?.len();
        faults.arm(k)?;
        let out = f.cli_config(&["cleanup"])?;
        let steps = faults.steps();
        faults.disarm()?;
        if out.status.success() {
            assert!(!steps.iter().any(|s| s.ends_with(" failed")), "{steps:?}");
            order = steps;
            assert!(polywan_rules(&t, Family::V4)?.is_empty());
            break;
        }
        assert_eq!(steps.len(), k + 1, "{steps:?}");
        let removed = steps.iter().filter(|s| s.starts_with("delete ipv4 rule")).count();
        let removed = removed - usize::from(steps[k].starts_with("delete ipv4 rule"));
        assert_eq!(
            polywan_rules(&t, Family::V4)?.len(),
            installed - removed,
            "after {k} steps: {steps:?}"
        );
        let nft_gone = k > 0;
        assert_eq!(
            t.router()
                .output("nft", ["list", "table", "inet", "polywan"])?
                .status
                .success(),
            !nft_gone,
            "the nftables table goes first"
        );
        let out = f.cli_config(&["cleanup"])?;
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(polywan_rules(&t, Family::V4)?.is_empty(), "a second cleanup completes");
        assert_eq!(foreign_objects(&t)?, foreign, "foreign objects untouched");
    }
    assert_eq!(foreign_objects(&t)?, foreign, "foreign objects untouched");
    // FR-REC-4 order. Rule offsets from rule_priority_base (1000): final
    // guard 699, balancing 600, source rules 501-563 each preceded by its
    // source guard 564 (source rules match disjoint addresses, so their
    // relative order is free), policy 3xx-4xx, path 2xx, main bypass 100,
    // probe 1-63, class guards 64, 264, 464.
    let stage = |s: &str| -> u8 {
        match s
            .strip_prefix("delete ipv4 rule ")
            .map(|p| p.parse::<u32>().unwrap_or(0) - 1000)
        {
            Some(64 | 264 | 464) => 2,
            Some(_) => 1,
            None if s == "remove the nftables table" => 0,
            None if s.starts_with("delete ipv4 route") => 3,
            None if s == "restore sysctls" => 4,
            None => 5,
        }
    };
    let stages: Vec<u8> = order.iter().map(|s| stage(s)).collect();
    assert!(stages.windows(2).all(|w| w[0] <= w[1]), "{order:#?}");
    assert_eq!(stages.first(), Some(&0), "{order:#?}");
    let offsets: Vec<u32> = order
        .iter()
        .filter_map(|s| s.strip_prefix("delete ipv4 rule "))
        .map(|p| p.parse::<u32>().unwrap_or(0) - 1000)
        .filter(|o| ![64, 264, 464].contains(o))
        .collect();
    assert_eq!(offsets.first(), Some(&699), "{order:#?}");
    for (i, o) in offsets.iter().enumerate() {
        if *o == 564 {
            assert!(
                offsets.get(i + 1).is_some_and(|n| (501..=563).contains(n)),
                "a source guard right before its source rule: {order:#?}"
            );
        }
    }
    let levels: Vec<u32> = offsets
        .iter()
        .map(|o| if (501..=564).contains(o) { 501 } else { *o })
        .collect();
    assert!(
        levels.windows(2).all(|w| w[0] >= w[1]),
        "lookup rules by increasing precedence: {order:#?}"
    );
    assert_eq!(
        order.last().map(String::as_str),
        Some("remove the state files and the manifest")
    );
    Ok(())
}

per_family!(as36_active_set_updates_under_new_connections);

/// AS-36: active-set updates under a continuous stream of new connections,
/// each first rejected by an injected failure before any mutation. A's
/// probes fail while A still forwards: until the retry new connections keep
/// using the previous set {A, B}, after it only B; then A recovers and,
/// after the rejected update is retried, rejoins. No new connection of the
/// stream fails, pinned connections are uninterrupted and the status is
/// degraded until the update is complete. (With no policies yet, an update
/// rejected before any mutation has no partial state; the IPv6 failure after
/// the first insertion is `as36_ipv6_update_failing_after_the_first_insertion`.)
fn as36_active_set_updates_under_new_connections(fam: Family) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let t = build();
    let mut f = t.prepare_polywan(&stack(fam, &ab()))?;
    let faults = Faults::new(&mut f);
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    t.reset_counters()?;
    let flows: Vec<_> = (80..86)
        .map(|n| t.start_flow(Node::Client, testbed::plan::server(fam, n), Duration::from_millis(50)))
        .collect::<Result<_>>()?;
    // Stops the stream also when an assertion below panics: the scope joins
    // the stream thread before it propagates the panic.
    struct StopOnDrop<'a>(&'a AtomicBool);
    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| -> Result<()> {
        let stopping = StopOnDrop(&stop);
        let stream = s.spawn(|| -> Result<Vec<testbed::ConnResult>> {
            let mut all = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                all.extend(t.connect_many(Node::Client, fam, 20, 20, false)?);
            }
            Ok(all)
        });
        let result = (|| -> Result<()> {
            let phase = |expected: &[Uplink], what: &str| -> Result<()> {
                let r = t.connect_many(Node::Client, fam, 30, 60, false)?;
                let used: std::collections::BTreeSet<Option<Uplink>> = r.iter().map(|c| c.uplink()).collect();
                let expected: std::collections::BTreeSet<Option<Uplink>> = expected.iter().copied().map(Some).collect();
                assert_eq!(used, expected, "{what}: {:?}", tally(&r));
                Ok(())
            };
            for (change, before, after) in [
                ("A out", vec![Uplink::A, Uplink::B], vec![Uplink::B]),
                ("A back", vec![Uplink::B], vec![Uplink::A, Uplink::B]),
            ] {
                let recovered = f.log().matches("desired state fully applied").count();
                // Only this family's routes: in the IPv6 variant (dual-stack)
                // A's IPv4 path fails too, and a rejected IPv4 update and its
                // retry would otherwise stand for the IPv6 boundary.
                faults.arm_matching(&format!("{fam} route"))?;
                if change == "A out" {
                    t.drop_probe_echoes(Uplink::A, 1)?;
                } else {
                    t.clear_provider_rules(Uplink::A)?;
                }
                t.wait_for(
                    &format!("{change}: the update rejected"),
                    Duration::from_secs(15),
                    || Ok(faults.injected()),
                )?;
                assert!(
                    faults
                        .steps()
                        .iter()
                        .filter(|s| s.contains(&format!("{fam} route")))
                        .all(|s| s.ends_with(" failed")),
                    "rejected before any mutation: {:?}",
                    faults.steps()
                );
                phase(&before, &format!("{change}, before the boundary"))?;
                faults.disarm()?;
                f.wait_log(
                    &t,
                    "desired state fully applied",
                    recovered + 1,
                    Duration::from_secs(70),
                )?;
                phase(&after, &format!("{change}, after the boundary"))?;
            }
            Ok(())
        })();
        drop(stopping);
        let all = stream.join().expect("stream thread")?;
        result?;
        assert!(all.len() >= 40, "a continuous stream: {} connections", all.len());
        assert!(
            all.iter().all(|c| c.outcome == Outcome::Ok),
            "every new connection succeeds: {:?}",
            tally(&all)
        );
        Ok(())
    })?;
    let log = f.log();
    assert_eq!(log.matches("status_degraded").count(), 2, "{log}");
    assert_eq!(log.matches("status_recovered").count(), 2, "{log}");
    let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    for r in &reports {
        assert!(r.continuous(Duration::from_secs(1)), "pinned flow interrupted: {r:?}");
    }
    assert_eq!(t.leaks(fam)?, 0, "INV-3");
    Ok(())
}

/// AS-36 (IPv6): an update rejected before any mutation behaves as for
/// IPv4 (the previous set until the retry, then the target set); then the
/// failure after the first insertion, simulated by the test hook because
/// the kernel's needs an allocation failure: the old route is gone and the
/// new one not installed. The empty balancing table is seen, new
/// connections are rejected without leaking and without leaving through an
/// uplink, pinned connections are not affected, the status is degraded,
/// and the retry restores the target set (FR-ROUTE-2).
#[test]
#[ignore = "needs root and network namespaces"]
fn as36_ipv6_update_failing_after_the_first_insertion() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::family(&ab(), Family::V6))?;
    let faults = Faults::new(&mut f);
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(10))?;
    // No more advertisements (their routes last 30 minutes): the address
    // updates they cause re-read the uplinks' tables, the balancing table
    // included, which would hide whether the failed update's own re-read
    // happens.
    for p in [Node::IspA, Node::IspB] {
        t.ns(p).nft(
            "table inet tb_ra {\n  chain out {\n    type filter hook output priority 0; policy accept;\n    icmpv6 type nd-router-advert drop\n  }\n}\n",
        )?;
    }
    std::thread::sleep(Duration::from_secs(1));
    t.reset_counters()?;
    let flows = start_flows(&t, Family::V6, 80, 6)?;
    let phase = |expected: &[Uplink], what: &str| -> Result<()> {
        let r = t.connect_many(Node::Client, Family::V6, 30, 60, false)?;
        let used: std::collections::BTreeSet<Option<Uplink>> = r.iter().map(|c| c.uplink()).collect();
        let expected: std::collections::BTreeSet<Option<Uplink>> = expected.iter().copied().map(Some).collect();
        assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{what}: {:?}", tally(&r));
        assert_eq!(used, expected, "{what}: {:?}", tally(&r));
        Ok(())
    };
    // A leaves, the update first rejected before any mutation.
    faults.arm(0)?;
    t.drop_probe_echoes(Uplink::A, 1)?;
    t.wait_for("the update rejected", Duration::from_secs(15), || Ok(faults.injected()))?;
    phase(&[Uplink::A, Uplink::B], "before the boundary")?;
    faults.disarm()?;
    f.wait_log(&t, "desired state fully applied", 1, Duration::from_secs(70))?;
    phase(&[Uplink::B], "after the boundary")?;
    // A comes back; the replacement fails after its first insertion. The
    // test hook hides the deletion's notification from the daemon, as a
    // kernel failure need not send one.
    faults.arm_empty("replace ipv6 route of table 1000")?;
    t.clear_provider_rules(Uplink::A)?;
    t.wait_for(
        "the failure injected",
        Duration::from_secs(15),
        || Ok(faults.injected()),
    )?;
    assert!(balancing_members(&t, Family::V6)?.is_empty(), "the old route is gone");
    let dsts = format!(
        "ip6 daddr {}-{}",
        testbed::plan::server(Family::V6, 150),
        testbed::plan::server(Family::V6, 159)
    );
    counter(&t, "left", &format!("oifname {{ \"wana\", \"wanb\" }} {dsts}"))?;
    let rejected = t.connect_to(
        Node::Client,
        &servers(Family::V6, 150, 10, TCP_PORT),
        20,
        false,
        Duration::from_secs(2),
    )?;
    assert!(
        rejected.iter().all(|c| c.outcome != Outcome::Ok),
        "new connections rejected by the final guard: {:?}",
        tally(&rejected)
    );
    assert_eq!(
        counter_value(&t, "left")?,
        0,
        "nothing of them leaves through an uplink"
    );
    assert_eq!(t.ipv6_leaks()?, 0, "INV-3, INV-4");
    assert!(f.log().contains("multipath route replace failed") || f.log().contains("failure injected"));
    // A fails again before the retry: the target is the previous set, {B},
    // which the daemon's view would still hold without the re-read of the
    // table after the failure, leaving the table empty.
    t.drop_probe_echoes(Uplink::A, 1)?;
    f.wait_log(&t, "uplink=1 family=ipv6 from=Up to=Down", 2, Duration::from_secs(15))?;
    faults.disarm()?;
    f.wait_log(&t, "desired state fully applied", 2, Duration::from_secs(70))?;
    wait_members(&t, Family::V6, &["wanb"], Duration::from_secs(5))?;
    phase(&[Uplink::B], "after the retry")?;
    t.clear_provider_rules(Uplink::A)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(15))?;
    phase(&[Uplink::A, Uplink::B], "A back")?;
    let log = f.log();
    assert_eq!(log.matches("status_degraded").count(), 2, "{log}");
    assert_eq!(log.matches("status_recovered").count(), 2, "{log}");
    let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    for r in &reports {
        assert!(r.continuous(Duration::from_secs(1)), "pinned flow interrupted: {r:?}");
    }
    assert_eq!(t.ipv6_leaks()?, 0, "INV-3");
    Ok(())
}
