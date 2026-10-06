//! M2 acceptance scenarios (SPEC.md §14.3, §17) that exist only for IPv6
//! or for both families together; the IPv6 variants of the M1 scenarios are
//! in `m1.rs`. The daemon under test (`POLYWAN_DAEMON_BIN`) runs in the router
//! namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::Result;
use testbed::dhcpv6::{DELEGATED_POOL, DHCPV6_T1, DHCPV6_T2, DHCPV6_UNICAST, DHCPV6_VALID, Dhcpv6Client};
use testbed::plan::{self, Family, Node, Uplink};
use testbed::polywan;
use testbed::traffic::tally;

mod common;
use common::*;

/// AS-12: IPv6 fails on A while IPv4 stays healthy; only the IPv6 path of A
/// is removed, and it comes back when its probes pass again.
#[test]
#[ignore = "needs root and network namespaces"]
fn as12_ipv6_fails_on_a_while_ipv4_stays_healthy() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::dual(&ab()))?;
    f.wait_installed(&t)?;
    for fam in Family::ALL {
        wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    }
    let targets: Vec<String> = plan::PROBE_TARGETS_V6.iter().map(|a| a.to_string()).collect();
    t.provider_rules(
        Uplink::A,
        &[format!(
            "iifname != \"core\" ip6 daddr {{ {} }} icmpv6 type echo-request drop",
            targets.join(", ")
        )],
    )?;
    wait_members(&t, Family::V6, &["wanb"], Duration::from_secs(10))?;
    assert_eq!(balancing_members(&t, Family::V4)?, ["wana", "wanb"]);
    let log = f.log();
    assert!(
        log.contains("uplink=1 family=ipv6 from=Up to=Down reason=probe_failed"),
        "{log}"
    );
    assert!(!log.contains("uplink=1 family=ipv4 from=Up to=Down"), "{log}");
    let v6 = t.connect_many(Node::Client, Family::V6, 20, 100, false)?;
    assert_eq!(tally(&v6).get(&Some(Uplink::B)), Some(&100), "{:?}", tally(&v6));
    let v4 = t.connect_many(Node::Client, Family::V4, 20, 100, false)?;
    let counts = tally(&v4);
    assert!(
        counts.get(&Some(Uplink::A)).is_some_and(|n| *n > 0) && counts.values().sum::<usize>() == 100,
        "IPv4 still balanced over A and B: {counts:?}"
    );
    t.clear_provider_rules(Uplink::A)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(15))?;
    Ok(())
}

/// AS-45(b): a reload removes the last IPv6 path of a dual-stack
/// configuration while pinned IPv4 connections run: IPv6 is handed back as
/// FR-REC-9 describes (rules, routes and nftables rules of IPv6 gone, IPv6
/// settings restored to what they were before PolyWAN), and the IPv4
/// connections are not interrupted.
#[test]
#[ignore = "needs root and network namespaces"]
fn as45b_reload_hands_ipv6_back_without_touching_ipv4() -> Result<()> {
    let t = build();
    let before = sysctl_values(&t, &IPV6_SETTINGS)?;
    let f = t.start_polywan(&polywan::dual(&ab()))?;
    f.wait_installed(&t)?;
    for fam in Family::ALL {
        wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    }
    assert_eq!(
        t.router().sysctl_get("net/ipv6/fib_multipath_hash_policy")?,
        "1",
        "FR-ROUTE-5"
    );
    let flows = start_flows(&t, Family::V4, 1, 20)?;
    std::thread::sleep(Duration::from_secs(1));
    f.write_config(&polywan::ipv4(&ab()))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    t.wait_for("IPv6 handed back", Duration::from_secs(10), || {
        Ok(ipv6_artifacts(&t)?.is_empty() && sysctl_values(&t, &IPV6_SETTINGS)? == before)
    })?;
    let table = t.router().run("nft", ["list", "table", "inet", "polywan"])?;
    assert!(table.contains("meta nfproto != ipv4 return"), "{table}");
    std::thread::sleep(Duration::from_secs(1));
    flows_on_continuous(flows, &[Uplink::A, Uplink::B])?;
    // IPv6 follows the operating system again: here, the harness's leak6
    // default route of the main table.
    t.reset_counters()?;
    t.connect_many(Node::Client, Family::V6, 5, 5, false)?;
    assert!(t.ipv6_leaks()? > 0, "IPv6 routed by the main table");
    assert_eq!(balancing_members(&t, Family::V4)?, ["wana", "wanb"]);
    Ok(())
}

/// AS-19, IPv6 part: a reload adds IPv6 to the uplinks of a running
/// IPv4-only configuration (the reverse of AS-45(b)). IPv6 is installed and
/// its new connections are balanced over both uplinks without leaks, its
/// long-lived connections keep their uplink, and the pinned IPv4
/// connections are not interrupted. Each new path joins the balancing route
/// only after its assignment exists, also while the replacement that
/// installs it fails (FR-REC-3 for a path).
#[test]
#[ignore = "needs root and network namespaces"]
fn as19_reload_adds_ipv6_to_running_ipv4_uplinks() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    // The replacement that installs the IPv6 assignments fails at first.
    let (wrapper, flag) = nft_wrapper(&t, &f, &["-f"], NFT_FAILS)?;
    let firewall = format!("[firewall]\nnft_path = \"{}\"\n", wrapper.display());
    let config = |families: &[Family]| polywan::config(&ab(), families, &polywan::HealthSpec::fast(), "", &firewall);
    f.write_config(&config(&[Family::V4]))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let flows4 = start_flows(&t, Family::V4, 1, 20)?;
    std::thread::sleep(Duration::from_secs(1));
    std::fs::write(&flag, "")?;
    f.write_config(&config(&Family::ALL))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    f.wait_log(&t, "apply_failed", 1, Duration::from_secs(10))?;
    // Paths added by reload start down and need `rise` passed rounds: once
    // both are up, they stay out of the balancing route while their
    // assignments are missing.
    f.wait_log(&t, "family=ipv6 from=Down to=Up", 2, Duration::from_secs(20))?;
    for _ in 0..4 {
        assert!(
            balancing_members(&t, Family::V6)?.is_empty(),
            "no IPv6 path before its assignment"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    std::fs::remove_file(&flag)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(70))?;
    t.reset_counters()?;
    let r = t.connect_many(Node::Client, Family::V6, 50, 200, false)?;
    let counts = tally(&r);
    assert!(
        r.iter().all(|c| c.outcome == testbed::Outcome::Ok)
            && counts.get(&Some(Uplink::A)).is_some_and(|n| *n > 0)
            && counts.get(&Some(Uplink::B)).is_some_and(|n| *n > 0),
        "{counts:?}"
    );
    assert_eq!(t.ipv6_leaks()?, 0, "INV-3");
    let flows6 = start_flows(&t, Family::V6, 20, 20)?;
    std::thread::sleep(Duration::from_secs(2));
    flows_on_continuous(flows6, &[Uplink::A])?;
    flows_on_continuous(flows4, &[Uplink::A, Uplink::B])
}

/// Removes the Router Advertisement default routes of an interface of the
/// router (after their advertisements stop or move to another address).
fn drop_ra_default_routes(t: &testbed::Topology, iface: &str) -> Result<()> {
    for _ in 0..8 {
        let out = t
            .router()
            .output("ip", ["-6", "route", "del", "default", "proto", "ra", "dev", iface])?;
        if !out.status.success() {
            break;
        }
    }
    Ok(())
}

/// The seconds left before the Router Advertisement default route of an
/// interface expires, as `ip route` shows them.
fn ra_expiry(t: &testbed::Topology, iface: &str) -> Result<Option<u64>> {
    let text = t
        .router()
        .run("ip", ["-6", "route", "show", "default", "proto", "ra", "dev", iface])?;
    Ok(text
        .split_whitespace()
        .skip_while(|w| *w != "expires")
        .nth(1)
        .and_then(|w| w.trim_end_matches("sec").parse().ok()))
}

/// AS-28: the same link-local gateway `fe80::1` on two uplinks: both paths
/// are usable independently, probes included (INV-6); then the default
/// router of A expires (its advertisements stop) and A is not ready within
/// the bound of FR-DISC-5 after the expiry, although the kernel collects
/// the expired route without a notification.
#[test]
#[ignore = "needs root and network namespaces"]
fn as28_identical_link_local_gateways_and_router_expiry() -> Result<()> {
    let t = build();
    for u in [Uplink::A, Uplink::B] {
        let ns = t.ns(u.provider());
        ns.ip("-6 addr flush dev wan scope link")?;
        ns.ip("addr add fe80::1/64 dev wan nodad")?;
        // dnsmasq takes its advertisements' source when it starts.
        t.set_router_lifetime(u, 1800)?;
    }
    for iface in ["wana", "wanb"] {
        drop_ra_default_routes(&t, iface)?;
    }
    t.wait_for(
        "RA default routes via fe80::1 on A and B",
        Duration::from_secs(15),
        || {
            Ok([Uplink::A, Uplink::B]
                .iter()
                .all(|u| gateway(&t, Family::V6, *u).is_ok_and(|g| g == "fe80::1")))
        },
    )?;
    let mut f = t.prepare_polywan(&polywan::family(&ab(), Family::V6))?;
    f.set_env("POLYWAN_LOG", "debug");
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(10))?;
    assert!(path_route(&t, Family::V6, 1001)?.contains("via fe80::1 dev wana"));
    assert!(path_route(&t, Family::V6, 1002)?.contains("via fe80::1 dev wanb"));
    t.reset_counters()?;
    let r = t.connect_many(Node::Client, Family::V6, 50, 200, false)?;
    let counts = tally(&r);
    assert!(
        counts.get(&Some(Uplink::A)).is_some_and(|n| *n > 0)
            && counts.get(&Some(Uplink::B)).is_some_and(|n| *n > 0)
            && counts.values().sum::<usize>() == 200,
        "{counts:?}"
    );
    assert_eq!(t.ipv6_leaks()?, 0, "INV-3");
    // A short router lifetime, then no more advertisements.
    t.set_router_lifetime(Uplink::A, 8)?;
    t.wait_for(
        "A's default route with the short lifetime",
        Duration::from_secs(15),
        || Ok(ra_expiry(&t, "wana")?.is_some_and(|s| s <= 8)),
    )?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(15))?;
    t.ns(Node::IspA).nft(
        "table inet tb_ra {\n  chain out {\n    type filter hook output priority 0; policy accept;\n    icmpv6 type nd-router-advert drop\n  }\n}\n",
    )?;
    let start = std::time::Instant::now();
    let left = ra_expiry(&t, "wana")?.expect("A's default route");
    t.wait_for("A's path route withdrawn", Duration::from_secs(left + 5), || {
        Ok(path_route(&t, Family::V6, 1001)?.is_empty())
    })?;
    let took = start.elapsed();
    // `expires` is rounded down to the second: the route expires within
    // `left + 1` s, and PolyWAN acts within the following second.
    assert!(
        took <= Duration::from_secs(left + 2) && took + Duration::from_secs(1) >= Duration::from_secs(left),
        "withdrawn after {took:?}, expiry in {left} s"
    );
    wait_members(&t, Family::V6, &["wanb"], Duration::from_secs(2))?;
    assert!(
        f.log()
            .contains("uplink=1 family=ipv6 from=Up to=Down reason=gateway_lost"),
        "{}",
        f.log()
    );
    assert!(path_route(&t, Family::V6, 1002)?.contains("via fe80::1 dev wanb"));
    Ok(())
}

/// FR-DISC-5: an advertisement without prefix information shortens the
/// router lifetime of A's default route. The kernel notifies neither the
/// change nor the later expiry, and sends no `RTM_NEWPREFIX`: PolyWAN sees the
/// advertisement itself, and A is not ready within a second of the expiry.
#[test]
#[ignore = "needs root and network namespaces"]
fn fr_disc_5_lifetime_shortened_without_prefix_information() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), Family::V6))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(10))?;
    let before = ra_expiry(&t, "wana")?.expect("A's default route");
    assert!(before > 60, "A's router lifetime: {before} s");
    options_free_ras(&t)?;
    send_short_ra(&t, 4)?;
    t.wait_for(
        "A's default route with the short lifetime",
        Duration::from_secs(5),
        || Ok(ra_expiry(&t, "wana")?.is_some_and(|s| s <= 4)),
    )?;
    withdrawn_at_expiry(&t)
}

/// FR-DISC-5, carried over from M2: A's default route is created again
/// (notified) with a short router lifetime, which advertisements without
/// prefix information then refresh before each expiry. The kernel notifies
/// no refresh: A stays ready across every previously known expiry, and is
/// not ready within a second of the last one once the refreshes stop.
#[test]
#[ignore = "needs root and network namespaces"]
fn fr_disc_5_lifetime_refreshed_without_a_notification() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), Family::V6))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(10))?;
    options_free_ras(&t)?;
    // The route's creation is notified with its expiry; its refreshes, every
    // 3 s, are not.
    drop_ra_default_routes(&t, "wana")?;
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| -> Result<()> {
        let refresher = s.spawn(|| -> Result<()> {
            let mut last: Option<Instant> = None;
            while !stop.load(Ordering::Relaxed) {
                if last.is_none_or(|l| l.elapsed() >= Duration::from_secs(3)) {
                    send_short_ra(&t, 6)?;
                    last = Some(Instant::now());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(())
        });
        let watched = (|| -> Result<()> {
            wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(10))?;
            assert!(ra_expiry(&t, "wana")?.is_some_and(|s| s <= 6));
            let cursor = f.latest_event()?;
            // 15 s cross four expiries of 6 s.
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(15) {
                anyhow::ensure!(
                    !path_route(&t, Family::V6, 1001)?.is_empty(),
                    "A withdrawn {:?} into the refreshes",
                    start.elapsed()
                );
                std::thread::sleep(Duration::from_millis(200));
            }
            let changes: Vec<_> = f
                .events()?
                .into_iter()
                .filter(|(seq, kind, _)| *seq > cursor && kind == "path_state_changed")
                .collect();
            anyhow::ensure!(changes.is_empty(), "{changes:?}");
            Ok(())
        })();
        stop.store(true, Ordering::Relaxed);
        refresher.join().expect("refresher")?;
        watched
    })?;
    // No more refreshes: A goes at the last expiry.
    withdrawn_at_expiry(&t)
}

/// From now on only advertisements without options leave the providers
/// (56 bytes with the IPv6 header). dnsmasq's carry prefix information:
/// their RTM_NEWPREFIX, B's too, would re-read the main table, which holds
/// both default routes. Advertisements already sent arrive first.
fn options_free_ras(t: &testbed::Topology) -> Result<()> {
    for p in [Node::IspA, Node::IspB] {
        t.ns(p).nft(
            "table inet tb_ra {\n  chain out {\n    type filter hook output priority 0; policy accept;\n    icmpv6 type nd-router-advert meta length != 56 drop\n  }\n}\n",
        )?;
    }
    std::thread::sleep(Duration::from_secs(1));
    Ok(())
}

/// An advertisement without options from A's provider with a router
/// lifetime of `lifetime` seconds.
fn send_short_ra(t: &testbed::Topology, lifetime: u32) -> Result<()> {
    t.ns(Node::IspA).run(
        &t.agent_bin().to_string_lossy(),
        [
            "agent",
            "send-ra",
            "--device",
            "wan",
            "--lifetime",
            &lifetime.to_string(),
            // dnsmasq's managed and other-configuration flags (0xc0): a change of
            // flags would also notify the interface's IPv6 settings.
            "--flags",
            "192",
        ],
    )?;
    Ok(())
}

/// A's path route is withdrawn at the expiry of its default route, then B
/// is the only member.
fn withdrawn_at_expiry(t: &testbed::Topology) -> Result<()> {
    let start = std::time::Instant::now();
    let left = ra_expiry(t, "wana")?.unwrap_or(0);
    t.wait_for("A's path route withdrawn", Duration::from_secs(left + 5), || {
        Ok(path_route(t, Family::V6, 1001)?.is_empty())
    })?;
    let took = start.elapsed();
    // As in AS-28: `expires` is rounded down to the second.
    assert!(
        took <= Duration::from_secs(left + 2) && took + Duration::from_secs(1) >= Duration::from_secs(left),
        "withdrawn after {took:?}, expiry in {left} s"
    );
    wait_members(t, Family::V6, &["wanb"], Duration::from_secs(2))?;
    Ok(())
}

/// FR-DISC-5 under a flood of advertisements with prefix information on
/// A, 5,000 a second for three seconds, each renewing the lifetimes of A's
/// SLAAC address: the daemon gathers them, re-reading its tables a bounded
/// number of times, and still withdraws B within a second of its carrier
/// loss (AS-04's bound).
#[test]
#[ignore = "needs root and network namespaces"]
fn fr_disc_5_advertisement_flood() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::family(&ab(), Family::V6))?;
    f.set_env("POLYWAN_LOG", "debug");
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(10))?;
    let rereads = || f.log().matches("re-reading tables").count();
    let before = rereads();
    let started = std::time::Instant::now();
    let mut flood = t.ns(Node::IspA).spawn(
        &t.agent_bin().to_string_lossy(),
        [
            "agent",
            "send-ra",
            "--device",
            "wan",
            "--lifetime",
            "1800",
            "--flags",
            "192",
            "--prefix",
            "2001:db8:a:ffff::",
            "--count",
            "15000",
            "--interval-us",
            "200",
        ],
        &t.dir().join("flood.log"),
    )?;
    std::thread::sleep(Duration::from_secs(1));
    t.carrier_down(Uplink::B)?;
    wait_members(&t, Family::V6, &["wana"], Duration::from_secs(1))?;
    assert!(flood.wait()?.success(), "the flood was sent");
    let lasted = started.elapsed();
    let n = rereads() - before;
    eprintln!("{n} table re-reads during a flood of {lasted:?}");
    // About ten a second, one per window of the advertisements, plus B's
    // carrier loss; without gathering them, a thousand and more.
    assert!(
        n as f64 <= 15.0 * lasted.as_secs_f64() + 10.0,
        "{n} re-reads in {lasted:?}"
    );
    t.carrier_up(Uplink::B)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(15))?;
    Ok(())
}

/// AS-35: IPv6 over PPP with the peer's link-local gateway: C's path joins
/// and leaves a multi-member active set (single → multiple → single) and
/// every route installation succeeds. Then C reconnects with a new
/// interface: its IPv6 path comes back with its per-interface settings.
#[test]
#[ignore = "needs root and network namespaces"]
fn as35_ipv6_over_ppp_joins_and_leaves_a_multipath_route() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&abc(), Family::V6))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["ppp0", "wana", "wanb"], Duration::from_secs(10))?;
    assert!(path_route(&t, Family::V6, 1003)?.contains("via fe80::1 dev ppp0"));
    let only_c = || -> Result<()> {
        t.upstream_down(Uplink::A)?;
        t.upstream_down(Uplink::B)?;
        wait_members(&t, Family::V6, &["ppp0"], Duration::from_secs(10))?;
        let r = t.connect_many(Node::Client, Family::V6, 10, 50, false)?;
        assert_eq!(tally(&r).get(&Some(Uplink::C)), Some(&50), "{:?}", tally(&r));
        Ok(())
    };
    only_c()?;
    t.upstream_up(Uplink::A)?;
    t.upstream_up(Uplink::B)?;
    wait_members(&t, Family::V6, &["ppp0", "wana", "wanb"], Duration::from_secs(15))?;
    only_c()?;
    assert!(!f.log().contains("apply_failed"), "{}", f.log());
    // Reconnection: a new ppp0.
    let before = t.ifindex("ppp0").expect("ppp0");
    t.pppoe_reset()?;
    t.wait_for("a new ppp0 with its IPv6 address", Duration::from_secs(30), || {
        Ok(t.ifindex("ppp0").is_some_and(|i| i != before) && !address(&t, Family::V6, Uplink::C)?.is_empty())
    })?;
    t.wait_for("C's IPv6 path route on the new ppp0", Duration::from_secs(10), || {
        Ok(path_route(&t, Family::V6, 1003)?.contains("via fe80::1 dev ppp0"))
    })?;
    assert_eq!(
        t.router()
            .sysctl_get("net.ipv6.conf.ppp0.ignore_routes_with_linkdown")?,
        "1",
        "per-interface settings applied to the new interface"
    );
    wait_members(&t, Family::V6, &["ppp0"], Duration::from_secs(10))?;
    t.upstream_up(Uplink::A)?;
    t.upstream_up(Uplink::B)?;
    Ok(())
}

/// AS-49: a default route through a single nexthop object makes the path
/// ready through the object's gateway (as systemd-networkd 257 installs
/// Router Advertisement routes); replacing the object's gateway and
/// deleting the object are applied within the bound of FR-DISC-5. An IPv4
/// object's deletion, which removes its routes without a notification, is
/// seen as well. A default route through a nexthop group is not used, with
/// a warning that recommends a static gateway.
#[test]
#[ignore = "needs root and network namespaces"]
fn as49_nexthop_objects_and_groups() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::dual(&ab()))?;
    f.wait_installed(&t)?;
    for fam in Family::ALL {
        wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    }
    let r = t.router();
    let within = |what: &str, cond: &dyn Fn() -> Result<bool>| -> Result<()> {
        let took = t.wait_for(what, Duration::from_secs(3), cond)?;
        assert!(took <= Duration::from_secs(1), "{what} after {took:?}");
        Ok(())
    };
    // IPv4: an object with another gateway, better than the DHCP route.
    t.ns(Node::IspA).ip("addr add 192.0.2.254/24 dev wan")?;
    r.ip("nexthop add id 30 via 192.0.2.254 dev wana")?;
    r.ip("route add default nhid 30 metric 50")?;
    within("A's IPv4 path through the object", &|| {
        Ok(path_route(&t, Family::V4, 1001)?.contains("via 192.0.2.254"))
    })?;
    r.ip("nexthop del id 30")?;
    within("A's IPv4 path back on the DHCP route", &|| {
        Ok(path_route(&t, Family::V4, 1001)?.contains("via 192.0.2.1 "))
    })?;
    // IPv6: the RA default route of A replaced by one through an object.
    let ll = gateway(&t, Family::V6, Uplink::A)?;
    r.sysctl(&["net.ipv6.conf.wana.accept_ra_defrtr=0"])?;
    drop_ra_default_routes(&t, "wana")?;
    t.wait_for("A's IPv6 path route withdrawn", Duration::from_secs(3), || {
        Ok(path_route(&t, Family::V6, 1001)?.is_empty())
    })?;
    r.ip(&format!("nexthop add id 10 via {ll} dev wana"))?;
    r.ip("-6 route add default nhid 10 metric 512")?;
    within("A's IPv6 path through the object", &|| {
        Ok(path_route(&t, Family::V6, 1001)?.contains(&format!("via {ll} dev wana")))
    })?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(10))?;
    t.ns(Node::IspA).ip("addr add fe80::99/64 dev wan nodad")?;
    r.ip("nexthop replace id 10 via fe80::99 dev wana")?;
    within("the object's new gateway", &|| {
        Ok(path_route(&t, Family::V6, 1001)?.contains("via fe80::99 dev wana"))
    })?;
    let c = t.connect_many(Node::Client, Family::V6, 20, 100, false)?;
    assert!(c.iter().all(|c| c.outcome == testbed::Outcome::Ok), "{:?}", tally(&c));
    r.ip("nexthop del id 10")?;
    within("A not ready after the object's deletion", &|| {
        Ok(path_route(&t, Family::V6, 1001)?.is_empty())
    })?;
    wait_members(&t, Family::V6, &["wanb"], Duration::from_secs(2))?;
    // A group over both uplinks, the only IPv6 default route: not used.
    let llb = gateway(&t, Family::V6, Uplink::B)?;
    r.sysctl(&["net.ipv6.conf.wanb.accept_ra_defrtr=0"])?;
    r.ip("nexthop add id 11 via fe80::99 dev wana")?;
    r.ip(&format!("nexthop add id 12 via {llb} dev wanb"))?;
    r.ip("nexthop add id 20 group 11/12")?;
    r.ip("-6 route add default nhid 20 metric 256")?;
    drop_ra_default_routes(&t, "wanb")?;
    t.wait_for("no IPv6 path ready", Duration::from_secs(3), || {
        Ok(path_route(&t, Family::V6, 1001)?.is_empty() && path_route(&t, Family::V6, 1002)?.is_empty())
    })?;
    f.wait_log(
        &t,
        "use a nexthop group, which PolyWAN does not use",
        2,
        Duration::from_secs(2),
    )?;
    assert_eq!(
        f.log()
            .matches("use a nexthop group, which PolyWAN does not use")
            .count(),
        2,
        "{}",
        f.log()
    );
    assert_eq!(balancing_members(&t, Family::V4)?, ["wana", "wanb"], "IPv4 unaffected");
    Ok(())
}

/// FR-SYS-3: startup and online `check-config` warn about `accept_ra = 1`
/// on an uplink with an automatic IPv6 gateway while forwarding is enabled;
/// an IPv6 path without a discovered gateway 30 s after startup gets a
/// warning that names the likely causes. The daemon's test hook
/// `POLYWAN_TEST_GATEWAY_WARNING_MS` shortens the 30 s to 3 s.
#[test]
#[ignore = "needs root and network namespaces"]
fn fr_sys_3_router_advertisement_warnings() -> Result<()> {
    let t = build();
    let r = t.router();
    r.sysctl(&["net.ipv6.conf.wana.accept_ra=1"])?;
    // B: no Router Advertisement processing and no default route.
    r.sysctl(&["net.ipv6.conf.wanb.accept_ra=0"])?;
    drop_ra_default_routes(&t, "wanb")?;
    let f = t.prepare_polywan(&polywan::family(&ab(), Family::V6))?;
    let out = f.cli_config(&["check-config"])?;
    let text = polywan::output_text(&out);
    assert!(text.contains("wana has accept_ra = 1"), "{text}");
    let mut f = f;
    let delay = Duration::from_secs(3);
    f.set_env("POLYWAN_TEST_GATEWAY_WARNING_MS", &delay.as_millis().to_string());
    let started = std::time::Instant::now();
    f.start(&t)?;
    f.wait_installed(&t)?;
    let log = f.log();
    assert!(log.contains("wana has accept_ra = 1"), "{log}");
    // Read before the delay has passed since the start, the log cannot
    // hold the warning yet.
    if started.elapsed() < delay {
        assert!(
            !log.contains("no IPv6 default route discovered"),
            "not before {delay:?}"
        );
    }
    f.wait_log(
        &t,
        "no IPv6 default route discovered on wanb",
        1,
        delay + Duration::from_secs(10),
    )?;
    assert!(started.elapsed() >= delay, "not before {delay:?}: {}", f.log());
    assert!(
        f.log().contains("accept_ra = 0: the kernel does not process"),
        "{}",
        f.log()
    );
    assert_eq!(
        f.log().matches("no IPv6 default route discovered").count(),
        1,
        "once, and not for A: {}",
        f.log()
    );
    // Router Advertisements again: B's link comes up again, as a network
    // manager would bring it up, and its solicitation gets an advertisement
    // at once (the provider's next unsolicited one can be minutes away).
    r.sysctl(&["net.ipv6.conf.wanb.accept_ra=2"])?;
    t.router_link(Uplink::B, false)?;
    t.router_link(Uplink::B, true)?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(20))?;
    Ok(())
}

/// FR-DISC-6 and FR-NAT-1 for IPv6: an uplink without a global address of
/// its own (a prefix-delegation-only provider that routes the LAN prefix)
/// with the LAN address as static source and `nat = "snat"`; then an uplink
/// with `nat = "none"` whose provider routes the LAN prefix: the servers see
/// the router's LAN address, then the client's own address.
#[test]
#[ignore = "needs root and network namespaces"]
fn fr_disc_6_static_source_and_ipv6_nat_choices() -> Result<()> {
    let t = build();
    let lan_prefix = "2001:db8:1::/64";
    // The router's link-local address on an uplink, the next hop of the
    // provider's route to the LAN prefix.
    let ll = |iface: &str| -> Result<String> {
        Ok(t.addresses(iface, Family::V6, "link")?
            .first()
            .map(|a| a.local.to_string())
            .unwrap_or_default())
    };
    let route_lan_via = |u: Uplink, core: &str| -> Result<()> {
        t.inet().ip(&format!("-6 route replace {lan_prefix} via {core}"))?;
        let gw = ll(u.l3_iface())?;
        t.ns(u.provider())
            .ip(&format!("-6 route replace {lan_prefix} via {gw} dev wan"))?;
        Ok(())
    };
    // B loses its own global address.
    let r = t.router();
    r.sysctl(&["net.ipv6.conf.wanb.autoconf=0"])?;
    let b = address(&t, Family::V6, Uplink::B)?;
    r.ip(&format!("addr del {b}/64 dev wanb"))?;
    route_lan_via(Uplink::B, "2001:db8:fff0:b::2")?;
    let snat = polywan::family(
        &[polywan::UplinkSpec::new(Uplink::B, 2)
            .ipv6_nat(Some("snat"))
            .path(Family::V6, &format!("source = \"{}\"", plan::LAN_ROUTER_V6))],
        Family::V6,
    );
    let mut f = t.start_polywan(&snat)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["wanb"], Duration::from_secs(10))?;
    assert!(path_route(&t, Family::V6, 1002)?.contains(&format!("src {}", plan::LAN_ROUTER_V6)));
    t.reset_counters()?;
    let c = t.connect_many(Node::Client, Family::V6, 10, 50, false)?;
    assert!(
        c.iter().all(
            |c| c.outcome == testbed::Outcome::Ok && c.observed.map(|o| o.ip()) == Some(plan::LAN_ROUTER_V6.into())
        ),
        "{:?}",
        c.iter().map(|c| (c.outcome, c.observed)).take(3).collect::<Vec<_>>()
    );
    assert!(t.egress_packets(Uplink::B, Family::V6)? >= 100);
    assert_eq!(t.ipv6_leaks()?, 0);
    f.stop()?;
    // `nat = "none"` on A, whose provider now routes the LAN prefix.
    route_lan_via(Uplink::A, "2001:db8:fff0:a::2")?;
    let none = polywan::family(
        &[polywan::UplinkSpec::new(Uplink::A, 1).ipv6_nat(Some("none"))],
        Family::V6,
    );
    f.write_config(&none)?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V6, &["wana"], Duration::from_secs(10))?;
    let c = t.connect_many(Node::Client, Family::V6, 10, 50, false)?;
    assert!(
        c.iter().all(
            |c| c.outcome == testbed::Outcome::Ok && c.observed.map(|o| o.ip()) == Some(plan::LAN_CLIENT_V6.into())
        ),
        "{:?}",
        c.iter().map(|c| (c.outcome, c.observed)).take(3).collect::<Vec<_>>()
    );
    Ok(())
}

/// AS-33 for IPv6: a foreign rule in PolyWAN's IPv6 priority range, or a route
/// in its IPv6 table range, refuses online `check-config` and startup, and
/// the foreign objects stay.
#[test]
#[ignore = "needs root and network namespaces"]
fn as33_colliding_ipv6_rule_and_route() -> Result<()> {
    let t = build();
    for (setup, undo, needle) in [
        (
            "-6 rule add pref 1650 lookup 5",
            "-6 rule del pref 1650",
            "ipv6: a rule at priority 1650",
        ),
        (
            "-6 route add 2001:db8:77::/64 dev lan table 1005",
            "-6 route del 2001:db8:77::/64 dev lan table 1005",
            "ipv6: table 1005 contains a route",
        ),
    ] {
        t.router().ip(setup)?;
        assert_refused(&t, &polywan::dual(&ab()), needle)?;
        t.router().ip(undo)?;
    }
    let f = t.start_polywan(&polywan::dual(&ab()))?;
    f.wait_installed(&t)?;
    Ok(())
}

/// Undoes what the kernel did with the providers' advertisements on an
/// uplink while the topology came up, as on a router that has not
/// configured it yet: no global address, no default route.
fn unconfigure_ipv6(t: &testbed::Topology, u: Uplink) -> Result<()> {
    let iface = u.carrier_iface();
    let r = t.router();
    r.sysctl(&[
        &format!("net.ipv6.conf.{iface}.accept_ra=0"),
        &format!("net.ipv6.conf.{iface}.autoconf=0"),
    ])?;
    r.ip(&format!("-6 addr flush dev {iface} scope global"))?;
    drop_ra_default_routes(t, iface)
}

/// Brings an uplink up again with advertisements accepted, as a network
/// manager would: its router solicitations get the gateway and SLAAC.
fn configure_ipv6(t: &testbed::Topology, u: Uplink) -> Result<()> {
    let iface = u.carrier_iface();
    t.router().sysctl(&[
        &format!("net.ipv6.conf.{iface}.accept_ra=2"),
        &format!("net.ipv6.conf.{iface}.autoconf=1"),
    ])?;
    t.router_link(u, false)?;
    t.router_link(u, true)
}

/// AS-44 (IPv6 parts without prefix delegation): the router starts PolyWAN,
/// for both families, before any uplink is configured: no lease, no global
/// address, no default route, an empty active set. Then router
/// solicitation and advertisement, duplicate address detection (the router
/// performs it) and SLAAC on A and B, neighbour discovery for the gateways,
/// and PPPoE with IPv6CP and advertisements over PPP on C succeed, and both
/// families route without leaks (FR-CT-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as44_ipv6_boot_before_any_uplink_is_configured() -> Result<()> {
    let t = build_with(testbed::Options {
        uplink_clients: false,
        ..testbed::Options::default()
    });
    for u in [Uplink::A, Uplink::B] {
        unconfigure_ipv6(&t, u)?;
    }
    for u in Uplink::ALL {
        for fam in Family::ALL {
            assert_eq!(t.uplink_address(u, fam)?, None, "{u} has no {fam} address yet");
            assert_eq!(t.os_default_route(u, fam)?, None, "{u} has no {fam} default route yet");
        }
    }
    let f = t.start_polywan(&polywan::dual(&abc()))?;
    f.wait_installed(&t)?;
    for fam in Family::ALL {
        assert!(balancing_members(&t, fam)?.is_empty(), "empty {fam} active set");
        assert!(
            !polywan_rules(&t, fam)?.is_empty(),
            "PolyWAN's {fam} rules are installed"
        );
    }
    for u in [Uplink::A, Uplink::B] {
        configure_ipv6(&t, u)?;
    }
    t.start_uplink_clients()?;
    t.wait_ready()?;
    for fam in Family::ALL {
        wait_members(&t, fam, &["ppp0", "wana", "wanb"], Duration::from_secs(20))?;
    }
    assert!(path_route(&t, Family::V6, 1003)?.contains("via fe80::1 dev ppp0"));
    t.reset_counters()?;
    for fam in Family::ALL {
        let c = t.connect_many(Node::Client, fam, 30, 90, false)?;
        assert!(
            c.iter().all(|c| c.outcome == testbed::Outcome::Ok),
            "{fam}: {:?}",
            tally(&c)
        );
        assert_eq!(t.leaks(fam)?, 0, "INV-3 for {fam}");
    }
    Ok(())
}

/// DHCPv6 message types (RFC 8415), the first byte of the UDP payload.
const DHCPV6_REQUEST: u8 = 3;
const DHCPV6_RENEW: u8 = 5;
const DHCPV6_REBIND: u8 = 6;

/// Counters of the DHCPv6 messages that reach provider B's server (table
/// `inet t44`, input hook): `uni`, `request_uni` (Request messages) and
/// `renew` (Renew messages) at its unicast address from the uplink's link,
/// `request_multi` and `rebind` by multicast; messages to the server from
/// the internet are counted in `elsewhere` (Requests also in
/// `request_elsewhere`) and dropped, as by a provider whose DHCPv6 service
/// only its access network reaches.
fn dhcpv6_counters(t: &testbed::Topology) -> Result<()> {
    t.ns(Node::IspB).nft(&format!(
        "table inet t44 {{\n  counter uni {{}}\n  counter request_uni {{}}\n  counter request_multi {{}}\n  counter request_elsewhere {{}}\n  counter renew {{}}\n  counter rebind {{}}\n  counter elsewhere {{}}\n  chain in {{\n    type filter hook input priority -10; policy accept;\n    iifname != \"wan\" udp dport 547 @th,64,8 {DHCPV6_REQUEST} counter name request_elsewhere\n    iifname != \"wan\" udp dport 547 counter name elsewhere drop\n    ip6 daddr {DHCPV6_UNICAST} udp dport 547 counter name uni\n    ip6 daddr {DHCPV6_UNICAST} udp dport 547 @th,64,8 {DHCPV6_REQUEST} counter name request_uni\n    ip6 daddr {DHCPV6_UNICAST} udp dport 547 @th,64,8 {DHCPV6_RENEW} counter name renew\n    ip6 daddr ff02::1:2 udp dport 547 @th,64,8 {DHCPV6_REQUEST} counter name request_multi\n    ip6 daddr ff02::1:2 udp dport 547 @th,64,8 {DHCPV6_REBIND} counter name rebind\n  }}\n}}\n"
    ))
}

/// The router's DHCPv6 address on B (from the server's pool,
/// 2001:db8:b:ffff::1000-1fff) and its valid lifetime.
fn dhcpv6_lease(t: &testbed::Topology) -> Result<Option<(IpAddr, u64)>> {
    let pool: plan::Prefix = "2001:db8:b:ffff::1000/116".parse()?;
    Ok(t.addresses("wanb", Family::V6, "global")?
        .into_iter()
        .filter(|a| a.prefixlen == 128 && pool.contains(a.local))
        .find_map(|a| Some((a.local, a.valid_lft?))))
}

/// The router's LAN address from the prefix that B delegated, and its
/// valid lifetime (the delegated prefix's).
fn delegated_lan(t: &testbed::Topology) -> Result<Option<(IpAddr, u64)>> {
    let pool: plan::Prefix = DELEGATED_POOL.parse()?;
    Ok(t.addresses("lan", Family::V6, "global")?
        .into_iter()
        .filter(|a| pool.contains(a.local))
        .find_map(|a| Some((a.local, a.valid_lft?))))
}

fn delegated_lan_address(t: &testbed::Topology) -> Result<Option<IpAddr>> {
    Ok(delegated_lan(t)?.map(|(a, _)| a))
}

/// AS-44 (DHCPv6 with prefix delegation and the server-unicast variant):
/// PolyWAN runs for IPv6 on A and B before either is configured (empty active
/// set). B's provider runs a DHCPv6 server that delegates prefixes and
/// announces the server-unicast option at an address outside the uplink's
/// on-link prefix; the router's client (dhcpcd, or ISC dhclient where
/// dhcpcd is not installed) gets an address and a prefix, assigned to the
/// LAN, and renews at T1 by unicast through B while B is in the active set.
/// While B is out of the active set (its probes fail, A is up), its
/// unicast renewals do not reach B's link: dhcpcd leaves their route lookup
/// unbound, so they are balanced through A (and dropped, the provider's
/// service being out of reach from the internet); dhclient binds them to
/// B's interface with a link-local source, so the balancing table, without
/// B, rejects them and they never leave through A. Either way the client
/// keeps its lease by rebinding at T2 by multicast (FR-CT-5).
#[test]
#[ignore = "needs root and network namespaces"]
fn as44_dhcpv6_prefix_delegation_and_server_unicast() -> Result<()> {
    let client = Dhcpv6Client::detect()?;
    eprintln!("DHCPv6 client: {client:?}");
    let t = build_with(testbed::Options {
        uplink_clients: false,
        ..testbed::Options::default()
    });
    for u in [Uplink::A, Uplink::B] {
        unconfigure_ipv6(&t, u)?;
    }
    t.start_dhcpv6_server()?;
    dhcpv6_counters(&t)?;
    let f = t.start_polywan(&polywan::family(&ab(), Family::V6))?;
    f.wait_installed(&t)?;
    assert!(balancing_members(&t, Family::V6)?.is_empty(), "empty active set");

    // B comes up: advertisements and DHCPv6. dhcpcd sends its Request by
    // unicast (the Advertise carries the option), rejected until B joins
    // the active set. dhclient sends it by multicast; it starts once B is
    // the active set, so that its acquisition is seen with B in it (the
    // other scenario sees it with A in it).
    configure_ipv6(&t, Uplink::B)?;
    if client == Dhcpv6Client::Dhclient {
        wait_members(&t, Family::V6, &["wanb"], Duration::from_secs(20))?;
    }
    t.start_dhcpv6_client(client)?;
    t.wait_for(
        "B's DHCPv6 address and delegated prefix",
        Duration::from_secs(60),
        || Ok(dhcpv6_lease(&t)?.is_some() && delegated_lan_address(&t)?.is_some()),
    )?;
    wait_members(&t, Family::V6, &["wanb"], Duration::from_secs(20))?;
    let requests = |name| provider_counter(&t, Node::IspB, "inet", "t44", name);
    match client {
        Dhcpv6Client::Dhcpcd => assert!(requests("request_uni")? > 0, "dhcpcd's Request by unicast through B"),
        Dhcpv6Client::Dhclient => {
            assert!(requests("request_multi")? > 0, "dhclient's Request by multicast");
            assert_eq!(requests("request_uni")?, 0, "no Request by unicast");
        }
    }
    let (leased, _) = dhcpv6_lease(&t)?.expect("the lease just seen");
    let lan = delegated_lan_address(&t)?;
    // The address and the delegated prefix, both renewed: a lease kept
    // without its prefix would leave the LAN at the prefix's first expiry.
    let renewed = || -> Result<bool> {
        let fresh = |l: Option<(IpAddr, u64)>, address: Option<IpAddr>| {
            l.is_some_and(|(a, valid)| Some(a) == address && valid + 10 >= DHCPV6_VALID)
        };
        Ok(fresh(dhcpv6_lease(&t)?, Some(leased)) && fresh(delegated_lan(&t)?, lan))
    };

    // Renewal at T1 by unicast through B, the only member of the active set.
    t.wait_for(
        "a Renew by unicast on B's link",
        Duration::from_secs(DHCPV6_T1 + 10),
        || Ok(provider_counter(&t, Node::IspB, "inet", "t44", "renew")? > 0),
    )?;
    t.wait_for("the renewed lease", Duration::from_secs(5), &renewed)?;
    assert_eq!(
        provider_counter(&t, Node::IspB, "inet", "t44", "elsewhere")?,
        0,
        "every message went through B"
    );

    // B fails its probes and A comes up, before the next T1.
    t.drop_probe_echoes(Uplink::B, 1)?;
    configure_ipv6(&t, Uplink::A)?;
    wait_members(&t, Family::V6, &["wana"], Duration::from_secs(20))?;
    let renew = provider_counter(&t, Node::IspB, "inet", "t44", "renew")?;
    let rebind = provider_counter(&t, Node::IspB, "inet", "t44", "rebind")?;
    t.wait_for("a Rebind by multicast", Duration::from_secs(DHCPV6_T2 + 10), || {
        Ok(provider_counter(&t, Node::IspB, "inet", "t44", "rebind")? > rebind)
    })?;
    t.wait_for("the rebound lease", Duration::from_secs(5), &renewed)?;
    assert_eq!(
        provider_counter(&t, Node::IspB, "inet", "t44", "renew")?,
        renew,
        "no Renew by unicast reached B's link while B was out of the active set"
    );
    let elsewhere = provider_counter(&t, Node::IspB, "inet", "t44", "elsewhere")?;
    match client {
        Dhcpv6Client::Dhcpcd => assert!(elsewhere > 0, "dhcpcd's unbound renewals were balanced through A"),
        Dhcpv6Client::Dhclient => assert_eq!(elsewhere, 0, "dhclient's renewals never left through A"),
    }
    assert_eq!(delegated_lan_address(&t)?, lan, "the delegated prefix stays on the LAN");
    assert_eq!(t.ipv6_leaks()?, 0, "INV-3");
    Ok(())
}

/// AS-44 (DHCPv6 acquisition while another uplink is the active set,
/// FR-CT-5): A is the only member of the active set when B's DHCPv6
/// client starts, B's probes failing. dhcpcd sends its Request by unicast
/// (the Advertise carries the server-unicast option) with an unbound route
/// lookup: balanced through A, every retransmission too, and dropped by the
/// provider, so no lease until B replaces A in the active set; the next
/// retransmission then goes through B and the client gets its address and
/// prefix. ISC dhclient sends its Request by multicast: it gets them while
/// B is still out of the active set, and nothing goes through A.
#[test]
#[ignore = "needs root and network namespaces"]
fn as44_dhcpv6_acquisition_while_another_uplink_is_active() -> Result<()> {
    let client = Dhcpv6Client::detect()?;
    eprintln!("DHCPv6 client: {client:?}");
    let t = build_with(testbed::Options {
        uplink_clients: false,
        ..testbed::Options::default()
    });
    for u in [Uplink::A, Uplink::B] {
        unconfigure_ipv6(&t, u)?;
    }
    t.start_dhcpv6_server()?;
    dhcpv6_counters(&t)?;
    let f = t.start_polywan(&polywan::family(&ab(), Family::V6))?;
    f.wait_installed(&t)?;
    configure_ipv6(&t, Uplink::A)?;
    wait_members(&t, Family::V6, &["wana"], Duration::from_secs(20))?;
    t.drop_probe_echoes(Uplink::B, 1)?;
    configure_ipv6(&t, Uplink::B)?;
    t.start_dhcpv6_client(client)?;
    let acquired = || -> Result<bool> { Ok(dhcpv6_lease(&t)?.is_some() && delegated_lan_address(&t)?.is_some()) };
    let counter = |name| provider_counter(&t, Node::IspB, "inet", "t44", name);
    match client {
        Dhcpv6Client::Dhcpcd => {
            t.wait_for("three Requests balanced through A", Duration::from_secs(40), || {
                Ok(counter("request_elsewhere")? >= 3)
            })?;
            assert_eq!(
                balancing_members(&t, Family::V6)?,
                ["wana"],
                "B stayed out of the active set"
            );
            assert_eq!(dhcpv6_lease(&t)?, None, "no address while A is the active set");
            assert_eq!(delegated_lan_address(&t)?, None, "no prefix while A is the active set");
            assert_eq!(counter("request_uni")?, 0, "no Request by unicast reached B's link");
            assert_eq!(counter("request_multi")?, 0, "no Request by multicast");
            t.clear_provider_rules(Uplink::B)?;
            t.drop_probe_echoes(Uplink::A, 1)?;
            wait_members(&t, Family::V6, &["wanb"], Duration::from_secs(20))?;
            t.wait_for(
                "B's DHCPv6 address and delegated prefix through B",
                Duration::from_secs(60),
                &acquired,
            )?;
            assert!(counter("request_uni")? > 0, "the Request by unicast went through B");
        }
        Dhcpv6Client::Dhclient => {
            t.wait_for(
                "B's DHCPv6 address and delegated prefix",
                Duration::from_secs(60),
                &acquired,
            )?;
            assert_eq!(
                balancing_members(&t, Family::V6)?,
                ["wana"],
                "B stayed out of the active set"
            );
            assert!(counter("request_multi")? > 0, "dhclient's Request by multicast");
            assert_eq!(counter("request_uni")?, 0, "no Request by unicast");
            assert_eq!(counter("elsewhere")?, 0, "nothing went through A");
        }
    }
    assert_eq!(t.ipv6_leaks()?, 0, "INV-3");
    Ok(())
}
