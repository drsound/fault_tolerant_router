//! M2 acceptance scenarios (SPEC.md §14.3, §17) that exist only for IPv6
//! or for both families together; the IPv6 variants of the M1 scenarios are
//! in `m1.rs`. The daemon under test (`FTR_DAEMON_BIN`) runs in the router
//! namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::time::Duration;

use anyhow::Result;
use testbed::ftr;
use testbed::plan::{self, Family, Node, Uplink};
use testbed::traffic::tally;

mod common;
use common::*;

/// AS-12: IPv6 fails on A while IPv4 stays healthy; only the IPv6 path of A
/// is removed, and it comes back when its probes pass again.
#[test]
#[ignore = "needs root and network namespaces"]
fn as12_ipv6_fails_on_a_while_ipv4_stays_healthy() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::dual(&ab()))?;
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
/// settings restored to what they were before FTR), and the IPv4
/// connections are not interrupted.
#[test]
#[ignore = "needs root and network namespaces"]
fn as45b_reload_hands_ipv6_back_without_touching_ipv4() -> Result<()> {
    let t = build();
    let keys = [
        "net/ipv6/conf/all/forwarding",
        "net/ipv6/fib_multipath_hash_policy",
        "net/ipv6/conf/wana/ignore_routes_with_linkdown",
        "net/ipv6/conf/wanb/ignore_routes_with_linkdown",
    ];
    let read = |k: &str| t.router().sysctl_get(k);
    let before: Vec<String> = keys.iter().map(|k| read(k)).collect::<Result<_>>()?;
    let f = t.start_ftr(&ftr::dual(&ab()))?;
    f.wait_installed(&t)?;
    for fam in Family::ALL {
        wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    }
    assert_eq!(read("net/ipv6/fib_multipath_hash_policy")?, "1", "FR-ROUTE-5");
    let flows = start_flows(&t, Family::V4, 1, 16)?;
    std::thread::sleep(Duration::from_secs(1));
    f.write_config(&ftr::ipv4(&ab()))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    t.wait_for("IPv6 handed back", Duration::from_secs(10), || {
        let rules = t.router().run("ip", ["-6", "rule", "show"])?;
        let routes = t
            .router()
            .run("ip", ["-6", "route", "show", "table", "all", "proto", "249"])?;
        let restored: Vec<String> = keys.iter().map(|k| read(k)).collect::<Result<_>>()?;
        Ok(!rules.contains("proto 249") && routes.trim().is_empty() && restored == before)
    })?;
    let table = t
        .router()
        .run("nft", ["list", "table", "inet", "fault_tolerant_router"])?;
    assert!(!table.contains("meta nfproto ipv6 "), "{table}");
    assert!(table.contains("meta nfproto != ipv4 return"), "{table}");
    std::thread::sleep(Duration::from_secs(1));
    let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    for u in [Uplink::A, Uplink::B] {
        let on_u: Vec<_> = reports.iter().filter(|r| r.uplink() == Some(u)).collect();
        assert!(!on_u.is_empty(), "no flow ran on {u}: {reports:?}");
        for r in on_u {
            assert!(
                r.continuous(Duration::from_secs(1)),
                "IPv4 flow on {u} interrupted: {r:?}"
            );
        }
    }
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
/// only after its assignment exists (FR-REC-3 for a path).
#[test]
#[ignore = "needs root and network namespaces"]
fn as19_reload_adds_ipv6_to_running_ipv4_uplinks() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let flows4 = start_flows(&t, Family::V4, 1, 16)?;
    std::thread::sleep(Duration::from_secs(1));
    f.write_config(&ftr::dual(&ab()))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    // Paths added by reload start down and need `rise` passed rounds.
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(20))?;
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
    let flows6 = start_flows(&t, Family::V6, 20, 12)?;
    std::thread::sleep(Duration::from_secs(2));
    flows_on_continuous(flows6, Uplink::A)?;
    let reports: Vec<_> = flows4.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    for u in [Uplink::A, Uplink::B] {
        let on_u: Vec<_> = reports.iter().filter(|r| r.uplink() == Some(u)).collect();
        assert!(!on_u.is_empty(), "no IPv4 flow ran on {u}: {reports:?}");
        for r in on_u {
            assert!(
                r.continuous(Duration::from_secs(1)),
                "IPv4 flow on {u} interrupted: {r:?}"
            );
        }
    }
    Ok(())
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
    let mut f = t.prepare_ftr(&ftr::family(&ab(), Family::V6))?;
    f.set_env("FTR_LOG", "debug");
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
    // `left + 1` s, and FTR acts within the following second.
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

/// AS-35: IPv6 over PPP with the peer's link-local gateway: C's path joins
/// and leaves a multi-member active set (single → multiple → single) and
/// every route installation succeeds. Then C reconnects with a new
/// interface: its IPv6 path comes back with its per-interface settings.
#[test]
#[ignore = "needs root and network namespaces"]
fn as35_ipv6_over_ppp_joins_and_leaves_a_multipath_route() -> Result<()> {
    let t = build();
    let f = t.start_ftr(&ftr::family(&abc(), Family::V6))?;
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
    let f = t.start_ftr(&ftr::dual(&ab()))?;
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
        "use a nexthop group, which FTR does not use",
        2,
        Duration::from_secs(2),
    )?;
    assert_eq!(
        f.log().matches("use a nexthop group, which FTR does not use").count(),
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
/// warning that names the likely causes.
#[test]
#[ignore = "needs root and network namespaces"]
fn fr_sys_3_router_advertisement_warnings() -> Result<()> {
    let t = build();
    let r = t.router();
    r.sysctl(&["net.ipv6.conf.wana.accept_ra=1"])?;
    // B: no Router Advertisement processing and no default route.
    r.sysctl(&["net.ipv6.conf.wanb.accept_ra=0"])?;
    drop_ra_default_routes(&t, "wanb")?;
    let f = t.prepare_ftr(&ftr::family(&ab(), Family::V6))?;
    let out = f.cli_config(&["check-config"])?;
    let text = ftr::output_text(&out);
    assert!(text.contains("wana has accept_ra = 1"), "{text}");
    let mut f = f;
    f.start(&t)?;
    f.wait_installed(&t)?;
    assert!(f.log().contains("wana has accept_ra = 1"), "{}", f.log());
    assert!(!f.log().contains("no IPv6 default route discovered"), "not before 30 s");
    f.wait_log(
        &t,
        "no IPv6 default route discovered on wanb 30 s after startup",
        1,
        Duration::from_secs(40),
    )?;
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
    // Router Advertisements again: B becomes ready.
    r.sysctl(&["net.ipv6.conf.wanb.accept_ra=2"])?;
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
        let v = t.router().ip_json(&format!("-6 addr show dev {iface} scope link"))?;
        // iproute2 lists an empty entry first.
        Ok(v[0]["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .find_map(|a| a["local"].as_str())
            .unwrap_or_default()
            .to_owned())
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
    let snat = ftr::family(&[ftr::UplinkSpec::new(Uplink::B, 2)], Family::V6).replace(
        "nat = \"masquerade\"",
        &format!("source = \"{}\"\nnat = \"snat\"", plan::LAN_ROUTER_V6),
    );
    let mut f = t.start_ftr(&snat)?;
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
    let none = ftr::family(&[ftr::UplinkSpec::new(Uplink::A, 1)], Family::V6).replace("masquerade", "none");
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

/// AS-33 for IPv6: a foreign rule in FTR's IPv6 priority range, or a route
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
        let f = t.prepare_ftr(&ftr::dual(&ab()))?;
        let out = f.cli_config(&["check-config"])?;
        let text = ftr::output_text(&out);
        assert!(!out.status.success() && text.contains(needle), "check-config: {text}");
        let mut f = f;
        f.start(&t)?;
        f.wait_exit(&t, Duration::from_secs(10))?;
        assert!(f.log().contains(needle), "{}", f.log());
        drop(f);
        t.router().ip(undo)?;
    }
    let f = t.start_ftr(&ftr::dual(&ab()))?;
    f.wait_installed(&t)?;
    Ok(())
}

/// AS-44 (IPv6 parts without prefix delegation): the router starts FTR,
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
    // The kernel processed the providers' advertisements while the
    // topology came up: undo it, as on a router that has not configured
    // its uplinks yet.
    let r = t.router();
    for iface in ["wana", "wanb"] {
        r.sysctl(&[
            &format!("net.ipv6.conf.{iface}.accept_ra=0"),
            &format!("net.ipv6.conf.{iface}.autoconf=0"),
        ])?;
        r.ip(&format!("-6 addr flush dev {iface} scope global"))?;
        drop_ra_default_routes(&t, iface)?;
    }
    for u in Uplink::ALL {
        for fam in Family::ALL {
            assert_eq!(t.uplink_address(u, fam)?, None, "{u} has no {fam} address yet");
            assert_eq!(t.os_default_route(u, fam)?, None, "{u} has no {fam} default route yet");
        }
    }
    let f = t.start_ftr(&ftr::dual(&abc()))?;
    f.wait_installed(&t)?;
    for fam in Family::ALL {
        assert!(balancing_members(&t, fam)?.is_empty(), "empty {fam} active set");
        assert!(!ftr_rules(&t, fam)?.is_empty(), "FTR's {fam} rules are installed");
    }
    // Router solicitations: the links come up again with advertisements
    // accepted, as a network manager would bring them up.
    for (u, iface) in [(Uplink::A, "wana"), (Uplink::B, "wanb")] {
        r.sysctl(&[
            &format!("net.ipv6.conf.{iface}.accept_ra=2"),
            &format!("net.ipv6.conf.{iface}.autoconf=1"),
        ])?;
        t.router_link(u, false)?;
        t.router_link(u, true)?;
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
