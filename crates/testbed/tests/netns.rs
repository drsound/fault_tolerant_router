//! Integration tests of the harness itself, with real namespaces and traffic.
//!
//! They need root, iproute2, nftables, dnsmasq, udhcpc, pppd and
//! pppoe-server: `sudo -E cargo test -p testbed -- --ignored`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use testbed::plan::{self, Family, Node, Uplink};
use testbed::traffic::tally;
use testbed::{Options, Outcome, PingOutcome, Topology, netns, topology};

fn options() -> Options {
    let bin = std::env::var_os("POLYWAN_TESTBED_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_polywan-testbed")));
    Options {
        agent_bin: bin,
        ..Options::default()
    }
}

fn build() -> Topology {
    assert!(
        testbed::is_root(),
        "these tests need root: sudo -E cargo test -p testbed -- --ignored"
    );
    Topology::build(options()).unwrap_or_else(|e| panic!("{e:#}"))
}

/// Ping from the router bound to the uplink's interface, as a probe would.
fn router_ping(t: &Topology, uplink: Uplink, dst: IpAddr) -> Result<bool> {
    let out = t.router().output(
        "ping",
        ["-n", "-c", "1", "-W", "1", "-I", uplink.l3_iface(), &dst.to_string()],
    )?;
    Ok(out.status.success())
}

/// Steers LAN traffic of both families through one uplink with a rule and
/// a table outside PolyWAN's default ranges (priority 90, table 90), and
/// masquerades it: these checks of the harness run without the daemon,
/// which routes only IPv4 until M2.
fn steer_lan(t: &Topology, uplink: Uplink) -> Result<()> {
    let r = t.router();
    clear_steering(t)?;
    for f in t.families(uplink) {
        let gw = t
            .os_default_route(uplink, f)?
            .with_context(|| format!("no {f} default route on {uplink}"))?;
        let via = gw.map(|g| format!("via {g} ")).unwrap_or_default();
        r.ip(&format!(
            "{} route replace default {via}dev {} table 90",
            f.flag(),
            uplink.l3_iface()
        ))?;
        r.ip(&format!("{} rule add pref 90 iif lan lookup 90", f.flag()))?;
    }
    r.nft(&format!(
        "table inet tb_steer {{\n  chain post {{\n    type nat hook postrouting priority 100;\n    iifname \"lan\" oifname \"{}\" masquerade\n  }}\n}}\n",
        uplink.l3_iface()
    ))
}

/// Removes what [`steer_lan`] installed.
fn clear_steering(t: &Topology) -> Result<()> {
    let r = t.router();
    for f in Family::ALL {
        while r
            .output("ip", [f.flag(), "rule", "del", "pref", "90"])?
            .status
            .success()
        {}
        let _ = r.output("ip", [f.flag(), "route", "flush", "table", "90"])?;
    }
    let _ = r.output("nft", ["delete", "table", "inet", "tb_steer"])?;
    Ok(())
}

#[test]
#[ignore = "needs root and network namespaces"]
fn topology_comes_up_with_os_default_routes_and_tears_down() -> Result<()> {
    let mut t = build();
    for u in t.uplinks() {
        for f in t.families(u) {
            assert!(t.uplink_address(u, f)?.is_some(), "{u} {f} address");
            assert!(t.os_default_route(u, f)?.is_some(), "{u} {f} default route");
            for target in plan::probe_targets(f) {
                assert!(router_ping(&t, u, target)?, "router ping {target} via {u}");
            }
        }
    }
    let a = t.uplink_address(Uplink::A, Family::V4)?.unwrap();
    assert!(plan::attribute(a) == Some(Uplink::A), "A got {a} from DHCP");
    let mtu = t.router().ip_json("link show dev ppp0")?[0]["mtu"].as_u64();
    assert_eq!(mtu, Some(1492), "PPPoE MTU");

    // Daemon handle, exercised with a stand-in process.
    let d = t.start_daemon(Path::new("/bin/sleep"), &["30"], &[])?;
    assert!(d.pid().is_some());
    let status = d.stop()?;
    assert!(!status.success(), "sleep ends by SIGTERM");

    let id = t.run_id().to_owned();
    let dir = t.dir().to_path_buf();
    t.teardown()?;
    let left: Vec<String> = netns::list()?
        .into_iter()
        .filter(|n| n.starts_with(&topology::prefix(&id)))
        .collect();
    assert!(left.is_empty(), "namespaces left behind: {left:?}");
    assert!(!dir.exists(), "{} left behind", dir.display());
    Ok(())
}

#[test]
#[ignore = "needs root"]
fn a_work_root_another_user_controls_is_refused() -> Result<()> {
    assert!(testbed::is_root(), "this test needs root");
    let base = PathBuf::from(format!("/tmp/polywan-testbed-refused-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir(&base)?;
    let taken = base.join("taken");
    std::fs::create_dir(&taken)?;
    std::os::unix::fs::chown(&taken, Some(65534), Some(65534))?;
    let link = base.join("link");
    std::os::unix::fs::symlink(&base, &link)?;
    for root in [&taken, &link] {
        let err = Topology::build(Options {
            work_root: root.clone(),
            ..options()
        })
        .err()
        .with_context(|| format!("{} accepted", root.display()))?;
        assert!(
            format!("{err:#}").contains("must be a directory owned by root"),
            "{err:#}"
        );
    }
    assert_eq!(std::fs::read_dir(&taken)?.count(), 0, "a run directory was created");
    std::fs::remove_dir_all(&base)?;
    Ok(())
}

#[test]
#[ignore = "needs root and network namespaces"]
fn lan_traffic_is_attributed_to_the_steered_uplink() -> Result<()> {
    let t = build();
    // LAN traffic routed by an operating-system route. The harness's leak
    // counter also sees the router's own packets (resets or ICMP errors for
    // connections already closed), which these checks do not steer.
    t.router().nft(&format!(
        "table ip t_lan_leak {{\n  counter c {{}}\n  chain post {{\n    type filter hook postrouting priority 400; policy accept;\n    iifname \"lan\" meta rtclassid {} counter name c\n  }}\n}}\n",
        plan::OS_ROUTE_REALM
    ))?;
    let lan_leaks = || t.router().counter("ip", "t_lan_leak", "c");
    for u in t.uplinks() {
        steer_lan(&t, u)?;
        t.reset_counters()?;
        // From here: steer_lan replaces the steering, and a late packet of
        // the previous uplink's connections can meet the gap.
        let leaks = lan_leaks()?;
        for f in t.families(u) {
            let tcp = t.connect_many(Node::Client, f, 50, 200, false)?;
            assert_eq!(
                tally(&tcp).get(&Some(u)).copied(),
                Some(200),
                "{u} {f} TCP: {:?}",
                tally(&tcp)
            );
            let distinct: std::collections::HashSet<_> = tcp.iter().map(|r| (r.dst, r.local)).collect();
            assert_eq!(distinct.len(), 200, "distinct 5-tuples");
            // UDP has no retransmission: a single unanswered datagram (seen
            // once in 50 for IPv6 on a loaded 6.1 guest) is not a routing
            // error; any datagram attributed to another uplink is.
            let udp = t.connect_many(Node::Client, f, 50, 50, true)?;
            let counts = tally(&udp);
            assert!(
                counts.get(&Some(u)).copied().unwrap_or(0) >= 48 && counts.keys().all(|k| k.is_none() || *k == Some(u)),
                "{u} {f} UDP: {counts:?}"
            );
            assert!(t.egress_packets(u, f)? >= 250, "{u} {f} egress counter");
        }
        assert_eq!(lan_leaks()? - leaks, 0, "steering routes carry no OS realm");
    }

    // One-way UDP flow, attributed from the server log.
    steer_lan(&t, Uplink::B)?;
    t.udp_send(
        Node::Client,
        plan::server(Family::V4, 7),
        40000,
        5,
        Duration::from_millis(20),
    )?;
    let seen: Vec<_> = t
        .server_events()?
        .into_iter()
        .filter(|e| e.proto == "udp" && e.port == plan::UDP_SINK_PORT)
        .collect();
    assert_eq!(seen.len(), 5);
    assert!(seen.iter().all(|e| e.uplink() == Some(Uplink::B)));

    // Leak detection: without the steering rule, LAN traffic follows the
    // operating-system default route of the main table.
    clear_steering(&t)?;
    t.router().nft("table inet tb_steer {\n  chain post {\n    type nat hook postrouting priority 100;\n    iifname \"lan\" masquerade\n  }\n}\n")?;
    t.reset_counters()?;
    let r = t.connect_many(Node::Client, Family::V4, 5, 5, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok));
    assert!(t.ipv4_leaks()? > 0, "OS default route use is counted");
    Ok(())
}

#[test]
#[ignore = "needs root and network namespaces"]
fn failure_injection() -> Result<()> {
    let t = build();
    let target = IpAddr::V4(plan::PROBE_TARGETS_V4[0]);

    // Deterministic loss: every third echo request towards the targets.
    t.drop_probe_echoes(Uplink::A, 3)?;
    let replies: Vec<bool> = (0..9)
        .map(|_| router_ping(&t, Uplink::A, target))
        .collect::<Result<_>>()?;
    assert_eq!(replies, [false, true, true, false, true, true, false, true, true]);
    let v6 = IpAddr::V6(plan::PROBE_TARGETS_V6[0]);
    let replies6: Vec<bool> = (0..3).map(|_| router_ping(&t, Uplink::A, v6)).collect::<Result<_>>()?;
    assert_eq!(replies6, [false, true, true]);
    t.clear_provider_rules(Uplink::A)?;
    assert!(router_ping(&t, Uplink::A, target)?);

    // netem.
    t.netem(Uplink::B, "loss 100%")?;
    assert!(!router_ping(&t, Uplink::B, target)?);
    t.clear_netem(Uplink::B)?;
    // The gateway's neighbour entry may have failed meanwhile: the first
    // ping can be spent resolving it again.
    t.wait_for("B answers again", Duration::from_secs(5), || {
        router_ping(&t, Uplink::B, target)
    })?;

    // Provider disconnected upstream, link up.
    t.upstream_down(Uplink::A)?;
    assert!(!router_ping(&t, Uplink::A, target)?);
    assert!(t.router().ip("link show dev wana")?.contains("LOWER_UP"));
    t.upstream_up(Uplink::A)?;
    t.wait_for("A upstream back", Duration::from_secs(5), || {
        router_ping(&t, Uplink::A, target)
    })?;

    // A long-lived flow on A survives failures of B, and stalls when A loses carrier.
    steer_lan(&t, Uplink::A)?;
    let flow = t.start_flow(Node::Client, plan::server(Family::V4, 1), Duration::from_millis(20))?;
    std::thread::sleep(Duration::from_millis(300));
    t.carrier_down(Uplink::B)?;
    t.wait_for("B carrier lost", Duration::from_secs(2), || {
        Ok(t.router().ip("link show dev wanb")?.contains("NO-CARRIER"))
    })?;
    t.carrier_up(Uplink::B)?;
    std::thread::sleep(Duration::from_millis(300));
    let rep = flow.stop()?;
    assert_eq!(rep.uplink(), Some(Uplink::A));
    assert!(rep.continuous(Duration::from_millis(500)), "{rep:?}");

    let flow = t.start_flow(Node::Client, plan::server(Family::V4, 2), Duration::from_millis(20))?;
    std::thread::sleep(Duration::from_millis(300));
    t.carrier_down(Uplink::A)?;
    std::thread::sleep(Duration::from_millis(1500));
    t.carrier_up(Uplink::A)?;
    std::thread::sleep(Duration::from_millis(1500));
    let rep = flow.stop()?;
    assert!(
        !rep.continuous(Duration::from_millis(1000)),
        "carrier loss must show as a gap: {rep:?}"
    );
    assert!(rep.max_gap_ms >= 1400, "{rep:?}");

    // PPPoE session reset: new ppp0 ifindex, default route restored.
    let before = t.ifindex("ppp0").expect("ppp0");
    t.pppoe_reset()?;
    t.wait_for("PPPoE reconnection", Duration::from_secs(20), || {
        Ok(t.ifindex("ppp0").is_some_and(|i| i != before) && t.os_default_route(Uplink::C, Family::V4)?.is_some())
    })?;
    Ok(())
}

#[test]
#[ignore = "needs root and network namespaces"]
fn unreachable_is_detected() -> Result<()> {
    let t = build();
    steer_lan(&t, Uplink::A)?;
    // IPv4 ICMP errors for packets rejected by routing are rate-limited per
    // source host by the host-wide net.ipv4.route.error_cost/error_burst
    // sysctls (one per second after a small burst), which no namespace can
    // change: keep the attempts a second apart.
    let gap = Duration::from_millis(1100);
    for f in Family::ALL {
        t.router()
            .ip(&format!("{} rule add pref 80 iif lan unreachable", f.flag()))?;
        for n in 1..=2 {
            let r = t.connect_many(Node::Client, f, n, 1, false)?;
            assert_eq!(r[0].outcome, Outcome::Unreachable, "{f}: {r:?}");
            assert!(r[0].millis < 500, "{f}: the ICMP error is immediate: {r:?}");
            std::thread::sleep(gap);
        }
        assert_eq!(t.ping(Node::Client, plan::server(f, 1))?, PingOutcome::Unreachable);
        t.router().ip(&format!("{} rule del pref 80", f.flag()))?;
        assert_eq!(t.ping(Node::Client, plan::server(f, 1))?, PingOutcome::Reply);
    }
    Ok(())
}
