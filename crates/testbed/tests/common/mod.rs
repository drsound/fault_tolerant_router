//! Helpers shared by the acceptance scenarios of `m1.rs` and `m2.rs`.

// Each scenario file uses part of them.
#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use testbed::plan::{Family, Node, Uplink};
use testbed::polywan::{self, HealthSpec, UplinkSpec};
use testbed::traffic::tally;
use testbed::{Options, Outcome, Topology};

pub fn build() -> Topology {
    build_with(Options::default())
}

/// `opts` with the agent of this build unless `POLYWAN_TESTBED_BIN` names one.
pub fn build_with(opts: Options) -> Topology {
    assert!(testbed::is_root(), "these tests need root: tests/vm/run-suite.sh");
    let agent_bin = std::env::var_os("POLYWAN_TESTBED_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_polywan-testbed")));
    Topology::build(Options { agent_bin, ..opts }).unwrap_or_else(|e| panic!("{e:#}"))
}

/// The configuration of a scenario variant over `uplinks`: IPv4 alone for
/// the IPv4 variant; both families for the IPv6 variant, so that IPv6's
/// artifacts coexist with IPv4's (the dual-stack variants of M2).
pub fn stack(fam: Family, uplinks: &[UplinkSpec]) -> String {
    polywan::config(uplinks, stack_families(fam), &HealthSpec::fast(), "", "")
}

/// The families a [`stack`] configuration manages.
pub fn stack_families(fam: Family) -> &'static [Family] {
    match fam {
        Family::V4 => &[Family::V4],
        Family::V6 => &Family::ALL,
    }
}

/// The nftables protocol keyword of a family (`ip`, `ip6`).
pub fn ip(fam: Family) -> &'static str {
    match fam {
        Family::V4 => "ip",
        Family::V6 => "ip6",
    }
}

/// The nftables ICMP keyword of a family (`icmp`, `icmpv6`).
pub fn icmp(fam: Family) -> &'static str {
    match fam {
        Family::V4 => "icmp",
        Family::V6 => "icmpv6",
    }
}

/// The nftables address type of a family.
pub fn addr_type(fam: Family) -> &'static str {
    match fam {
        Family::V4 => "ipv4_addr",
        Family::V6 => "ipv6_addr",
    }
}

/// The prefix of the test servers of a family.
pub fn servers_prefix(fam: Family) -> &'static str {
    match fam {
        Family::V4 => testbed::plan::SERVERS_V4,
        Family::V6 => testbed::plan::SERVERS_V6,
    }
}

/// The LAN client's address of a family.
pub fn lan_client(fam: Family) -> IpAddr {
    match fam {
        Family::V4 => testbed::plan::LAN_CLIENT_V4.into(),
        Family::V6 => testbed::plan::LAN_CLIENT_V6.into(),
    }
}

/// `address:port`, with brackets for IPv6.
pub fn endpoint(address: &str, port: u16) -> String {
    match address.parse::<IpAddr>() {
        Ok(a) => SocketAddr::new(a, port).to_string(),
        Err(_) => format!("{address}:{port}"),
    }
}

/// Rules of PolyWAN (protocol 249) of a family in the router, as `ip rule`
/// lines.
pub fn polywan_rules(t: &Topology, fam: Family) -> Result<Vec<String>> {
    Ok(t.router()
        .run("ip", [fam.flag(), "rule", "show"])?
        .lines()
        .filter(|l| l.contains("proto 249"))
        .map(str::to_owned)
        .collect())
}

/// The route of a family in table `table`, as `ip route` prints it.
pub fn path_route(t: &Topology, fam: Family, table: u32) -> Result<String> {
    let out = t
        .router()
        .output("ip", [fam.flag(), "route", "show", "table", &table.to_string()])?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

pub fn ab() -> Vec<UplinkSpec> {
    vec![UplinkSpec::new(Uplink::A, 1), UplinkSpec::new(Uplink::B, 2)]
}

pub fn abc() -> Vec<UplinkSpec> {
    vec![
        UplinkSpec::new(Uplink::A, 1),
        UplinkSpec::new(Uplink::B, 2),
        UplinkSpec::new(Uplink::C, 3),
    ]
}

/// The members of a family's balancing route (table 1000), by interface
/// name.
pub fn balancing_members(t: &Topology, f: Family) -> Result<Vec<String>> {
    // A table without routes does not exist: an empty set.
    let out = t.router().output("ip", [f.flag(), "route", "show", "table", "1000"])?;
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

pub fn wait_members(t: &Topology, f: Family, expected: &[&str], timeout: Duration) -> Result<Duration> {
    t.wait_for(&format!("{f} balancing members {expected:?}"), timeout, || {
        Ok(balancing_members(t, f)? == expected)
    })
}

/// Long-lived flows from the client to test servers `first..first+count`.
pub fn start_flows(t: &Topology, f: Family, first: u8, count: u8) -> Result<Vec<testbed::traffic::Flow>> {
    (first..first + count)
        .map(|n| t.start_flow(Node::Client, testbed::plan::server(f, n), Duration::from_millis(50)))
        .collect()
}

/// Stops `flows` and checks, for each of `uplinks`, that at least one ran on
/// it and that every flow on it was uninterrupted (no stall longer than a
/// second): a check that cannot pass because no flow happened to use it.
pub fn flows_on_continuous(flows: Vec<testbed::traffic::Flow>, uplinks: &[Uplink]) -> Result<()> {
    let reports: Vec<_> = flows.into_iter().map(|f| f.stop()).collect::<Result<_>>()?;
    for &u in uplinks {
        let on_u: Vec<_> = reports.iter().filter(|r| r.uplink() == Some(u)).collect();
        assert!(!on_u.is_empty(), "no flow ran on {u}: {reports:?}");
        for r in on_u {
            assert!(r.continuous(Duration::from_secs(1)), "flow on {u} interrupted: {r:?}");
        }
    }
    Ok(())
}

/// A statistical split (§14.3): five samples of 1,000 connections to 50
/// destinations, each through A or B; A's share of the 5,000 is within
/// `centre ± half` per mille, and of each sample within twice that.
pub fn split(t: &Topology, f: Family, centre: usize, half: usize) -> Result<()> {
    let mut on_a = Vec::new();
    for sample in 0..5 {
        let r = t.connect_many(Node::Client, f, 50, 1000, false)?;
        let counts = tally(&r);
        assert!(
            r.iter().all(|c| c.outcome == Outcome::Ok)
                && counts.keys().all(|u| matches!(u, Some(Uplink::A | Uplink::B))),
            "{f} sample {sample}: every connection succeeds through A or B: {counts:?}"
        );
        on_a.push(counts.get(&Some(Uplink::A)).copied().unwrap_or(0));
    }
    eprintln!("{f} connections through A per sample of 1,000: {on_a:?}");
    let total: usize = on_a.iter().sum();
    assert!(
        (5 * (centre - half)..=5 * (centre + half)).contains(&total),
        "{f}: A got {total} of 5,000 (per sample: {on_a:?})"
    );
    for (sample, n) in on_a.iter().enumerate() {
        assert!(
            (centre - 2 * half..=centre + 2 * half).contains(n),
            "{f} sample {sample}: A got {n} of 1,000 (per sample: {on_a:?})"
        );
    }
    Ok(())
}

pub fn gateway(t: &Topology, f: Family, u: Uplink) -> Result<String> {
    Ok(t.os_default_route(u, f)?
        .flatten()
        .map(|g| g.to_string())
        .unwrap_or_default())
}

pub fn address(t: &Topology, f: Family, u: Uplink) -> Result<String> {
    Ok(t.uplink_address(u, f)?.map(|a| a.to_string()).unwrap_or_default())
}

/// Destinations `ip:port` (`[ip]:port` for IPv6) on test servers
/// `first..first+count`, for example on [`testbed::plan::TCP_PORT`].
pub fn servers(f: Family, first: u8, count: u8, port: u16) -> Vec<String> {
    (first..first + count)
        .map(|n| SocketAddr::new(testbed::plan::server(f, n), port).to_string())
        .collect()
}

/// A counter in the router namespace (table `inet t_<name>`, postrouting
/// priority 300) counting packets that match `selector`.
pub fn counter(t: &Topology, name: &str, selector: &str) -> Result<()> {
    t.router().nft(&format!(
        "table inet t_{name} {{\n  counter c {{}}\n  chain post {{\n    type filter hook postrouting priority 300; policy accept;\n    {selector} counter name c\n  }}\n}}\n"
    ))
}

pub fn counter_value(t: &Topology, name: &str) -> Result<u64> {
    t.router().counter("inet", &format!("t_{name}"), "c")
}

/// A named counter of table `<family> <table>` in a node's namespace (the
/// providers' counters of DHCP messages, AS-44).
pub fn provider_counter(t: &Topology, node: Node, family: &str, table: &str, name: &str) -> Result<u64> {
    t.ns(node).counter(family, table, name)
}

/// The IPv6 settings that PolyWAN changes on uplinks A and B and gives back when
/// it no longer manages IPv6 (AS-45, FR-REC-9), as paths under
/// `/proc/sys`.
pub const IPV6_SETTINGS: [&str; 4] = [
    "net/ipv6/conf/all/forwarding",
    "net/ipv6/fib_multipath_hash_policy",
    "net/ipv6/conf/wana/ignore_routes_with_linkdown",
    "net/ipv6/conf/wanb/ignore_routes_with_linkdown",
];

/// The values of sysctls in the router.
pub fn sysctl_values(t: &Topology, keys: &[&str]) -> Result<Vec<String>> {
    keys.iter().map(|k| t.router().sysctl_get(k)).collect()
}

/// PolyWAN's IPv6 artifacts in the router, one line each: its IPv6 rules and
/// routes (protocol 249, in any table) and the IPv6 rules of its nftables
/// table. Empty when PolyWAN manages no IPv6 (AS-45).
pub fn ipv6_artifacts(t: &Topology) -> Result<Vec<String>> {
    let mut left = polywan_rules(t, Family::V6)?;
    let routes = t
        .router()
        .run("ip", ["-6", "route", "show", "table", "all", "proto", "249"])?;
    let table = t.router().run("nft", ["list", "table", "inet", "polywan"])?;
    left.extend(
        routes
            .lines()
            .filter(|l| !l.trim().is_empty())
            .chain(table.lines().filter(|l| l.contains("meta nfproto ipv6 ")))
            .map(str::to_owned),
    );
    Ok(left)
}

/// Starts PolyWAN with `config` while the router holds a foreign object that
/// collides with it: online `check-config` fails and startup is refused,
/// both naming `needle` (AS-33).
pub fn assert_refused(t: &Topology, config: &str, needle: &str) -> Result<()> {
    let mut f = t.prepare_polywan(config)?;
    let check = f.cli_config(&["check-config"])?;
    let text = polywan::output_text(&check);
    assert!(!check.status.success() && text.contains(needle), "check-config: {text}");
    f.start(t)?;
    f.wait_exit(t, Duration::from_secs(10))?;
    assert!(f.log().contains(needle), "expected {needle:?} in:\n{}", f.log());
    Ok(())
}

/// An `nft` wrapper for `firewall.nft_path` whose invocations containing one
/// of `failing` (for example `list flowtables`) fail while the returned flag
/// file exists.
pub fn nft_wrapper(t: &Topology, f: &polywan::Polywan, failing: &[&str]) -> Result<(PathBuf, PathBuf)> {
    let nft = t.router().sh("command -v nft")?.trim().to_owned();
    let flag = f.dir.join("nft-fails");
    let wrapper = t.exec_dir()?.join("nft");
    let patterns: Vec<String> = failing.iter().map(|p| format!("*\" {p} \"*")).collect();
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nif [ -e {flag} ]; then\n  case \" $* \" in {}) echo 'injected nft failure' >&2; exit 1 ;; esac\nfi\nexec {nft} \"$@\"\n",
            patterns.join("|"),
            flag = flag.display()
        ),
    )?;
    std::fs::set_permissions(&wrapper, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    Ok((wrapper, flag))
}
