//! FR-REC-9 against the running kernel: a dual-stack layout installed with
//! the production modules, then IPv6 handed back by reconciling with an
//! IPv4-only configuration. Run as root under `unshare -n` (see
//! kernel_netlink.rs).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fault_tolerant_router::config::{self, Config};
use fault_tolerant_router::discover;
use fault_tolerant_router::model::Family;
use fault_tolerant_router::netlink::Client;
use fault_tolerant_router::nft;
use fault_tolerant_router::nftctl;
use fault_tolerant_router::observer;
use fault_tolerant_router::plan::{self, Input, Layout, PathInput};
use fault_tolerant_router::reconcile::{self, DiffInput};
use fault_tolerant_router::select::{self, Candidate};
use fault_tolerant_router::state::{Manifest, StateDir};
use fault_tolerant_router::sysctl;
use fault_tolerant_router::system::Scope;

mod common;
use common::{private_netns, sh};

fn nft_path() -> PathBuf {
    ["/usr/local/sbin/nft", "/usr/sbin/nft", "/sbin/nft"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("nft")
}

const DUAL: &str = r#"version = 2
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "d1"
priority = 1
[uplink.ipv4]
[uplink.ipv6]
nat = "masquerade"
[[uplink]]
id = 2
name = "b"
interface = "d2"
priority = 1
[uplink.ipv4]
[uplink.ipv6]
nat = "masquerade"
"#;

fn topology() {
    sh("ip link set lo up");
    for (n, v4, v6, gw4, metric) in [
        ("d1", "192.0.2.2/24", "2001:db8:1::2/64", "192.0.2.1", 100),
        ("d2", "198.51.100.2/24", "2001:db8:2::2/64", "198.51.100.1", 200),
    ] {
        let _ = Command::new("ip")
            .args(["link", "del", n])
            .stderr(Stdio::null())
            .status();
        sh(&format!(
            "ip link add {n} type dummy && ip addr add {v4} dev {n} && ip addr add {v6} dev {n} nodad && ip link set {n} up"
        ));
        sh(&format!("ip route add default via {gw4} dev {n} metric {metric}"));
        sh(&format!("ip -6 route add default via fe80::1 dev {n} metric {metric}"));
    }
    let _ = Command::new("ip")
        .args(["link", "del", "lan"])
        .stderr(Stdio::null())
        .status();
    sh("ip link add lan type dummy && ip addr add 10.1.0.1/24 dev lan && ip link set lan up");
}

/// One reconciliation as the daemon performs it after startup: discovery,
/// cold-start health (every ready path up), selection, plan, ordered diff,
/// execution, then the settings of departed families (FR-REC-9 step 4).
async fn converge(cfg: &Config, dir: &StateDir, manifest: &mut Manifest, nft_pending: bool) -> usize {
    let layout = Layout::of(cfg);
    let scope = Scope {
        ftr_tables: layout.tables(),
        discovery_tables: cfg.routing.discovery_tables.clone(),
    };
    let client = Client::new().unwrap();
    let mut system = observer::full(&client, &scope).await.unwrap();
    let discovered = discover::discover(cfg, &system, &BTreeMap::new(), cfg.routing.route_protocol);
    let mut input = Input::default();
    for (key, d) in &discovered {
        input.paths.insert(
            *key,
            PathInput {
                ready: d.ready.as_ref().ok().copied(),
                local_addresses: d.local_addresses.clone(),
                healthy: d.ready.is_ok(),
                drained: false,
            },
        );
    }
    let families: Vec<Family> = Family::ALL.into_iter().filter(|f| cfg.manages(*f)).collect();
    for f in &families {
        let candidates: Vec<Candidate> = cfg
            .uplinks
            .iter()
            .filter_map(|u| {
                let p = input.paths.get(&fault_tolerant_router::model::PathKey {
                    uplink: u.id,
                    family: *f,
                })?;
                p.ready.map(|_| Candidate {
                    uplink: u.id,
                    priority: u.priority.unwrap_or(1),
                    healthy: true,
                })
            })
            .collect();
        input.active.insert(
            *f,
            select::active_set(&candidates, cfg.routing.all_down_policy, &Default::default()),
        );
    }
    let desired = plan::plan(cfg, &input);
    let ops = reconcile::diff(
        &system,
        &DiffInput {
            layout,
            protocol: cfg.routing.route_protocol,
            families: &families,
            before_nft: &desired,
            desired: &desired,
            nft_pending,
            teardown: false,
        },
    );
    let n = ops.len();
    let text = nft::transaction(cfg);
    let nft = nft_path();
    reconcile::execute(&client, &mut system, &scope, cfg.routing.route_protocol, ops, || {
        let (nft, text) = (nft.clone(), text.clone());
        async move { nftctl::apply(&nft, &text).await }
    })
    .await
    .unwrap_or_else(|f| panic!("{}: {}", f.op, f.error));
    // Settings: record baselines write-ahead, then apply.
    let diffs = sysctl::differences(&sysctl::desired(cfg), sysctl::read).unwrap();
    sysctl::record(manifest, &diffs);
    for f in sysctl::departed(manifest, cfg) {
        let h = sysctl::hand_back(manifest, f, sysctl::read, sysctl::write);
        assert!(h.failed.is_empty(), "{:?}", h.failed);
    }
    manifest.bind(cfg);
    dir.write_manifest(manifest).unwrap();
    for d in diffs {
        sysctl::write(&d.setting.key, d.setting.value).unwrap();
    }
    n
}

fn output(cmd: &str) -> String {
    let o = Command::new("sh").args(["-c", cmd]).output().unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn read(key: &str) -> String {
    sysctl::read(key).unwrap()
}

#[tokio::test]
#[ignore = "needs root in a private network namespace"]
async fn ipv6_is_handed_back_and_ipv4_left_alone() {
    private_netns();
    topology();
    let dir = StateDir::open(Path::new(&format!("/tmp/ftr-handoff-test-{}", std::process::id()))).unwrap();
    let dual = config::parse(DUAL).unwrap();
    let mut manifest = Manifest::new(&dual);
    // A foreign rule and route that must survive.
    sh("ip rule add priority 900 from 203.0.113.9 lookup 77 && ip route add 198.18.9.0/24 dev lan table 77");
    sh("sysctl -qw net.ipv6.conf.d2.ignore_routes_with_linkdown=0");

    assert!(converge(&dual, &dir, &mut manifest, true).await > 0);
    assert_eq!(read("net/ipv6/conf/all/forwarding"), "1");
    assert_eq!(
        read("net/ipv6/conf/d1/forwarding"),
        "1",
        "all/forwarding propagates to interfaces"
    );
    assert_eq!(read("net/ipv6/conf/d1/ignore_routes_with_linkdown"), "1");
    let v4_rules = output("ip -4 rule show | grep \"proto 249\"");
    let v4_routes = output("ip -4 route show table all proto 249");
    assert!(!output("ip -6 rule show | grep \"proto 249\"").is_empty());
    assert!(output("nft list table inet fault_tolerant_router").contains("meta nfproto ipv6"));
    // The administrator changes one IPv6 setting FTR set: it is left alone.
    sh("sysctl -qw net.ipv6.conf.d2.ignore_routes_with_linkdown=0");

    let v4_only = config::parse(&DUAL.replace("[uplink.ipv6]\nnat = \"masquerade\"\n", "")).unwrap();
    assert!(manifest.check(&v4_only).is_empty());
    converge(&v4_only, &dir, &mut manifest, true).await;

    assert_eq!(
        output("ip -6 rule show | grep \"proto 249\""),
        "",
        "IPv6 rules and guards removed"
    );
    assert_eq!(
        output("ip -6 route show table all proto 249"),
        "",
        "IPv6 routes removed"
    );
    assert_eq!(
        output("ip -4 rule show | grep \"proto 249\""),
        v4_rules,
        "IPv4 rules untouched"
    );
    assert_eq!(
        output("ip -4 route show table all proto 249"),
        v4_routes,
        "IPv4 routes untouched"
    );
    let table = output("nft list table inet fault_tolerant_router");
    assert!(!table.contains("meta nfproto ipv6 "), "no IPv6 assignment or NAT left");
    assert!(table.contains("meta nfproto ipv4 iifname \"d1\""));
    assert_eq!(read("net/ipv6/conf/all/forwarding"), "0", "restored baseline");
    assert_eq!(
        read("net/ipv6/conf/d1/forwarding"),
        "0",
        "per-interface effect of the restoration"
    );
    assert_eq!(read("net/ipv6/conf/d1/ignore_routes_with_linkdown"), "0");
    assert_eq!(read("net/ipv6/conf/d2/ignore_routes_with_linkdown"), "0");
    assert_eq!(read("net/ipv4/ip_forward"), "1", "IPv4 settings kept");
    assert!(
        output("ip rule show priority 900").contains("lookup 77"),
        "foreign rule kept"
    );
    assert!(
        output("ip route show table 77").contains("198.18.9.0/24"),
        "foreign route kept"
    );
    let m = dir.manifest().unwrap().unwrap();
    assert_eq!(m.families, ["ipv4"]);
    assert!(m.sysctl_set.keys().all(|k| k.starts_with("net/ipv4/")));
    assert_eq!(
        m.uplinks.iter().map(|b| b.id).collect::<Vec<_>>(),
        [1, 2],
        "id reservations kept"
    );

    // Converged: a further reconciliation changes nothing.
    assert_eq!(converge(&v4_only, &dir, &mut manifest, false).await, 0);
    std::fs::remove_dir_all(&dir.path).unwrap();
}
