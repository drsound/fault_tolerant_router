//! Netlink layer against the running kernel. These tests change rules and
//! routes, so they refuse to run in the initial network namespace: run them
//! as root under `unshare -n`, for example
//! `sudo unshare -n cargo test -p fault-tolerant-router --test kernel_netlink -- --ignored`.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

use fault_tolerant_router::config;
use fault_tolerant_router::model::{Family, PathKey, UplinkId};
use fault_tolerant_router::netlink::msg::{self, ObservedAddress, ObservedLink, ObservedRoute, ObservedRule};
use fault_tolerant_router::netlink::{Client, EEXIST, Mutation};
use fault_tolerant_router::plan::{self, Input, PathInput, ReadyPath};
use netlink_packet_route::RouteNetlinkMessage;

fn private_netns() {
    let own = std::fs::read_link("/proc/self/ns/net").expect("own netns");
    let init = std::fs::read_link("/proc/1/ns/net").expect("netns of pid 1 (needs root)");
    assert_ne!(
        own, init,
        "refusing to change rules in the initial network namespace; run under `unshare -n`"
    );
}

fn ip(args: &str) {
    let ok = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .expect("ip")
        .success();
    assert!(ok, "ip {args}");
}

/// Two dummy uplinks with IPv4 and IPv6 addresses.
fn topology() -> (u32, u32) {
    ip("link set lo up");
    for (n, v4, v6) in [
        ("d1", "192.0.2.2/24", "2001:db8:1::2/64"),
        ("d2", "198.51.100.2/24", "2001:db8:2::2/64"),
    ] {
        let _ = Command::new("ip")
            .args(["link", "del", n])
            .stderr(Stdio::null())
            .status();
        ip(&format!("link add {n} type dummy"));
        ip(&format!("addr add {v4} dev {n}"));
        ip(&format!("addr add {v6} dev {n} nodad"));
        ip(&format!("link set {n} up"));
    }
    (ifindex("d1"), ifindex("d2"))
}

fn ifindex(name: &str) -> u32 {
    // /sys/class/net shows the namespace sysfs was mounted in, not ours.
    let out = Command::new("ip")
        .args(["-o", "link", "show", name])
        .output()
        .expect("ip");
    let text = String::from_utf8_lossy(&out.stdout);
    text.split(':')
        .next()
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("no interface {name}"))
}

const CONFIG: &str = r#"version = 2
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "d1"
priority = 1
weight = 3
[uplink.ipv4]
[[uplink]]
id = 2
name = "b"
interface = "d2"
priority = 1
[uplink.ipv4]
"#;

async fn rules(c: &Client, f: Family) -> Vec<ObservedRule> {
    let d = c.dump(msg::rule_dump(f)).await.unwrap();
    d.messages
        .iter()
        .filter_map(|m| match m {
            RouteNetlinkMessage::NewRule(r) => ObservedRule::parse(r),
            _ => None,
        })
        .collect()
}

async fn routes(c: &Client, f: Family, table: u32) -> Vec<ObservedRoute> {
    let d = c.dump(msg::route_dump(f, Some(table))).await.unwrap();
    d.messages
        .iter()
        .filter_map(|m| match m {
            RouteNetlinkMessage::NewRoute(r) => ObservedRoute::parse(r),
            _ => None,
        })
        .filter(|r| r.table == table)
        .collect()
}

#[tokio::test]
#[ignore = "needs root in a private network namespace"]
async fn planned_layout_is_installed_dumped_and_removed() {
    private_netns();
    let (d1, d2) = topology();
    let cfg = config::parse(CONFIG).unwrap();
    let id = |n| UplinkId::new(n).unwrap();
    let path = |ifindex, gw: [u8; 4], src: [u8; 4]| PathInput {
        ready: Some(ReadyPath {
            ifindex,
            gateway: Some(IpAddr::from(gw)),
            onlink: false,
            source: IpAddr::from(src),
        }),
        local_addresses: [IpAddr::from(src)].into(),
        healthy: true,
        drained: false,
    };
    let mut input = Input::default();
    input.paths.insert(
        PathKey {
            uplink: id(1),
            family: Family::V4,
        },
        path(d1, [192, 0, 2, 1], [192, 0, 2, 2]),
    );
    input.paths.insert(
        PathKey {
            uplink: id(2),
            family: Family::V4,
        },
        path(d2, [198, 51, 100, 1], [198, 51, 100, 2]),
    );
    input.active.insert(Family::V4, [id(1), id(2)].into());
    let desired = plan::plan(&cfg, &input);
    let proto = cfg.routing.route_protocol;
    let c = Client::new().unwrap();

    for r in desired.routes.values() {
        c.mutate(
            RouteNetlinkMessage::NewRoute(msg::route_message(r, proto)),
            Mutation::Replace,
        )
        .await
        .unwrap();
    }
    for r in &desired.rules {
        c.mutate(
            RouteNetlinkMessage::NewRule(msg::rule_message(r, proto)),
            Mutation::Create,
        )
        .await
        .unwrap();
    }

    // Every planned rule is found exactly once; nothing else carries our protocol.
    let dumped = rules(&c, Family::V4).await;
    for r in &desired.rules {
        assert_eq!(dumped.iter().filter(|o| o.is(r, proto)).count(), 1, "{r:?}");
    }
    assert_eq!(
        dumped.iter().filter(|o| o.protocol == proto).count(),
        desired.rules.len()
    );
    // The kernel's rules (local, main, default) are not ours.
    assert!(dumped.iter().any(|o| o.priority == 0 && o.protocol != proto));

    // Duplicates are refused (NLM_F_EXCL) without an extended ack message.
    let any = desired.rules.iter().next().unwrap();
    let e = c
        .mutate(
            RouteNetlinkMessage::NewRule(msg::rule_message(any, proto)),
            Mutation::Create,
        )
        .await
        .unwrap_err();
    assert_eq!(e.errno, EEXIST);

    // Routes compare equal to the plan, including the weighted multipath.
    for ((f, t), r) in &desired.routes {
        let got = routes(&c, *f, *t).await;
        assert_eq!(got.len(), 1, "table {t}");
        assert_eq!(got[0].as_planned().as_ref(), Some(r), "table {t}");
    }

    // Replacement to a single member and back (FR-ROUTE-2).
    input.active.insert(Family::V4, [id(2)].into());
    let single = plan::plan(&cfg, &input);
    let bal = &single.routes[&(Family::V4, 1000)];
    c.mutate(
        RouteNetlinkMessage::NewRoute(msg::route_message(bal, proto)),
        Mutation::Replace,
    )
    .await
    .unwrap();
    let got = routes(&c, Family::V4, 1000).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].as_planned().as_ref(), Some(bal));

    // A gateway off the interface's subnet carries an extended ack (PLAT-1).
    let mut bad = bal.clone();
    bad.nexthops[0].gateway = Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)));
    let e = c
        .mutate(
            RouteNetlinkMessage::NewRoute(msg::route_message(&bad, proto)),
            Mutation::Replace,
        )
        .await
        .unwrap_err();
    assert!(e.extack.is_some(), "{e}");

    // Deletion by key, then by rule message.
    for (f, t) in desired.routes.keys() {
        c.mutate(
            RouteNetlinkMessage::DelRoute(msg::route_delete_key(*f, *t, proto)),
            Mutation::Delete,
        )
        .await
        .unwrap();
        assert!(routes(&c, *f, *t).await.is_empty());
    }
    for r in &desired.rules {
        c.mutate(
            RouteNetlinkMessage::DelRule(msg::rule_message(r, proto)),
            Mutation::Delete,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        rules(&c, Family::V4)
            .await
            .iter()
            .filter(|o| o.protocol == proto)
            .count(),
        0
    );
}

#[tokio::test]
#[ignore = "needs root in a private network namespace"]
async fn ipv6_multipath_with_link_local_gateways() {
    private_netns();
    let (d1, d2) = topology();
    let c = Client::new().unwrap();
    let ll: IpAddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into();
    let hop = |ifindex, weight| plan::NextHop {
        ifindex,
        gateway: Some(ll),
        onlink: false,
        weight,
    };
    let r = plan::Route {
        family: Family::V6,
        table: 1000,
        source: None,
        nexthops: vec![hop(d1, 10), hop(d2, 3)],
    };
    c.mutate(
        RouteNetlinkMessage::NewRoute(msg::route_message(&r, 249)),
        Mutation::Replace,
    )
    .await
    .unwrap();
    let got = routes(&c, Family::V6, 1000).await;
    assert_eq!(got.len(), 1, "one message with RTA_MULTIPATH");
    assert_eq!(got[0].as_planned().as_ref(), Some(&r));
    c.mutate(
        RouteNetlinkMessage::DelRoute(msg::route_delete_key(Family::V6, 1000, 249)),
        Mutation::Delete,
    )
    .await
    .unwrap();
    assert!(routes(&c, Family::V6, 1000).await.is_empty());
}

#[tokio::test]
#[ignore = "needs root in a private network namespace"]
async fn links_and_addresses_are_parsed() {
    private_netns();
    let (d1, _) = topology();
    let c = Client::new().unwrap();
    let links: Vec<ObservedLink> = c
        .dump(msg::link_dump())
        .await
        .unwrap()
        .messages
        .iter()
        .filter_map(|m| match m {
            RouteNetlinkMessage::NewLink(l) => ObservedLink::parse(l),
            _ => None,
        })
        .collect();
    let l = links.iter().find(|l| l.name == "d1").unwrap();
    assert_eq!(l.index, d1);
    assert!(l.up && !l.point_to_point);
    let mut seen = BTreeSet::new();
    for f in Family::ALL {
        for m in c.dump(msg::address_dump(f)).await.unwrap().messages {
            if let RouteNetlinkMessage::NewAddress(a) = m {
                let a = ObservedAddress::parse(&a).unwrap();
                if a.index == d1 && a.global() {
                    assert!(!a.tentative(), "nodad");
                    seen.insert(a.address.to_string());
                }
            }
        }
    }
    assert_eq!(seen, ["192.0.2.2", "2001:db8:1::2"].map(String::from).into());
}
