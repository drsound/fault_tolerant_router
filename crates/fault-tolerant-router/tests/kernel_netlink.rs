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

mod common;
use common::private_netns;

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
    let d = c.dump(msg::rule_dump(f).into()).await.unwrap();
    d.routing()
        .filter_map(|m| match m {
            RouteNetlinkMessage::NewRule(r) => ObservedRule::parse(r),
            _ => None,
        })
        .collect()
}

async fn routes(c: &Client, f: Family, table: u32) -> Vec<ObservedRoute> {
    let d = c.dump(msg::route_dump(f, Some(table)).into()).await.unwrap();
    d.routing()
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
        .dump(msg::link_dump().into())
        .await
        .unwrap()
        .routing()
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
        for m in c.dump(msg::address_dump(f).into()).await.unwrap().routing() {
            if let RouteNetlinkMessage::NewAddress(a) = m {
                let a = ObservedAddress::parse(a).unwrap();
                if a.index == d1 && a.global() {
                    assert!(!a.tentative(), "nodad");
                    seen.insert(a.address.to_string());
                }
            }
        }
    }
    assert_eq!(seen, ["192.0.2.2", "2001:db8:1::2"].map(String::from).into());
}

/// Nexthop object messages, which FTR parses itself (FR-DISC-3, IMPL-2):
/// a dump and the notifications of creation, replacement and deletion of
/// single objects and groups, and the routes that use them.
#[tokio::test]
#[ignore = "needs root in a private network namespace"]
async fn nexthop_objects_are_dumped_and_notified() {
    use fault_tolerant_router::netlink::{Message, Notification, Subscription, groups};
    private_netns();
    let (d1, d2) = topology();
    let mut sub = Subscription::new(&groups::ALL, 1 << 20).unwrap();
    ip("nexthop add id 10 via fe80::1 dev d1");
    ip("nexthop add id 11 via fe80::2 dev d2 onlink");
    ip("nexthop add id 20 group 10/11");
    ip("nexthop add id 30 via 192.0.2.1 dev d1");
    ip("-6 route add default nhid 10 metric 512");
    let c = Client::new().unwrap();
    let dump = c.dump(Message::GetNexthops).await.unwrap();
    let objects: Vec<_> = dump
        .messages
        .iter()
        .filter_map(|m| match m {
            Message::NewNexthop(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    let by_id = |id: u32| {
        objects
            .iter()
            .find(|n| n.id == id)
            .unwrap_or_else(|| panic!("{id} in {objects:?}"))
    };
    let ll1: IpAddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into();
    assert_eq!((by_id(10).ifindex, by_id(10).gateway), (Some(d1), Some(ll1)));
    assert!(by_id(11).onlink && by_id(11).ifindex == Some(d2));
    assert_eq!(by_id(20).group, vec![10, 11]);
    assert_eq!(by_id(30).gateway, Some(Ipv4Addr::new(192, 0, 2, 1).into()));
    // The route that uses object 10 carries its id and its resolved hop.
    let r = routes(&c, Family::V6, 254).await;
    let def = r.iter().find(|r| r.is_default()).expect("default route");
    assert_eq!(def.nexthop_id, Some(10));
    // Notifications: replacement of the gateway, then deletion.
    ip("nexthop replace id 10 via fe80::9 dev d1");
    ip("nexthop del id 10");
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while let Ok(Some(n)) = tokio::time::timeout_at(deadline, sub.next()).await {
        if let Notification::Message { message, .. } = n {
            match message {
                Message::NewNexthop(m) if m.id == 10 => seen.push(format!("new {:?}", m.gateway)),
                Message::DelNexthop(m) if m.id == 10 => seen.push("del".into()),
                _ => {}
            }
        }
    }
    let ll9: IpAddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9).into();
    assert!(seen.contains(&format!("new {:?}", Some(ll1))), "{seen:?}");
    assert!(seen.contains(&format!("new {:?}", Some(ll9))), "{seen:?}");
    assert_eq!(seen.last().map(String::as_str), Some("del"), "{seen:?}");
    ip("nexthop flush");
}
