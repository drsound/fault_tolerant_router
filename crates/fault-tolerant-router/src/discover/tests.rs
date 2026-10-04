use std::net::Ipv4Addr;

use netlink_packet_route::address::AddressFlags;
use netlink_packet_route::route::{RouteMessage, RouteType};

use super::*;
use crate::config;
use crate::model::UplinkId;
use crate::netlink::NexthopMessage;
use crate::netlink::msg::{ObservedHop, ObservedLink};

const CONFIG: &str = r#"version = 2
[routing]
discovery_tables = ["main", 200]
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "wana"
priority = 1
[uplink.ipv4]
[[uplink]]
id = 2
name = "c"
interface = "ppp0"
priority = 1
[uplink.ipv4]
"#;

fn v4(a: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(a))
}

fn link(index: u32, name: &str, up: bool, ptp: bool) -> ObservedLink {
    ObservedLink {
        index,
        name: name.into(),
        up,
        lower_up: up,
        point_to_point: ptp,
    }
}

fn addr(index: u32, a: [u8; 4], flags: AddressFlags) -> ObservedAddress {
    ObservedAddress {
        index,
        family: Family::V4,
        address: v4(a),
        prefix_len: 24,
        scope: 0,
        flags,
    }
}

fn default_route(table: u32, metric: u32, hops: &[(u32, [u8; 4])]) -> ObservedRoute {
    ObservedRoute {
        family: Family::V4,
        table,
        protocol: 16, // dhcp
        metric,
        destination: None,
        kind: RouteType::Unicast,
        source: None,
        nexthops: hops
            .iter()
            .map(|(i, g)| ObservedHop {
                ifindex: *i,
                gateway: Some(v4(*g)),
                weight: 1,
                onlink: false,
                dead: false,
                linkdown: false,
            })
            .collect(),
        nexthop_id: None,
        preference: 0,
        expires_at: None,
        message: RouteMessage::default(),
    }
}

fn connected_route(ifindex: u32, net: [u8; 4], len: u8) -> ObservedRoute {
    let mut r = default_route(254, 0, &[]);
    r.destination = Some((v4(net), len));
    r.protocol = 2;
    r.nexthops = vec![ObservedHop {
        ifindex,
        gateway: None,
        weight: 1,
        onlink: false,
        dead: false,
        linkdown: false,
    }];
    r
}

fn system() -> System {
    let mut s = System::default();
    s.links.insert(5, link(5, "wana", true, false));
    s.links.insert(9, link(9, "ppp0", true, true));
    s.links.insert(3, link(3, "lan", true, false));
    for a in [
        addr(5, [192, 0, 2, 20], AddressFlags::empty()),
        addr(5, [192, 0, 2, 2], AddressFlags::Permanent),
        addr(5, [192, 0, 2, 99], AddressFlags::Permanent | AddressFlags::Secondary),
        addr(9, [203, 0, 113, 10], AddressFlags::Permanent),
        addr(3, [198, 51, 100, 1], AddressFlags::Permanent),
    ] {
        s.addresses.insert((a.index, a.address), a);
    }
    for r in [
        default_route(254, 200, &[(5, [192, 0, 2, 1])]),
        default_route(200, 100, &[(5, [192, 0, 2, 254])]),
        connected_route(5, [192, 0, 2, 0], 24),
    ] {
        s.insert_route(&scope(), r);
    }
    s
}

fn scope() -> crate::system::Scope {
    crate::system::Scope {
        ftr_tables: 1000..=1191,
        discovery_tables: vec![254, 200],
    }
}

fn key(id: u8) -> PathKey {
    PathKey {
        uplink: UplinkId::new(id).unwrap(),
        family: Family::V4,
    }
}

fn run(cfg: &Config, s: &System) -> BTreeMap<PathKey, Discovered> {
    discover(cfg, s, 249)
}

#[test]
fn ethernet_and_point_to_point_paths_are_ready() {
    let cfg = config::parse(CONFIG).unwrap();
    let d = run(&cfg, &system());
    let a = d[&key(1)].ready.unwrap();
    // Permanent before dynamic, primary before secondary, then lowest.
    assert_eq!(a.source, v4([192, 0, 2, 2]));
    // Lowest metric wins across the discovery tables.
    assert_eq!(a.gateway, Some(v4([192, 0, 2, 254])));
    assert_eq!(
        d[&key(1)].local_addresses.len(),
        3,
        "secondary and dynamic addresses get source rules"
    );
    let c = d[&key(2)].ready.unwrap();
    assert_eq!((c.gateway, c.source, c.ifindex), (None, v4([203, 0, 113, 10]), 9));
}

#[test]
fn readiness_reasons() {
    let cfg = config::parse(CONFIG).unwrap();
    let mut s = system();
    s.links.get_mut(&5).unwrap().lower_up = false;
    assert_eq!(run(&cfg, &s)[&key(1)].ready, Err(Reason::CarrierLost));
    s.links.remove(&5);
    let d = run(&cfg, &s);
    assert_eq!(d[&key(1)].ready, Err(Reason::InterfaceRemoved));
    assert_eq!(d[&key(1)].ifindex, None);

    let mut s = system();
    s.routes.retain(|_, r| !r.is_default());
    assert_eq!(run(&cfg, &s)[&key(1)].ready, Err(Reason::GatewayLost));

    let mut s = system();
    s.addresses.retain(|(i, _), _| *i != 5);
    assert_eq!(run(&cfg, &s)[&key(1)].ready, Err(Reason::AddressLost));

    // Tentative and deprecated addresses are not source candidates.
    let mut s = system();
    s.addresses.retain(|(i, _), _| *i != 5);
    for a in [
        addr(5, [192, 0, 2, 7], AddressFlags::Tentative),
        addr(5, [192, 0, 2, 8], AddressFlags::Deprecated),
    ] {
        s.addresses.insert((a.index, a.address), a);
    }
    let d = run(&cfg, &s);
    assert_eq!(d[&key(1)].ready, Err(Reason::AddressLost));
    assert_eq!(
        d[&key(1)].local_addresses,
        [v4([192, 0, 2, 8])].into(),
        "deprecated addresses keep their rules"
    );
}

#[test]
fn dead_and_linkdown_members_and_own_routes_are_ignored() {
    let cfg = config::parse(CONFIG).unwrap();
    let mut s = system();
    for r in s.routes.values_mut() {
        if r.table == 200 {
            r.nexthops[0].linkdown = true;
        }
    }
    assert_eq!(run(&cfg, &s)[&key(1)].ready.unwrap().gateway, Some(v4([192, 0, 2, 1])));
    for r in s.routes.values_mut() {
        if r.is_default() {
            r.protocol = 249;
        }
    }
    assert_eq!(run(&cfg, &s)[&key(1)].ready, Err(Reason::GatewayLost));
}

#[test]
fn multipath_defaults_and_nexthop_objects() {
    let cfg = config::parse(CONFIG).unwrap();
    let mut s = system();
    s.routes.retain(|_, r| !r.is_default());
    let r = default_route(254, 50, &[(7, [10, 0, 0, 1]), (5, [192, 0, 2, 33])]);
    s.insert_route(&scope(), r);
    assert_eq!(run(&cfg, &s)[&key(1)].ready.unwrap().gateway, Some(v4([192, 0, 2, 33])));

    // A route with RTA_NH_ID is used only through a resolved single object.
    let mut r = default_route(254, 10, &[(5, [192, 0, 2, 44])]);
    r.nexthop_id = Some(7);
    s.insert_route(&scope(), r);
    assert_eq!(run(&cfg, &s)[&key(1)].ready.unwrap().gateway, Some(v4([192, 0, 2, 33])));
    let object = NexthopMessage {
        id: 7,
        ifindex: Some(5),
        gateway: Some(v4([192, 0, 2, 45])),
        ..NexthopMessage::default()
    };
    s.nexthops.insert(7, object.clone());
    assert_eq!(run(&cfg, &s)[&key(1)].ready.unwrap().gateway, Some(v4([192, 0, 2, 45])));
    // A dead or linkdown object is not used.
    s.nexthops.insert(
        7,
        NexthopMessage {
            dead: true,
            ..object.clone()
        },
    );
    assert_eq!(run(&cfg, &s)[&key(1)].ready.unwrap().gateway, Some(v4([192, 0, 2, 33])));
    s.nexthops.insert(
        7,
        NexthopMessage {
            linkdown: true,
            ..object
        },
    );
    assert_eq!(run(&cfg, &s)[&key(1)].ready.unwrap().gateway, Some(v4([192, 0, 2, 33])));
}

#[test]
fn nexthop_groups_are_never_used() {
    let cfg = config::parse(CONFIG_V6).unwrap();
    let mut s = system6();
    s.routes.retain(|_, r| !r.is_default());
    // `default nhid 20` over the members 10 (wana) and 11 (wanb), as the
    // kernel dumps it: the resolved members as multipath next hops.
    let mut r = ra_route(5, "fe80::1", 600, 0);
    r.nexthops.push(ObservedHop {
        ifindex: 6,
        gateway: Some(v6("fe80::2")),
        weight: 1,
        onlink: false,
        dead: false,
        linkdown: false,
    });
    r.nexthop_id = Some(20);
    s.insert_route(&scope(), r);
    s.nexthops.insert(
        20,
        NexthopMessage {
            id: 20,
            group: vec![10, 11],
            ..NexthopMessage::default()
        },
    );
    let d = run(&cfg, &s);
    assert_eq!(d[&key6(1)].ready, Err(Reason::GatewayLost));
    assert!(d[&key6(1)].group_only && d[&key6(2)].group_only && !d[&key6(3)].group_only);
    // A single object on A makes A ready; the group stays unused for B.
    let mut r = ra_route(5, "fe80::1", 512, 0);
    r.nexthop_id = Some(10);
    s.insert_route(&scope(), r);
    s.nexthops.insert(
        10,
        NexthopMessage {
            id: 10,
            ifindex: Some(5),
            gateway: Some(v6("fe80::9")),
            ..NexthopMessage::default()
        },
    );
    let d = run(&cfg, &s);
    assert_eq!(d[&key6(1)].ready.unwrap().gateway, Some(v6("fe80::9")));
    assert!(!d[&key6(1)].group_only && d[&key6(2)].group_only);
}

#[test]
fn static_gateway_needs_a_connected_route_or_onlink() {
    let text = CONFIG.replace(
        "[uplink.ipv4]\n[[uplink]]",
        "[uplink.ipv4]\ngateway = \"198.18.0.1\"\n[[uplink]]",
    );
    let cfg = config::parse(&text).unwrap();
    assert_eq!(run(&cfg, &system())[&key(1)].ready, Err(Reason::GatewayLost));
    let cfg = config::parse(&text.replace(
        "gateway = \"198.18.0.1\"",
        "gateway = \"198.18.0.1\"\ngateway_onlink = true",
    ))
    .unwrap();
    let r = run(&cfg, &system())[&key(1)].ready.unwrap();
    assert_eq!((r.gateway, r.onlink), (Some(v4([198, 18, 0, 1])), true));
    let cfg = config::parse(&text.replace("198.18.0.1", "192.0.2.5")).unwrap();
    assert_eq!(
        run(&cfg, &system())[&key(1)].ready.unwrap().gateway,
        Some(v4([192, 0, 2, 5]))
    );
}

#[test]
fn static_source_on_another_interface_and_conflicts() {
    let text = CONFIG.replace(
        "[uplink.ipv4]\n[[uplink]]",
        "[uplink.ipv4]\nsource = \"198.51.100.1\"\nnat = \"snat\"\n[[uplink]]",
    );
    let cfg = config::parse(&text).unwrap();
    let d = run(&cfg, &system());
    assert_eq!(d[&key(1)].ready.unwrap().source, v4([198, 51, 100, 1]));
    assert!(d[&key(1)].local_addresses.contains(&v4([198, 51, 100, 1])));

    // The same address on both uplinks: both paths not ready.
    let mut s = system();
    let dup = addr(9, [192, 0, 2, 2], AddressFlags::Permanent);
    s.addresses.insert((9, dup.address), dup);
    let d = run(&config::parse(CONFIG).unwrap(), &s);
    assert_eq!(d[&key(1)].ready, Err(Reason::AddressConflict));
    assert_eq!(d[&key(2)].ready, Err(Reason::AddressConflict));
}

const CONFIG_V6: &str = r#"version = 2
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "wana"
priority = 1
[uplink.ipv6]
nat = "masquerade"
[[uplink]]
id = 2
name = "b"
interface = "wanb"
priority = 1
[uplink.ipv6]
nat = "masquerade"
[[uplink]]
id = 3
name = "c"
interface = "ppp0"
priority = 1
[uplink.ipv6]
nat = "masquerade"
"#;

fn v6(a: &str) -> IpAddr {
    a.parse().unwrap()
}

fn addr6(index: u32, a: &str, scope: u8, flags: AddressFlags) -> ObservedAddress {
    ObservedAddress {
        index,
        family: Family::V6,
        address: v6(a),
        prefix_len: 64,
        scope,
        flags,
    }
}

/// An IPv6 default route of main with a single next hop.
fn ra_route(ifindex: u32, gw: &str, metric: u32, preference: i8) -> ObservedRoute {
    let mut r = default_route(254, metric, &[]);
    r.family = Family::V6;
    r.protocol = 9; // ra
    r.preference = preference;
    r.nexthops = vec![ObservedHop {
        ifindex,
        gateway: Some(v6(gw)),
        weight: 1,
        onlink: false,
        dead: false,
        linkdown: false,
    }];
    r
}

fn key6(id: u8) -> PathKey {
    PathKey {
        uplink: UplinkId::new(id).unwrap(),
        family: Family::V6,
    }
}

fn system6() -> System {
    let mut s = System::default();
    s.links.insert(5, link(5, "wana", true, false));
    s.links.insert(6, link(6, "wanb", true, false));
    s.links.insert(9, link(9, "ppp0", true, true));
    for a in [
        addr6(5, "fe80::5", 253, AddressFlags::Permanent),
        addr6(5, "2001:db8:a:ffff::1234", 0, AddressFlags::empty()),
        addr6(6, "fe80::6", 253, AddressFlags::Permanent),
        addr6(6, "2001:db8:b:ffff::99", 0, AddressFlags::empty()),
        addr6(9, "fe80::9", 253, AddressFlags::Permanent),
    ] {
        s.addresses.insert((a.index, a.address), a);
    }
    // Router Advertisements of both providers from the same link-local
    // address and with the kernel's default metric (AS-28).
    for r in [ra_route(5, "fe80::1", 1024, 0), ra_route(6, "fe80::1", 1024, 0)] {
        s.insert_route(&scope(), r);
    }
    s
}

#[test]
fn identical_link_local_gateways_on_two_uplinks_are_distinct() {
    let cfg = config::parse(CONFIG_V6).unwrap();
    let d = run(&cfg, &system6());
    let a = d[&key6(1)].ready.unwrap();
    let b = d[&key6(2)].ready.unwrap();
    assert_eq!((a.ifindex, a.gateway), (5, Some(v6("fe80::1"))));
    assert_eq!((b.ifindex, b.gateway), (6, Some(v6("fe80::1"))));
    assert_eq!(a.source, v6("2001:db8:a:ffff::1234"));
    // Link-local addresses are neither local addresses nor sources.
    assert_eq!(d[&key6(1)].local_addresses, [v6("2001:db8:a:ffff::1234")].into());
}

#[test]
fn ipv6_sources_exclude_temporary_deprecated_and_tentative_addresses() {
    let cfg = config::parse(CONFIG_V6).unwrap();
    let mut s = system6();
    // IFA_F_TEMPORARY shares its bit with IFA_F_SECONDARY (S3).
    for a in [
        addr6(5, "2001:db8:a:ffff::1", 0, AddressFlags::Secondary),
        addr6(5, "2001:db8:a:ffff::2", 0, AddressFlags::Deprecated),
        addr6(5, "2001:db8:a:ffff::3", 0, AddressFlags::Tentative),
        addr6(5, "2001:db8:a:ffff::4", 0, AddressFlags::Dadfailed),
    ] {
        s.addresses.insert((a.index, a.address), a);
    }
    let d = &run(&cfg, &s)[&key6(1)];
    assert_eq!(d.ready.unwrap().source, v6("2001:db8:a:ffff::1234"));
    // Temporary and deprecated addresses keep their source rules.
    assert_eq!(
        d.local_addresses,
        [
            v6("2001:db8:a:ffff::1"),
            v6("2001:db8:a:ffff::2"),
            v6("2001:db8:a:ffff::1234")
        ]
        .into()
    );
    // A permanent address is preferred over a dynamic one.
    let p = addr6(5, "2001:db8:a:ffff::ffff", 0, AddressFlags::Permanent);
    s.addresses.insert((p.index, p.address), p);
    assert_eq!(
        run(&cfg, &s)[&key6(1)].ready.unwrap().source,
        v6("2001:db8:a:ffff::ffff")
    );
    // Only temporary or deprecated addresses: no source.
    s.addresses
        .retain(|(i, a), _| *i != 5 || ["2001:db8:a:ffff::1", "2001:db8:a:ffff::2"].contains(&a.to_string().as_str()));
    assert_eq!(run(&cfg, &s)[&key6(1)].ready, Err(Reason::AddressLost));
}

#[test]
fn ipv6_router_preference_breaks_metric_ties() {
    let cfg = config::parse(CONFIG_V6).unwrap();
    let mut s = system6();
    s.insert_route(&scope(), ra_route(5, "fe80::2", 1024, 1));
    s.insert_route(&scope(), ra_route(5, "fe80::3", 1024, -1));
    assert_eq!(run(&cfg, &s)[&key6(1)].ready.unwrap().gateway, Some(v6("fe80::2")));
    // A lower metric wins over a higher preference.
    s.insert_route(&scope(), ra_route(5, "fe80::4", 512, -1));
    assert_eq!(run(&cfg, &s)[&key6(1)].ready.unwrap().gateway, Some(v6("fe80::4")));
}

#[test]
fn ipv6_point_to_point_paths_need_a_gateway() {
    let cfg = config::parse(CONFIG_V6).unwrap();
    let mut s = system6();
    assert_eq!(run(&cfg, &s)[&key6(3)].ready, Err(Reason::AddressLost));
    // No Router Advertisement: neither address nor gateway (FR-SYS-3).
    assert!(run(&cfg, &s)[&key6(3)].gateway_missing);
    assert!(!run(&cfg, &s)[&key6(1)].gateway_missing);
    let g = addr6(9, "2001:db8:c:ffff::10", 0, AddressFlags::empty());
    s.addresses.insert((g.index, g.address), g);
    // Unlike IPv4, no device-only next hop (Q12).
    assert_eq!(run(&cfg, &s)[&key6(3)].ready, Err(Reason::GatewayLost));
    s.insert_route(&scope(), ra_route(9, "fe80::1", 1024, 0));
    let r = run(&cfg, &s)[&key6(3)].ready.unwrap();
    assert_eq!((r.ifindex, r.gateway), (9, Some(v6("fe80::1"))));
    assert!(!run(&cfg, &s)[&key6(3)].gateway_missing);
    // Without carrier, nothing is awaited.
    s.links.get_mut(&9).unwrap().lower_up = false;
    s.routes.clear();
    assert!(!run(&cfg, &s)[&key6(3)].gateway_missing);
}

#[test]
fn static_link_local_gateway_uses_the_interface_s_connected_route() {
    let text = CONFIG_V6.replacen("nat = \"masquerade\"", "nat = \"masquerade\"\ngateway = \"fe80::1\"", 1);
    let cfg = config::parse(&text).unwrap();
    let mut s = system6();
    s.routes.retain(|_, r| !r.is_default());
    assert_eq!(run(&cfg, &s)[&key6(1)].ready, Err(Reason::GatewayLost));
    // fe80::/64 exists on every interface with the same metric: only A's
    // covers A's gateway.
    for i in [6, 9, 5] {
        let mut r = ra_route(i, "fe80::1", 256, 0);
        r.protocol = 2;
        r.destination = Some((v6("fe80::"), 64));
        r.nexthops[0].gateway = None;
        s.insert_route(&scope(), r);
    }
    let r = run(&cfg, &s)[&key6(1)].ready.unwrap();
    assert_eq!((r.ifindex, r.gateway, r.onlink), (5, Some(v6("fe80::1")), false));
}

#[test]
fn expired_router_advertisement_routes_are_not_used() {
    let cfg = config::parse(CONFIG_V6).unwrap();
    let mut s = system6();
    let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
    for r in s.routes.values_mut().filter(|r| r.nexthops[0].ifindex == 5) {
        r.expires_at = Some(past);
    }
    assert_eq!(run(&cfg, &s)[&key6(1)].ready, Err(Reason::GatewayLost));
    let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
    for r in s.routes.values_mut().filter(|r| r.nexthops[0].ifindex == 5) {
        r.expires_at = Some(future);
    }
    assert!(run(&cfg, &s)[&key6(1)].ready.is_ok());
}
