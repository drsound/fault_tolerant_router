use std::net::Ipv4Addr;

use netlink_packet_route::address::AddressFlags;
use netlink_packet_route::route::{RouteMessage, RouteType};

use super::*;
use crate::config;
use crate::model::UplinkId;
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
        s.routes.insert((r.family, r.table, r.destination, r.metric), r);
    }
    s
}

fn key(id: u8) -> PathKey {
    PathKey {
        uplink: UplinkId::new(id).unwrap(),
        family: Family::V4,
    }
}

fn run(cfg: &Config, s: &System) -> BTreeMap<PathKey, Discovered> {
    discover(cfg, s, &BTreeMap::new(), 249)
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
    s.routes.insert((r.family, r.table, None, r.metric), r);
    assert_eq!(run(&cfg, &s)[&key(1)].ready.unwrap().gateway, Some(v4([192, 0, 2, 33])));

    // A route with RTA_NH_ID is used only through a resolved single object.
    let mut r = default_route(254, 10, &[(5, [192, 0, 2, 44])]);
    r.nexthop_id = Some(7);
    s.routes.insert((r.family, r.table, None, r.metric), r);
    assert_eq!(run(&cfg, &s)[&key(1)].ready.unwrap().gateway, Some(v4([192, 0, 2, 33])));
    let objects = [(
        7,
        NexthopObject {
            ifindex: 5,
            gateway: Some(v4([192, 0, 2, 45])),
            onlink: false,
        },
    )]
    .into();
    assert_eq!(
        discover(&cfg, &s, &objects, 249)[&key(1)].ready.unwrap().gateway,
        Some(v4([192, 0, 2, 45]))
    );
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
