//! Construction and parsing of rule, route, link and address messages, with
//! the normalisation that dumps need (FR-REC-6, S3): `FRA_SUPPRESS_PREFIXLEN`
//! `0xffffffff` means unset; a zero mark is dumped with `FRA_FWMASK` only;
//! `unreachable` rules carry table 0; a single-nexthop route equals a
//! one-member multipath route.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage, RouteNextHop, RouteNextHopFlags,
    RoutePreference, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};

use crate::model::Family;
use crate::plan::{Action, NextHop, ROUTE_METRIC, Route, Rule};

pub const TABLE_MAIN: u32 = 254;

pub fn address_family(f: Family) -> AddressFamily {
    match f {
        Family::V4 => AddressFamily::Inet,
        Family::V6 => AddressFamily::Inet6,
    }
}

pub fn family(af: AddressFamily) -> Option<Family> {
    match af {
        AddressFamily::Inet => Some(Family::V4),
        AddressFamily::Inet6 => Some(Family::V6),
        _ => None,
    }
}

fn host_len(a: IpAddr) -> u8 {
    match a {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// `rta_expires` of `RTA_CACHEINFO`: clock ticks (`USER_HZ`, 100 on every
/// supported architecture) until expiry, negative once past, 0 without
/// expiry.
fn expiry(ticks: u32) -> Option<Instant> {
    let ticks = ticks as i32;
    let left = Duration::from_millis(u64::from(ticks.unsigned_abs()) * 10);
    let now = Instant::now();
    match ticks {
        0 => None,
        t if t > 0 => Some(now + left),
        _ => Some(now.checked_sub(left).unwrap_or(now)),
    }
}

fn ip(a: &RouteAddress) -> Option<IpAddr> {
    match a {
        RouteAddress::Inet(v) => Some(IpAddr::V4(*v)),
        RouteAddress::Inet6(v) => Some(IpAddr::V6(*v)),
        _ => None,
    }
}

// ------------------------------------------------------------------ rules

/// The message that creates (or, as a `DelRule`, deletes) a planned rule.
pub fn rule_message(r: &Rule, protocol: u8) -> RuleMessage {
    let mut m = RuleMessage::default();
    m.header.family = address_family(r.family);
    m.header.table = 0;
    m.attributes.push(RuleAttribute::Priority(r.priority));
    m.attributes
        .push(RuleAttribute::Protocol(RouteProtocol::from(protocol)));
    match r.action {
        Action::Lookup(t) => {
            m.header.action = RuleAction::ToTable;
            m.attributes.push(RuleAttribute::Table(t));
        }
        Action::LookupMainSuppressDefault => {
            m.header.action = RuleAction::ToTable;
            m.attributes.push(RuleAttribute::Table(TABLE_MAIN));
            m.attributes.push(RuleAttribute::SuppressPrefixLen(0));
        }
        Action::Unreachable => m.header.action = RuleAction::Unreachable,
    }
    if let Some((mark, mask)) = r.fwmark {
        m.attributes.push(RuleAttribute::FwMark(mark));
        m.attributes.push(RuleAttribute::FwMask(mask));
    }
    if let Some(a) = r.source {
        m.header.src_len = host_len(a);
        m.attributes.push(RuleAttribute::Source(a));
    }
    m
}

/// What a dumped rule does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedAction {
    Lookup {
        table: u32,
        suppress_prefixlen: Option<u32>,
    },
    Unreachable,
    /// `l3mdev` (VRF), goto, nop, blackhole, prohibit…
    Other,
}

/// A dumped rule, normalised.
#[derive(Clone, Debug)]
pub struct ObservedRule {
    pub family: Family,
    pub priority: u32,
    pub protocol: u8,
    pub fwmark: Option<(u32, u32)>,
    pub source: Option<(IpAddr, u8)>,
    pub action: ObservedAction,
    /// Selectors FTR never uses (destination, interfaces, ports, tos, uid,
    /// inverted match, l3mdev…).
    pub foreign_selectors: bool,
    /// The kernel's VRF rule (`l3mdev`), not a collision (FR-ROUTE-6).
    pub l3mdev: bool,
    pub message: RuleMessage,
}

impl ObservedRule {
    pub fn parse(m: &RuleMessage) -> Option<ObservedRule> {
        let family = family(m.header.family)?;
        let (mut priority, mut protocol, mut table) = (0, 0, u32::from(m.header.table));
        let (mut mark, mut mask, mut source, mut spl) = (None, None, None, None);
        let mut foreign = m.header.dst_len != 0 || m.header.tos != 0 || !m.header.flags.is_empty();
        let mut l3mdev = false;
        for a in &m.attributes {
            match a {
                RuleAttribute::Priority(p) => priority = *p,
                RuleAttribute::Protocol(p) => protocol = u8::from(*p),
                RuleAttribute::Table(t) => table = *t,
                RuleAttribute::FwMark(v) => mark = Some(*v),
                RuleAttribute::FwMask(v) => mask = Some(*v),
                RuleAttribute::Source(s) => source = Some((*s, m.header.src_len)),
                RuleAttribute::SuppressPrefixLen(v) => spl = (*v != u32::MAX).then_some(*v),
                RuleAttribute::L3MDev(true) => l3mdev = true,
                RuleAttribute::L3MDev(false) | RuleAttribute::SuppressIfGroup(_) => {}
                _ => foreign = true,
            }
        }
        let fwmark = match (mark, mask) {
            (None, None) => None,
            (m, k) => Some((m.unwrap_or(0), k.unwrap_or(u32::MAX))),
        };
        let action = match m.header.action {
            _ if l3mdev => ObservedAction::Other,
            RuleAction::ToTable => ObservedAction::Lookup {
                table,
                suppress_prefixlen: spl,
            },
            RuleAction::Unreachable => ObservedAction::Unreachable,
            _ => ObservedAction::Other,
        };
        Some(ObservedRule {
            family,
            priority,
            protocol,
            fwmark,
            source,
            action,
            foreign_selectors: foreign || l3mdev,
            l3mdev,
            message: m.clone(),
        })
    }

    /// Whether this dumped rule is the planned rule (same identity,
    /// protocol included).
    pub fn is(&self, r: &Rule, protocol: u8) -> bool {
        let action = match r.action {
            Action::Lookup(t) => ObservedAction::Lookup {
                table: t,
                suppress_prefixlen: None,
            },
            Action::LookupMainSuppressDefault => ObservedAction::Lookup {
                table: TABLE_MAIN,
                suppress_prefixlen: Some(0),
            },
            Action::Unreachable => ObservedAction::Unreachable,
        };
        self.family == r.family
            && self.priority == r.priority
            && self.protocol == protocol
            && !self.foreign_selectors
            && self.fwmark == r.fwmark
            && self.source == r.source.map(|a| (a, host_len(a)))
            && self.action == action
    }
}

/// Dump filter for the rules of a family.
pub fn rule_dump(f: Family) -> RouteNetlinkMessage {
    let mut m = RuleMessage::default();
    m.header.family = address_family(f);
    RouteNetlinkMessage::GetRule(m)
}

// ----------------------------------------------------------------- routes

fn route_header(m: &mut RouteMessage, family: Family, table: u32, protocol: u8) {
    m.header.address_family = address_family(family);
    m.header.table = RouteHeader::RT_TABLE_UNSPEC;
    m.header.protocol = RouteProtocol::from(protocol);
    m.header.scope = RouteScope::Universe;
    m.header.kind = RouteType::Unicast;
    m.attributes.push(RouteAttribute::Table(table));
    m.attributes.push(RouteAttribute::Priority(ROUTE_METRIC));
}

/// The message that installs a planned route (with `NLM_F_REPLACE`).
pub fn route_message(r: &Route, protocol: u8) -> RouteMessage {
    let mut m = RouteMessage::default();
    route_header(&mut m, r.family, r.table, protocol);
    if let Some(s) = r.source {
        m.attributes.push(RouteAttribute::PrefSource(s.into()));
    }
    match r.nexthops.as_slice() {
        [h] => {
            if let Some(g) = h.gateway {
                m.attributes.push(RouteAttribute::Gateway(g.into()));
            }
            m.attributes.push(RouteAttribute::Oif(h.ifindex));
            if h.onlink {
                m.header.flags |= RouteFlags::Onlink;
            }
        }
        hops => {
            let hops = hops
                .iter()
                .map(|h| {
                    let mut n = RouteNextHop::default();
                    n.interface_index = h.ifindex;
                    // `weight − 1` is the kernel's representation (S3).
                    n.hops = u8::try_from(h.weight.clamp(1, 256) - 1).unwrap_or(u8::MAX);
                    if h.onlink {
                        n.flags |= RouteNextHopFlags::Onlink;
                    }
                    if let Some(g) = h.gateway {
                        n.attributes.push(RouteAttribute::Gateway(g.into()));
                    }
                    n
                })
                .collect();
            m.attributes.push(RouteAttribute::MultiPath(hops));
        }
    }
    m
}

/// The exact key that deletes the route of an FTR table (§4.3).
pub fn route_delete_key(family: Family, table: u32, protocol: u8) -> RouteMessage {
    let mut m = RouteMessage::default();
    route_header(&mut m, family, table, protocol);
    m
}

/// Strict dump filter: the routes of one table, or of every table.
pub fn route_dump(f: Family, table: Option<u32>) -> RouteNetlinkMessage {
    let mut m = RouteMessage::default();
    m.header.address_family = address_family(f);
    m.header.kind = RouteType::Unspec;
    m.header.scope = RouteScope::Universe;
    m.header.protocol = RouteProtocol::Unspec;
    if let Some(t) = table {
        m.attributes.push(RouteAttribute::Table(t));
    }
    RouteNetlinkMessage::GetRoute(m)
}

/// A next hop of a dumped route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedHop {
    pub ifindex: u32,
    pub gateway: Option<IpAddr>,
    pub weight: u16,
    pub onlink: bool,
    pub dead: bool,
    pub linkdown: bool,
}

/// A dumped or notified route, normalised.
#[derive(Clone, Debug)]
pub struct ObservedRoute {
    pub family: Family,
    pub table: u32,
    pub protocol: u8,
    pub metric: u32,
    /// `None` for a default route.
    pub destination: Option<(IpAddr, u8)>,
    pub kind: RouteType,
    pub source: Option<IpAddr>,
    pub nexthops: Vec<ObservedHop>,
    /// `RTA_NH_ID`: the route uses a nexthop object (FR-DISC-3); the kernel
    /// also reports the resolved gateway and interface.
    pub nexthop_id: Option<u32>,
    /// IPv6 router preference: -1 low, 0 medium, 1 high.
    pub preference: i8,
    /// When the route expires (Router Advertisement routes), as of the
    /// message's parsing. The kernel collects an expired route without a
    /// deletion notification and refreshes the expiry without a
    /// notification either (FR-DISC-5).
    pub expires_at: Option<Instant>,
    pub message: RouteMessage,
}

impl ObservedRoute {
    pub fn parse(m: &RouteMessage) -> Option<ObservedRoute> {
        let family = family(m.header.address_family)?;
        let mut table = u32::from(m.header.table);
        let (mut metric, mut dst, mut source, mut gateway, mut oif, mut nh_id) = (0, None, None, None, None, None);
        let mut multipath = None;
        let mut preference = 0;
        let mut expires_at = None;
        for a in &m.attributes {
            match a {
                RouteAttribute::CacheInfo(c) => expires_at = expiry(c.expires),
                RouteAttribute::Table(t) => table = *t,
                RouteAttribute::Priority(p) => metric = *p,
                RouteAttribute::Destination(d) => dst = ip(d),
                RouteAttribute::PrefSource(s) => source = ip(s),
                RouteAttribute::Gateway(g) => gateway = ip(g),
                RouteAttribute::Oif(i) => oif = Some(*i),
                RouteAttribute::NhId(i) => nh_id = Some(*i),
                RouteAttribute::MultiPath(h) => multipath = Some(h),
                RouteAttribute::Preference(p) => {
                    preference = match p {
                        RoutePreference::High => 1,
                        RoutePreference::Low => -1,
                        _ => 0,
                    }
                }
                _ => {}
            }
        }
        let flags = m.header.flags;
        let nexthops = match multipath {
            Some(hops) => hops
                .iter()
                .map(|h| ObservedHop {
                    ifindex: h.interface_index,
                    gateway: h.attributes.iter().find_map(|a| match a {
                        RouteAttribute::Gateway(g) => ip(g),
                        _ => None,
                    }),
                    weight: u16::from(h.hops) + 1,
                    onlink: h.flags.contains(RouteNextHopFlags::Onlink),
                    dead: h.flags.contains(RouteNextHopFlags::Dead),
                    linkdown: h.flags.contains(RouteNextHopFlags::Linkdown),
                })
                .collect(),
            None => oif
                .map(|i| ObservedHop {
                    ifindex: i,
                    gateway,
                    weight: 1,
                    onlink: flags.contains(RouteFlags::Onlink),
                    dead: flags.contains(RouteFlags::Dead),
                    linkdown: flags.contains(RouteFlags::Linkdown),
                })
                .into_iter()
                .collect(),
        };
        let destination = match (dst, m.header.destination_prefix_length) {
            (_, 0) => None,
            (Some(d), len) => Some((d, len)),
            (None, len) => Some((
                if family == Family::V4 {
                    [0u8; 4].into()
                } else {
                    [0u8; 16].into()
                },
                len,
            )),
        };
        Some(ObservedRoute {
            family,
            table,
            protocol: u8::from(m.header.protocol),
            metric,
            destination,
            kind: m.header.kind,
            source,
            nexthops,
            nexthop_id: nh_id,
            preference,
            expires_at,
            message: m.clone(),
        })
    }

    /// Whether the route has expired (an expired route can stay listed for
    /// a moment before the kernel collects it).
    pub fn expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }

    pub fn is_default(&self) -> bool {
        self.destination.is_none()
    }

    /// The planned form of an FTR route, for comparison with the desired
    /// state; `None` if it is not a usable FTR-shaped default route.
    pub fn as_planned(&self) -> Option<Route> {
        if !self.is_default()
            || self.kind != RouteType::Unicast
            || self.metric != ROUTE_METRIC
            || self.nexthops.is_empty()
        {
            return None;
        }
        let single = self.nexthops.len() == 1;
        let mut nexthops: Vec<NextHop> = self
            .nexthops
            .iter()
            .map(|h| NextHop {
                ifindex: h.ifindex,
                gateway: h.gateway,
                onlink: h.onlink,
                weight: if single { 1 } else { h.weight },
            })
            .collect();
        nexthops.sort();
        Some(Route {
            family: self.family,
            table: self.table,
            source: self.source,
            nexthops,
        })
    }
}

// ------------------------------------------------------------------ links

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedLink {
    pub index: u32,
    pub name: String,
    pub up: bool,
    pub lower_up: bool,
    pub point_to_point: bool,
}

impl ObservedLink {
    pub fn parse(m: &LinkMessage) -> Option<ObservedLink> {
        let name = m.attributes.iter().find_map(|a| match a {
            LinkAttribute::IfName(n) => Some(n.clone()),
            _ => None,
        })?;
        let f = m.header.flags;
        Some(ObservedLink {
            index: m.header.index,
            name,
            up: f.contains(LinkFlags::Up),
            lower_up: f.contains(LinkFlags::LowerUp),
            point_to_point: f.contains(LinkFlags::Pointopoint),
        })
    }

    /// Up with carrier (SPEC.md §2, "ready").
    pub fn usable(&self) -> bool {
        self.up && self.lower_up
    }
}

pub fn link_dump() -> RouteNetlinkMessage {
    RouteNetlinkMessage::GetLink(LinkMessage::default())
}

// -------------------------------------------------------------- addresses

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedAddress {
    pub index: u32,
    pub family: Family,
    pub address: IpAddr,
    pub prefix_len: u8,
    /// `RT_SCOPE_*`: 0 universe (global), 253 link, 254 host.
    pub scope: u8,
    pub flags: AddressFlags,
}

impl ObservedAddress {
    pub fn parse(m: &AddressMessage) -> Option<ObservedAddress> {
        let family = family(m.header.family)?;
        let (mut local, mut address, mut flags) = (None, None, None);
        for a in &m.attributes {
            match a {
                AddressAttribute::Local(l) => local = Some(*l),
                AddressAttribute::Address(a) => address = Some(*a),
                AddressAttribute::Flags(f) => flags = Some(*f),
                _ => {}
            }
        }
        // IFA_LOCAL is the local address; on IPv4 point-to-point links
        // IFA_ADDRESS is the peer.
        let address = local.or(address)?;
        let flags = flags.unwrap_or_else(|| AddressFlags::from_bits_retain(u32::from(m.header.flags.bits())));
        Some(ObservedAddress {
            index: m.header.index,
            family,
            address,
            prefix_len: m.header.prefix_len,
            scope: u8::from(m.header.scope),
            flags,
        })
    }

    pub fn global(&self) -> bool {
        self.scope == 0
    }

    pub fn tentative(&self) -> bool {
        self.flags.contains(AddressFlags::Tentative)
    }

    pub fn dad_failed(&self) -> bool {
        self.flags.contains(AddressFlags::Dadfailed)
    }

    pub fn deprecated(&self) -> bool {
        self.flags.contains(AddressFlags::Deprecated)
    }

    /// IPv6 temporary (privacy) address: `IFA_F_TEMPORARY` shares bit 0x01
    /// with `IFA_F_SECONDARY` (S3).
    pub fn temporary(&self) -> bool {
        self.family == Family::V6 && self.flags.contains(AddressFlags::Secondary)
    }

    /// IPv4 secondary address.
    pub fn secondary(&self) -> bool {
        self.family == Family::V4 && self.flags.contains(AddressFlags::Secondary)
    }

    pub fn permanent(&self) -> bool {
        self.flags.contains(AddressFlags::Permanent)
    }
}

pub fn address_dump(f: Family) -> RouteNetlinkMessage {
    let mut m = AddressMessage::default();
    m.header.family = address_family(f);
    RouteNetlinkMessage::GetAddress(m)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use netlink_packet_core::NetlinkMessage;

    use super::*;
    use crate::plan::RuleKind;

    /// Serialises and parses a message, as the kernel would see and echo it.
    fn reparse(m: RouteNetlinkMessage) -> RouteNetlinkMessage {
        let mut nl = NetlinkMessage::from(m);
        nl.finalize();
        let mut buf = vec![0u8; nl.buffer_len()];
        nl.serialize(&mut buf);
        match NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf)
            .unwrap()
            .payload
        {
            netlink_packet_core::NetlinkPayload::InnerMessage(i) => i,
            p => panic!("unexpected payload {p:?}"),
        }
    }

    fn reparse_rule(m: &RuleMessage) -> RuleMessage {
        match reparse(RouteNetlinkMessage::NewRule(m.clone())) {
            RouteNetlinkMessage::NewRule(r) => r,
            o => panic!("{o:?}"),
        }
    }

    fn reparse_route(m: &RouteMessage) -> RouteMessage {
        match reparse(RouteNetlinkMessage::NewRoute(m.clone())) {
            RouteNetlinkMessage::NewRoute(r) => r,
            o => panic!("{o:?}"),
        }
    }

    fn rule(priority: u32, fwmark: Option<(u32, u32)>, source: Option<IpAddr>, action: Action) -> Rule {
        Rule {
            family: Family::V4,
            priority,
            fwmark,
            source,
            action,
            kind: RuleKind::FinalGuard,
        }
    }

    #[test]
    fn planned_rules_survive_a_round_trip() {
        let a: IpAddr = Ipv4Addr::new(192, 0, 2, 2).into();
        for r in [
            rule(1001, Some((0x41_0000, 0xff_0000)), None, Action::Lookup(1001)),
            rule(1100, None, None, Action::LookupMainSuppressDefault),
            rule(1501, Some((0, 0xff_0000)), Some(a), Action::Lookup(1001)),
            rule(1699, None, None, Action::Unreachable),
        ] {
            let o = ObservedRule::parse(&reparse_rule(&rule_message(&r, 249))).unwrap();
            assert!(o.is(&r, 249), "{r:?} vs {o:?}");
            assert!(!o.is(&r, 4), "the protocol is part of the identity");
        }
    }

    #[test]
    fn dumped_rules_are_normalised() {
        // The kernel's dump of `from 192.0.2.2 fwmark 0/0xff0000 unreachable`:
        // FRA_FWMASK only, table 0, suppress_prefixlen unset (0xffffffff).
        let a: IpAddr = Ipv4Addr::new(192, 0, 2, 2).into();
        let mut m = RuleMessage::default();
        m.header.family = AddressFamily::Inet;
        m.header.action = RuleAction::Unreachable;
        m.header.src_len = 32;
        m.attributes = vec![
            RuleAttribute::Priority(1564),
            RuleAttribute::Protocol(RouteProtocol::from(249)),
            RuleAttribute::FwMask(0xff_0000),
            RuleAttribute::Source(a),
            RuleAttribute::SuppressPrefixLen(u32::MAX),
            RuleAttribute::Table(0),
        ];
        let o = ObservedRule::parse(&m).unwrap();
        assert!(o.is(&rule(1564, Some((0, 0xff_0000)), Some(a), Action::Unreachable), 249));
        // A rule with an interface selector is never ours.
        m.attributes.push(RuleAttribute::Iifname("lan".into()));
        assert!(
            !ObservedRule::parse(&m)
                .unwrap()
                .is(&rule(1564, Some((0, 0xff_0000)), Some(a), Action::Unreachable), 249)
        );
    }

    #[test]
    fn routes_survive_a_round_trip_and_single_equals_one_member() {
        let gw: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let gw2: IpAddr = Ipv4Addr::new(100, 64, 0, 1).into();
        let multi = Route {
            family: Family::V4,
            table: 1000,
            source: None,
            nexthops: vec![
                NextHop {
                    ifindex: 5,
                    gateway: Some(gw),
                    onlink: false,
                    weight: 10,
                },
                NextHop {
                    ifindex: 6,
                    gateway: Some(gw2),
                    onlink: true,
                    weight: 256,
                },
                NextHop {
                    ifindex: 7,
                    gateway: None,
                    onlink: false,
                    weight: 1,
                },
            ],
        };
        let o = ObservedRoute::parse(&reparse_route(&route_message(&multi, 249))).unwrap();
        assert_eq!(o.as_planned().unwrap(), multi);
        assert_eq!((o.table, o.protocol, o.metric), (1000, 249, 100));
        let single = Route {
            family: Family::V4,
            table: 1001,
            source: Some(Ipv4Addr::new(192, 0, 2, 2).into()),
            nexthops: vec![NextHop {
                ifindex: 5,
                gateway: Some(gw),
                onlink: true,
                weight: 1,
            }],
        };
        let o = ObservedRoute::parse(&reparse_route(&route_message(&single, 249))).unwrap();
        assert_eq!(o.as_planned().unwrap(), single);
        // A one-member RTA_MULTIPATH dump compares equal to the single route.
        let mut m = route_message(&single, 249);
        m.header.flags = RouteFlags::empty();
        m.attributes
            .retain(|a| !matches!(a, RouteAttribute::Gateway(_) | RouteAttribute::Oif(_)));
        let mut hop = RouteNextHop::default();
        hop.interface_index = 5;
        hop.hops = 4;
        hop.flags = RouteNextHopFlags::Onlink | RouteNextHopFlags::Linkdown;
        hop.attributes.push(RouteAttribute::Gateway(gw.into()));
        m.attributes.push(RouteAttribute::MultiPath(vec![hop]));
        let o = ObservedRoute::parse(&m).unwrap();
        assert!(o.nexthops[0].linkdown);
        assert_eq!(o.as_planned().unwrap(), single);
    }

    #[test]
    fn route_expiry_follows_the_cache_info_ticks() {
        let before = Instant::now();
        assert_eq!(expiry(0), None, "no expiry");
        let t = expiry(1800 * 100).unwrap();
        assert!(t >= before + Duration::from_secs(1800));
        assert!(t <= Instant::now() + Duration::from_secs(1800));
        // Listed after its expiry, before the kernel collects it.
        assert!(expiry((-150i32) as u32).unwrap() < before);
        let gw: IpAddr = "fe80::1".parse().unwrap();
        let route = Route {
            family: Family::V6,
            table: 254,
            source: None,
            nexthops: vec![NextHop {
                ifindex: 5,
                gateway: Some(gw),
                onlink: false,
                weight: 1,
            }],
        };
        let mut o = ObservedRoute::parse(&route_message(&route, 9)).unwrap();
        assert!(!o.expired(Instant::now()));
        o.expires_at = expiry(100);
        assert!(!o.expired(before));
        assert!(o.expired(before + Duration::from_secs(2)));
    }

    #[test]
    fn delete_key_has_no_next_hop() {
        let m = route_delete_key(Family::V6, 1003, 249);
        let o = ObservedRoute::parse(&m).unwrap();
        assert!(o.nexthops.is_empty() && o.is_default());
        assert_eq!((o.table, o.metric), (1003, 100));
    }
}
