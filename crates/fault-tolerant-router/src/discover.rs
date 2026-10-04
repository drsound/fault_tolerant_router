//! Uplink discovery (SPEC.md §5.1): readiness, local addresses, source and
//! next hop of every configured path, derived from the observed system.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::config::{AutoOr, Config, PathSettings, Uplink};
use crate::health::Reason;
use crate::model::{Family, PathKey};
use crate::netlink::msg::{ObservedAddress, ObservedRoute, TABLE_MAIN};
use crate::plan::ReadyPath;
use crate::system::System;

/// A single (non-group) nexthop object, resolved (FR-DISC-3). Filled by the
/// observer once nexthop messages are validated (M2, AS-49).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NexthopObject {
    pub ifindex: u32,
    pub gateway: Option<IpAddr>,
    pub onlink: bool,
}

/// The discovered state of one path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    /// The interface index, when the interface exists (FR-DISC-1).
    pub ifindex: Option<u32>,
    /// `Ok` when the path is ready; otherwise the reason it is not.
    pub ready: Result<ReadyPath, Reason>,
    /// Local addresses (FR-DISC-2), each with a source rule and a guard.
    pub local_addresses: BTreeSet<IpAddr>,
}

/// Discovers every configured path.
pub fn discover(
    config: &Config,
    system: &System,
    nexthops: &BTreeMap<u32, NexthopObject>,
    own_protocol: u8,
) -> BTreeMap<PathKey, Discovered> {
    let mut out = BTreeMap::new();
    for u in &config.uplinks {
        for family in u.families() {
            let p = u.path(family).expect("families() lists configured paths");
            let d = discover_path(config, system, nexthops, own_protocol, u, family, p);
            out.insert(PathKey { uplink: u.id, family }, d);
        }
    }
    // FR-DISC-2: an address in the local sets of two paths of the same
    // family makes both paths not ready.
    let keys: Vec<PathKey> = out.keys().copied().collect();
    let mut conflicted = BTreeSet::new();
    for (i, a) in keys.iter().enumerate() {
        for b in &keys[i + 1..] {
            if a.family == b.family && !out[a].local_addresses.is_disjoint(&out[b].local_addresses) {
                conflicted.insert(*a);
                conflicted.insert(*b);
            }
        }
    }
    for k in conflicted {
        if let Some(d) = out.get_mut(&k) {
            d.ready = Err(Reason::AddressConflict);
        }
    }
    out
}

fn usable(a: &ObservedAddress) -> bool {
    a.global() && !a.tentative() && !a.dad_failed()
}

fn discover_path(
    config: &Config,
    system: &System,
    nexthops: &BTreeMap<u32, NexthopObject>,
    own_protocol: u8,
    u: &Uplink,
    family: Family,
    p: &PathSettings,
) -> Discovered {
    let Some(link) = system.link_by_name(&u.interface) else {
        // A static source on another interface is still a local address.
        let local = static_source_elsewhere(system, p, None).into_iter().collect();
        return Discovered {
            ifindex: None,
            ready: Err(Reason::InterfaceRemoved),
            local_addresses: local,
        };
    };
    let ifindex = link.index;
    let on_link: Vec<&ObservedAddress> = system
        .addresses
        .values()
        .filter(|a| a.index == ifindex && a.family == family && usable(a))
        .collect();
    let mut local: BTreeSet<IpAddr> = on_link.iter().map(|a| a.address).collect();
    local.extend(static_source_elsewhere(system, p, Some(ifindex)));
    let discovered = |ready| Discovered {
        ifindex: Some(ifindex),
        ready,
        local_addresses: local.clone(),
    };

    if !link.usable() {
        return discovered(Err(Reason::CarrierLost));
    }
    let source = match p.source {
        AutoOr::Static(s) => {
            let present = system
                .addresses
                .values()
                .any(|a| a.address == s && usable(a) && !a.deprecated());
            present.then_some(s)
        }
        AutoOr::Auto => auto_source(&on_link),
    };
    let Some(source) = source else {
        return discovered(Err(Reason::AddressLost));
    };
    let hop = match p.gateway {
        AutoOr::Static(gw) => {
            let reachable = p.gateway_onlink || connected(system, family, ifindex, gw);
            reachable.then_some((Some(gw), p.gateway_onlink))
        }
        AutoOr::Auto if family == Family::V4 && link.point_to_point => Some((None, false)),
        AutoOr::Auto => auto_gateway(config, system, nexthops, own_protocol, family, ifindex),
    };
    match hop {
        Some((gateway, onlink)) => discovered(Ok(ReadyPath {
            ifindex,
            gateway,
            onlink,
            source,
        })),
        None => discovered(Err(Reason::GatewayLost)),
    }
}

/// A static source assigned to another interface (FR-DISC-6).
fn static_source_elsewhere(system: &System, p: &PathSettings, ifindex: Option<u32>) -> Option<IpAddr> {
    let AutoOr::Static(s) = p.source else { return None };
    system
        .addresses
        .values()
        .find(|a| a.address == s && Some(a.index) != ifindex && usable(a))
        .map(|a| a.address)
}

/// FR-DISC-2: among the source candidates (local addresses of the interface
/// that are neither temporary nor deprecated), prefer permanent addresses,
/// then IPv4 primary addresses, then the numerically lowest.
fn auto_source(on_link: &[&ObservedAddress]) -> Option<IpAddr> {
    on_link
        .iter()
        .filter(|a| !a.temporary() && !a.deprecated())
        .min_by_key(|a| (!a.permanent(), a.secondary(), a.address))
        .map(|a| a.address)
}

/// FR-DISC-4: the gateway is covered by a connected route of the interface
/// in the main table.
fn connected(system: &System, family: Family, ifindex: u32, gw: IpAddr) -> bool {
    system.routes_in(family, TABLE_MAIN).any(|r| {
        let Some((net, len)) = r.destination else { return false };
        r.nexthops.iter().any(|h| h.ifindex == ifindex && h.gateway.is_none()) && contains(net, len, gw)
    })
}

fn contains(net: IpAddr, len: u8, a: IpAddr) -> bool {
    match (net, a) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len.min(32)))
            };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len.min(128)))
            };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// FR-DISC-3: the best default route of the discovery tables that uses the
/// interface.
fn auto_gateway(
    config: &Config,
    system: &System,
    nexthops: &BTreeMap<u32, NexthopObject>,
    own_protocol: u8,
    family: Family,
    ifindex: u32,
) -> Option<(Option<IpAddr>, bool)> {
    let tables = &config.routing.discovery_tables;
    // Ordered by metric, router preference (highest first), table order, gateway.
    type Rank = (u32, i8, usize, IpAddr);
    let mut best: Option<(Rank, (Option<IpAddr>, bool))> = None;
    let now = std::time::Instant::now();
    for (order, table) in tables.iter().enumerate() {
        for r in system.routes_in(family, *table) {
            if !r.is_default()
                || r.kind != netlink_packet_route::route::RouteType::Unicast
                || r.protocol == own_protocol
                || r.expired(now)
            {
                continue;
            }
            for (gw, onlink) in route_gateways(r, nexthops, ifindex) {
                let key = (r.metric, -r.preference, order, gw);
                if best.as_ref().is_none_or(|(k, _)| key < *k) {
                    best = Some((key, (Some(gw), onlink)));
                }
            }
        }
    }
    best.map(|(_, hop)| hop)
}

/// Usable gateways of a default route on the interface.
fn route_gateways(r: &ObservedRoute, nexthops: &BTreeMap<u32, NexthopObject>, ifindex: u32) -> Vec<(IpAddr, bool)> {
    if let Some(id) = r.nexthop_id {
        // Recognised by RTA_NH_ID although the kernel also reports the
        // resolved gateway; only single nexthop objects are used.
        return match nexthops.get(&id) {
            Some(n) if n.ifindex == ifindex => n.gateway.map(|g| vec![(g, n.onlink)]).unwrap_or_default(),
            _ => Vec::new(),
        };
    }
    r.nexthops
        .iter()
        .filter(|h| h.ifindex == ifindex && !h.dead && !h.linkdown)
        .filter_map(|h| h.gateway.map(|g| (g, h.onlink)))
        .collect()
}

#[cfg(test)]
mod tests;
