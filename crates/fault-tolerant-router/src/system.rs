//! The observed system: links, addresses, routes and rules as the kernel
//! reports them through dumps and notifications (SPEC.md §12.2 Observer).
//! Only what FTR needs is kept: every route of FTR's tables, default routes
//! of the discovery tables, connected routes of `main` and every rule.

use std::collections::BTreeMap;
use std::net::IpAddr;

use netlink_packet_core::{NLM_F_APPEND, NLM_F_REPLACE};
use netlink_packet_route::RouteNetlinkMessage;

use crate::model::Family;
use crate::netlink::msg::{ObservedAddress, ObservedLink, ObservedRoute, ObservedRule, TABLE_MAIN};

/// A route's identity in the kernel: (family, table, destination, metric,
/// next hop). Outside FTR's tables, routes with the same destination and
/// metric coexist when their next hops differ: IPv6 keeps the Router
/// Advertisement default routes of every interface, `fe80::/64` of every
/// interface and routes using different nexthop objects.
pub type RouteKey = (Family, u32, Option<(IpAddr, u8)>, u32, Via);

/// The next-hop part of a route's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Via {
    /// FTR's tables hold one route each (§4.3): a replacement changes the
    /// next hops of the same route.
    Table,
    /// A nexthop object (`RTA_NH_ID`).
    Object(u32),
    /// A single next hop: interface and gateway.
    Hop(u32, Option<IpAddr>),
    /// Several next hops, or none (unreachable, blackhole…).
    Other,
}

/// Which routes the model keeps.
#[derive(Clone, Debug)]
pub struct Scope {
    pub ftr_tables: std::ops::RangeInclusive<u32>,
    pub discovery_tables: Vec<u32>,
}

impl Scope {
    pub fn keeps(&self, r: &ObservedRoute) -> bool {
        self.ftr_tables.contains(&r.table)
            || (r.is_default() && self.discovery_tables.contains(&r.table))
            || (r.table == TABLE_MAIN && !r.is_default() && r.nexthops.iter().all(|h| h.gateway.is_none()))
    }
}

#[derive(Clone, Debug, Default)]
pub struct System {
    pub links: BTreeMap<u32, ObservedLink>,
    /// Keyed by (ifindex, address).
    pub addresses: BTreeMap<(u32, IpAddr), ObservedAddress>,
    pub routes: BTreeMap<RouteKey, ObservedRoute>,
    pub rules: Vec<ObservedRule>,
}

/// What a notification changed, for the consumers that react to events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Link(u32),
    Address(u32),
    Route { family: Family, table: u32, removed: bool },
    Rule { family: Family, removed: bool },
    None,
}

fn route_key(scope: &Scope, r: &ObservedRoute) -> RouteKey {
    let via = if scope.ftr_tables.contains(&r.table) {
        Via::Table
    } else if let Some(id) = r.nexthop_id {
        Via::Object(id)
    } else if let [h] = r.nexthops.as_slice() {
        Via::Hop(h.ifindex, h.gateway)
    } else {
        Via::Other
    };
    (r.family, r.table, r.destination, r.metric, via)
}

impl System {
    pub fn link_by_name(&self, name: &str) -> Option<&ObservedLink> {
        self.links.values().find(|l| l.name == name)
    }

    /// Applies a dumped or notified message.
    pub fn apply(&mut self, scope: &Scope, m: &RouteNetlinkMessage) -> Change {
        match m {
            RouteNetlinkMessage::NewLink(l) => match ObservedLink::parse(l) {
                Some(l) => {
                    let i = l.index;
                    self.links.insert(i, l);
                    Change::Link(i)
                }
                None => Change::None,
            },
            RouteNetlinkMessage::DelLink(l) => {
                let i = l.header.index;
                self.links.remove(&i);
                self.addresses.retain(|(idx, _), _| *idx != i);
                Change::Link(i)
            }
            RouteNetlinkMessage::NewAddress(a) => match ObservedAddress::parse(a) {
                Some(a) => {
                    let i = a.index;
                    self.addresses.insert((i, a.address), a);
                    Change::Address(i)
                }
                None => Change::None,
            },
            RouteNetlinkMessage::DelAddress(a) => match ObservedAddress::parse(a) {
                Some(a) => {
                    self.addresses.remove(&(a.index, a.address));
                    Change::Address(a.index)
                }
                None => Change::None,
            },
            RouteNetlinkMessage::NewRoute(r) => match ObservedRoute::parse(r) {
                Some(r) if scope.keeps(&r) => {
                    let (family, table) = (r.family, r.table);
                    self.routes.insert(route_key(scope, &r), r);
                    Change::Route {
                        family,
                        table,
                        removed: false,
                    }
                }
                _ => Change::None,
            },
            RouteNetlinkMessage::DelRoute(r) => match ObservedRoute::parse(r) {
                Some(r) if scope.keeps(&r) => {
                    self.routes.remove(&route_key(scope, &r));
                    Change::Route {
                        family: r.family,
                        table: r.table,
                        removed: true,
                    }
                }
                _ => Change::None,
            },
            RouteNetlinkMessage::NewRule(r) => match ObservedRule::parse(r) {
                Some(r) => {
                    // The same rule arrives from a dump, from FTR's own
                    // mutation and from its notification, with slightly
                    // different attributes: one entry per identity.
                    let family = r.family;
                    self.rules.retain(|o| !same_rule(o, &r));
                    self.rules.push(r);
                    Change::Rule { family, removed: false }
                }
                None => Change::None,
            },
            RouteNetlinkMessage::DelRule(r) => match ObservedRule::parse(r) {
                Some(r) => {
                    self.rules.retain(|o| !same_rule(o, &r));
                    Change::Rule {
                        family: r.family,
                        removed: true,
                    }
                }
                None => Change::None,
            },
            _ => Change::None,
        }
    }

    /// Replaces every route of a family and table with a fresh dump (the
    /// re-reads of §12.2).
    pub fn replace_table(&mut self, scope: &Scope, family: Family, table: u32, dump: &[RouteNetlinkMessage]) {
        self.routes.retain(|(f, t, ..), _| !(*f == family && *t == table));
        for m in dump {
            if let RouteNetlinkMessage::NewRoute(r) = m
                && let Some(r) = ObservedRoute::parse(r)
                && r.family == family
                && r.table == table
                && scope.keeps(&r)
            {
                self.routes.insert(route_key(scope, &r), r);
            }
        }
    }

    /// Adds a route as a dump would.
    pub fn insert_route(&mut self, scope: &Scope, r: ObservedRoute) {
        self.routes.insert(route_key(scope, &r), r);
    }

    /// The table to re-read after a route notification that can leave a
    /// stale entry in the view: a replacement or an append outside FTR's
    /// tables (the kernel drops or merges the old route without a deletion
    /// notification, in both families), or a deletion that matches no
    /// entry (one member of a multipath route).
    pub fn stale_after(&self, scope: &Scope, m: &RouteNetlinkMessage, flags: u16) -> Option<(Family, u32)> {
        let (r, deleted) = match m {
            RouteNetlinkMessage::NewRoute(r) => (ObservedRoute::parse(r)?, false),
            RouteNetlinkMessage::DelRoute(r) => (ObservedRoute::parse(r)?, true),
            _ => return None,
        };
        if !scope.keeps(&r) || scope.ftr_tables.contains(&r.table) {
            return None;
        }
        let stale = if deleted {
            !self.routes.contains_key(&route_key(scope, &r))
        } else {
            flags & (NLM_F_REPLACE | NLM_F_APPEND) != 0
        };
        stale.then_some((r.family, r.table))
    }

    pub fn routes_in(&self, family: Family, table: u32) -> impl Iterator<Item = &ObservedRoute> {
        self.routes
            .values()
            .filter(move |r| r.family == family && r.table == table)
    }
}

/// Rule identity: the fields FTR's rules use, plus the protocol; rules with
/// other selectors are compared by their whole message.
fn same_rule(a: &ObservedRule, b: &ObservedRule) -> bool {
    if a.foreign_selectors || b.foreign_selectors {
        return a.message == b.message;
    }
    a.family == b.family
        && a.priority == b.priority
        && a.protocol == b.protocol
        && a.fwmark == b.fwmark
        && a.source == b.source
        && a.action == b.action
}

#[cfg(test)]
mod tests {
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::route::{RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteType};
    use netlink_packet_route::rule::RuleAttribute;

    use super::*;
    use crate::netlink::msg;
    use crate::plan::{Action, Rule, RuleKind};

    #[test]
    fn a_rule_is_kept_once_whatever_its_source() {
        let scope = Scope {
            ftr_tables: 1000..=1191,
            discovery_tables: vec![254],
        };
        let rule = Rule {
            family: Family::V4,
            priority: 1600,
            fwmark: None,
            source: None,
            action: Action::Lookup(1000),
            kind: RuleKind::Balance,
        };
        let ours = msg::rule_message(&rule, 249);
        // The kernel's notification carries attributes FTR did not send.
        let mut notified = ours.clone();
        notified.attributes.push(RuleAttribute::SuppressPrefixLen(u32::MAX));
        let mut s = System::default();
        s.apply(&scope, &RouteNetlinkMessage::NewRule(ours.clone()));
        s.apply(&scope, &RouteNetlinkMessage::NewRule(notified.clone()));
        assert_eq!(s.rules.len(), 1);
        s.apply(&scope, &RouteNetlinkMessage::DelRule(notified));
        assert!(s.rules.is_empty(), "a third-party deletion removes it");
    }

    fn scope() -> Scope {
        Scope {
            ftr_tables: 1000..=1191,
            discovery_tables: vec![254],
        }
    }

    /// A route message as the kernel notifies it.
    fn route(table: u32, ifindex: u32, gw: &str, metric: u32) -> RouteMessage {
        let mut m = RouteMessage::default();
        m.header.address_family = AddressFamily::Inet6;
        m.header.table = RouteHeader::RT_TABLE_UNSPEC;
        m.header.kind = RouteType::Unicast;
        m.header.protocol = RouteProtocol::Ra;
        m.attributes.push(RouteAttribute::Table(table));
        m.attributes.push(RouteAttribute::Priority(metric));
        m.attributes
            .push(RouteAttribute::Gateway(gw.parse::<IpAddr>().unwrap().into()));
        m.attributes.push(RouteAttribute::Oif(ifindex));
        m
    }

    #[test]
    fn routes_with_the_same_destination_and_metric_coexist_outside_ftr_tables() {
        let scope = scope();
        let mut s = System::default();
        // RA default routes of two uplinks: same destination, metric and
        // link-local gateway (S1, AS-28).
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(route(254, 5, "fe80::1", 1024)));
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(route(254, 6, "fe80::1", 1024)));
        assert_eq!(s.routes_in(Family::V6, 254).count(), 2);
        s.apply(&scope, &RouteNetlinkMessage::DelRoute(route(254, 5, "fe80::1", 1024)));
        let left: Vec<u32> = s.routes_in(Family::V6, 254).map(|r| r.nexthops[0].ifindex).collect();
        assert_eq!(left, [6]);
        // FTR's tables hold one route: a replacement replaces it.
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(route(1001, 5, "fe80::1", 100)));
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(route(1001, 6, "fe80::2", 100)));
        let ftr: Vec<u32> = s.routes_in(Family::V6, 1001).map(|r| r.nexthops[0].ifindex).collect();
        assert_eq!(ftr, [6]);
    }

    #[test]
    fn replacements_appends_and_unmatched_deletions_call_for_a_reread() {
        let scope = scope();
        let mut s = System::default();
        let a = RouteNetlinkMessage::NewRoute(route(254, 5, "fe80::1", 1024));
        assert_eq!(s.stale_after(&scope, &a, 0x600), None, "a plain addition");
        s.apply(&scope, &a);
        // The kernel replaced the first route with that metric, whatever
        // its interface, without notifying its removal.
        let replaced = RouteNetlinkMessage::NewRoute(route(254, 6, "fe80::5", 1024));
        assert_eq!(s.stale_after(&scope, &replaced, 0x100), Some((Family::V6, 254)));
        let appended = RouteNetlinkMessage::NewRoute(route(254, 6, "fe80::5", 1024));
        assert_eq!(s.stale_after(&scope, &appended, 0x800), Some((Family::V6, 254)));
        let known = RouteNetlinkMessage::DelRoute(route(254, 5, "fe80::1", 1024));
        assert_eq!(s.stale_after(&scope, &known, 0), None);
        let unknown = RouteNetlinkMessage::DelRoute(route(254, 7, "fe80::1", 1024));
        assert_eq!(s.stale_after(&scope, &unknown, 0), Some((Family::V6, 254)));
        // FTR's own tables and tables outside the scope never need it.
        let ftr = RouteNetlinkMessage::NewRoute(route(1000, 6, "fe80::5", 100));
        assert_eq!(s.stale_after(&scope, &ftr, 0x100), None);
        let other = RouteNetlinkMessage::NewRoute(route(300, 6, "fe80::5", 1024));
        assert_eq!(s.stale_after(&scope, &other, 0x100), None);
    }
}
