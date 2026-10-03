//! The observed system: links, addresses, routes and rules as the kernel
//! reports them through dumps and notifications (SPEC.md §12.2 Observer).
//! Only what FTR needs is kept: every route of FTR's tables, default routes
//! of the discovery tables, connected routes of `main` and every rule.

use std::collections::BTreeMap;
use std::net::IpAddr;

use netlink_packet_route::RouteNetlinkMessage;

use crate::model::Family;
use crate::netlink::msg::{ObservedAddress, ObservedLink, ObservedRoute, ObservedRule, TABLE_MAIN};

/// A route's identity in the kernel: (family, table, destination, metric).
pub type RouteKey = (Family, u32, Option<(IpAddr, u8)>, u32);

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

fn route_key(r: &ObservedRoute) -> RouteKey {
    (r.family, r.table, r.destination, r.metric)
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
                    self.routes.insert(route_key(&r), r);
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
                    self.routes.remove(&route_key(&r));
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
                    let family = r.family;
                    if !self.rules.iter().any(|o| o.message == r.message) {
                        self.rules.push(r);
                    }
                    Change::Rule { family, removed: false }
                }
                None => Change::None,
            },
            RouteNetlinkMessage::DelRule(r) => match ObservedRule::parse(r) {
                Some(r) => {
                    // Notifications of deletions carry the full rule.
                    if let Some(pos) = self.rules.iter().position(|o| same_rule(o, &r)) {
                        self.rules.remove(pos);
                    }
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
        self.routes.retain(|(f, t, _, _), _| !(*f == family && *t == table));
        for m in dump {
            if let RouteNetlinkMessage::NewRoute(r) = m
                && let Some(r) = ObservedRoute::parse(r)
                && r.family == family
                && r.table == table
                && scope.keeps(&r)
            {
                self.routes.insert(route_key(&r), r);
            }
        }
    }

    pub fn routes_in(&self, family: Family, table: u32) -> impl Iterator<Item = &ObservedRoute> {
        self.routes
            .values()
            .filter(move |r| r.family == family && r.table == table)
    }
}

fn same_rule(a: &ObservedRule, b: &ObservedRule) -> bool {
    a.family == b.family
        && a.priority == b.priority
        && a.protocol == b.protocol
        && a.fwmark == b.fwmark
        && a.source == b.source
        && a.action == b.action
        && a.foreign_selectors == b.foreign_selectors
}
