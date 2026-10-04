//! The observed system: links, addresses, routes and rules as the kernel
//! reports them through dumps and notifications (SPEC.md §12.2 Observer).
//! Only what FTR needs is kept: every route of FTR's tables, default routes
//! of the discovery tables, connected routes of `main` and every rule.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Instant;

use netlink_packet_core::{NLM_F_APPEND, NLM_F_REPLACE};
use netlink_packet_route::RouteNetlinkMessage;

use crate::model::Family;
use crate::netlink::msg::{ObservedAddress, ObservedLink, ObservedRoute, ObservedRule, TABLE_MAIN};
use crate::netlink::{Message, NexthopMessage};

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
    /// Nexthop objects by id (FR-DISC-3).
    pub nexthops: BTreeMap<u32, NexthopMessage>,
}

/// What a notification changed, for the consumers that react to events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Link(u32),
    Address(u32),
    Route {
        family: Family,
        table: u32,
        removed: bool,
    },
    Rule {
        family: Family,
        removed: bool,
    },
    Nexthop {
        removed: bool,
    },
    /// A Router Advertisement with prefix information arrived on the
    /// interface: it may have refreshed or shortened the lifetime of the
    /// default route it installed, which the kernel does not notify.
    RouterAdvertisement(u32),
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

    /// Applies a dumped or notified message, nexthop objects included.
    pub fn apply_message(&mut self, scope: &Scope, m: &Message) -> Change {
        match m {
            Message::Route(r) => self.apply(scope, r),
            Message::NewNexthop(n) => {
                self.nexthops.insert(n.id, n.clone());
                Change::Nexthop { removed: false }
            }
            Message::DelNexthop(n) => {
                self.nexthops.remove(&n.id);
                Change::Nexthop { removed: true }
            }
            Message::GetNexthops => Change::None,
        }
    }

    /// Applies a dumped or notified route netlink message.
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
            RouteNetlinkMessage::NewRoute(r) => {
                ObservedRoute::parse(r).map_or(Change::None, |r| self.apply_route(scope, r, false))
            }
            RouteNetlinkMessage::DelRoute(r) => {
                ObservedRoute::parse(r).map_or(Change::None, |r| self.apply_route(scope, r, true))
            }
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
            RouteNetlinkMessage::NewPrefix(p) => Change::RouterAdvertisement(p.header.ifindex as u32),
            _ => Change::None,
        }
    }

    /// Applies a parsed route, dumped or notified: an addition, or a
    /// deletion when `deleted`.
    pub fn apply_route(&mut self, scope: &Scope, mut r: ObservedRoute, deleted: bool) -> Change {
        if !scope.keeps(&r) {
            return Change::None;
        }
        let (family, table) = (r.family, r.table);
        let key = route_key(scope, &r);
        if deleted {
            self.routes.remove(&key);
        } else {
            keep_expiry(self.routes.get(&key).and_then(|o| o.expires_at), &mut r);
            self.routes.insert(key, r);
        }
        Change::Route {
            family,
            table,
            removed: deleted,
        }
    }

    /// Replaces every route of a family and table with a fresh dump (the
    /// re-reads of §12.2).
    pub fn replace_table(&mut self, scope: &Scope, family: Family, table: u32, dump: &[RouteNetlinkMessage]) {
        let mut expiries: BTreeMap<RouteKey, Instant> = BTreeMap::new();
        self.routes.retain(|k, r| {
            let keep = !(k.0 == family && k.1 == table);
            if !keep && let Some(t) = r.expires_at {
                expiries.insert(*k, t);
            }
            keep
        });
        for m in dump {
            if let RouteNetlinkMessage::NewRoute(r) = m
                && let Some(mut r) = ObservedRoute::parse(r)
                && r.family == family
                && r.table == table
                && scope.keeps(&r)
            {
                let key = route_key(scope, &r);
                keep_expiry(expiries.get(&key).copied(), &mut r);
                self.routes.insert(key, r);
            }
        }
    }

    /// Gives the routes of a new view, built from a full dump, the expiries
    /// that `old` knows and the dump showed as none (see [`keep_expiry`]).
    pub fn keep_expiries(&mut self, old: &System) {
        for (k, r) in &mut self.routes {
            keep_expiry(old.routes.get(k).and_then(|o| o.expires_at), r);
        }
    }

    /// Adds a route as a dump would.
    #[cfg(test)]
    pub fn insert_route(&mut self, scope: &Scope, r: ObservedRoute) {
        self.routes.insert(route_key(scope, &r), r);
    }

    /// The table to re-read after a route notification that can leave a
    /// stale entry in the view, outside FTR's tables (which hold one route
    /// each): a replacement when the view holds another route with the same
    /// destination and metric, which the kernel may have dropped without a
    /// deletion notification (in both families; replacing the route of the
    /// same identity is captured exactly by applying the notification); an
    /// append, which merges into an existing route; a deletion that matches
    /// no entry (one member of a multipath route). It must be evaluated
    /// against the view before the notification is applied.
    pub fn stale_after(&self, scope: &Scope, r: &ObservedRoute, deleted: bool, flags: u16) -> Option<(Family, u32)> {
        if scope.ftr_tables.contains(&r.table) {
            return None;
        }
        let key = route_key(scope, r);
        let stale = if deleted {
            scope.keeps(r) && !self.routes.contains_key(&key)
        } else if flags & NLM_F_APPEND != 0 {
            scope.keeps(r)
        } else if flags & NLM_F_REPLACE != 0 {
            // The replaced route has the same destination and metric; only
            // an entry of the new route's identity is replaced exactly, and
            // only when the new route is kept.
            let kept = scope.keeps(r);
            self.routes
                .keys()
                .any(|k| (k.0, k.1, k.2, k.3) == (key.0, key.1, key.2, key.3) && (*k != key || !kept))
        } else {
            false
        };
        stale.then_some((r.family, r.table))
    }

    /// The family and table of every route of the view that uses a nexthop
    /// object, directly or through a group that the view knows contains it.
    pub fn nexthop_users(&self, id: u32) -> BTreeSet<(Family, u32)> {
        self.routes
            .values()
            .filter(|r| {
                r.nexthop_id
                    .is_some_and(|n| n == id || self.nexthops.get(&n).is_some_and(|g| g.group.contains(&id)))
            })
            .map(|r| (r.family, r.table))
            .collect()
    }

    pub fn routes_in(&self, family: Family, table: u32) -> impl Iterator<Item = &ObservedRoute> {
        self.routes
            .values()
            .filter(move |r| r.family == family && r.table == table)
    }
}

/// `rta_expires` is 0 both for a route without expiry and within a clock
/// tick of its expiry: a route read again at that moment keeps the expiry
/// already known when it is due within a second (FR-DISC-5).
fn keep_expiry(old: Option<Instant>, new: &mut ObservedRoute) {
    if new.expires_at.is_none()
        && let Some(t) = old
        && t <= Instant::now() + std::time::Duration::from_secs(1)
    {
        new.expires_at = Some(t);
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
    fn an_expiry_about_to_pass_survives_a_read_that_shows_none() {
        let scope = scope();
        let m = route(254, 5, "fe80::1", 1024);
        let mut s = System::default();
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(m.clone()));
        let soon = std::time::Instant::now() + std::time::Duration::from_millis(5);
        s.routes.values_mut().for_each(|r| r.expires_at = Some(soon));
        // Read again within a tick of the expiry: rta_expires 0.
        s.replace_table(&scope, Family::V6, 254, &[RouteNetlinkMessage::NewRoute(m.clone())]);
        assert_eq!(s.routes.values().next().unwrap().expires_at, Some(soon));
        // A distant expiry is not kept: the route lost its expiry.
        let later = std::time::Instant::now() + std::time::Duration::from_secs(60);
        s.routes.values_mut().for_each(|r| r.expires_at = Some(later));
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(m));
        assert_eq!(s.routes.values().next().unwrap().expires_at, None);
    }

    #[test]
    fn replacements_appends_and_unmatched_deletions_call_for_a_reread() {
        let scope = scope();
        let mut s = System::default();
        let stale = |s: &System, m: RouteMessage, deleted: bool, flags: u16| {
            s.stale_after(&scope, &ObservedRoute::parse(&m).unwrap(), deleted, flags)
        };
        let a = route(254, 5, "fe80::1", 1024);
        assert_eq!(stale(&s, a.clone(), false, 0x600), None, "a plain addition");
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(a.clone()));
        // The kernel replaced the first route with that metric, whatever
        // its interface, without notifying its removal.
        let replaced = route(254, 6, "fe80::5", 1024);
        assert_eq!(stale(&s, replaced.clone(), false, 0x100), Some((Family::V6, 254)));
        // The only route with that metric is the one replaced.
        assert_eq!(stale(&s, a.clone(), false, 0x100), None, "the same route replaced");
        assert_eq!(
            stale(&s, route(254, 6, "fe80::5", 512), false, 0x100),
            None,
            "another metric"
        );
        assert_eq!(stale(&s, replaced, false, 0x800), Some((Family::V6, 254)));
        assert_eq!(stale(&s, a, true, 0), None, "a known deletion");
        let unknown = route(254, 7, "fe80::1", 1024);
        assert_eq!(stale(&s, unknown, true, 0), Some((Family::V6, 254)));
        // FTR's own tables and tables outside the scope never need it.
        assert_eq!(stale(&s, route(1000, 6, "fe80::5", 100), false, 0x100), None);
        assert_eq!(stale(&s, route(300, 6, "fe80::5", 1024), false, 0x100), None);
    }

    #[test]
    fn a_new_view_keeps_an_expiry_due_within_a_second() {
        let scope = scope();
        let soon = std::time::Instant::now() + std::time::Duration::from_millis(300);
        let later = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut old = System::default();
        let mut new = System::default();
        for (ifindex, expiry) in [(5, soon), (6, later)] {
            let m = route(254, ifindex, "fe80::1", 1024);
            let mut r = ObservedRoute::parse(&m).unwrap();
            new.insert_route(&scope, r.clone());
            r.expires_at = Some(expiry);
            old.insert_route(&scope, r);
        }
        new.keep_expiries(&old);
        let expiries: Vec<_> = new.routes.values().map(|r| r.expires_at).collect();
        // A dump within the last clock tick shows no expiry; one that shows
        // none a minute before the known expiry is a refresh without one.
        assert_eq!(expiries, [Some(soon), None]);
    }

    #[test]
    fn the_users_of_a_nexthop_object_include_its_groups_routes() {
        let scope = scope();
        let mut s = System::default();
        let mut direct = route(254, 5, "fe80::1", 1024);
        direct.attributes.push(RouteAttribute::NhId(10));
        let mut grouped = route(254, 6, "fe80::2", 1024);
        grouped.attributes.push(RouteAttribute::NhId(20));
        grouped.header.address_family = AddressFamily::Inet;
        grouped.attributes.retain(|a| !matches!(a, RouteAttribute::Gateway(_)));
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(direct));
        s.apply(&scope, &RouteNetlinkMessage::NewRoute(grouped));
        s.nexthops.insert(
            20,
            NexthopMessage {
                id: 20,
                group: vec![10, 11],
                ..NexthopMessage::default()
            },
        );
        assert_eq!(
            s.nexthop_users(10).into_iter().collect::<Vec<_>>(),
            [(Family::V4, 254), (Family::V6, 254)]
        );
        assert_eq!(s.nexthop_users(11).into_iter().collect::<Vec<_>>(), [(Family::V4, 254)]);
        assert!(s.nexthop_users(12).is_empty());
    }
}
