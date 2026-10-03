//! The observer against scripted dumps that reproduce what spike S3
//! (`dumpskip`) observed: entries omitted or repeated without any flag,
//! flagged address dumps, dumps that never complete.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::route::{RouteAttribute, RouteMessage, RouteProtocol};

use super::*;
use crate::config;
use crate::discover;
use crate::model::{Family, PathKey, UplinkId};
use crate::plan::{Action, Rule, RuleKind};

/// What kind of dump a filter asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Kind {
    Links,
    Addresses(Family),
    Rules(Family),
    Routes(Family, Option<u32>),
}

fn kind(m: &RouteNetlinkMessage) -> Kind {
    match m {
        RouteNetlinkMessage::GetLink(_) => Kind::Links,
        RouteNetlinkMessage::GetAddress(a) => Kind::Addresses(msg::family(a.header.family).unwrap()),
        RouteNetlinkMessage::GetRule(r) => Kind::Rules(msg::family(r.header.family).unwrap()),
        RouteNetlinkMessage::GetRoute(r) => Kind::Routes(
            msg::family(r.header.address_family).unwrap(),
            r.attributes.iter().find_map(|a| match a {
                RouteAttribute::Table(t) => Some(*t),
                _ => None,
            }),
        ),
        other => panic!("unexpected filter {other:?}"),
    }
}

/// The answer to the n-th dump of a kind: messages and the interrupted
/// flag, or `None` for a dump that never completes.
type Script = dyn Fn(Kind, usize) -> Option<(Vec<RouteNetlinkMessage>, bool)> + Send + Sync;

#[derive(Clone)]
struct Fake {
    script: Arc<Script>,
    calls: Arc<Mutex<BTreeMap<Kind, usize>>>,
}

impl Fake {
    fn new(f: impl Fn(Kind, usize) -> Option<(Vec<RouteNetlinkMessage>, bool)> + Send + Sync + 'static) -> Fake {
        Fake {
            script: Arc::new(f),
            calls: Arc::default(),
        }
    }

    fn calls(&self, k: Kind) -> usize {
        self.calls.lock().unwrap().get(&k).copied().unwrap_or(0)
    }
}

impl Dumper for Fake {
    fn dump(&self, filter: RouteNetlinkMessage) -> impl Future<Output = Result<Dump, KernelError>> + Send {
        let k = kind(&filter);
        let n = {
            let mut c = self.calls.lock().unwrap();
            let e = c.entry(k).or_insert(0);
            *e += 1;
            *e - 1
        };
        let answer = (self.script)(k, n);
        async move {
            match answer {
                Some((messages, interrupted)) => Ok(Dump { messages, interrupted }),
                None => std::future::pending().await,
            }
        }
    }

    fn fresh(&self) -> std::io::Result<Fake> {
        Ok(self.clone())
    }
}

// --------------------------------------------------------------- fixtures

fn scope() -> Scope {
    Scope {
        ftr_tables: 1000..=1191,
        discovery_tables: vec![254],
    }
}

fn link(index: u32, name: &str) -> RouteNetlinkMessage {
    let mut m = LinkMessage::default();
    m.header.index = index;
    m.header.flags = LinkFlags::Up | LinkFlags::LowerUp;
    m.attributes.push(LinkAttribute::IfName(name.into()));
    RouteNetlinkMessage::NewLink(m)
}

fn address(index: u32, a: &str) -> RouteNetlinkMessage {
    let ip: IpAddr = a.parse().unwrap();
    let mut m = AddressMessage::default();
    m.header.family = msg::address_family(Family::of(ip));
    m.header.index = index;
    m.header.prefix_len = 24;
    m.attributes.push(AddressAttribute::Local(ip));
    m.attributes.push(AddressAttribute::Address(ip));
    RouteNetlinkMessage::NewAddress(m)
}

fn foreign_rule(priority: u32) -> RouteNetlinkMessage {
    let r = Rule {
        family: Family::V4,
        priority,
        fwmark: None,
        source: None,
        action: Action::Lookup(5),
        kind: RuleKind::Balance,
    };
    RouteNetlinkMessage::NewRule(msg::rule_message(&r, 4))
}

/// A default route of main through `gw` on `ifindex` with `metric`.
fn default_route(ifindex: u32, gw: &str, metric: u32) -> RouteNetlinkMessage {
    let mut m = RouteMessage::default();
    m.header.address_family = msg::address_family(Family::V4);
    m.header.table = 254;
    m.header.protocol = RouteProtocol::Dhcp;
    m.header.kind = netlink_packet_route::route::RouteType::Unicast;
    m.attributes.push(RouteAttribute::Table(254));
    m.attributes.push(RouteAttribute::Priority(metric));
    m.attributes
        .push(RouteAttribute::Gateway(gw.parse::<IpAddr>().unwrap().into()));
    m.attributes.push(RouteAttribute::Oif(ifindex));
    RouteNetlinkMessage::NewRoute(m)
}

fn world() -> BTreeMap<Kind, Vec<RouteNetlinkMessage>> {
    let mut w = BTreeMap::new();
    w.insert(Kind::Links, vec![link(5, "wana"), link(6, "wanb")]);
    w.insert(
        Kind::Addresses(Family::V4),
        vec![address(5, "192.0.2.2"), address(6, "100.64.0.2")],
    );
    w.insert(Kind::Rules(Family::V4), vec![foreign_rule(900), foreign_rule(950)]);
    w.insert(
        Kind::Routes(Family::V4, None),
        vec![
            default_route(5, "192.0.2.1", 100),
            default_route(6, "100.64.0.1", 200),
            default_route(5, "192.0.2.254", 300),
        ],
    );
    w
}

fn answer(w: &BTreeMap<Kind, Vec<RouteNetlinkMessage>>, k: Kind) -> Vec<RouteNetlinkMessage> {
    match k {
        Kind::Routes(f, Some(t)) => w
            .get(&Kind::Routes(f, None))
            .into_iter()
            .flatten()
            .filter(|m| matches!(m, RouteNetlinkMessage::NewRoute(r) if msg::ObservedRoute::parse(r).is_some_and(|o| o.table == t)))
            .cloned()
            .collect(),
        k => w.get(&k).cloned().unwrap_or_default(),
    }
}

/// A faithful source: every dump returns the world.
fn faithful() -> Fake {
    let w = world();
    Fake::new(move |k, _| Some((answer(&w, k), false)))
}

async fn baseline() -> System {
    full(&faithful(), &scope()).await.unwrap().system
}

const CONFIG: &str = r#"version = 2
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "wana"
[uplink.ipv4]
[[uplink]]
id = 2
name = "b"
interface = "wanb"
[uplink.ipv4]
"#;

fn gateway(s: &System, id: u8) -> Option<IpAddr> {
    let cfg = config::parse(CONFIG).unwrap();
    let d = discover::discover(&cfg, s, &BTreeMap::new(), 249);
    d[&PathKey {
        uplink: UplinkId::new(id).unwrap(),
        family: Family::V4,
    }]
        .ready
        .ok()
        .and_then(|r| r.gateway)
}

// ------------------------------------------------------------------ cases

#[tokio::test]
async fn a_rule_omitted_by_one_dump_is_kept_after_confirmation() {
    let old = baseline().await;
    let w = world();
    // The first rule dump skips rule 900 (a deletion before the resume point
    // shifted the position, S3); the confirming dump returns it.
    let f = Fake::new(move |k, n| {
        let mut v = answer(&w, k);
        if k == Kind::Rules(Family::V4) && n == 0 {
            v.remove(0);
        }
        Some((v, false))
    });
    let new = resync(&f, &scope(), &old).await.unwrap().system;
    assert_eq!(new.rules.len(), 2);
    assert_eq!(f.calls(Kind::Rules(Family::V4)), 2, "one confirming dump");
}

#[tokio::test]
async fn a_rule_absent_from_both_dumps_is_gone() {
    let old = baseline().await;
    let w = world();
    let f = Fake::new(move |k, _| {
        let mut v = answer(&w, k);
        if k == Kind::Rules(Family::V4) {
            v.remove(0);
        }
        Some((v, false))
    });
    let new = resync(&f, &scope(), &old).await.unwrap().system;
    assert_eq!(new.rules.len(), 1);
}

#[tokio::test]
async fn repeated_entries_are_merged() {
    let w = world();
    let f = Fake::new(move |k, _| {
        let mut v = answer(&w, k);
        let again = v.clone();
        v.extend(again);
        Some((v, false))
    });
    let s = full(&f, &scope()).await.unwrap().system;
    assert_eq!(s.rules.len(), 2);
    assert_eq!(s.addresses.len(), 2);
    assert_eq!(s.routes.len(), 3);
}

#[tokio::test]
async fn default_routes_missing_from_a_full_dump_keep_the_path_ready() {
    let old = baseline().await;
    assert_eq!(gateway(&old, 2), Some("100.64.0.1".parse().unwrap()));
    let w = world();
    // The full route dump loses the higher-metric default routes of main
    // (the IPv6 case of S3; the logic is the same for both families); the
    // strict dump of table 254 has them.
    let f = Fake::new(move |k, _| {
        let mut v = answer(&w, k);
        if k == Kind::Routes(Family::V4, None) {
            v.truncate(1);
        }
        Some((v, false))
    });
    let new = resync(&f, &scope(), &old).await.unwrap().system;
    assert_eq!(new.routes.len(), 3);
    assert_eq!(
        gateway(&new, 2),
        Some("100.64.0.1".parse().unwrap()),
        "B keeps its gateway"
    );
    assert_eq!(
        f.calls(Kind::Routes(Family::V4, Some(254))),
        1,
        "confirmed by a strict dump of main"
    );
}

#[tokio::test]
async fn an_address_omitted_without_a_flag_is_confirmed() {
    let old = baseline().await;
    let w = world();
    let f = Fake::new(move |k, n| {
        let mut v = answer(&w, k);
        if k == Kind::Addresses(Family::V4) && n == 0 {
            v.remove(1);
        }
        Some((v, false))
    });
    let new = resync(&f, &scope(), &old).await.unwrap().system;
    assert_eq!(new.addresses.len(), 2);
}

#[tokio::test]
async fn flagged_dumps_are_retried_a_bounded_number_of_times() {
    let w = world();
    // Two interrupted address dumps (one of them incomplete), then a clean one.
    let w2 = w.clone();
    let f = Fake::new(move |k, n| {
        let mut v = answer(&w2, k);
        let flagged = k == Kind::Addresses(Family::V4) && n < 2;
        if flagged {
            v.truncate(1);
        }
        Some((v, flagged))
    });
    let s = full(&f, &scope()).await.unwrap().system;
    assert_eq!(s.addresses.len(), 2);
    assert_eq!(f.calls(Kind::Addresses(Family::V4)), 3);
    // Always flagged: used after the bounded retries, with a full
    // resynchronisation due.
    let f = Fake::new(move |k, _| Some((answer(&w, k), k == Kind::Addresses(Family::V4))));
    assert!(full(&f, &scope()).await.unwrap().interrupted);
    assert_eq!(f.calls(Kind::Addresses(Family::V4)), 1 + INTERRUPTED_RETRIES);
    assert!(!full(&faithful(), &scope()).await.unwrap().interrupted);
}

#[tokio::test(start_paused = true)]
async fn a_dump_past_its_deadline_is_retried_on_a_new_socket() {
    let w = world();
    // The first route dump never completes (an IPv6 node that keeps
    // restarting, S3); the retry answers.
    let f = Fake::new(move |k, n| (k != Kind::Routes(Family::V4, None) || n > 0).then(|| (answer(&w, k), false)));
    let s = full(&f, &scope()).await.unwrap().system;
    assert_eq!(s.routes.len(), 3);
    // A dump that never completes fails after the bounded attempts.
    let f = Fake::new(move |k, _| (k != Kind::Links).then(|| (Vec::new(), false)));
    let e = full(&f, &scope()).await.unwrap_err();
    assert!(e.to_string().contains("dump not completed"), "{e}");
    assert_eq!(f.calls(Kind::Links), 1 + DEADLINE_RETRIES);
}

#[tokio::test]
async fn a_reread_removes_a_route_only_when_two_reads_agree() {
    let mut s = baseline().await;
    let w = world();
    let f = Fake::new(move |k, n| {
        let mut v = answer(&w, k);
        if matches!(k, Kind::Routes(_, Some(254))) && n == 0 {
            v.truncate(1);
        }
        Some((v, false))
    });
    reread(&f, &scope(), &mut s, &[(Family::V4, 254)]).await.unwrap();
    assert_eq!(
        s.routes_in(Family::V4, 254).count(),
        3,
        "a single short read changes nothing"
    );
    let w = world();
    let f = Fake::new(move |k, _| {
        let mut v = answer(&w, k);
        if matches!(k, Kind::Routes(_, Some(254))) {
            v.truncate(1);
        }
        Some((v, false))
    });
    reread(&f, &scope(), &mut s, &[(Family::V4, 254)]).await.unwrap();
    assert_eq!(s.routes_in(Family::V4, 254).count(), 1, "confirmed removal");
}

#[tokio::test]
async fn a_reread_confirms_by_identity_and_merges_both_reads() {
    let mut s = baseline().await;
    let w = world();
    // The first read repeats one route and omits another (as many messages
    // as routes); the confirming read has them all.
    let f = Fake::new(move |k, n| {
        let mut v = answer(&w, k);
        if matches!(k, Kind::Routes(_, Some(254))) && n == 0 {
            v[2] = v[0].clone();
        }
        Some((v, false))
    });
    reread(&f, &scope(), &mut s, &[(Family::V4, 254)]).await.unwrap();
    assert_eq!(f.calls(Kind::Routes(Family::V4, Some(254))), 2, "confirmed");
    assert_eq!(s.routes_in(Family::V4, 254).count(), 3);
    // Each read omits a different route: both were seen, both stay.
    let w = world();
    let f = Fake::new(move |k, n| {
        let mut v = answer(&w, k);
        if matches!(k, Kind::Routes(_, Some(254))) {
            v.remove(if n == 0 { 1 } else { 2 });
        }
        Some((v, false))
    });
    reread(&f, &scope(), &mut s, &[(Family::V4, 254)]).await.unwrap();
    assert_eq!(s.routes_in(Family::V4, 254).count(), 3);
    assert_eq!(gateway(&s, 2), Some("100.64.0.1".parse().unwrap()));
}
