use std::net::IpAddr;

use super::*;
use crate::config::{self, Config};
use crate::model::PathKey;
use crate::plan::{self, Input, PathInput, ReadyPath};
use crate::system::Scope;

const CONFIG: &str = r#"version = 2
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
name = "b"
interface = "wanb"
priority = 1
[uplink.ipv4]
"#;

fn id(n: u8) -> UplinkId {
    UplinkId::new(n).unwrap()
}

fn ready(ifindex: u32, src: [u8; 4]) -> PathInput {
    PathInput {
        ready: Some(ReadyPath {
            ifindex,
            gateway: Some(IpAddr::from([src[0], src[1], src[2], 1])),
            onlink: false,
            source: IpAddr::from(src),
        }),
        local_addresses: [IpAddr::from(src)].into(),
        healthy: true,
        drained: false,
    }
}

fn input(ids: &[u8]) -> Input {
    let mut i = Input::default();
    for n in ids {
        i.paths.insert(
            PathKey {
                uplink: id(*n),
                family: Family::V4,
            },
            ready(4 + u32::from(*n), [192, 0, 2 + n, 2]),
        );
    }
    i.active.insert(Family::V4, ids.iter().map(|n| id(*n)).collect());
    i
}

fn scope(cfg: &Config) -> Scope {
    Scope {
        ftr_tables: Layout::of(cfg).tables(),
        discovery_tables: vec![254],
    }
}

/// Applies the netlink operations to the view, as a successful execution would.
fn apply(system: &mut System, cfg: &Config, ops: &[Op]) {
    for op in ops {
        if !matches!(op, Op::ApplyNft) {
            let (m, _, _) = netlink_op(op, 249);
            system.apply(&scope(cfg), &m);
        }
    }
}

fn diff_for(system: &System, cfg: &Config, before: &Desired, desired: &Desired, nft_pending: bool) -> Vec<Op> {
    diff(
        system,
        &DiffInput {
            layout: Layout::of(cfg),
            protocol: 249,
            families: &[Family::V4],
            before_nft: before,
            desired,
            nft_pending,
            teardown: false,
        },
    )
}

fn rule_kinds(ops: &[Op]) -> Vec<String> {
    ops.iter()
        .map(|o| match o {
            Op::ReplaceRoute(r) => format!("route {}", r.table),
            Op::AddRule(r) => format!("+{:?}", r.kind),
            Op::ApplyNft => "nft".into(),
            Op::DeleteRule(r) => format!("-{}", r.priority),
            Op::DeleteRoute { table, .. } => format!("-route {table}"),
        })
        .collect()
}

fn position(v: &[String], s: &str) -> usize {
    v.iter()
        .position(|x| x == s)
        .unwrap_or_else(|| panic!("{s} not in {v:?}"))
}

#[test]
fn cold_installation_follows_fr_rec_1() {
    let cfg = config::parse(CONFIG).unwrap();
    let desired = plan::plan(&cfg, &input(&[1, 2]));
    let ops = diff_for(&System::default(), &cfg, &desired, &desired, true);
    let v = rule_kinds(&ops);
    // Routes first, then guards, lookups in decreasing precedence, the final
    // guard, and the nftables table last.
    let last_route = v.iter().rposition(|s| s.starts_with("route")).unwrap();
    let first_rule = v.iter().position(|s| s.starts_with('+')).unwrap();
    assert!(last_route < first_rule);
    assert_eq!(v.last().unwrap(), "nft");
    assert_eq!(v[v.len() - 2], "+FinalGuard");
    let guards = ["+ProbeGuard", "+PathGuard", "+PolicyBlockGuard"].map(|g| position(&v, g));
    let lookups = [
        "+ProbeLookup(UplinkId(1))",
        "+MainBypass",
        "+PathLookup(UplinkId(1))",
        "+PolicyBalanceLookup(UplinkId(1))",
        "+Balance",
    ]
    .map(|g| position(&v, g));
    assert!(guards.iter().all(|g| lookups.iter().all(|l| g < l)));
    assert!(lookups.windows(2).all(|w| w[0] < w[1]), "{v:?}");
    // Each source rule is followed by its source guard.
    for (i, op) in ops.iter().enumerate() {
        if let Op::AddRule(r) = op
            && let RuleKind::SourceLookup(_) = r.kind
        {
            match &ops[i + 1] {
                Op::AddRule(g) => assert!(g.kind == RuleKind::SourceGuard && g.source == r.source),
                o => panic!("{o:?} after a source rule"),
            }
        }
    }
    // Once applied, nothing is left to do.
    let mut s = System::default();
    apply(&mut s, &cfg, &ops);
    assert!(diff_for(&s, &cfg, &desired, &desired, false).is_empty());
}

#[test]
fn teardown_withdraws_every_route_after_the_rules() {
    let cfg = config::parse(CONFIG).unwrap();
    let desired = plan::plan(&cfg, &input(&[1, 2]));
    let install = diff_for(&System::default(), &cfg, &desired, &desired, true);
    let mut s = System::default();
    apply(&mut s, &cfg, &install);
    let empty = Desired::default();
    let teardown = |teardown| {
        rule_kinds(&diff(
            &s,
            &DiffInput {
                layout: Layout::of(&cfg),
                protocol: 249,
                families: &[Family::V4],
                before_nft: &empty,
                desired: &empty,
                nft_pending: false,
                teardown,
            },
        ))
    };
    // FR-REC-4: final guard first, class guards last among the rules, then
    // every route.
    let v = teardown(true);
    let last_rule = v.iter().rposition(|x| !x.starts_with("-route")).unwrap();
    let first_route = v.iter().position(|x| x.starts_with("-route")).unwrap();
    assert!(last_rule < first_route, "{v:?}");
    assert_eq!(v[0], "-1699");
    assert!(position(&v, "-1600") < position(&v, "-1064"), "{v:?}");
    // At runtime the balancing route goes before the rules (FR-REC-3).
    let v = teardown(false);
    assert!(position(&v, "-route 1000") < position(&v, "-1699"), "{v:?}");
    assert!(position(&v, "-1064") < position(&v, "-route 1001"), "{v:?}");
}

#[test]
fn an_added_uplink_joins_the_balancing_route_after_its_assignments() {
    let cfg = config::parse(CONFIG).unwrap();
    let mut s = System::default();
    let only_a = config::parse(&CONFIG[..CONFIG.find("[[uplink]]\nid = 2").unwrap()]).unwrap();
    let one = plan::plan(&only_a, &input(&[1]));
    apply(
        &mut s,
        &only_a,
        &diff_for(&System::default(), &only_a, &one, &one, false),
    );
    let two = plan::plan(&cfg, &input(&[1, 2]));
    // Before nftables: B's path table but not B in the balancing route.
    let mut before = two.clone();
    before
        .routes
        .insert((Family::V4, 1000), one.routes[&(Family::V4, 1000)].clone());
    let v = rule_kinds(&diff_for(&s, &cfg, &before, &two, true));
    let nft = position(&v, "nft");
    assert!(position(&v, "route 1002") < position(&v, "+PathLookup(UplinkId(2))"));
    assert!(position(&v, "+PathLookup(UplinkId(2))") < nft);
    assert!(nft < position(&v, "route 1000"), "{v:?}");
}

#[test]
fn a_removed_uplink_loses_rules_in_increasing_precedence_then_routes() {
    let cfg = config::parse(CONFIG).unwrap();
    let mut s = System::default();
    let two = plan::plan(&cfg, &input(&[1, 2]));
    apply(&mut s, &cfg, &diff_for(&System::default(), &cfg, &two, &two, false));
    let only_a = config::parse(&CONFIG[..CONFIG.find("[[uplink]]\nid = 2").unwrap()]).unwrap();
    let one = plan::plan(&only_a, &input(&[1]));
    let v = rule_kinds(&diff_for(&s, &only_a, &one, &one, true));
    // Balancing route first (B excluded), nftables without B's assignments,
    // then B's rules (source guard before source rule), then its routes.
    assert_eq!(v[0], "route 1000");
    let nft = position(&v, "nft");
    let guard = position(&v, "-1564");
    let source = position(&v, "-1502");
    assert!(nft < guard && guard < source, "{v:?}");
    assert!(position(&v, "-1402") < position(&v, "-1202") && position(&v, "-1202") < position(&v, "-1002"));
    assert!(position(&v, "-1002") < position(&v, "-route 1002"));
    // Policy tables are emptied before the nftables replacement (FR-REC-3).
    assert!(
        position(&v, "-route 1066") < nft && position(&v, "-route 1130") < nft,
        "{v:?}"
    );
    assert!(!v.iter().any(|x| x == "-1264" || x == "-1699"), "guards stay: {v:?}");
}

#[test]
fn an_address_change_adds_new_rules_before_removing_old_ones() {
    let cfg = config::parse(CONFIG).unwrap();
    let mut s = System::default();
    let old = plan::plan(&cfg, &input(&[1, 2]));
    apply(&mut s, &cfg, &diff_for(&System::default(), &cfg, &old, &old, false));
    let mut i = input(&[1, 2]);
    i.paths.insert(
        PathKey {
            uplink: id(1),
            family: Family::V4,
        },
        ready(5, [192, 0, 3, 77]),
    );
    let new = plan::plan(&cfg, &i);
    let ops = diff_for(&s, &cfg, &new, &new, false);
    let v = rule_kinds(&ops);
    let adds: Vec<usize> = v
        .iter()
        .enumerate()
        .filter(|(_, x)| x.starts_with('+'))
        .map(|(i, _)| i)
        .collect();
    let dels: Vec<usize> = v
        .iter()
        .enumerate()
        .filter(|(_, x)| x.starts_with("-1"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!((adds.len(), dels.len()), (2, 2), "{v:?}");
    assert!(adds.iter().max() < dels.iter().min());
    assert!(position(&v, "-1564") < position(&v, "-1501"));
    assert!(
        position(&v, "route 1001") < adds[0],
        "the path route with the new source comes first"
    );
}

#[test]
fn foreign_rules_and_routes_are_never_touched() {
    let cfg = config::parse(CONFIG).unwrap();
    let mut s = System::default();
    let desired = plan::plan(&cfg, &input(&[1]));
    apply(
        &mut s,
        &cfg,
        &diff_for(&System::default(), &cfg, &desired, &desired, false),
    );
    // A foreign rule in FTR's range (a collision, refused at startup) and a
    // foreign route in an FTR table are left alone at runtime.
    let mut foreign = crate::netlink::msg::rule_message(
        &plan::Rule {
            family: Family::V4,
            priority: 1650,
            fwmark: None,
            source: None,
            action: plan::Action::Lookup(5),
            kind: RuleKind::Balance,
        },
        4,
    );
    foreign.header.tos = 0;
    s.apply(&scope(&cfg), &RouteNetlinkMessage::NewRule(foreign));
    let mut r = desired.routes[&(Family::V4, 1001)].clone();
    r.table = 1010;
    s.apply(
        &scope(&cfg),
        &RouteNetlinkMessage::NewRoute(crate::netlink::msg::route_message(&r, 4)),
    );
    assert!(diff_for(&s, &cfg, &desired, &desired, false).is_empty());
}

#[test]
fn classification_by_offset() {
    let l = Layout {
        table_base: 1000,
        priority_base: 1000,
        mask: crate::model::FwMask::DEFAULT,
    };
    assert_eq!(classify(l, 1001), Some(RuleKind::ProbeLookup(id(1))));
    assert_eq!(classify(l, 1263), Some(RuleKind::PathLookup(id(63))));
    assert_eq!(classify(l, 1564), Some(RuleKind::SourceGuard));
    assert_eq!(classify(l, 1200), None);
    assert_eq!(classify(l, 999), None);
}

const DUAL: &str = r#"version = 2
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "wana"
priority = 1
[uplink.ipv4]
[uplink.ipv6]
nat = "masquerade"
[[uplink]]
id = 2
name = "b"
interface = "wanb"
priority = 1
[uplink.ipv4]
[uplink.ipv6]
nat = "masquerade"
"#;

fn dual_input() -> Input {
    let mut i = input(&[1, 2]);
    for n in [1u8, 2] {
        let src: IpAddr = format!("2001:db8:{n}::2").parse().unwrap();
        i.paths.insert(
            PathKey {
                uplink: id(n),
                family: Family::V6,
            },
            PathInput {
                ready: Some(ReadyPath {
                    ifindex: 4 + u32::from(n),
                    gateway: Some("fe80::1".parse().unwrap()),
                    onlink: false,
                    source: src,
                }),
                local_addresses: [src].into(),
                healthy: true,
                drained: false,
            },
        );
    }
    i.active.insert(Family::V6, [id(1), id(2)].into());
    i
}

#[test]
fn family_handoff_follows_fr_rec_9_and_leaves_the_other_family_alone() {
    let dual = config::parse(DUAL).unwrap();
    let before = plan::plan(&dual, &dual_input());
    let mut s = System::default();
    let install = diff(
        &System::default(),
        &DiffInput {
            layout: Layout::of(&dual),
            protocol: 249,
            families: &[Family::V4, Family::V6],
            before_nft: &before,
            desired: &before,
            nft_pending: true,
            teardown: false,
        },
    );
    apply(&mut s, &dual, &install);
    let v4_only = config::parse(&DUAL.replace("[uplink.ipv6]\nnat = \"masquerade\"\n", "")).unwrap();
    assert!(!v4_only.manages(Family::V6));
    let mut i = dual_input();
    i.paths.retain(|k, _| k.family == Family::V4);
    i.active.remove(&Family::V6);
    let after = plan::plan(&v4_only, &i);
    let ops = diff(
        &s,
        &DiffInput {
            layout: Layout::of(&v4_only),
            protocol: 249,
            families: &[Family::V4],
            before_nft: &after,
            desired: &after,
            nft_pending: true,
            teardown: false,
        },
    );
    // Nothing of IPv4 is touched.
    let family = |o: &Op| match o {
        Op::ReplaceRoute(r) => Some(r.family),
        Op::AddRule(r) => Some(r.family),
        Op::DeleteRule(r) => Some(r.family),
        Op::DeleteRoute { family, .. } => Some(*family),
        Op::ApplyNft => None,
    };
    assert!(ops.iter().all(|o| family(o) != Some(Family::V4)), "{ops:?}");
    // (1) balancing and policy tables, (2) nftables, (3) rules, then path tables.
    let v = rule_kinds(&ops);
    let nft = position(&v, "nft");
    for t in ["1000", "1065", "1066", "1129", "1130"] {
        assert!(position(&v, &format!("-route {t}")) < nft, "{v:?}");
    }
    assert!(nft < position(&v, "-1699"));
    assert!(
        position(&v, "-1064") < position(&v, "-route 1001"),
        "class guards before path routes: {v:?}"
    );
    assert!(
        v.iter().filter(|x| x.starts_with("-1")).count()
            == before.rules.iter().filter(|r| r.family == Family::V6).count()
    );
    let mut done = s.clone();
    apply(&mut done, &v4_only, &ops);
    let again = diff(
        &done,
        &DiffInput {
            layout: Layout::of(&v4_only),
            protocol: 249,
            families: &[Family::V4],
            before_nft: &after,
            desired: &after,
            nft_pending: false,
            teardown: false,
        },
    );
    assert!(again.is_empty(), "converged: {again:?}");
}
