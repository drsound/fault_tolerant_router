//! Planner (SPEC.md §12.2): a pure function from the configuration and the
//! observed state of the paths to the routing artifacts FTR wants installed
//! (rules of FR-ROUTE-3 and the routes of the table layout of §4.3).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::config::Config;
use crate::model::{Family, FieldValue, FwMask, PathKey, UplinkId};

/// What a rule does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    Lookup(u32),
    /// `lookup main suppress_prefixlength 0` (main bypass).
    LookupMainSuppressDefault,
    Unreachable,
}

/// Role of a rule in the layout; it orders installation (FR-REC-1) and
/// removal (FR-REC-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuleKind {
    ProbeLookup(UplinkId),
    ProbeGuard,
    MainBypass,
    PathLookup(UplinkId),
    PathGuard,
    PolicyBalanceLookup(UplinkId),
    PolicyBlockLookup(UplinkId),
    PolicyBlockGuard,
    SourceLookup(UplinkId),
    SourceGuard,
    Balance,
    FinalGuard,
}

impl RuleKind {
    /// Guards are installed before every lookup rule (FR-REC-1 step 4),
    /// except the source guards, which follow their source rule, and the
    /// final guard, which comes last.
    pub fn is_class_guard(self) -> bool {
        matches!(
            self,
            RuleKind::ProbeGuard | RuleKind::PathGuard | RuleKind::PolicyBlockGuard
        )
    }
}

/// A routing rule. Every FTR rule carries the configured protocol, which is
/// part of its identity (FR-REC-6) and is not repeated here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rule {
    pub family: Family,
    pub priority: u32,
    /// `(mark, mask)`; a zero mark with a non-zero mask selects a zero field.
    pub fwmark: Option<(u32, u32)>,
    /// Host source selector (`from ADDRESS`).
    pub source: Option<IpAddr>,
    pub action: Action,
    pub kind: RuleKind,
}

/// One next hop of a route. `gateway: None` is a device route (IPv4
/// point-to-point interfaces only, FR-DISC-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NextHop {
    pub ifindex: u32,
    pub gateway: Option<IpAddr>,
    pub onlink: bool,
    /// 1–256 (FR-ROUTE-2); 1 for single-path routes.
    pub weight: u16,
}

/// The only route an FTR table holds: `default` with metric 100 (§4.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Route {
    pub family: Family,
    pub table: u32,
    pub source: Option<IpAddr>,
    /// Sorted by interface index; more than one means a multipath route.
    pub nexthops: Vec<NextHop>,
}

pub const ROUTE_METRIC: u32 = 100;

/// Observed state of a ready path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyPath {
    pub ifindex: u32,
    pub gateway: Option<IpAddr>,
    pub onlink: bool,
    pub source: IpAddr,
}

/// Planner input for one configured path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathInput {
    /// `Some` when the path is ready (SPEC.md §2).
    pub ready: Option<ReadyPath>,
    /// Local addresses of the path (FR-DISC-2), each with a source rule and
    /// a source guard.
    pub local_addresses: BTreeSet<IpAddr>,
    pub healthy: bool,
    pub drained: bool,
}

/// Everything the planner needs besides the configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Input {
    pub paths: BTreeMap<PathKey, PathInput>,
    /// Active set of each family (§4.4), computed by the selection module.
    pub active: BTreeMap<Family, BTreeSet<UplinkId>>,
}

/// The desired routing artifacts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Desired {
    pub rules: BTreeSet<Rule>,
    /// Keyed by (family, table); a table without an entry must be empty.
    pub routes: BTreeMap<(Family, u32), Route>,
}

/// Table and priority arithmetic of §4.3 and FR-ROUTE-3.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub table_base: u32,
    pub priority_base: u32,
    pub mask: FwMask,
}

impl Layout {
    pub fn of(config: &Config) -> Layout {
        Layout {
            table_base: config.routing.table_base,
            priority_base: config.routing.rule_priority_base,
            mask: config.routing.fwmark_mask,
        }
    }

    pub fn balancing_table(self) -> u32 {
        self.table_base
    }

    pub fn path_table(self, id: UplinkId) -> u32 {
        self.table_base + u32::from(id.get())
    }

    pub fn policy_balance_table(self, id: UplinkId) -> u32 {
        self.table_base + 64 + u32::from(id.get())
    }

    pub fn policy_block_table(self, id: UplinkId) -> u32 {
        self.table_base + 128 + u32::from(id.get())
    }

    /// Every table FTR owns.
    pub fn tables(self) -> std::ops::RangeInclusive<u32> {
        self.table_base..=self.table_base + 191
    }

    /// Every rule priority FTR owns.
    pub fn priorities(self) -> std::ops::RangeInclusive<u32> {
        self.priority_base..=self.priority_base + 699
    }

    fn value(self, v: FieldValue) -> (u32, u32) {
        (self.mask.encode(v), self.mask.mask())
    }

    fn class(self, v: FieldValue) -> (u32, u32) {
        (self.mask.encode(v), self.mask.class_mask())
    }

    /// The rules that do not depend on addresses: guards and the lookup
    /// rules of the configured paths of the family.
    pub fn static_rules(self, family: Family, uplinks: &[UplinkId]) -> Vec<Rule> {
        let b = self.priority_base;
        let rule = |priority, fwmark, action, kind| Rule {
            family,
            priority,
            fwmark,
            source: None,
            action,
            kind,
        };
        let mut v = Vec::new();
        for &id in uplinks {
            let n = u32::from(id.get());
            v.push(rule(
                b + n,
                Some(self.value(FieldValue::probe(id))),
                Action::Lookup(self.path_table(id)),
                RuleKind::ProbeLookup(id),
            ));
            v.push(rule(
                b + 200 + n,
                Some(self.value(FieldValue::path(id))),
                Action::Lookup(self.path_table(id)),
                RuleKind::PathLookup(id),
            ));
            v.push(rule(
                b + 300 + n,
                Some(self.value(FieldValue::policy_balance(id))),
                Action::Lookup(self.policy_balance_table(id)),
                RuleKind::PolicyBalanceLookup(id),
            ));
            v.push(rule(
                b + 400 + n,
                Some(self.value(FieldValue::policy_block(id))),
                Action::Lookup(self.policy_block_table(id)),
                RuleKind::PolicyBlockLookup(id),
            ));
        }
        v.push(rule(
            b + 64,
            Some(self.class(FieldValue::PROBE_CLASS)),
            Action::Unreachable,
            RuleKind::ProbeGuard,
        ));
        v.push(rule(
            b + 100,
            None,
            Action::LookupMainSuppressDefault,
            RuleKind::MainBypass,
        ));
        // Path guard: any non-zero path-class value, as six rules
        // `fwmark 2^k / (0xc0 + 2^k)` (FR-ROUTE-3).
        for k in 0..6 {
            let bit = 1u8 << k;
            let mark = self.mask.encode(FieldValue::raw(bit));
            let mask = self.mask.encode(FieldValue::raw(0xc0 | bit));
            v.push(rule(
                b + 264,
                Some((mark, mask)),
                Action::Unreachable,
                RuleKind::PathGuard,
            ));
        }
        v.push(rule(
            b + 464,
            Some(self.class(FieldValue::POLICY_BLOCK_CLASS)),
            Action::Unreachable,
            RuleKind::PolicyBlockGuard,
        ));
        v.push(rule(
            b + 600,
            None,
            Action::Lookup(self.balancing_table()),
            RuleKind::Balance,
        ));
        v.push(rule(b + 699, None, Action::Unreachable, RuleKind::FinalGuard));
        v
    }

    /// Source rule and source guard of a local address (FR-ROUTE-3).
    pub fn source_rules(self, family: Family, id: UplinkId, address: IpAddr) -> [Rule; 2] {
        let zero = Some((0, self.mask.mask()));
        [
            Rule {
                family,
                priority: self.priority_base + 500 + u32::from(id.get()),
                fwmark: zero,
                source: Some(address),
                action: Action::Lookup(self.path_table(id)),
                kind: RuleKind::SourceLookup(id),
            },
            Rule {
                family,
                priority: self.priority_base + 564,
                fwmark: zero,
                source: Some(address),
                action: Action::Unreachable,
                kind: RuleKind::SourceGuard,
            },
        ]
    }
}

/// Computes the desired artifacts.
pub fn plan(config: &Config, input: &Input) -> Desired {
    let layout = Layout::of(config);
    let mut desired = Desired::default();
    for family in Family::ALL {
        if !config.manages(family) {
            continue;
        }
        let uplinks: Vec<&crate::config::Uplink> = config.uplinks.iter().filter(|u| u.path(family).is_some()).collect();
        let ids: Vec<UplinkId> = uplinks.iter().map(|u| u.id).collect();
        desired.rules.extend(layout.static_rules(family, &ids));
        let mut members = Vec::new();
        let active = input.active.get(&family);
        for u in &uplinks {
            let key = PathKey { uplink: u.id, family };
            let Some(p) = input.paths.get(&key) else { continue };
            for a in &p.local_addresses {
                desired.rules.extend(layout.source_rules(family, u.id, *a));
            }
            let Some(r) = p.ready else { continue };
            let hop = NextHop {
                ifindex: r.ifindex,
                gateway: r.gateway,
                onlink: r.onlink,
                weight: 1,
            };
            let route = |table| Route {
                family,
                table,
                source: Some(r.source),
                nexthops: vec![hop],
            };
            desired
                .routes
                .insert((family, layout.path_table(u.id)), route(layout.path_table(u.id)));
            if p.healthy && !p.drained {
                for t in [layout.policy_balance_table(u.id), layout.policy_block_table(u.id)] {
                    desired.routes.insert((family, t), route(t));
                }
            }
            if active.is_some_and(|a| a.contains(&u.id)) {
                members.push(NextHop {
                    weight: u.weight,
                    ..hop
                });
            }
        }
        if !members.is_empty() {
            members.sort();
            if members.len() == 1 {
                members[0].weight = 1;
            }
            let table = layout.balancing_table();
            desired.routes.insert(
                (family, table),
                Route {
                    family,
                    table,
                    source: None,
                    nexthops: members,
                },
            );
        }
    }
    desired
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::config;

    fn two_uplinks() -> Config {
        config::parse(
            r#"version = 2
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "wana"
priority = 1
weight = 3
[uplink.ipv4]
[[uplink]]
id = 2
name = "b"
interface = "wanb"
priority = 1
[uplink.ipv4]
"#,
        )
        .unwrap()
    }

    fn id(n: u8) -> UplinkId {
        UplinkId::new(n).unwrap()
    }

    fn ready(ifindex: u32, gw: [u8; 4], src: [u8; 4]) -> PathInput {
        PathInput {
            ready: Some(ReadyPath {
                ifindex,
                gateway: Some(IpAddr::from(gw)),
                onlink: false,
                source: IpAddr::from(src),
            }),
            local_addresses: [IpAddr::from(src)].into(),
            healthy: true,
            drained: false,
        }
    }

    fn input() -> Input {
        let mut i = Input::default();
        i.paths.insert(
            PathKey {
                uplink: id(1),
                family: Family::V4,
            },
            ready(5, [192, 0, 2, 1], [192, 0, 2, 2]),
        );
        i.paths.insert(
            PathKey {
                uplink: id(2),
                family: Family::V4,
            },
            ready(6, [100, 64, 0, 1], [100, 64, 0, 2]),
        );
        i.active.insert(Family::V4, [id(1), id(2)].into());
        i
    }

    /// `ip rule` text for a planned rule, in the format of the S1/S3 spikes.
    fn show(r: &Rule) -> String {
        let mut s = format!(
            "{}:\tfrom {}",
            r.priority,
            r.source.map_or("all".into(), |a| a.to_string())
        );
        if let Some((m, k)) = r.fwmark {
            s += &format!(" fwmark {m:#x}/{k:#x}");
        }
        s += &match r.action {
            Action::Lookup(t) => format!(" lookup {t}"),
            Action::LookupMainSuppressDefault => " lookup main suppress_prefixlength 0".into(),
            Action::Unreachable => " unreachable".into(),
        };
        s
    }

    #[test]
    fn rule_layout_matches_fr_route_3() {
        let d = plan(&two_uplinks(), &input());
        let text: Vec<String> = d.rules.iter().map(show).collect();
        let mut sorted = text.clone();
        sorted.sort_by_key(|l| l.split(':').next().unwrap().parse::<u32>().unwrap());
        let expected = [
            "1001:\tfrom all fwmark 0x410000/0xff0000 lookup 1001",
            "1002:\tfrom all fwmark 0x420000/0xff0000 lookup 1002",
            "1064:\tfrom all fwmark 0x400000/0xc00000 unreachable",
            "1100:\tfrom all lookup main suppress_prefixlength 0",
            "1201:\tfrom all fwmark 0x10000/0xff0000 lookup 1001",
            "1202:\tfrom all fwmark 0x20000/0xff0000 lookup 1002",
            "1264:\tfrom all fwmark 0x10000/0xc10000 unreachable",
            "1264:\tfrom all fwmark 0x20000/0xc20000 unreachable",
            "1264:\tfrom all fwmark 0x40000/0xc40000 unreachable",
            "1264:\tfrom all fwmark 0x80000/0xc80000 unreachable",
            "1264:\tfrom all fwmark 0x100000/0xd00000 unreachable",
            "1264:\tfrom all fwmark 0x200000/0xe00000 unreachable",
            "1301:\tfrom all fwmark 0x810000/0xff0000 lookup 1065",
            "1302:\tfrom all fwmark 0x820000/0xff0000 lookup 1066",
            "1401:\tfrom all fwmark 0xc10000/0xff0000 lookup 1129",
            "1402:\tfrom all fwmark 0xc20000/0xff0000 lookup 1130",
            "1464:\tfrom all fwmark 0xc00000/0xc00000 unreachable",
            "1501:\tfrom 192.0.2.2 fwmark 0x0/0xff0000 lookup 1001",
            "1502:\tfrom 100.64.0.2 fwmark 0x0/0xff0000 lookup 1002",
            "1564:\tfrom 100.64.0.2 fwmark 0x0/0xff0000 unreachable",
            "1564:\tfrom 192.0.2.2 fwmark 0x0/0xff0000 unreachable",
            "1600:\tfrom all lookup 1000",
            "1699:\tfrom all unreachable",
        ];
        let mut got = sorted;
        let mut want: Vec<String> = expected.iter().map(|s| (*s).to_owned()).collect();
        got.sort();
        want.sort();
        assert_eq!(got, want);
        assert!(
            d.rules.iter().all(|r| r.family == Family::V4),
            "no IPv6 artifact for an IPv4-only configuration"
        );
    }

    #[test]
    fn routes_follow_readiness_health_and_the_active_set() {
        let cfg = two_uplinks();
        let mut i = input();
        let d = plan(&cfg, &i);
        let bal = &d.routes[&(Family::V4, 1000)];
        assert_eq!(bal.source, None);
        assert_eq!(
            bal.nexthops.iter().map(|h| (h.ifindex, h.weight)).collect::<Vec<_>>(),
            [(5, 3), (6, 1)]
        );
        let a = &d.routes[&(Family::V4, 1001)];
        assert_eq!(a.source, Some(IpAddr::from(Ipv4Addr::new(192, 0, 2, 2))));
        assert_eq!(a.nexthops.len(), 1);
        assert_eq!(d.routes.len(), 7, "balancing, two path tables, four policy tables");

        // A unhealthy and out of the active set: path table kept, policy
        // tables emptied, single-member balancing route.
        let pa = i
            .paths
            .get_mut(&PathKey {
                uplink: id(1),
                family: Family::V4,
            })
            .unwrap();
        pa.healthy = false;
        i.active.insert(Family::V4, [id(2)].into());
        let d = plan(&cfg, &i);
        assert!(d.routes.contains_key(&(Family::V4, 1001)));
        assert!(!d.routes.contains_key(&(Family::V4, 1065)));
        assert!(!d.routes.contains_key(&(Family::V4, 1129)));
        assert_eq!(d.routes[&(Family::V4, 1000)].nexthops.len(), 1);

        // B not ready: no path table; its source rules stay while the
        // address exists. Empty active set: no balancing route.
        let pb = i
            .paths
            .get_mut(&PathKey {
                uplink: id(2),
                family: Family::V4,
            })
            .unwrap();
        pb.ready = None;
        i.active.insert(Family::V4, BTreeSet::new());
        let d = plan(&cfg, &i);
        assert!(!d.routes.contains_key(&(Family::V4, 1002)));
        assert!(!d.routes.contains_key(&(Family::V4, 1000)));
        assert_eq!(
            d.rules
                .iter()
                .filter(|r| r.kind == RuleKind::SourceLookup(id(2)))
                .count(),
            1
        );
    }

    #[test]
    fn drained_uplinks_lose_their_policy_tables_only() {
        let cfg = two_uplinks();
        let mut i = input();
        i.paths
            .get_mut(&PathKey {
                uplink: id(2),
                family: Family::V4,
            })
            .unwrap()
            .drained = true;
        let d = plan(&cfg, &i);
        assert!(d.routes.contains_key(&(Family::V4, 1002)));
        assert!(!d.routes.contains_key(&(Family::V4, 1066)));
        assert!(!d.routes.contains_key(&(Family::V4, 1130)));
    }

    #[test]
    fn encoded_values_follow_the_mask() {
        let mut cfg = two_uplinks();
        cfg.routing.fwmark_mask = FwMask::new(0xff).unwrap();
        let d = plan(&cfg, &input());
        let probe = d.rules.iter().find(|r| r.kind == RuleKind::ProbeLookup(id(2))).unwrap();
        assert_eq!(probe.fwmark, Some((0x42, 0xff)));
        let guards: Vec<_> = d
            .rules
            .iter()
            .filter(|r| r.kind == RuleKind::PathGuard)
            .map(|r| r.fwmark.unwrap())
            .collect();
        assert_eq!(guards.len(), 6);
        assert!(guards.contains(&(0x20, 0xe0)));
    }
}
