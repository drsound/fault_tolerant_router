//! Reconciler (SPEC.md §12.2): diffs the desired artifacts against the
//! observed ones and orders the operations so that every intermediate state
//! keeps the invariants (FR-REC-1 to FR-REC-5):
//!
//! 1. routes (path tables; balancing and policy tables without uplinks whose
//!    mark assignments are not installed yet), and the withdrawal of
//!    balancing and policy routes that must go;
//! 2. rule additions, guards first, then lookup rules in decreasing
//!    precedence, each source rule followed by its source guard, the final
//!    guard last;
//! 3. the nftables table, when it must change;
//! 4. routes that include the uplinks just given mark assignments;
//! 5. rule deletions in increasing precedence, each source guard before its
//!    source rule, class guards last;
//! 6. deletion of path routes.

use std::collections::BTreeSet;
use std::fmt;

use netlink_packet_route::RouteNetlinkMessage;

use crate::model::{Family, UplinkId};
use crate::netlink::msg::{self, ObservedRule};
use crate::netlink::{Client, EEXIST, ENOENT, ESRCH, KernelError, Mutation};
use crate::plan::{Action, Desired, Layout, Route, Rule, RuleKind};
use crate::system::System;

/// One kernel or nftables operation.
#[derive(Clone, Debug)]
pub enum Op {
    ReplaceRoute(Route),
    AddRule(Rule),
    ApplyNft,
    DeleteRule(ObservedRule),
    /// The route of a table, tagged with `protocol` (IMPL-7: cleanup
    /// removes the routes of each layout with its own protocol).
    DeleteRoute {
        family: Family,
        table: u32,
        protocol: u8,
    },
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::ReplaceRoute(r) => write!(f, "replace {} route of table {}", r.family, r.table),
            Op::AddRule(r) => write!(f, "add {} rule {} ({:?})", r.family, r.priority, r.kind),
            Op::ApplyNft => write!(f, "apply the nftables table"),
            Op::DeleteRule(r) => write!(f, "delete {} rule {}", r.family, r.priority),
            Op::DeleteRoute { family, table, .. } => write!(f, "delete {family} route of table {table}"),
        }
    }
}

/// The role of a rule found in PolyWAN's priority range, from its offset
/// (FR-ROUTE-3).
pub fn classify(layout: Layout, priority: u32) -> Option<RuleKind> {
    let off = priority.checked_sub(layout.priority_base)?;
    let id = |base: u32| UplinkId::new(u8::try_from(off - base).ok()?);
    Some(match off {
        1..=63 => RuleKind::ProbeLookup(id(0)?),
        64 => RuleKind::ProbeGuard,
        100 => RuleKind::MainBypass,
        201..=263 => RuleKind::PathLookup(id(200)?),
        264 => RuleKind::PathGuard,
        301..=363 => RuleKind::PolicyBalanceLookup(id(300)?),
        401..=463 => RuleKind::PolicyBlockLookup(id(400)?),
        464 => RuleKind::PolicyBlockGuard,
        501..=563 => RuleKind::SourceLookup(id(500)?),
        564 => RuleKind::SourceGuard,
        600 => RuleKind::Balance,
        699 => RuleKind::FinalGuard,
        _ => return None,
    })
}

/// Installation order (FR-REC-1 steps 4 to 6); a source guard sorts right
/// after the source rule of the same address.
fn install_rank(kind: RuleKind) -> u8 {
    match kind {
        RuleKind::ProbeGuard | RuleKind::PathGuard | RuleKind::PolicyBlockGuard => 0,
        RuleKind::ProbeLookup(_) => 1,
        RuleKind::MainBypass => 2,
        RuleKind::PathLookup(_) => 3,
        RuleKind::PolicyBalanceLookup(_) | RuleKind::PolicyBlockLookup(_) => 4,
        RuleKind::SourceLookup(_) | RuleKind::SourceGuard => 5,
        RuleKind::Balance => 6,
        RuleKind::FinalGuard => 7,
    }
}

/// Removal order (FR-REC-4): the reverse, with each source guard before its
/// source rule; rules of unknown role (not produced by this version) go with
/// the lookup rules.
fn removal_rank(kind: Option<RuleKind>) -> u8 {
    match kind {
        Some(RuleKind::FinalGuard) => 0,
        Some(RuleKind::Balance) => 1,
        Some(RuleKind::SourceLookup(_) | RuleKind::SourceGuard) => 2,
        Some(RuleKind::PolicyBalanceLookup(_) | RuleKind::PolicyBlockLookup(_)) => 3,
        Some(RuleKind::PathLookup(_)) | None => 4,
        Some(RuleKind::MainBypass) => 5,
        Some(RuleKind::ProbeLookup(_)) => 6,
        Some(RuleKind::ProbeGuard | RuleKind::PathGuard | RuleKind::PolicyBlockGuard) => 7,
    }
}

/// PolyWAN's rules as observed: tagged with its protocol, in its priority range.
pub fn observed_rules(system: &System, layout: Layout, protocol: u8) -> Vec<&ObservedRule> {
    system
        .rules
        .iter()
        .filter(|r| r.protocol == protocol && layout.priorities().contains(&r.priority))
        .collect()
}

fn route_present(system: &System, protocol: u8, r: &Route) -> bool {
    system
        .routes_in(r.family, r.table)
        .any(|o| o.protocol == protocol && o.as_planned().as_ref() == Some(r))
}

/// Inputs of a diff besides the desired state.
pub struct DiffInput<'a> {
    pub layout: Layout,
    pub protocol: u8,
    pub families: &'a [Family],
    /// Desired state restricted to uplinks whose mark assignments are
    /// already installed (step 1); equal to `desired` when none is new.
    pub before_nft: &'a Desired,
    pub desired: &'a Desired,
    pub nft_pending: bool,
}

/// Computes the ordered operations.
pub fn diff(system: &System, d: &DiffInput) -> Vec<Op> {
    let mut ops = Vec::new();
    for r in d.before_nft.routes.values() {
        if !route_present(system, d.protocol, r) {
            ops.push(Op::ReplaceRoute(r.clone()));
        }
    }
    // Routes to withdraw. Path tables go last, after the rules that use them
    // (FR-REC-4). Balancing and policy tables go first, by comparison with
    // the state before the nftables replacement: a removed uplink leaves
    // the active set and its policy tables before its assignments do
    // (FR-REC-3, FR-REC-9), also when an added uplink takes its place; the
    // final state's routes come back after the replacement.
    let (early, late): (Vec<_>, Vec<_>) = observed_tables(system, d.layout, d.protocol)
        .into_iter()
        .partition(|(_, t)| !d.layout.is_path_table(*t));
    let early: Vec<_> = early
        .into_iter()
        .filter(|key| !d.before_nft.routes.contains_key(key))
        .collect();
    // A path table that a desired rule still looks up (its path is no
    // longer ready) loses its route at once, before the nftables step that
    // a pass may wait for (INV-2, IMPL-4); the others go after the rules
    // that use them.
    let (withdrawn, late): (Vec<_>, Vec<_>) = late
        .into_iter()
        .filter(|key| !d.desired.routes.contains_key(key))
        .partition(|&(family, table)| {
            d.desired
                .rules
                .iter()
                .any(|r| r.family == family && r.action == Action::Lookup(table))
        });
    let protocol = d.protocol;
    for &(family, table) in early.iter().chain(&withdrawn) {
        ops.push(Op::DeleteRoute {
            family,
            table,
            protocol,
        });
    }
    let observed = observed_rules(system, d.layout, d.protocol);
    let mut adds: Vec<&Rule> = d
        .desired
        .rules
        .iter()
        .filter(|r| !observed.iter().any(|o| o.is(r, d.protocol)))
        .collect();
    adds.sort_by_key(|r| {
        let source_order = u8::from(r.kind == RuleKind::SourceGuard);
        (install_rank(r.kind), r.source, source_order, r.family, r.priority)
    });
    ops.extend(adds.into_iter().cloned().map(Op::AddRule));
    if d.nft_pending {
        ops.push(Op::ApplyNft);
    }
    for (key, r) in &d.desired.routes {
        if d.before_nft.routes.get(key) != Some(r) && (early.contains(key) || !route_present(system, d.protocol, r)) {
            ops.push(Op::ReplaceRoute(r.clone()));
        }
    }
    let mut deletes: Vec<&ObservedRule> = observed
        .into_iter()
        .filter(|o| d.families.contains(&o.family) || !d.desired.rules.iter().any(|r| r.family == o.family))
        .filter(|o| !d.desired.rules.iter().any(|r| o.is(r, d.protocol)))
        .collect();
    deletes.sort_by_key(|o| removal_key(d.layout, o));
    ops.extend(deletes.into_iter().cloned().map(Op::DeleteRule));
    for (family, table) in late {
        ops.push(Op::DeleteRoute {
            family,
            table,
            protocol,
        });
    }
    ops
}

/// The tables holding a PolyWAN route of `layout`, tagged with `protocol`.
fn observed_tables(system: &System, layout: Layout, protocol: u8) -> BTreeSet<(Family, u32)> {
    system
        .routes
        .values()
        .filter(|r| r.protocol == protocol && layout.tables().contains(&r.table) && r.as_planned().is_some())
        .map(|r| (r.family, r.table))
        .collect()
}

/// The removal order of a rule of `layout` (FR-REC-4): by role, each source
/// guard before its source rule.
fn removal_key(layout: Layout, o: &ObservedRule) -> impl Ord + use<> {
    let kind = classify(layout, o.priority);
    let guard_first = u8::from(kind != Some(RuleKind::SourceGuard));
    (
        removal_rank(kind),
        o.source,
        guard_first,
        o.family,
        std::cmp::Reverse(o.priority),
    )
}

/// Whether `o` is the rule that its priority's role in `layout` installs:
/// the same fwmark, source and action.
fn has_role(layout: Layout, o: &ObservedRule) -> bool {
    let Some(kind) = classify(layout, o.priority) else {
        return false;
    };
    let shaped = |r: &Rule| r.kind == kind && o.is(r, o.protocol);
    match (kind, o.source) {
        (RuleKind::SourceLookup(id), Some((address, _))) => {
            layout.source_rules(o.family, id, address).iter().any(shaped)
        }
        (RuleKind::SourceGuard, Some((address, _))) => {
            // The guard does not depend on the uplink.
            UplinkId::new(1).is_some_and(|id| layout.source_rules(o.family, id, address).iter().any(shaped))
        }
        _ => {
            let ids: Vec<_> = (1..=63).filter_map(UplinkId::new).collect();
            layout.static_rules(o.family, &ids).iter().any(shaped)
        }
    }
}

/// Cleanup's operations (FR-REC-4, IMPL-7) over the union of `layouts`,
/// each with its route protocol: the rules of every layout in removal
/// order, then every route; an object that two layouts share is removed
/// once, and objects tagged with another protocol are kept (FR-ROUTE-6).
/// A rule in the ranges of two layouts with one protocol is ordered by the
/// role it has in the layout whose rule it is, by its shape.
pub fn teardown(system: &System, layouts: &[(Layout, u8)]) -> Vec<Op> {
    let mut rules: Vec<(_, &ObservedRule)> = Vec::new();
    for o in &system.rules {
        let mut owners = layouts
            .iter()
            .filter(|(l, protocol)| o.protocol == *protocol && l.priorities().contains(&o.priority))
            .map(|(l, _)| *l);
        let Some(first) = owners.clone().next() else {
            continue;
        };
        let layout = owners.find(|l| has_role(*l, o)).unwrap_or(first);
        rules.push((removal_key(layout, o), o));
    }
    let mut routes = BTreeSet::new();
    for &(layout, protocol) in layouts {
        for (family, table) in observed_tables(system, layout, protocol) {
            routes.insert((protocol, family, table));
        }
    }
    rules.sort_by(|a, b| a.0.cmp(&b.0));
    let mut ops: Vec<Op> = rules.into_iter().map(|(_, o)| Op::DeleteRule(o.clone())).collect();
    ops.extend(routes.into_iter().map(|(protocol, family, table)| Op::DeleteRoute {
        family,
        table,
        protocol,
    }));
    ops
}

/// The kind of artifact a failed step concerned (FR-REC-5,
/// `polywan_apply_failures_total{kind}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureKind {
    Route,
    Rule,
    Nftables,
    Sysctl,
}

impl FailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureKind::Route => "route",
            FailureKind::Rule => "rule",
            FailureKind::Nftables => "nftables",
            FailureKind::Sysctl => "sysctl",
        }
    }
}

/// The outcome of a failed operation (FR-REC-5): the operation, its kind,
/// and for kernel operations the errno and extended acknowledgement
/// (PLAT-1); `error` is the diagnostic for the log.
#[derive(Clone, Debug)]
pub struct Failure {
    pub op: String,
    pub kind: FailureKind,
    pub error: String,
    pub errno: Option<i32>,
    pub extack: Option<String>,
    /// The route that failed, if it was a route installation (FR-DISC-7).
    pub route: Option<(Family, u32)>,
}

impl Failure {
    /// A failure without kernel details.
    pub fn new(op: impl Into<String>, kind: FailureKind, error: impl Into<String>) -> Failure {
        Failure {
            op: op.into(),
            kind,
            error: error.into(),
            errno: None,
            extack: None,
            route: None,
        }
    }
}

/// Executes operations in order, stopping at the first failure: later
/// operations may depend on it (FR-REC-5). It stops at the nftables step
/// too, once its test hook has passed: the caller applies the table outside
/// the State task (IMPL-4) and runs the operations that follow it once the
/// application succeeded. Returns whether the nftables step was reached.
/// Successful netlink mutations are applied to the view at once; their
/// notifications are idempotent.
pub async fn execute(
    client: &Client,
    system: &mut System,
    scope: &crate::system::Scope,
    protocol: u8,
    ops: Vec<Op>,
) -> Result<bool, Failure> {
    for op in ops {
        let kind = match &op {
            Op::ReplaceRoute(_) | Op::DeleteRoute { .. } => FailureKind::Route,
            Op::AddRule(_) | Op::DeleteRule(_) => FailureKind::Rule,
            Op::ApplyNft => FailureKind::Nftables,
        };
        let fail = |error: String| Failure {
            route: match &op {
                Op::ReplaceRoute(r) => Some((r.family, r.table)),
                _ => None,
            },
            ..Failure::new(op.to_string(), kind, error)
        };
        if let Err(e) = crate::test_hooks::step(&op) {
            if e.removes_route
                && let Op::ReplaceRoute(r) = &op
            {
                // The outcome of FR-ROUTE-2's IPv6 failure after the first
                // insertion, which needs an allocation failure in the
                // kernel: the old route is gone, the new one not installed.
                // Its deletion notification is hidden from the daemon, which
                // handles notifications only after this pass.
                let key = msg::route_delete_key(r.family, r.table, protocol);
                if client
                    .mutate(RouteNetlinkMessage::DelRoute(key), Mutation::Delete)
                    .await
                    .is_ok()
                {
                    crate::test_hooks::hide_deletion(r.family, r.table);
                }
            }
            return Err(fail(e.message));
        }
        match &op {
            Op::ApplyNft => return Ok(true),
            _ => {
                let (message, kind, tolerated) = netlink_op(&op, protocol);
                match client.mutate(message.clone(), kind).await {
                    Ok(()) => {}
                    Err(KernelError { errno, .. }) if tolerated.contains(&errno) => {}
                    Err(e) => {
                        return Err(Failure {
                            errno: Some(e.errno),
                            extack: e.extack.clone(),
                            ..fail(e.to_string())
                        });
                    }
                }
                system.apply(scope, &message);
            }
        }
    }
    Ok(false)
}

/// The message of an operation, its flags and the errnos that mean the
/// kernel is already in the wanted state (a dump can miss or repeat
/// entries, S3).
fn netlink_op(op: &Op, protocol: u8) -> (RouteNetlinkMessage, Mutation, &'static [i32]) {
    match op {
        Op::ReplaceRoute(r) => (
            RouteNetlinkMessage::NewRoute(msg::route_message(r, protocol)),
            Mutation::Replace,
            &[],
        ),
        Op::AddRule(r) => (
            RouteNetlinkMessage::NewRule(msg::rule_message(r, protocol)),
            Mutation::Create,
            &[EEXIST],
        ),
        Op::DeleteRule(o) => (
            RouteNetlinkMessage::DelRule(o.message.clone()),
            Mutation::Delete,
            &[ENOENT],
        ),
        Op::DeleteRoute {
            family,
            table,
            protocol,
        } => (
            RouteNetlinkMessage::DelRoute(msg::route_delete_key(*family, *table, *protocol)),
            Mutation::Delete,
            &[ESRCH, ENOENT],
        ),
        Op::ApplyNft => unreachable!("handled by the caller"),
    }
}

#[cfg(test)]
mod tests;
