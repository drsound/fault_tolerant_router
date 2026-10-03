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
use crate::plan::{Desired, Layout, Route, Rule, RuleKind};
use crate::system::System;

/// One kernel or nftables operation.
#[derive(Clone, Debug)]
pub enum Op {
    ReplaceRoute(Route),
    AddRule(Rule),
    ApplyNft,
    DeleteRule(ObservedRule),
    DeleteRoute { family: Family, table: u32 },
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::ReplaceRoute(r) => write!(f, "replace {} route of table {}", r.family, r.table),
            Op::AddRule(r) => write!(f, "add {} rule {} ({:?})", r.family, r.priority, r.kind),
            Op::ApplyNft => write!(f, "apply the nftables table"),
            Op::DeleteRule(r) => write!(f, "delete {} rule {}", r.family, r.priority),
            Op::DeleteRoute { family, table } => write!(f, "delete {family} route of table {table}"),
        }
    }
}

/// The role of a rule found in FTR's priority range, from its offset
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

/// FTR's rules as observed: tagged with its protocol, in its priority range.
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
    // Routes to withdraw. Balancing and policy tables are emptied first, so
    // that a removed uplink or family leaves the active set and its policy
    // tables before anything else changes (FR-REC-3, FR-REC-9); path tables
    // are emptied last, after the rules that use them (FR-REC-4).
    let mut tables = BTreeSet::new();
    for r in system.routes.values() {
        if r.protocol == d.protocol && d.layout.tables().contains(&r.table) && r.as_planned().is_some() {
            tables.insert((r.family, r.table));
        }
    }
    let (early, late): (Vec<_>, Vec<_>) = tables
        .into_iter()
        .filter(|key| !d.desired.routes.contains_key(key))
        .partition(|(_, t)| *t == d.layout.balancing_table() || *t >= d.layout.table_base + 65);
    for (family, table) in early {
        ops.push(Op::DeleteRoute { family, table });
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
        if d.before_nft.routes.get(key) != Some(r) && !route_present(system, d.protocol, r) {
            ops.push(Op::ReplaceRoute(r.clone()));
        }
    }
    let mut deletes: Vec<&ObservedRule> = observed
        .into_iter()
        .filter(|o| d.families.contains(&o.family) || !d.desired.rules.iter().any(|r| r.family == o.family))
        .filter(|o| !d.desired.rules.iter().any(|r| o.is(r, d.protocol)))
        .collect();
    deletes.sort_by_key(|o| {
        let kind = classify(d.layout, o.priority);
        let guard_first = u8::from(kind != Some(RuleKind::SourceGuard));
        (
            removal_rank(kind),
            o.source,
            guard_first,
            o.family,
            std::cmp::Reverse(o.priority),
        )
    });
    ops.extend(deletes.into_iter().cloned().map(Op::DeleteRule));
    for (family, table) in late {
        ops.push(Op::DeleteRoute { family, table });
    }
    ops
}

/// The outcome of a failed operation (FR-REC-5).
#[derive(Clone, Debug)]
pub struct Failure {
    pub op: String,
    pub error: String,
    /// The route that failed, if it was a route installation (FR-DISC-7).
    pub route: Option<(Family, u32)>,
}

/// Executes operations in order, stopping at the first failure: later
/// operations may depend on it (FR-REC-5). Successful netlink mutations are
/// applied to the view at once; their notifications are idempotent.
pub async fn execute<F, Fut>(
    client: &Client,
    system: &mut System,
    scope: &crate::system::Scope,
    protocol: u8,
    ops: Vec<Op>,
    mut nft: F,
) -> Result<usize, Failure>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut done = 0;
    for op in ops {
        let fail = |error: String| Failure {
            op: op.to_string(),
            error,
            route: match &op {
                Op::ReplaceRoute(r) => Some((r.family, r.table)),
                _ => None,
            },
        };
        match &op {
            Op::ApplyNft => nft().await.map_err(fail)?,
            _ => {
                let (message, kind, tolerated) = netlink_op(&op, protocol);
                match client.mutate(message.clone(), kind).await {
                    Ok(()) => {}
                    Err(KernelError { errno, .. }) if tolerated.contains(&errno) => {}
                    Err(e) => return Err(fail(e.to_string())),
                }
                system.apply(scope, &message);
            }
        }
        done += 1;
    }
    Ok(done)
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
        Op::DeleteRoute { family, table } => (
            RouteNetlinkMessage::DelRoute(msg::route_delete_key(*family, *table, protocol)),
            Mutation::Delete,
            &[ESRCH, ENOENT],
        ),
        Op::ApplyNft => unreachable!("handled by the caller"),
    }
}

#[cfg(test)]
mod tests;
