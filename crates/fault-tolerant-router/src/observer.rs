//! Observer dumps (SPEC.md §12.2, spike S3).
//!
//! Notifications arrive on a separate subscribed socket; the daemon reads it
//! only between dumps, so notifications received during a dump stay queued
//! and are applied in order after it. Dumps are not consistent snapshots:
//! rule and route dumps can omit or repeat entries without any flag, and
//! address dumps are flagged in most such cases only (S3 `dumpskip`). So
//! results are merged by identity, flagged dumps are retried a bounded
//! number of times, and an entry that disappears from a full dump without a
//! deletion notification is removed only when a confirming read also lacks
//! it.

use std::future::Future;

use netlink_packet_route::RouteNetlinkMessage;

use crate::model::Family;
use crate::netlink::msg;
use crate::netlink::{Client, Dump, KernelError};
use crate::system::{Scope, System};

/// Where dumps come from: a netlink socket, or a scripted source in tests.
pub trait Dumper: Sized {
    fn dump(&self, filter: RouteNetlinkMessage) -> impl Future<Output = Result<Dump, KernelError>> + Send;
    /// A new source for a retry after a deadline (a new socket).
    fn fresh(&self) -> std::io::Result<Self>;
}

impl Dumper for Client {
    fn dump(&self, filter: RouteNetlinkMessage) -> impl Future<Output = Result<Dump, KernelError>> + Send {
        Client::dump(self, filter)
    }

    fn fresh(&self) -> std::io::Result<Client> {
        Client::new()
    }
}

const INTERRUPTED_RETRIES: usize = 5;

/// A dump that takes longer is abandoned and retried on a new socket: an
/// IPv6 table dump can restart over and over while routes are added (S3).
pub const DUMP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
const DEADLINE_RETRIES: usize = 3;

/// One dump within the deadline, on `c` first and then on new sockets.
async fn bounded<D: Dumper>(c: &D, filter: &RouteNetlinkMessage) -> Result<Dump, KernelError> {
    match tokio::time::timeout(DUMP_DEADLINE, c.dump(filter.clone())).await {
        Ok(r) => return r,
        Err(_) => tracing::warn!(
            "a netlink dump exceeded {} s; retrying on a new socket",
            DUMP_DEADLINE.as_secs()
        ),
    }
    for _ in 0..DEADLINE_RETRIES {
        let fresh = c.fresh().map_err(KernelError::transport)?;
        if let Ok(r) = tokio::time::timeout(DUMP_DEADLINE, fresh.dump(filter.clone())).await {
            return r;
        }
    }
    Err(KernelError::transport(format!(
        "dump not completed within {} attempts",
        DEADLINE_RETRIES + 1
    )))
}

/// A dump, retried while the kernel flags it as interrupted.
async fn dump<D: Dumper>(c: &D, filter: RouteNetlinkMessage) -> Result<Dump, KernelError> {
    let mut last = bounded(c, &filter).await?;
    for _ in 0..INTERRUPTED_RETRIES {
        if !last.interrupted {
            break;
        }
        last = bounded(c, &filter).await?;
    }
    Ok(last)
}

/// A view built from dumps.
#[derive(Debug)]
pub struct View {
    pub system: System,
    /// A dump still flagged as interrupted after its retries was used: a
    /// full resynchronisation is due (§12.2).
    pub interrupted: bool,
}

/// The complete view: links, addresses, rules and routes of both families.
pub async fn full<D: Dumper>(c: &D, scope: &Scope) -> Result<View, KernelError> {
    let mut v = View {
        system: System::default(),
        interrupted: false,
    };
    let mut filters = vec![msg::link_dump()];
    for f in Family::ALL {
        filters.push(msg::address_dump(f));
        filters.push(msg::rule_dump(f));
        filters.push(msg::route_dump(f, None));
    }
    for filter in filters {
        let d = dump(c, filter).await?;
        v.interrupted |= d.interrupted;
        for m in d.messages {
            v.system.apply(scope, &m);
        }
    }
    Ok(v)
}

/// A full resynchronisation: a new full dump, with every route, rule and
/// address of the old view that the dump lacks confirmed by a second read.
pub async fn resync<D: Dumper>(c: &D, scope: &Scope, old: &System) -> Result<View, KernelError> {
    let View {
        system: mut new,
        mut interrupted,
    } = full(c, scope).await?;
    let missing_tables: std::collections::BTreeSet<(Family, u32)> = old
        .routes
        .keys()
        .filter(|k| !new.routes.contains_key(k))
        .map(|(f, t, ..)| (*f, *t))
        .collect();
    for (f, t) in missing_tables {
        // A strict dump of one table is small enough for one batch.
        let d = dump(c, msg::route_dump(f, Some(t))).await?;
        for m in &d.messages {
            if let RouteNetlinkMessage::NewRoute(_) = m {
                new.apply(scope, m);
            }
        }
    }
    let rules_missing = old
        .rules
        .iter()
        .any(|o| !new.rules.iter().any(|n| n.message == o.message));
    if rules_missing {
        for f in Family::ALL {
            for m in dump(c, msg::rule_dump(f)).await?.messages {
                new.apply(scope, &m);
            }
        }
    }
    let addresses_missing = old.addresses.keys().any(|k| !new.addresses.contains_key(k));
    if addresses_missing {
        for f in Family::ALL {
            let d = dump(c, msg::address_dump(f)).await?;
            interrupted |= d.interrupted;
            for m in d.messages {
                new.apply(scope, &m);
            }
        }
    }
    Ok(View {
        system: new,
        interrupted,
    })
}

/// Re-reads tables after a link or address event of an uplink: the kernel
/// removes IPv4 routes and changes nexthop flags without notification (S3).
/// A route of the view missing from the re-read is removed only when a
/// second read also lacks it; a route either read saw stays, with the
/// attributes of the later read.
pub async fn reread<D: Dumper>(
    c: &D,
    scope: &Scope,
    system: &mut System,
    tables: &[(Family, u32)],
) -> Result<(), KernelError> {
    for &(f, t) in tables {
        let mut messages = dump(c, msg::route_dump(f, Some(t))).await?.messages;
        // Identities, not counts: a dump can repeat one entry and omit
        // another (S3).
        let mut seen = System::default();
        seen.replace_table(scope, f, t, &messages);
        let missing = system
            .routes
            .keys()
            .any(|k| k.0 == f && k.1 == t && !seen.routes.contains_key(k));
        if missing {
            messages.extend(dump(c, msg::route_dump(f, Some(t))).await?.messages);
        }
        system.replace_table(scope, f, t, &messages);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
