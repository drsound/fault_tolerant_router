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

use netlink_packet_route::RouteNetlinkMessage;

use crate::model::Family;
use crate::netlink::msg;
use crate::netlink::{Client, Dump, KernelError};
use crate::system::{Scope, System};

const INTERRUPTED_RETRIES: usize = 5;

/// A dump, retried while the kernel flags it as interrupted.
async fn dump(c: &Client, filter: RouteNetlinkMessage) -> Result<Dump, KernelError> {
    let mut last = c.dump(filter.clone()).await?;
    for _ in 0..INTERRUPTED_RETRIES {
        if !last.interrupted {
            break;
        }
        last = c.dump(filter.clone()).await?;
    }
    Ok(last)
}

/// The complete view: links, addresses, rules and routes of both families.
pub async fn full(c: &Client, scope: &Scope) -> Result<System, KernelError> {
    let mut s = System::default();
    let mut filters = vec![msg::link_dump()];
    for f in Family::ALL {
        filters.push(msg::address_dump(f));
        filters.push(msg::rule_dump(f));
        filters.push(msg::route_dump(f, None));
    }
    for filter in filters {
        for m in dump(c, filter).await?.messages {
            s.apply(scope, &m);
        }
    }
    Ok(s)
}

/// A full resynchronisation: a new full dump, with every route, rule and
/// address of the old view that the dump lacks confirmed by a second read.
pub async fn resync(c: &Client, scope: &Scope, old: &System) -> Result<System, KernelError> {
    let mut new = full(c, scope).await?;
    let missing_tables: std::collections::BTreeSet<(Family, u32)> = old
        .routes
        .keys()
        .filter(|k| !new.routes.contains_key(k))
        .map(|(f, t, _, _)| (*f, *t))
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
            for m in dump(c, msg::address_dump(f)).await?.messages {
                new.apply(scope, &m);
            }
        }
    }
    Ok(new)
}

/// Re-reads tables after a link or address event of an uplink: the kernel
/// removes IPv4 routes and changes nexthop flags without notification (S3).
/// A route missing from the re-read is removed only when a second read
/// agrees.
pub async fn reread(
    c: &Client,
    scope: &Scope,
    system: &mut System,
    tables: &[(Family, u32)],
) -> Result<(), KernelError> {
    for (f, t) in tables {
        let first = dump(c, msg::route_dump(*f, Some(*t))).await?.messages;
        let had = system.routes_in(*f, *t).count();
        let got = first
            .iter()
            .filter(|m| matches!(m, RouteNetlinkMessage::NewRoute(_)))
            .count();
        let messages = if got < had {
            dump(c, msg::route_dump(*f, Some(*t))).await?.messages
        } else {
            first
        };
        system.replace_table(scope, *f, *t, &messages);
    }
    Ok(())
}
