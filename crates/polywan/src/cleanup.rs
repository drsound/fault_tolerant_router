//! Cleanup (SPEC.md FR-REC-4, IMPL-7): removes every PolyWAN artifact listed in
//! the manifest and the configuration, in the reverse order of installation:
//! nftables table, final guard, lookup rules in increasing precedence (each
//! source guard before its source rule), class guards, routes, sysctls, and
//! the manifest last.

use anyhow::{Context, Result, anyhow, bail};
use tracing::info;

use crate::config::{Config, FirewallMode};
use crate::model::{Family, FwMask};
use crate::netlink::Client;
use crate::nft;
use crate::nftctl;
use crate::observer;
use crate::plan::{Desired, Layout};
use crate::reconcile::{self, DiffInput};
use crate::state::{self, Mode, StateDir};
use crate::sysctl;
use crate::system::Scope;
use crate::test_hooks;

pub async fn run(cfg: &Config, state_dir: &StateDir) -> Result<()> {
    let manifest = state_dir.manifest().context("manifest")?;
    let (layout, protocol, managed) = match &manifest {
        Some(m) => (
            Layout {
                table_base: m.structure.table_base,
                priority_base: m.structure.rule_priority_base,
                mask: m.structure.mask().unwrap_or(FwMask::DEFAULT),
            },
            m.structure.route_protocol,
            m.structure.firewall_mode == Mode::Managed,
        ),
        None => (
            Layout::of(cfg),
            cfg.routing.route_protocol,
            cfg.firewall.mode == FirewallMode::Managed,
        ),
    };
    if managed {
        test_hooks::step("remove the nftables table").map_err(|e| anyhow!(e))?;
        nftctl::apply(&cfg.firewall.nft_path, &nft::removal())
            .await
            .map_err(|e| anyhow!("removing table inet {}: {e}", nft::TABLE))?;
        info!("removed table inet {}", nft::TABLE);
    }
    let client = Client::new().context("netlink socket")?;
    let scope = Scope {
        polywan_tables: layout.tables(),
        discovery_tables: Vec::new(),
    };
    let mut system = observer::full(&client, &scope)
        .await
        .map_err(|e| anyhow!("dump: {e}"))?
        .system;
    let empty = Desired::default();
    let ops = reconcile::diff(
        &system,
        &DiffInput {
            layout,
            protocol,
            families: &Family::ALL,
            before_nft: &empty,
            desired: &empty,
            nft_pending: false,
            teardown: true,
        },
    );
    let n = ops.len();
    reconcile::execute(&client, &mut system, &scope, protocol, ops, || async { Ok(()) })
        .await
        .map_err(|f| anyhow!("{}: {}", f.op, f.error))?;
    info!(operations = n, "removed PolyWAN's rules and routes");
    test_hooks::step("restore sysctls").map_err(|e| anyhow!(e))?;
    if let Some(m) = &manifest {
        let mut failed = Vec::new();
        for (key, result) in sysctl::restore(m, |_| true, sysctl::read, sysctl::write) {
            match result {
                Ok(()) => info!("restored {}", sysctl::dotted(key)),
                Err(e) => failed.push(format!("{}: {e}", sysctl::dotted(key))),
            }
        }
        // The manifest holds the baselines: it stays until every one is
        // restored, so that cleanup can run again.
        if !failed.is_empty() {
            bail!(
                "restoring sysctls (the manifest is kept; run cleanup again): {}",
                failed.join("; ")
            );
        }
    }
    test_hooks::step("remove the state files and the manifest").map_err(|e| anyhow!(e))?;
    state_dir.reset().context("state files")?;
    let path = state_dir.path.join(state::MANIFEST);
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).with_context(|| path.display().to_string()),
        _ => Ok(()),
    }
}
