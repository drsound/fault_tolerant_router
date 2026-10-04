//! The daemon (SPEC.md §12.2): one task owns all mutable state and reacts to
//! netlink notifications, probe reports, timers and signals by recomputing
//! the desired state and reconciling the kernel and nftables with it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use netlink_packet_route::RouteNetlinkMessage;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, error, info, warn};

use crate::checks;
use crate::config::{self, Config, FirewallMode, OnShutdown};
use crate::discover::{self, Discovered};
use crate::health::{self, Hysteresis, Machine, Reason, Round};
use crate::model::{Family, FieldValue, PathKey, UplinkId};
use crate::netlink::{Client, Message, Notification, Subscription, groups};
use crate::nft;
use crate::nftctl;
use crate::observer;
use crate::plan::{self, Input, Layout, PathInput};
use crate::probe;
use crate::reconcile::{self, DiffInput, Failure, Op};
use crate::select::{self, Candidate};
use crate::state::{self, Checkpoint, InstanceLock, Manifest, PathCheckpoint, StateDir};
use crate::sysctl;
use crate::system::{Change, Scope, System};

pub struct Options {
    pub config: PathBuf,
    pub dry_run: bool,
    pub reset_state: bool,
    pub lock: PathBuf,
}

/// One configured path at runtime.
struct PathRuntime {
    discovered: Option<Discovered>,
    machine: Machine,
    since_ms: u64,
    generation: u64,
    prober: Option<(probe::Spec, tokio::task::JoinHandle<()>)>,
    /// Since when an automatic IPv6 gateway is awaited on a usable link,
    /// and whether the FR-SYS-3 warning was given.
    gateway_wait: Option<(Instant, bool)>,
}

impl PathRuntime {
    fn new(discovered: Option<Discovered>, machine: Machine) -> PathRuntime {
        PathRuntime {
            discovered,
            machine,
            since_ms: now_ms(),
            generation: 0,
            prober: None,
            gateway_wait: None,
        }
    }
}

/// FR-SYS-3: how long an IPv6 path waits for a discovered gateway, after
/// startup or after its link comes up, before the warning.
const GATEWAY_WARNING: Duration = Duration::from_secs(30);

/// [`GATEWAY_WARNING`], or the delay a scenario sets (test hooks).
fn gateway_warning() -> Duration {
    crate::test_hooks::gateway_warning(GATEWAY_WARNING)
}

/// Retry state after a failed application (FR-REC-5).
struct Retry {
    at: Instant,
    backoff: Duration,
    /// What failed: the pending sysctls, or the operations of the pass.
    /// Only the same attempt waits for the backoff; a newer desired state
    /// supersedes it at once (FR-REC-5).
    attempt: String,
}

/// A set of sysctls applied together.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SysctlScope {
    Global,
    Interface(String),
}

impl std::fmt::Display for SysctlScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysctlScope::Global => f.write_str("global"),
            SysctlScope::Interface(i) => f.write_str(i),
        }
    }
}

/// The attempt of a failed sysctl application.
const SYSCTL_ATTEMPT: &str = "sysctls";

/// FR-COEX-4 bookkeeping for one kind of artifact.
#[derive(Default)]
struct Ownership {
    removals: VecDeque<Instant>,
    conflict: bool,
    clean_reconciliations: u8,
}

struct Daemon {
    cfg: Config,
    layout: Layout,
    scope: Scope,
    protocol: u8,
    client: Client,
    dumper: Client,
    system: System,
    state_dir: StateDir,
    manifest: Manifest,
    paths: BTreeMap<PathKey, PathRuntime>,
    active: BTreeMap<Family, BTreeSet<UplinkId>>,
    drained: BTreeSet<UplinkId>,
    route_failed: BTreeMap<PathKey, String>,
    /// The transaction last applied and the paths it assigns.
    nft_applied: Option<(String, BTreeSet<PathKey>)>,
    nft_listing: Option<serde_json::Value>,
    nft_missing: bool,
    /// Configured paths that FTR's table found at startup already assigns
    /// (warm adoption, FR-REC-8); `None` without such a table. The others
    /// were added while FTR was stopped: like an addition by reload, they
    /// join the balancing and policy routes only after the replacement
    /// installs their assignments (FR-REC-3).
    nft_adopted: Option<BTreeSet<PathKey>>,
    retry: Option<Retry>,
    degraded: BTreeSet<&'static str>,
    ownership: BTreeMap<&'static str, Ownership>,
    /// Artifacts removed by a third party while immediate repairs of their
    /// kind are suspended (FR-COEX-4): re-created only by a full
    /// reconciliation.
    held_rules: Vec<crate::netlink::msg::ObservedRule>,
    held_routes: BTreeSet<(Family, u32)>,
    /// The next pass is part of a full reconciliation: no repair is held.
    full_pass: bool,
    /// A view was built from a dump still flagged as interrupted after its
    /// retries: a full resynchronisation is due soon (§12.2).
    resync_due: bool,
    /// Sysctls to apply before the next routes and rules (FR-REC-3), by
    /// interface (`None`: every setting); a failure is retried (FR-REC-5).
    sysctls_pending: BTreeSet<SysctlScope>,
    /// Interfaces whose settings failed, and their retries, each with its
    /// own backoff (FR-REC-5). An uplink whose interface has settings
    /// pending is not ready (FR-DISC-7).
    sysctls_failed: BTreeMap<String, String>,
    sysctl_retries: BTreeMap<String, Retry>,
    /// The last prober generation: unique across paths, so that a round of
    /// a removed and re-added uplink's old prober is never taken as current.
    probe_generation: u64,
    probe_tx: mpsc::Sender<probe::Report>,
    boot_id: String,
    dirty: bool,
    reread: BTreeSet<(Family, u32)>,
    /// Route expiries up to this instant have been handled by a re-read;
    /// a later one, even one already past, is still due (FR-DISC-5).
    expiry_checked: std::time::Instant,
    last_checkpoint: Instant,
}

const RECEIVE_BUFFER: usize = 4 << 20;

/// Delay of the full resynchronisation that follows a dump still flagged as
/// interrupted after its retries; it also bounds how often a kernel that
/// keeps interrupting dumps makes the daemon resynchronise.
const RESYNC_AFTER_INTERRUPTED: Duration = Duration::from_secs(1);

fn now_ms() -> u64 {
    state::boottime_ms().unwrap_or(0)
}

/// `run`: startup (FR-REC-1, FR-REC-8, IMPL-6) and the event loop.
pub async fn run(opts: Options) -> Result<()> {
    let cfg = config::load(&opts.config).map_err(|e| anyhow::anyhow!("{e}"))?;
    let unsupported = cfg.unsupported_features();
    if !unsupported.is_empty() {
        bail!("not supported by this development build: {}", unsupported.join(", "));
    }
    // FR-CFG-5: nothing configured runs before its ownership is verified.
    report(&checks::trusted(&opts.config, &cfg))?;
    let mut findings = checks::kernel(&std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default());
    if cfg.firewall.mode == FirewallMode::Managed {
        let v = nftctl::run(&cfg.firewall.nft_path, &["--version"], None)
            .await
            .unwrap_or_default();
        findings.extend(checks::nftables(&v));
    }
    report(&findings)?;

    let _lock = if opts.dry_run {
        None
    } else {
        Some(InstanceLock::acquire(&opts.lock).with_context(|| format!("instance lock {}", opts.lock.display()))?)
    };
    let state_dir = if opts.dry_run {
        StateDir {
            path: cfg.state_dir.clone(),
        }
    } else {
        StateDir::open(&cfg.state_dir).context("state directory")?
    };
    if opts.reset_state && !opts.dry_run {
        state_dir.reset().context("--reset-state")?;
    }
    let (manifest, without_manifest) = match state_dir.manifest().context("manifest")? {
        Some(m) => {
            let conflicts = m.check(&cfg);
            if !conflicts.is_empty() {
                bail!(
                    "{}",
                    conflicts.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
                );
            }
            (m, false)
        }
        None => (Manifest::new(&cfg), true),
    };

    // Subscribe before the first dump; notifications received meanwhile
    // stay queued and are applied after it (§12.2).
    let subscription = Subscription::new(&groups::ALL, RECEIVE_BUFFER).context("netlink subscription")?;
    let client = Client::new().context("netlink socket")?;
    let dumper = Client::new().context("netlink socket")?;
    let layout = Layout::of(&cfg);
    let scope = Scope {
        ftr_tables: layout.tables(),
        discovery_tables: cfg.routing.discovery_tables.clone(),
    };
    let observer::View { system, interrupted } = observer::full(&dumper, &scope)
        .await
        .map_err(|e| anyhow::anyhow!("initial dump: {e}"))?;

    let families: Vec<Family> = Family::ALL.into_iter().filter(|f| cfg.manages(*f)).collect();
    let mut findings = checks::routing(&system, layout, cfg.routing.route_protocol, &families);
    if without_manifest {
        findings.extend(checks::adoptable(&system, layout, cfg.routing.route_protocol));
    }
    findings.extend(checks::downlinks(&system, &cfg));
    findings.extend(checks::accept_ra(&cfg, sysctl::read));
    if checks::networkd_running() {
        findings.extend(checks::networkd(Path::new("/")));
    }
    match nftctl::ruleset(&cfg.firewall.nft_path).await {
        Ok(r) => findings.extend(checks::ruleset(&r, &cfg)),
        Err(e) => findings
            .warnings
            .push(format!("cannot inspect the nftables ruleset: {e}")),
    }
    report(&findings)?;

    let (probe_tx, probe_rx) = mpsc::channel(256);
    let mut d = Daemon {
        protocol: cfg.routing.route_protocol,
        layout,
        scope,
        client,
        dumper,
        system,
        resync_due: interrupted,
        state_dir,
        manifest,
        paths: BTreeMap::new(),
        active: BTreeMap::new(),
        drained: BTreeSet::new(),
        route_failed: BTreeMap::new(),
        nft_applied: None,
        nft_listing: None,
        nft_missing: false,
        nft_adopted: None,
        retry: None,
        degraded: BTreeSet::new(),
        ownership: BTreeMap::new(),
        held_rules: Vec::new(),
        held_routes: BTreeSet::new(),
        full_pass: false,
        sysctls_pending: BTreeSet::new(),
        sysctls_failed: BTreeMap::new(),
        sysctl_retries: BTreeMap::new(),
        probe_generation: 0,
        probe_tx,
        boot_id: state::boot_id().unwrap_or_default(),
        dirty: true,
        reread: BTreeSet::new(),
        expiry_checked: std::time::Instant::now(),
        last_checkpoint: Instant::now(),
        cfg,
    };
    if opts.dry_run {
        return d.dry_run();
    }
    d.manifest.bind(&d.cfg);
    d.state_dir
        .write_manifest(&d.manifest)
        .context("writing the manifest")?;
    // Applied by the first pass, with the failure handling of any other
    // (FR-REC-3, FR-REC-5).
    d.sysctls_pending.extend(d.sysctl_scopes());
    d.load_drain_and_checkpoint();
    if d.cfg.firewall.mode == FirewallMode::Managed
        && let Ok(Some(listing)) = nftctl::table(&d.cfg.firewall.nft_path).await
    {
        // The paths whose assignments the table has.
        let mask = d.cfg.routing.fwmark_mask;
        d.nft_adopted = Some(
            d.configured_paths()
                .into_iter()
                .filter(|k| {
                    let u = d.cfg.uplink(k.uplink).expect("configured");
                    nftctl::assigns(
                        &listing,
                        k.family.key(),
                        &u.interface,
                        mask.encode(FieldValue::path(u.id)),
                    )
                })
                .collect(),
        );
    }
    d.check_nft().await;
    info!(
        uplinks = d.cfg.uplinks.len(),
        mode = ?d.cfg.firewall.mode,
        "fault-tolerant-router {} started",
        env!("CARGO_PKG_VERSION")
    );
    if d.cfg.firewall.mode == FirewallMode::External {
        info!("external firewall mode: marking and NAT are the administrator's responsibility (export-nft)");
    }
    d.event_loop(subscription, probe_rx, &opts).await
}

/// The system checks of `check-config` without `--offline` (§9).
pub async fn check_system(path: &Path, cfg: &Config) -> Result<checks::Findings> {
    // FR-CFG-5: nothing configured runs before its ownership is verified.
    let mut f = checks::trusted(path, cfg);
    if !f.errors.is_empty() {
        return Ok(f);
    }
    f.extend(checks::kernel(
        &std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default(),
    ));
    if cfg.firewall.mode == FirewallMode::Managed {
        let v = nftctl::run(&cfg.firewall.nft_path, &["--version"], None)
            .await
            .unwrap_or_default();
        f.extend(checks::nftables(&v));
    }
    let layout = Layout::of(cfg);
    let scope = Scope {
        ftr_tables: layout.tables(),
        discovery_tables: cfg.routing.discovery_tables.clone(),
    };
    let client = Client::new().context("netlink socket")?;
    let system = observer::full(&client, &scope)
        .await
        .map_err(|e| anyhow::anyhow!("dump: {e}"))?
        .system;
    let families: Vec<Family> = Family::ALL.into_iter().filter(|x| cfg.manages(*x)).collect();
    f.extend(checks::routing(&system, layout, cfg.routing.route_protocol, &families));
    f.extend(checks::downlinks(&system, cfg));
    f.extend(checks::accept_ra(cfg, sysctl::read));
    if checks::networkd_running() {
        f.extend(checks::networkd(Path::new("/")));
    }
    match nftctl::ruleset(&cfg.firewall.nft_path).await {
        Ok(r) => f.extend(checks::ruleset(&r, cfg)),
        Err(e) => f.warnings.push(format!("cannot inspect the nftables ruleset: {e}")),
    }
    for d in sysctl::differences(&sysctl::desired(cfg), sysctl::read)? {
        let what = if cfg.routing.manage_sysctls {
            "will be set to"
        } else {
            "should be"
        };
        f.warnings.push(format!(
            "{} is {} and {what} {}",
            d.setting.display(),
            d.current,
            d.setting.value
        ));
    }
    Ok(f)
}

fn report(f: &checks::Findings) -> Result<()> {
    for w in &f.warnings {
        warn!("{w}");
    }
    if !f.errors.is_empty() {
        bail!("{}", f.errors.join("\n"));
    }
    Ok(())
}

impl Daemon {
    fn hysteresis(&self, id: UplinkId) -> Hysteresis {
        let h = &self
            .cfg
            .uplink(id)
            .expect("paths exist only for configured uplinks")
            .health;
        Hysteresis {
            fall: h.fall,
            rise: h.rise,
        }
    }

    /// Drops the paths that `keep` rejects and stops their probers.
    fn prune_paths(&mut self, keep: impl Fn(&PathKey) -> bool) {
        self.paths.retain(|k, p| {
            let kept = keep(k);
            if !kept && let Some((_, h)) = p.prober.take() {
                h.abort();
            }
            kept
        });
    }

    fn load_drain_and_checkpoint(&mut self) {
        match self.state_dir.drain() {
            Ok(d) => {
                self.drained = self
                    .cfg
                    .uplinks
                    .iter()
                    .filter(|u| d.drained.contains(&u.name))
                    .map(|u| u.id)
                    .collect();
            }
            Err(e) => warn!("drain state ignored: {e}"),
        }
        let structure: state::RecordedStructure = self.cfg.structural().into();
        let checkpoint = match self.state_dir.checkpoint() {
            Ok(Some(c)) if c.valid(&self.boot_id, now_ms(), &structure) => Some(c),
            Ok(_) => None,
            Err(e) => {
                warn!("health checkpoint ignored: {e}");
                None
            }
        };
        let discovered = discover::discover(&self.cfg, &self.system, self.protocol);
        for (key, d) in discovered {
            if d.group_only {
                self.warn_group_only(key);
            }
            let ready = d.ready.as_ref().ok();
            let warm = checkpoint.as_ref().and_then(|c| {
                let p = c
                    .paths
                    .iter()
                    .find(|p| p.uplink == key.uplink.get() && p.family == key.family.key())?;
                let same = p.ifindex == d.ifindex
                    && p.source == ready.map(|r| r.source)
                    && p.gateway == ready.and_then(|r| r.gateway);
                same.then_some(health::Snapshot {
                    state: if p.up { health::State::Up } else { health::State::Down },
                    passes: p.passes,
                    failures: p.failures,
                })
            });
            let reason = d.ready.as_ref().err().copied().unwrap_or(Reason::Startup);
            let machine = Machine::new(ready.is_some(), reason, warm);
            info!(uplink = key.uplink.get(), family = %key.family, state = ?machine.state(), warm = warm.is_some(), "initial path state");
            self.paths.insert(key, PathRuntime::new(Some(d), machine));
        }
        if let Some(c) = checkpoint {
            let ids = |v: &[u8]| v.iter().filter_map(|i| UplinkId::new(*i)).collect::<BTreeSet<_>>();
            self.active.insert(Family::V4, ids(&c.active_v4));
            self.active.insert(Family::V6, ids(&c.active_v6));
        }
    }

    /// FR-SYS: record baselines (write-ahead), then change; with
    /// `manage_sysctls = false`, only warn. `only` restricts to one interface.
    fn apply_sysctls(&mut self, scope: &SysctlScope) -> Result<()> {
        let wanted: Vec<_> = sysctl::desired(&self.cfg)
            .into_iter()
            .filter(|s| match scope {
                SysctlScope::Global => s.interface.is_none(),
                SysctlScope::Interface(i) => s.interface.as_ref() == Some(i),
            })
            .collect();
        let diffs = match sysctl::differences(&wanted, sysctl::read) {
            Ok(diffs) => diffs,
            // Only checked, never a prerequisite of readiness.
            Err(e) if !self.cfg.routing.manage_sysctls => {
                warn!("checking sysctls: {e} (manage_sysctls = false)");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        if diffs.is_empty() {
            return Ok(());
        }
        if !self.cfg.routing.manage_sysctls {
            for d in diffs {
                warn!(
                    "{} is {}, FTR needs {} (manage_sysctls = false)",
                    d.setting.display(),
                    d.current,
                    d.setting.value
                );
            }
            return Ok(());
        }
        sysctl::record(&mut self.manifest, &diffs);
        self.state_dir.write_manifest(&self.manifest)?;
        crate::test_hooks::step(format_args!("set sysctls ({scope})")).map_err(|e| anyhow::anyhow!(e))?;
        for d in diffs {
            sysctl::write(&d.setting.key, d.setting.value).with_context(|| d.setting.display())?;
            info!("set {} = {} (was {})", d.setting.display(), d.setting.value, d.current);
        }
        Ok(())
    }

    async fn check_nft(&mut self) {
        if self.cfg.firewall.mode == FirewallMode::External {
            match nftctl::table(&self.cfg.firewall.nft_path).await {
                Ok(Some(_)) => {
                    self.recover("external_ruleset_missing");
                }
                Ok(None) => {
                    if !self.degraded.contains("external_ruleset_missing") {
                        self.degrade("external_ruleset_missing");
                        warn!(
                            "external firewall mode: table inet {} is missing; load `export-nft` output",
                            nft::TABLE
                        );
                    }
                }
                Err(e) => warn!("nftables listing failed: {e}"),
            }
            return;
        }
        match nftctl::table(&self.cfg.firewall.nft_path).await {
            Ok(listing) => {
                let differs = listing.is_none() || (self.nft_listing.is_some() && listing != self.nft_listing);
                if differs && self.nft_applied.is_some() {
                    warn!("the nftables table is missing or was changed by a third party; it will be replaced");
                    self.count_removal("nftables");
                }
                self.nft_missing = differs || self.nft_listing.is_none();
            }
            Err(e) => warn!("nftables listing failed: {e}"),
        }
    }

    /// Adds a degradation reason; `status_degraded` on the overall
    /// transition (FR-EV-1, FR-API-2).
    fn degrade(&mut self, reason: &'static str) {
        let was_ok = self.degraded.is_empty();
        if self.degraded.insert(reason) && was_ok {
            warn!(reason, "status_degraded");
        }
    }

    /// Clears a degradation reason; `status_recovered` only when no other
    /// reason remains.
    fn recover(&mut self, reason: &'static str) {
        if self.degraded.remove(reason) && self.degraded.is_empty() {
            info!(reason, "status_recovered");
        }
    }

    /// FR-CT-2 runtime inspection against the running configuration.
    async fn inspect_flowtables(&mut self) {
        let listing = nftctl::flowtables(&self.cfg.firewall.nft_path).await;
        self.record_flowtables(&listing);
    }

    /// The `flow_offload` reason from a flowtable listing, against the
    /// running configuration.
    fn record_flowtables(&mut self, listing: &std::result::Result<serde_json::Value, String>) {
        match listing {
            Ok(r) => {
                let found = checks::flowtables(r, &self.cfg);
                if found.is_empty() {
                    self.recover("flow_offload");
                } else {
                    for e in &found {
                        error!("{e}");
                    }
                    self.degrade("flow_offload");
                }
            }
            // A failed inspection is reported and never clears the reason.
            Err(e) => error!("flowtable inspection failed: {e}"),
        }
    }

    fn count_removal(&mut self, kind: &'static str) {
        let o = self.ownership.entry(kind).or_default();
        let now = Instant::now();
        o.removals.push_back(now);
        while o
            .removals
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(300))
        {
            o.removals.pop_front();
        }
        o.clean_reconciliations = 0;
        if o.removals.len() > 3 && !o.conflict {
            o.conflict = true;
            self.degrade("ownership_conflict");
            warn!(
                kind,
                "artifacts removed by a third party more than 3 times in 5 minutes: immediate repairs stop (FR-COEX-4)"
            );
        }
    }

    fn immediate_repairs(&self, kind: &str) -> bool {
        !self.ownership.get(kind).is_some_and(|o| o.conflict)
    }

    /// FR-DISC-3: a path whose only candidate routes use nexthop groups.
    fn warn_group_only(&self, key: PathKey) {
        let u = self.cfg.uplink(key.uplink).expect("configured");
        warn!(
            uplink = %u.name,
            family = %key.family,
            "the only default routes on {} use a nexthop group, which FTR does not use: the path is not ready; configure a static gateway (FR-DISC-3)",
            u.interface
        );
    }

    /// Notification handling (§12.2, FR-COEX-3).
    fn notification(&mut self, message: Message, port: u32, flags: u16) {
        let message = match message {
            Message::Route(m) => m,
            other => {
                self.nexthop_notification(&other);
                return;
            }
        };
        let removed_rule = match &message {
            RouteNetlinkMessage::DelRule(r) => crate::netlink::msg::ObservedRule::parse(r)
                .filter(|o| o.protocol == self.protocol && self.layout.priorities().contains(&o.priority)),
            _ => None,
        };
        let mut removed_route = None;
        let change = match &message {
            RouteNetlinkMessage::NewRoute(r) | RouteNetlinkMessage::DelRoute(r) => {
                let deleted = matches!(message, RouteNetlinkMessage::DelRoute(_));
                match crate::netlink::msg::ObservedRoute::parse(r) {
                    Some(r) => {
                        // Against the view before the notification is
                        // applied: which entries a replacement may have
                        // dropped, whether a deletion matches an entry.
                        if let Some(table) = self.system.stale_after(&self.scope, &r, deleted, flags) {
                            self.reread.insert(table);
                        }
                        if deleted && r.protocol == self.protocol && self.layout.tables().contains(&r.table) {
                            removed_route = Some((r.family, r.table));
                        }
                        self.system.apply_route(&self.scope, r, deleted)
                    }
                    None => Change::None,
                }
            }
            _ => self.system.apply(&self.scope, &message),
        };
        let third_party = port != 0 && port != self.client.port();
        if third_party && let Some(r) = removed_rule {
            warn!(
                kind = "rules",
                port,
                priority = r.priority,
                "FTR artifact removed by a third party"
            );
            self.count_removal("rules");
            if !self.immediate_repairs("rules") {
                self.held_rules.push(r);
            }
        }
        if third_party && let Some(key) = removed_route {
            warn!(
                kind = "routes",
                port,
                table = key.1,
                "FTR artifact removed by a third party"
            );
            self.count_removal("routes");
            if !self.immediate_repairs("routes") {
                self.held_routes.insert(key);
            }
        }
        match change {
            Change::Link(i) | Change::Address(i) => {
                if let Some(u) = self.uplink_on(i) {
                    for f in Family::ALL {
                        self.reread.insert((f, self.layout.balancing_table()));
                        self.reread.insert((f, self.layout.path_table(u)));
                        for t in &self.cfg.routing.discovery_tables {
                            self.reread.insert((f, *t));
                        }
                    }
                    if matches!(change, Change::Link(_))
                        && let Some(up) = self.cfg.uplink(u)
                    {
                        // A new incarnation of the interface gets its
                        // settings at once, not after the old one's backoff.
                        self.sysctls_pending
                            .insert(SysctlScope::Interface(up.interface.clone()));
                        self.sysctl_retries.remove(&up.interface);
                    }
                }
                self.dirty = true;
            }
            Change::RouterAdvertisement(i) => self.router_advertisement(i),
            Change::Route { .. } | Change::Rule { .. } | Change::Nexthop { .. } => self.dirty = true,
            Change::None => {}
        }
    }

    /// A Router Advertisement arrived on an interface (seen by the
    /// listener of `ra.rs`, or announced by `RTM_NEWPREFIX` when it carries
    /// prefix information). FR-DISC-5: it may have refreshed or shortened
    /// the lifetime of the default routes it installed on the interface
    /// without a route notification; their creation and their deletion by a
    /// zero lifetime are notified. A route of the kernel's Router
    /// Advertisement protocol counts even without a known expiry: a read
    /// within a clock tick of the expiry shows none.
    fn router_advertisement(&mut self, i: u32) {
        if self.uplink_on(i).is_none() {
            return;
        }
        let ra = u8::from(netlink_packet_route::route::RouteProtocol::Ra);
        let tables: BTreeSet<(Family, u32)> = self
            .discovery_defaults()
            .filter(|r| {
                r.family == Family::V6
                    && (r.expires_at.is_some() || r.protocol == ra)
                    && r.nexthops.iter().any(|h| h.ifindex == i)
            })
            .map(|r| (r.family, r.table))
            .collect();
        if !tables.is_empty() {
            debug!(
                ifindex = i,
                ?tables,
                "router advertisement: re-reading the tables of its routes"
            );
            self.reread.extend(tables);
            self.dirty = true;
        }
    }

    /// A nexthop object notification. Only the routes that use the object,
    /// directly or through a group, depend on it: an object that no route
    /// of the view uses cannot change discovery (a route that comes to use
    /// it arrives as its own notification), and replacing the gateway of
    /// one that routes use notifies them (FR-DISC-3).
    fn nexthop_notification(&mut self, m: &Message) {
        let (id, deleted) = match m {
            Message::NewNexthop(n) => (n.id, false),
            Message::DelNexthop(n) => (n.id, true),
            Message::Route(_) | Message::GetNexthops => return,
        };
        // Before applying: a deletion drops the object, and with it the
        // group membership by which its users are found.
        let users = self.system.nexthop_users(id);
        self.system.apply_message(&self.scope, m);
        if users.is_empty() {
            return;
        }
        if deleted {
            // Deleting an object deletes the IPv4 routes that use it
            // without a notification, and with nexthop_compat_mode = 0
            // possibly the IPv6 ones too (FR-COEX-3): their tables are
            // re-read.
            self.reread.extend(users);
        }
        self.dirty = true;
    }

    /// The default routes of the discovery tables, which make paths ready.
    fn discovery_defaults(&self) -> impl Iterator<Item = &crate::netlink::msg::ObservedRoute> {
        self.system.routes.values().filter(|r| {
            r.is_default() && r.protocol != self.protocol && self.cfg.routing.discovery_tables.contains(&r.table)
        })
    }

    /// The next expiry of a discovery-table default route (Router
    /// Advertisements) not handled yet, possibly already past: the kernel
    /// collects an expired route without a notification.
    fn next_expiry(&self) -> Option<Instant> {
        // Just after the expiry: the re-read then shows it past.
        self.discovery_defaults()
            .filter_map(|r| r.expires_at)
            .filter(|t| *t > self.expiry_checked)
            .min()
            .map(|t| Instant::from_std(t) + Duration::from_millis(50))
    }

    /// Re-reads the tables of routes whose known expiry has passed since
    /// the last check, before the next evaluation, which would otherwise
    /// count them as gone: an advertisement may have refreshed them without
    /// a notification (FR-DISC-5). Every pass does it, not only the
    /// expiry's own wake-up 50 ms later, since another event can come
    /// first. The re-read lists a route that has expired but is not
    /// collected yet with an expiry in the past, which counts as handled.
    fn reread_expired(&mut self) {
        let now = std::time::Instant::now();
        let tables: BTreeSet<(Family, u32)> = self
            .discovery_defaults()
            .filter(|r| r.expires_at.is_some_and(|t| t > self.expiry_checked) && r.expired(now))
            .map(|r| (r.family, r.table))
            .collect();
        if !tables.is_empty() {
            debug!(?tables, "re-reading the tables of expired routes");
            self.reread.extend(tables);
        }
        self.expiry_checked = now;
    }

    /// The uplink on an interface, also after the interface is gone.
    fn uplink_on(&self, ifindex: u32) -> Option<UplinkId> {
        let name = self.system.links.get(&ifindex).map(|l| l.name.as_str());
        self.cfg
            .uplinks
            .iter()
            .find(|u| {
                name == Some(u.interface.as_str())
                    || self.paths.iter().any(|(k, p)| {
                        k.uplink == u.id && p.discovered.as_ref().and_then(|d| d.ifindex) == Some(ifindex)
                    })
            })
            .map(|u| u.id)
    }

    fn probe_report(&mut self, r: probe::Report) {
        match r {
            probe::Report::Failed(e) => {
                warn!(uplink = e.path.uplink.get(), family = %e.path.family, "prober failed: {}", e.error);
                if let Some(p) = self.paths.get_mut(&e.path)
                    && p.generation == e.generation
                {
                    p.prober = None;
                    self.dirty = true;
                }
            }
            probe::Report::Round(r) => {
                // Rounds already queued when their prober was replaced, or
                // when a reload removed the uplink and its paths.
                if self.paths.get(&r.path).is_none_or(|p| p.generation != r.generation) {
                    debug!("discarding a round of an older generation (FR-PROBE-3)");
                    return;
                }
                let h = self.hysteresis(r.path.uplink);
                let p = self.paths.get_mut(&r.path).expect("checked above");
                let round = if r.passed { Round::Passed } else { Round::Failed };
                debug!(uplink = r.path.uplink.get(), family = %r.path.family, passed = r.passed, reachable = r.reachable, "probe round");
                if let Some(t) = p.machine.round(round, h) {
                    p.since_ms = now_ms();
                    info!(uplink = r.path.uplink.get(), family = %r.path.family, from = ?t.from, to = ?t.to, reason = %t.reason, "path state changed");
                    self.dirty = true;
                    self.write_checkpoint();
                }
            }
        }
    }

    fn write_checkpoint(&mut self) {
        let c = Checkpoint {
            version: 1,
            boot_id: self.boot_id.clone(),
            boottime_ms: now_ms(),
            config_digest: self.cfg.digest.clone(),
            structure: self.cfg.structural().into(),
            paths: self
                .paths
                .iter()
                .map(|(k, p)| {
                    let ready = p.discovered.as_ref().and_then(|d| d.ready.as_ref().ok());
                    let snap = p.machine.snapshot();
                    PathCheckpoint {
                        uplink: k.uplink.get(),
                        family: k.family.key().into(),
                        ifindex: p.discovered.as_ref().and_then(|d| d.ifindex),
                        source: ready.map(|r| r.source),
                        gateway: ready.and_then(|r| r.gateway),
                        up: p.machine.is_up(),
                        since_ms: p.since_ms,
                        passes: snap.passes,
                        failures: snap.failures,
                    }
                })
                .collect(),
            active_v4: self
                .active
                .get(&Family::V4)
                .map(|s| s.iter().map(|i| i.get()).collect())
                .unwrap_or_default(),
            active_v6: self
                .active
                .get(&Family::V6)
                .map(|s| s.iter().map(|i| i.get()).collect())
                .unwrap_or_default(),
        };
        if let Err(e) = self.state_dir.write_checkpoint(&c) {
            warn!("health checkpoint: {e}");
        }
        self.last_checkpoint = Instant::now();
    }

    /// Discovery, readiness, probers and active sets; returns the planner
    /// input.
    fn evaluate(&mut self) -> Input {
        let discovered = discover::discover(&self.cfg, &self.system, self.protocol);
        let mut input = Input::default();
        for (key, raw) in discovered {
            let previous = self.paths.get(&key).and_then(|p| p.discovered.as_ref());
            let unchanged = previous == Some(&raw);
            if raw.group_only && !previous.is_some_and(|d| d.group_only) {
                self.warn_group_only(key);
            }
            if !unchanged {
                // FR-DISC-7: installation is retried at each discovery change.
                self.route_failed.remove(&key);
            }
            let mut d = raw.clone();
            if let Some(e) = self.route_failed.get(&key)
                && d.ready.is_ok()
            {
                debug!("path {key:?} not ready: route installation failed ({e})");
                d.ready = Err(Reason::RouteInstallFailed);
            }
            // The interface's settings are part of the path's installation:
            // a path is not ready while they are pending, failed or not.
            if let Some(u) = self.cfg.uplink(key.uplink)
                && self
                    .sysctls_pending
                    .contains(&SysctlScope::Interface(u.interface.clone()))
                && d.ready.is_ok()
            {
                debug!(
                    "path {key:?} not ready: sysctls of {} pending ({})",
                    u.interface,
                    self.sysctls_failed
                        .get(&u.interface)
                        .map_or("not applied yet", String::as_str)
                );
                d.ready = Err(Reason::RouteInstallFailed);
            }
            let p = self
                .paths
                .entry(key)
                .or_insert_with(|| PathRuntime::new(None, Machine::new(false, Reason::Startup, None)));
            if key.family == Family::V6 && raw.gateway_missing {
                let (since, warned) = p.gateway_wait.get_or_insert((Instant::now(), false));
                let delay = gateway_warning();
                if !*warned && since.elapsed() >= delay {
                    *warned = true;
                    let u = self.cfg.uplink(key.uplink).expect("configured");
                    let delay = if delay.subsec_millis() == 0 {
                        format!("{} s", delay.as_secs())
                    } else {
                        format!("{} ms", delay.as_millis())
                    };
                    warn!(
                        uplink = %u.name,
                        "no IPv6 default route discovered on {} {delay} after startup or after its link came up: {}; a static gateway avoids depending on Router Advertisements (FR-SYS-3)",
                        u.interface,
                        checks::gateway_causes(&u.interface, sysctl::read)
                    );
                }
            } else {
                p.gateway_wait = None;
            }
            if !unchanged {
                info!(uplink = key.uplink.get(), family = %key.family, ready = ?raw.ready.as_ref().map(|r| (r.source, r.gateway, r.ifindex)), "path discovery changed");
            }
            let reason = d.ready.as_ref().err().copied().unwrap_or(Reason::Startup);
            if let Some(t) = p.machine.set_ready(d.ready.is_ok(), reason) {
                p.since_ms = now_ms();
                info!(uplink = key.uplink.get(), family = %key.family, from = ?t.from, to = ?t.to, reason = %t.reason, "path state changed");
            }
            p.discovered = Some(raw);
            input.paths.insert(
                key,
                PathInput {
                    ready: d.ready.as_ref().ok().copied(),
                    local_addresses: d.local_addresses.clone(),
                    healthy: p.machine.is_up(),
                    drained: self.drained.contains(&key.uplink),
                },
            );
        }
        self.prune_paths(|k| input.paths.contains_key(k));
        self.manage_probers();
        for family in Family::ALL {
            if !self.cfg.manages(family) {
                continue;
            }
            let candidates: Vec<Candidate> = self
                .cfg
                .uplinks
                .iter()
                .filter_map(|u| {
                    let key = PathKey { uplink: u.id, family };
                    let p = input.paths.get(&key)?;
                    let priority = u.priority?;
                    (p.ready.is_some() && !p.drained).then_some(Candidate {
                        uplink: u.id,
                        priority,
                        healthy: p.healthy,
                    })
                })
                .collect();
            let previous = self.active.get(&family).cloned().unwrap_or_default();
            let set = select::active_set(&candidates, self.cfg.routing.all_down_policy, &previous);
            if set != previous {
                info!(family = %family, old = ?previous, new = ?set, "active set changed");
                self.active.insert(family, set.clone());
                self.write_checkpoint();
            }
            input.active.insert(family, set);
        }
        input
    }

    /// Starts, restarts or stops probers: a prober runs while its path is
    /// ready, installation included (FR-DISC-7); any change of interface,
    /// source or settings is a new generation (FR-PROBE-1, FR-PROBE-3).
    fn manage_probers(&mut self) {
        let mask = self.cfg.routing.fwmark_mask;
        for (key, p) in self.paths.iter_mut() {
            let u = self.cfg.uplink(key.uplink).expect("configured");
            let ready = p
                .discovered
                .as_ref()
                .and_then(|d| d.ready.as_ref().ok())
                .filter(|_| p.machine.is_ready())
                .copied();
            let wanted = ready.map(|r| probe::Spec {
                path: *key,
                generation: 0,
                interface: u.interface.clone(),
                ifindex: r.ifindex,
                source: r.source,
                mark: mask.encode(FieldValue::probe(key.uplink)),
                targets: u.health.targets(key.family).to_vec(),
                interval: u.health.interval,
                timeout: u.health.timeout,
                attempts: u.health.attempts,
                required_reachable: u.health.required_reachable,
                run_to_completion: u.health.quality.enabled(),
            });
            let current = p.prober.as_ref().map(|(s, _)| probe::Spec {
                generation: 0,
                ..s.clone()
            });
            if wanted == current {
                continue;
            }
            if let Some((_, h)) = p.prober.take() {
                h.abort();
            }
            self.probe_generation += 1;
            p.generation = self.probe_generation;
            if let Some(mut spec) = wanted {
                spec.generation = p.generation;
                let handle = probe::spawn(spec.clone(), self.probe_tx.clone());
                p.prober = Some((spec, handle));
            }
        }
    }

    /// Every configured path.
    fn configured_paths(&self) -> BTreeSet<PathKey> {
        self.cfg
            .uplinks
            .iter()
            .flat_map(|u| u.families().map(|family| PathKey { uplink: u.id, family }))
            .collect()
    }

    /// Every scope of the desired settings: the global ones, then each
    /// interface's.
    fn sysctl_scopes(&self) -> Vec<SysctlScope> {
        let interfaces: BTreeSet<String> = sysctl::desired(&self.cfg)
            .into_iter()
            .filter_map(|s| s.interface)
            .collect();
        std::iter::once(SysctlScope::Global)
            .chain(interfaces.into_iter().map(SysctlScope::Interface))
            .collect()
    }

    /// Applies the pending sysctls before the routes and rules that rely on
    /// them (FR-REC-3). A failure of the global settings fails the pass:
    /// everything depends on them. A failure of an interface's settings
    /// keeps them pending, retried with that interface's own backoff, and
    /// the rest of the pass goes on (FR-REC-5); `evaluate` keeps the
    /// uplinks of interfaces with pending settings not ready.
    fn apply_pending_sysctls(&mut self, global: bool) -> std::result::Result<(), Failure> {
        let pending: Vec<SysctlScope> = self.sysctls_pending.iter().cloned().collect();
        for scope in pending {
            let SysctlScope::Interface(i) = &scope else { continue };
            if self.sysctl_retries.get(i).is_some_and(|r| Instant::now() < r.at) {
                continue;
            }
            match self.apply_sysctls(&scope) {
                Ok(()) => {
                    self.sysctls_pending.remove(&scope);
                    self.sysctl_retries.remove(i);
                    self.sysctls_failed.remove(i);
                }
                Err(e) => {
                    error!(interface = %i, "apply_failed: set sysctls: {e:#}");
                    self.sysctls_failed.insert(i.clone(), format!("{e:#}"));
                    self.degrade("apply_failed");
                    let backoff = self
                        .sysctl_retries
                        .get(i)
                        .map_or(Duration::from_secs(1), |r| (r.backoff * 2).min(Duration::from_secs(60)));
                    self.sysctl_retries.insert(
                        i.clone(),
                        Retry {
                            at: Instant::now() + backoff,
                            backoff,
                            attempt: SYSCTL_ATTEMPT.to_owned(),
                        },
                    );
                }
            }
        }
        // Interfaces first: a failure of the global settings does not keep
        // them from their own.
        if global && self.sysctls_pending.contains(&SysctlScope::Global) {
            self.apply_sysctls(&SysctlScope::Global).map_err(|e| Failure {
                op: "set sysctls".into(),
                error: format!("{e:#}"),
                route: None,
            })?;
            self.sysctls_pending.remove(&SysctlScope::Global);
        }
        Ok(())
    }

    /// One reconciliation pass.
    async fn step(&mut self) {
        // A failed attempt waits for its backoff; evaluation does not.
        let waiting = self
            .retry
            .as_ref()
            .filter(|r| Instant::now() < r.at)
            .map(|r| r.attempt.clone());
        // FR-REC-3: sysctls before the routes and rules that rely on them.
        if !self.sysctls_pending.is_empty() {
            let global = waiting.as_deref() != Some(SYSCTL_ATTEMPT);
            if let Err(f) = self.apply_pending_sysctls(global) {
                self.failed(f, SYSCTL_ATTEMPT.to_owned());
            }
            // Everything depends on the global settings.
            if self.sysctls_pending.contains(&SysctlScope::Global) {
                self.evaluate();
                return;
            }
        }
        self.reread_expired();
        if !self.reread.is_empty() {
            let tables: Vec<_> = std::mem::take(&mut self.reread).into_iter().collect();
            if let Err(e) = observer::reread(&self.dumper, &self.scope, &mut self.system, &tables).await {
                warn!("re-reading tables: {e}");
            }
        }
        let input = self.evaluate();
        let managed = self.cfg.firewall.mode == FirewallMode::Managed;
        let transaction = nft::transaction(&self.cfg);
        let configured = self.configured_paths();
        let nft_pending =
            managed && (self.nft_missing || self.nft_applied.as_ref().map(|(t, _)| t) != Some(&transaction));
        // Paths without assignments yet, also a family added to an existing
        // uplink, join the balancing and policy routes after them (FR-REC-3).
        let new_paths: BTreeSet<PathKey> = match (&self.nft_applied, &self.nft_adopted, managed) {
            (Some((_, applied)), _, true) => configured.difference(applied).copied().collect(),
            (None, Some(adopted), true) => configured.difference(adopted).copied().collect(),
            _ => BTreeSet::new(),
        };
        let desired = plan::plan(&self.cfg, &input);
        let before = (!new_paths.is_empty()).then(|| plan::plan(&self.cfg, &plan::without(&input, &new_paths)));
        let families: Vec<Family> = Family::ALL.into_iter().filter(|f| self.cfg.manages(*f)).collect();
        let ops = reconcile::diff(
            &self.system,
            &DiffInput {
                layout: self.layout,
                protocol: self.protocol,
                families: &families,
                before_nft: before.as_ref().unwrap_or(&desired),
                desired: &desired,
                nft_pending,
                teardown: false,
            },
        );
        // FR-COEX-4: while repairs of a kind are suspended, artifacts that a
        // third party removed come back only with a full reconciliation.
        let full = std::mem::take(&mut self.full_pass);
        if full {
            self.held_rules.clear();
            self.held_routes.clear();
        }
        let before = ops.len();
        let ops: Vec<Op> = ops
            .into_iter()
            .filter(|op| match op {
                Op::AddRule(r) => !self.held_rules.iter().any(|h| h.is(r, self.protocol)),
                Op::ReplaceRoute(r) => !self.held_routes.contains(&(r.family, r.table)),
                _ => true,
            })
            .collect();
        if ops.len() != before {
            debug!(
                held = before - ops.len(),
                "repairs held until the next full reconciliation (FR-COEX-4)"
            );
        }
        let attempt = format!("{ops:?}");
        if waiting.as_ref() == Some(&attempt) {
            self.full_pass |= full;
            return;
        }
        if ops.is_empty() {
            // Routing and nftables no longer hold a departed family's
            // artifacts: its settings go back last (FR-REC-9 step 4).
            if let Err(f) = self.hand_back_families() {
                self.failed(f, attempt);
                return;
            }
            self.applied();
            return;
        }
        for op in &ops {
            debug!("{op}");
        }
        let count = ops.len();
        let had_nft = ops.iter().any(|o| matches!(o, Op::ApplyNft));
        let nft_path = self.cfg.firewall.nft_path.clone();
        let result = reconcile::execute(&self.client, &mut self.system, &self.scope, self.protocol, ops, || {
            let path = nft_path.clone();
            let text = transaction.clone();
            async move { nftctl::apply(&path, &text).await }
        })
        .await;
        match result {
            Ok(_) => {
                if had_nft {
                    self.nft_applied = Some((transaction, configured));
                    self.nft_missing = false;
                    self.nft_listing = nftctl::table(&self.cfg.firewall.nft_path).await.ok().flatten();
                }
                info!(operations = count, "applied");
                self.applied();
                // Routes of uplinks whose assignments were just installed
                // and paths whose routes failed are reconsidered.
                self.dirty = true;
            }
            Err(f) => self.failed(f, attempt),
        }
    }

    fn hand_back_families(&mut self) -> std::result::Result<(), Failure> {
        let departed = sysctl::departed(&self.manifest, &self.cfg);
        if departed.is_empty() || !self.cfg.routing.manage_sysctls {
            return Ok(());
        }
        let mut failures = Vec::new();
        for family in departed {
            let h = sysctl::hand_back(&mut self.manifest, family, sysctl::read, sysctl::write);
            for k in &h.restored {
                info!("restored {} (family {family} handed back)", sysctl::dotted(k));
            }
            for k in &h.released {
                info!("{} left as it is: changed since FTR set it, or gone", sysctl::dotted(k));
            }
            for (k, e) in h.failed {
                failures.push(format!("{}: {e}", sysctl::dotted(k)));
            }
        }
        if let Err(e) = self.state_dir.write_manifest(&self.manifest) {
            failures.push(format!("manifest: {e}"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Failure {
                op: "restore sysctls of a handed-back family".into(),
                error: failures.join("; "),
                route: None,
            })
        }
    }

    fn applied(&mut self) {
        let retried = self.retry.take().is_some();
        if self.sysctls_failed.is_empty() && (retried || self.degraded.contains("apply_failed")) {
            info!("desired state fully applied");
            self.recover("apply_failed");
        }
    }

    /// FR-REC-5: report, count, retry with exponential backoff (1 s to 60 s).
    fn failed(&mut self, f: Failure, attempt: String) {
        error!(operation = %f.op, "apply_failed: {}", f.error);
        self.degrade("apply_failed");
        if let Some((family, table)) = f.route {
            // The view follows a route mutation only when it succeeds, but
            // a failed one may still have changed the table: it is re-read
            // before the next pass. FR-ROUTE-2's case: a failed IPv6
            // replacement can leave the table empty (the kernel removes the
            // members it inserted, and the old route is gone).
            self.reread.insert((family, table));
            if let Some(key) = self
                .paths
                .keys()
                .find(|k| k.family == family && self.layout.path_table(k.uplink) == table)
            {
                // FR-DISC-7: the path is not ready until discovery changes.
                self.route_failed.insert(*key, f.error.clone());
            }
        }
        // The backoff grows while the same attempt keeps failing.
        let backoff = match &self.retry {
            Some(r) if r.attempt == attempt => (r.backoff * 2).min(Duration::from_secs(60)),
            _ => Duration::from_secs(1),
        };
        self.retry = Some(Retry {
            at: Instant::now() + backoff,
            backoff,
            attempt,
        });
        self.dirty = true;
    }

    async fn full_reconciliation(&mut self) {
        match observer::resync(&self.dumper, &self.scope, &self.system).await {
            Ok(v) => {
                self.system = v.system;
                self.resync_due |= v.interrupted;
            }
            Err(e) => warn!("full reconciliation dump failed: {e}"),
        }
        self.check_nft().await;
        self.inspect_flowtables().await;
        for o in self.ownership.values_mut() {
            if o.conflict {
                o.clean_reconciliations += 1;
                if o.clean_reconciliations >= 2 {
                    o.conflict = false;
                    info!("ownership conflict cleared");
                }
            }
        }
        if self.ownership.values().all(|o| !o.conflict) {
            self.recover("ownership_conflict");
        }
        self.route_failed.clear();
        self.full_pass = true;
        self.dirty = true;
    }

    async fn reload(&mut self, path: &Path) {
        let new = match config::load(path) {
            Ok(c) => c,
            Err(e) => {
                error!("reload_failed: {e}");
                return;
            }
        };
        let unsupported = new.unsupported_features();
        if !unsupported.is_empty() {
            error!(
                "reload_failed: not supported by this development build: {}",
                unsupported.join(", ")
            );
            return;
        }
        if new.structural() != self.cfg.structural() {
            error!("reload_failed: structural settings cannot change on reload (FR-CFG-4)");
            return;
        }
        // The state directory holds the bindings and the sysctl baselines.
        if new.state_dir != self.cfg.state_dir {
            error!("reload_failed: state_dir cannot change on reload; stop, move the state directory, then start");
            return;
        }
        // FR-CFG-5: nothing configured runs before its ownership is verified.
        let trust = checks::trusted(path, &new);
        if !trust.errors.is_empty() {
            for e in trust.errors {
                error!("reload_failed: {e}");
            }
            return;
        }
        // FR-CT-2: inspect against the running configuration, and refuse a
        // proposed configuration that would match.
        let listing = nftctl::flowtables(&self.cfg.firewall.nft_path).await;
        self.record_flowtables(&listing);
        let proposed = if new.firewall.nft_path == self.cfg.firewall.nft_path {
            listing
        } else {
            nftctl::flowtables(&new.firewall.nft_path).await
        };
        match proposed {
            Ok(r) => {
                let found = checks::flowtables(&r, &new);
                if !found.is_empty() {
                    for e in found {
                        error!("reload_failed: {e}");
                    }
                    return;
                }
            }
            Err(e) => {
                error!("reload_failed: cannot inspect the flowtables: {e}");
                return;
            }
        }
        let conflicts = self.manifest.check(&new);
        if !conflicts.is_empty() {
            for c in conflicts {
                error!("reload_failed: {c}");
            }
            return;
        }
        let mut manifest = self.manifest.clone();
        manifest.bind(&new);
        if let Err(e) = self.state_dir.write_manifest(&manifest) {
            error!("reload_failed: {e}");
            return;
        }
        self.manifest = manifest;
        self.cfg = new;
        // Paths exist only for configured uplinks: those of removed uplinks
        // go at once, with their probers.
        let configured: BTreeSet<UplinkId> = self.cfg.uplinks.iter().map(|u| u.id).collect();
        self.prune_paths(|k| configured.contains(&k.uplink));
        self.scope.discovery_tables = self.cfg.routing.discovery_tables.clone();
        // The settings of removed uplinks' interfaces are no longer FTR's
        // to apply, nor their retries to keep: re-added, they start afresh.
        self.sysctls_pending = self.sysctl_scopes().into_iter().collect();
        let kept = |i: &String| self.sysctls_pending.contains(&SysctlScope::Interface(i.clone()));
        self.sysctl_retries.retain(|i, _| kept(i));
        self.sysctls_failed.retain(|i, _| kept(i));
        // Only checked from now on: nothing waits for the backoff of a
        // failed application.
        if !self.cfg.routing.manage_sysctls {
            self.sysctl_retries.clear();
            self.sysctls_failed.clear();
            if self.retry.as_ref().is_some_and(|r| r.attempt == SYSCTL_ATTEMPT) {
                self.retry = None;
            }
        }
        info!("config_reloaded");
        self.dirty = true;
    }

    async fn event_loop(
        &mut self,
        mut subscription: Subscription,
        mut probe_rx: mpsc::Receiver<probe::Report>,
        opts: &Options,
    ) -> Result<()> {
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        let mut hup = signal(SignalKind::hangup())?;
        let mut next_full = Instant::now() + self.cfg.routing.reconcile_interval;
        let (ra_tx, mut ra_rx) = mpsc::unbounded_channel();
        let listener = match crate::ra::spawn(ra_tx) {
            Ok(h) => Some(h),
            Err(e) => {
                // RTM_NEWPREFIX still covers advertisements with prefix
                // information.
                warn!(
                    "cannot listen to Router Advertisements: {e}; a lifetime shortened without prefix information is seen at its previous expiry"
                );
                None
            }
        };
        loop {
            if self.dirty {
                self.dirty = false;
                self.step().await;
            }
            if std::mem::take(&mut self.resync_due) {
                info!("a netlink dump was still interrupted after its retries: full resynchronisation");
                next_full = next_full.min(Instant::now() + RESYNC_AFTER_INTERRUPTED);
            }
            let wake = self
                .retry
                .iter()
                .chain(self.sysctl_retries.values())
                .map(|r| r.at)
                .chain(self.next_expiry())
                .chain(self.paths.values().filter_map(|p| match p.gateway_wait {
                    Some((since, false)) => Some(since + gateway_warning()),
                    _ => None,
                }))
                .fold(next_full, Instant::min);
            let checkpoint_due = self.last_checkpoint + Duration::from_secs(30);
            tokio::select! {
                n = subscription.next() => match n {
                    Some(Notification::Message { message, port, flags }) => self.notification(message, port, flags),
                    Some(Notification::Overrun) => {
                        warn!("netlink notifications were lost (ENOBUFS): full resynchronisation");
                        self.full_reconciliation().await;
                    }
                    None => bail!("the netlink subscription closed"),
                },
                r = probe_rx.recv() => if let Some(r) = r { self.probe_report(r) },
                Some(i) = ra_rx.recv() => self.router_advertisement(i),
                _ = sleep_until(wake) => {
                    if Instant::now() >= next_full {
                        next_full = Instant::now() + self.cfg.routing.reconcile_interval;
                        self.full_reconciliation().await;
                    } else {
                        // An expiry, a retry or a warning: the pass handles
                        // each (an expiry by reread_expired).
                        self.dirty = true;
                    }
                }
                _ = sleep_until(checkpoint_due) => self.write_checkpoint(),
                _ = hup.recv() => self.reload(&opts.config).await,
                _ = term.recv() => break,
                _ = int.recv() => break,
            }
        }
        info!("daemon_stopping");
        if let Some(h) = listener {
            h.abort();
        }
        for p in self.paths.values_mut() {
            if let Some((_, h)) = p.prober.take() {
                h.abort();
            }
        }
        self.write_checkpoint();
        if self.cfg.routing.on_shutdown == OnShutdown::Cleanup {
            crate::cleanup::run(&self.cfg, &self.state_dir).await?;
        }
        Ok(())
    }

    fn dry_run(&mut self) -> Result<()> {
        // Cold-start view: every ready path is up (FR-HEALTH-1).
        let discovered = discover::discover(&self.cfg, &self.system, self.protocol);
        for (key, d) in discovered {
            let ready = d.ready.is_ok();
            let reason = d.ready.as_ref().err().copied().unwrap_or(Reason::Startup);
            info!(uplink = key.uplink.get(), family = %key.family, ready, reason = %reason, "dry run: path");
            self.paths
                .insert(key, PathRuntime::new(Some(d), Machine::new(ready, reason, None)));
        }
        let mut input = Input::default();
        for (key, p) in &self.paths {
            let d = p.discovered.as_ref().expect("set above");
            input.paths.insert(
                *key,
                PathInput {
                    ready: d.ready.as_ref().ok().copied(),
                    local_addresses: d.local_addresses.clone(),
                    healthy: p.machine.is_up(),
                    drained: false,
                },
            );
        }
        for family in Family::ALL.into_iter().filter(|f| self.cfg.manages(*f)) {
            let candidates: Vec<Candidate> = self
                .cfg
                .uplinks
                .iter()
                .filter_map(|u| {
                    let p = input.paths.get(&PathKey { uplink: u.id, family })?;
                    (p.ready.is_some()).then_some(Candidate {
                        uplink: u.id,
                        priority: u.priority?,
                        healthy: p.healthy,
                    })
                })
                .collect();
            input.active.insert(
                family,
                select::active_set(&candidates, self.cfg.routing.all_down_policy, &BTreeSet::new()),
            );
        }
        let desired = plan::plan(&self.cfg, &input);
        let families: Vec<Family> = Family::ALL.into_iter().filter(|f| self.cfg.manages(*f)).collect();
        let ops = reconcile::diff(
            &self.system,
            &DiffInput {
                layout: self.layout,
                protocol: self.protocol,
                families: &families,
                before_nft: &desired,
                desired: &desired,
                nft_pending: self.cfg.firewall.mode == FirewallMode::Managed,
                teardown: false,
            },
        );
        for op in &ops {
            info!("dry run: would {op}");
        }
        for d in sysctl::differences(&sysctl::desired(&self.cfg), sysctl::read)? {
            info!(
                "dry run: would set {} = {} (now {})",
                d.setting.display(),
                d.setting.value,
                d.current
            );
        }
        info!(operations = ops.len(), "dry run complete; nothing was changed");
        Ok(())
    }
}
