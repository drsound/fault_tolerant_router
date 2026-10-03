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
use crate::netlink::{Client, Notification, Subscription, groups};
use crate::nft;
use crate::nftctl;
use crate::observer;
use crate::plan::{self, Desired, Input, Layout, PathInput};
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
}

/// Retry state after a failed application (FR-REC-5).
struct Retry {
    at: Instant,
    backoff: Duration,
}

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
    nft_applied: Option<(String, BTreeSet<UplinkId>)>,
    nft_listing: Option<serde_json::Value>,
    nft_missing: bool,
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
    sysctls_pending: BTreeSet<Option<String>>,
    /// The last prober generation: unique across paths, so that a round of
    /// a removed and re-added uplink's old prober is never taken as current.
    probe_generation: u64,
    probe_tx: mpsc::Sender<probe::Report>,
    boot_id: String,
    dirty: bool,
    reread: BTreeSet<(Family, u32)>,
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
    let mut findings = checks::kernel(&std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default());
    findings.extend(checks::ownership(&opts.config, "configuration"));
    if cfg.firewall.mode == FirewallMode::Managed {
        findings.extend(checks::ownership(&cfg.firewall.nft_path, "firewall.nft_path"));
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
    let manifest = match state_dir.manifest().context("manifest")? {
        Some(m) => {
            let conflicts = m.check(&cfg);
            if !conflicts.is_empty() {
                bail!(
                    "{}",
                    conflicts.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
                );
            }
            m
        }
        None => Manifest::new(&cfg),
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
    findings.extend(checks::downlinks(&system, &cfg));
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
        retry: None,
        degraded: BTreeSet::new(),
        ownership: BTreeMap::new(),
        held_rules: Vec::new(),
        held_routes: BTreeSet::new(),
        full_pass: false,
        sysctls_pending: BTreeSet::new(),
        probe_generation: 0,
        probe_tx,
        boot_id: state::boot_id().unwrap_or_default(),
        dirty: true,
        reread: BTreeSet::new(),
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
    d.apply_sysctls(None).context("sysctls")?;
    d.load_drain_and_checkpoint();
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
    let mut f = checks::kernel(&std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default());
    f.extend(checks::ownership(path, "configuration"));
    if cfg.firewall.mode == FirewallMode::Managed {
        f.extend(checks::ownership(&cfg.firewall.nft_path, "firewall.nft_path"));
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
        let discovered = discover::discover(&self.cfg, &self.system, &BTreeMap::new(), self.protocol);
        for (key, d) in discovered {
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
            self.paths.insert(
                key,
                PathRuntime {
                    discovered: Some(d),
                    machine,
                    since_ms: now_ms(),
                    generation: 0,
                    prober: None,
                },
            );
        }
        if let Some(c) = checkpoint {
            let ids = |v: &[u8]| v.iter().filter_map(|i| UplinkId::new(*i)).collect::<BTreeSet<_>>();
            self.active.insert(Family::V4, ids(&c.active_v4));
            self.active.insert(Family::V6, ids(&c.active_v6));
        }
    }

    /// FR-SYS: record baselines (write-ahead), then change; with
    /// `manage_sysctls = false`, only warn. `only` restricts to one interface.
    fn apply_sysctls(&mut self, only: Option<&str>) -> Result<()> {
        let wanted: Vec<_> = sysctl::desired(&self.cfg)
            .into_iter()
            .filter(|s| only.is_none() || s.interface.as_deref() == only)
            .collect();
        let diffs = sysctl::differences(&wanted, sysctl::read)?;
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
        crate::test_hooks::step("set sysctls").map_err(|e| anyhow::anyhow!(e))?;
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

    /// Notification handling (§12.2, FR-COEX-3).
    fn notification(&mut self, message: RouteNetlinkMessage, port: u32) {
        let removed_rule = match &message {
            RouteNetlinkMessage::DelRule(r) => crate::netlink::msg::ObservedRule::parse(r)
                .filter(|o| o.protocol == self.protocol && self.layout.priorities().contains(&o.priority)),
            _ => None,
        };
        let removed_route = match &message {
            RouteNetlinkMessage::DelRoute(r) => crate::netlink::msg::ObservedRoute::parse(r)
                .filter(|o| o.protocol == self.protocol && self.layout.tables().contains(&o.table))
                .map(|o| (o.family, o.table)),
            _ => None,
        };
        let change = self.system.apply(&self.scope, &message);
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
                        self.sysctls_pending.insert(Some(up.interface.clone()));
                    }
                }
                self.dirty = true;
            }
            Change::Route { .. } | Change::Rule { .. } => self.dirty = true,
            Change::None => {}
        }
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
        let discovered = discover::discover(&self.cfg, &self.system, &BTreeMap::new(), self.protocol);
        let mut input = Input::default();
        for (key, raw) in discovered {
            let unchanged = self.paths.get(&key).and_then(|p| p.discovered.as_ref()) == Some(&raw);
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
            let p = self.paths.entry(key).or_insert_with(|| PathRuntime {
                discovered: None,
                machine: Machine::new(false, Reason::Startup, None),
                since_ms: now_ms(),
                generation: 0,
                prober: None,
            });
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
    /// ready; any change of interface, source or settings is a new
    /// generation (FR-PROBE-1, FR-PROBE-3).
    fn manage_probers(&mut self) {
        let mask = self.cfg.routing.fwmark_mask;
        for (key, p) in self.paths.iter_mut() {
            let u = self.cfg.uplink(key.uplink).expect("configured");
            let ready = p.discovered.as_ref().and_then(|d| d.ready.as_ref().ok()).copied();
            let wanted = ready.map(|r| probe::Spec {
                path: *key,
                generation: 0,
                interface: u.interface.clone(),
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

    fn desired(&self, input: &Input, exclude: &BTreeSet<UplinkId>) -> Desired {
        if exclude.is_empty() {
            return plan::plan(&self.cfg, input);
        }
        let mut i = input.clone();
        for (k, p) in i.paths.iter_mut() {
            if exclude.contains(&k.uplink) {
                p.healthy = false;
            }
        }
        for set in i.active.values_mut() {
            set.retain(|u| !exclude.contains(u));
        }
        plan::plan(&self.cfg, &i)
    }

    /// Applies the pending sysctls, keeping those that failed.
    fn apply_pending_sysctls(&mut self) -> std::result::Result<(), Failure> {
        while let Some(only) = self.sysctls_pending.first().cloned() {
            self.apply_sysctls(only.as_deref()).map_err(|e| Failure {
                op: "set sysctls".into(),
                error: format!("{e:#}"),
                route: None,
            })?;
            if only.is_none() {
                // Every setting, every interface included.
                self.sysctls_pending.clear();
            } else {
                self.sysctls_pending.remove(&only);
            }
        }
        Ok(())
    }

    /// One reconciliation pass.
    async fn step(&mut self) {
        if let Some(r) = &self.retry
            && Instant::now() < r.at
        {
            return;
        }
        // FR-REC-3: sysctls before the routes and rules that rely on them.
        if let Err(f) = self.apply_pending_sysctls() {
            self.failed(f);
            return;
        }
        if !self.reread.is_empty() {
            let tables: Vec<_> = std::mem::take(&mut self.reread).into_iter().collect();
            if let Err(e) = observer::reread(&self.dumper, &self.scope, &mut self.system, &tables).await {
                warn!("re-reading tables: {e}");
            }
        }
        let input = self.evaluate();
        let managed = self.cfg.firewall.mode == FirewallMode::Managed;
        let transaction = nft::transaction(&self.cfg);
        let configured: BTreeSet<UplinkId> = self.cfg.uplinks.iter().map(|u| u.id).collect();
        let nft_pending =
            managed && (self.nft_missing || self.nft_applied.as_ref().map(|(t, _)| t) != Some(&transaction));
        let new_uplinks: BTreeSet<UplinkId> = match (&self.nft_applied, managed) {
            (Some((_, applied)), true) => configured.difference(applied).copied().collect(),
            _ => BTreeSet::new(),
        };
        let desired = self.desired(&input, &BTreeSet::new());
        let before = self.desired(&input, &new_uplinks);
        let families: Vec<Family> = Family::ALL.into_iter().filter(|f| self.cfg.manages(*f)).collect();
        let ops = reconcile::diff(
            &self.system,
            &DiffInput {
                layout: self.layout,
                protocol: self.protocol,
                families: &families,
                before_nft: &before,
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
        if ops.is_empty() {
            // Routing and nftables no longer hold a departed family's
            // artifacts: its settings go back last (FR-REC-9 step 4).
            if let Err(f) = self.hand_back_families() {
                self.failed(f);
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
            Err(f) => self.failed(f),
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
        if self.retry.take().is_some() || self.degraded.contains("apply_failed") {
            info!("desired state fully applied");
            self.recover("apply_failed");
        }
    }

    /// FR-REC-5: report, count, retry with exponential backoff (1 s to 60 s).
    fn failed(&mut self, f: Failure) {
        error!(operation = %f.op, "apply_failed: {}", f.error);
        self.degrade("apply_failed");
        if let Some((family, table)) = f.route
            && let Some(key) = self
                .paths
                .keys()
                .find(|k| k.family == family && self.layout.path_table(k.uplink) == table)
        {
            // FR-DISC-7: the path is not ready until discovery changes.
            self.route_failed.insert(*key, f.error.clone());
        }
        let backoff = self
            .retry
            .as_ref()
            .map_or(Duration::from_secs(1), |r| (r.backoff * 2).min(Duration::from_secs(60)));
        self.retry = Some(Retry {
            at: Instant::now() + backoff,
            backoff,
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
        self.sysctls_pending.insert(None);
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
        loop {
            if self.dirty {
                self.dirty = false;
                self.step().await;
            }
            if std::mem::take(&mut self.resync_due) {
                info!("a netlink dump was still interrupted after its retries: full resynchronisation");
                next_full = next_full.min(Instant::now() + RESYNC_AFTER_INTERRUPTED);
            }
            let wake = self.retry.as_ref().map(|r| r.at).unwrap_or(next_full).min(next_full);
            let checkpoint_due = self.last_checkpoint + Duration::from_secs(30);
            tokio::select! {
                n = subscription.next() => match n {
                    Some(Notification::Message { message, port }) => self.notification(message, port),
                    Some(Notification::Overrun) => {
                        warn!("netlink notifications were lost (ENOBUFS): full resynchronisation");
                        self.full_reconciliation().await;
                    }
                    None => bail!("the netlink subscription closed"),
                },
                r = probe_rx.recv() => if let Some(r) = r { self.probe_report(r) },
                _ = sleep_until(wake) => {
                    if Instant::now() >= next_full {
                        next_full = Instant::now() + self.cfg.routing.reconcile_interval;
                        self.full_reconciliation().await;
                    } else {
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
        let discovered = discover::discover(&self.cfg, &self.system, &BTreeMap::new(), self.protocol);
        for (key, d) in discovered {
            let ready = d.ready.is_ok();
            let reason = d.ready.as_ref().err().copied().unwrap_or(Reason::Startup);
            info!(uplink = key.uplink.get(), family = %key.family, ready, reason = %reason, "dry run: path");
            self.paths.insert(
                key,
                PathRuntime {
                    discovered: Some(d),
                    machine: Machine::new(ready, reason, None),
                    since_ms: 0,
                    generation: 0,
                    prober: None,
                },
            );
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
