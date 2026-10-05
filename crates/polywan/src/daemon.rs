//! The daemon (SPEC.md §12.2): one task owns all mutable state and reacts to
//! netlink notifications, probe reports, timers and signals by recomputing
//! the desired state and reconciling the kernel and nftables with it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper::StatusCode;
use netlink_packet_route::RouteNetlinkMessage;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, sleep_until};
use tracing::{debug, error, info, warn};

use crate::api::{Action, Answer, Order};
use crate::checks;
use crate::config::{self, Config, FirewallMode, OnShutdown};
use crate::discover::{self, Discovered};
use crate::events::{self, Bus, NewEvent};
use crate::health::{self, Hysteresis, Machine, Reason, Round};
use crate::model::{Family, FieldValue, PathKey, UplinkId};
use crate::netlink::{Client, Message, Notification, Subscription, groups};
use crate::nft;
use crate::nftctl;
use crate::observer;
use crate::plan::{self, Input, Layout, PathInput};
use crate::probe;
use crate::quality;
use crate::reconcile::{self, DiffInput, Failure, FailureKind, Op};
use crate::select::{self, Candidate};
use crate::state::{self, Checkpoint, InstanceLock, Manifest, PathCheckpoint, StateDir};
use crate::status::{self, Status};
use crate::sysctl;
use crate::system::{Change, Scope, System};
use crate::worker::{self, Done, Io, Lanes, Lost, NftJob, PersistJob, SysctlScope};

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
    /// Samples of the last rounds of the current probing generation, their
    /// statistics, and whether a quality gate is violated (FR-PROBE-5).
    window: quality::Window,
    stats: quality::Stats,
    violating: bool,
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
            window: quality::Window::default(),
            stats: quality::Stats::default(),
            violating: false,
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

/// Queued netlink notifications handled before the pass they lead to, a
/// bound that keeps the other events of the loop served.
const NOTIFICATION_BATCH: usize = 1000;

/// `first` and the items `queued` yields, at most `limit` in all, ending
/// with the first one that `ends` the batch; no item is taken beyond them.
fn batch<T>(first: T, mut queued: impl FnMut() -> Option<T>, limit: usize, ends: impl Fn(&T) -> bool) -> Vec<T> {
    let mut items = vec![first];
    while items.len() < limit
        && !items.last().is_some_and(&ends)
        && let Some(n) = queued()
    {
        items.push(n);
    }
    items
}

/// A path's mark assignment in the nftables table: the path and the
/// interface its rules match.
type Assignment = (PathKey, String);

/// FR-REC-3: the configured paths whose assignments the table does not
/// hold (`known`: the assignments last applied, or adopted at startup), a
/// family added to an uplink or an uplink moved to another interface
/// included. They join the balancing and policy routes only after the
/// replacement installs them; without a known table, none is held back.
fn unassigned(configured: &BTreeSet<Assignment>, known: Option<&BTreeSet<Assignment>>) -> BTreeSet<PathKey> {
    known.map_or_else(BTreeSet::new, |known| {
        configured.difference(known).map(|(k, _)| *k).collect()
    })
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

/// The attempt of a failed sysctl application.
const SYSCTL_ATTEMPT: &str = "sysctls";

/// FR-COEX-4 bookkeeping for one kind of artifact.
#[derive(Default)]
struct Ownership {
    removals: VecDeque<Instant>,
    conflict: bool,
    clean_reconciliations: u8,
}

/// The command of the control socket in progress (FR-API-3).
enum Active {
    /// The drain intent is being written (FR-SEL-3).
    Persisting {
        seq: u64,
        uplink: UplinkId,
        drain: bool,
        reply: oneshot::Sender<Answer>,
    },
    /// A reload requested through the API: answered when it ends, with its
    /// errors or, once committed, when applied (FR-API-3).
    Reloading { reply: oneshot::Sender<Answer> },
    /// The binding of a removed uplink is being released (FR-MARK-4).
    Forgetting {
        seq: u64,
        uplink: String,
        reply: oneshot::Sender<Answer>,
    },
    /// Applied when the applied generation reaches `target`, which the pass
    /// after the change sets (FR-REC-5).
    Applying {
        target: Option<u64>,
        since: Instant,
        /// The test hook step before the answer (AS-46).
        step: &'static str,
        answer: serde_json::Value,
        reply: oneshot::Sender<Answer>,
    },
}

/// How long a command waits for its application before it answers that
/// it is still pending (within the API's deadline, FR-API-4).
const COMMAND_WAIT: Duration = Duration::from_secs(8);

/// The settings of one scope and whether they are managed or only checked.
type SysctlJob = (Vec<sysctl::Setting>, bool);

/// The nftables transaction being applied by the nftables lane (IMPL-4).
struct NftFlight {
    seq: u64,
    transaction: Arc<str>,
    configured: BTreeSet<Assignment>,
    /// The operations of the pass that started it, for the retry of a
    /// failure (FR-REC-5).
    attempt: String,
}

/// A reload in progress: validated on the I/O runtime, then bound in the
/// manifest by the persistence lane, then committed (FR-CFG-3).
enum ReloadPhase {
    Validating(u64),
    /// The API listeners of the new configuration are being bound.
    Preparing {
        seq: u64,
        config: Arc<Config>,
    },
    Binding {
        seq: u64,
        config: Arc<Config>,
        drained: BTreeSet<UplinkId>,
    },
}

struct Daemon {
    cfg: Config,
    config_path: PathBuf,
    /// The I/O thread; taken at shutdown, which stops its lanes.
    io: Option<Io>,
    lanes: Lanes,
    /// Sequence numbers of the jobs given to the lanes.
    seq: u64,
    nft_flight: Option<NftFlight>,
    inspection: Option<u64>,
    /// Scopes whose settings the persistence lane is applying, with the
    /// job's sequence number; a reload forgets them, so that a completion of
    /// superseded settings only updates the manifest.
    sysctls_flight: BTreeMap<SysctlScope, (u64, SysctlJob)>,
    /// The settings last applied (or checked) per scope. A reload checks
    /// every scope again, but settings applied earlier keep their paths
    /// ready meanwhile; only new settings and failures take them out
    /// (FR-CFG-3, FR-DISC-7).
    sysctls_applied: BTreeMap<SysctlScope, SysctlJob>,
    /// Startup (installation, FR-REC-1 step 2): passes wait until the first
    /// settings of every scope completed, so that warm adoption never sees
    /// the paths of pending interfaces as not ready (FR-REC-8).
    installing: bool,
    hand_back: Option<(u64, String)>,
    reload: Option<ReloadPhase>,
    reload_again: bool,
    /// Operations applied since the last pass that left nothing to do,
    /// across the passes an nftables application splits.
    applied_ops: usize,
    /// An internal task ended (FR-REC-7): the daemon exits with this error.
    fatal: Option<String>,
    /// FR-REC-5: the desired generation changes with every change of the
    /// planner's input or of the configuration; the applied generation is
    /// the last desired one whose pass left nothing pending, settings
    /// included.
    desired_generation: u64,
    applied_generation: u64,
    /// What the desired generation was computed from.
    last_desired: Option<(plan::Desired, Arc<str>, String)>,
    bus: Bus,
    /// Events of the current step, emitted in order once it ends.
    pending_events: Vec<NewEvent>,
    status: watch::Sender<Arc<Status>>,
    status_dirty: bool,
    started: std::time::SystemTime,
    /// Kinds of artifacts a third party removed, reported as repaired once
    /// a pass leaves nothing to do (FR-COEX-3).
    repairs: BTreeSet<&'static str>,
    /// The totals of FR-MET-2, shared with the metrics' scrape.
    totals: Arc<Mutex<crate::metrics::Totals>>,
    /// The API listener manager; none in a dry run.
    api: Option<crate::api::Api>,
    /// The notification settings the notifiers follow (reloads change them).
    notify_config: watch::Sender<Arc<config::Notify>>,
    /// The email notifier's requests (the flush at shutdown).
    mail: Option<mpsc::Sender<crate::mail::Request>>,
    /// Commands of the control socket, one at a time.
    orders: VecDeque<Order>,
    command: Option<Active>,
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
    /// The transaction of the configuration (a function of it alone).
    nft_transaction: Arc<str>,
    /// The transaction last applied and the assignments it holds.
    nft_applied: Option<(Arc<str>, BTreeSet<Assignment>)>,
    nft_listing: Option<serde_json::Value>,
    nft_missing: bool,
    /// Configured paths that PolyWAN's table found at startup already assigns
    /// (warm adoption, FR-REC-8); `None` without such a table. The others
    /// were added while PolyWAN was stopped: like an addition by reload, they
    /// join the balancing and policy routes only after the replacement
    /// installs their assignments (FR-REC-3).
    nft_adopted: Option<BTreeSet<Assignment>>,
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

/// The scope a desired setting is applied in.
fn sysctl_scope(s: &sysctl::Setting) -> SysctlScope {
    match &s.interface {
        Some(i) => SysctlScope::Interface(i.clone()),
        None => SysctlScope::Global,
    }
}

fn state_name(s: health::State) -> &'static str {
    match s {
        health::State::Up => "up",
        health::State::Down => "down",
    }
}

/// `path_state_changed` (FR-EV-1, FR-HEALTH-4).
fn path_event(uplink: &str, family: Family, t: health::Transition) -> NewEvent {
    let (from, to) = (state_name(t.from), state_name(t.to));
    NewEvent::new(
        "path_state_changed",
        format!("uplink {uplink} {family}: {from} -> {to} ({})", t.reason),
    )
    .path(uplink, family.key())
    .change(from, to)
    .reason(t.reason.as_str())
}

/// `path_address_changed` or `path_gateway_changed`.
fn change_event(
    kind: &'static str,
    what: &str,
    uplink: &str,
    family: Family,
    old: Option<std::net::IpAddr>,
    new: Option<std::net::IpAddr>,
) -> NewEvent {
    let text = |a: Option<std::net::IpAddr>| a.map_or_else(|| "none".to_owned(), |a| a.to_string());
    let value = |a: Option<std::net::IpAddr>| a.map_or(serde_json::Value::Null, |a| a.to_string().into());
    NewEvent::new(
        kind,
        format!("uplink {uplink} {family}: {what} {} -> {}", text(old), text(new)),
    )
    .path(uplink, family.key())
    .change(value(old), value(new))
}

/// `apply_failed` (FR-REC-5): the operation, its kind, the errno and the
/// extended acknowledgement, nothing else of the diagnostic.
fn failure_event(op: &str, kind: FailureKind, errno: Option<i32>, extack: Option<&str>) -> NewEvent {
    let mut message = format!("{op} failed");
    if let Some(e) = errno {
        message += &format!(" (errno {e})");
    }
    if let Some(x) = extack {
        message += &format!(": {x}");
    }
    NewEvent::new("apply_failed", message).reason(kind.as_str())
}

/// `run`: startup (FR-REC-1, FR-REC-8, IMPL-6) and the event loop.
pub async fn run(opts: Options) -> Result<()> {
    let cfg = config::load(&opts.config).map_err(|e| anyhow::anyhow!("{e}"))?;
    // FR-CFG-5: nothing configured runs before its ownership is verified.
    report(&checks::trusted(&opts.config, &cfg))?;
    report(&checks::identities(&cfg))?;
    // FR-HOOK-3: no subprocess may inherit a descriptor of ours.
    let inherited = crate::subprocess::inherited_descriptors();
    if let Some(e) = crate::subprocess::descriptor_errors(&cfg, &inherited).first() {
        bail!("{e}");
    }
    if !inherited.is_empty() {
        warn!(
            ?inherited,
            "descriptors inherited without close-on-exec: hooks and sendmail stay refused while they are open"
        );
    }
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
    // IMPL-6: unreadable drain intent refuses startup before any mutation;
    // FR-SEL-3: the intent of uplinks no longer configured is dropped
    // durably before routing changes.
    let mut drain = state_dir
        .drain()
        .map_err(|e| anyhow::anyhow!("drain state: {e} (`run --reset-state` discards it)"))?;
    let recorded = drain.drained.len();
    drain.drained.retain(|n| cfg.uplinks.iter().any(|u| u.name == *n));
    if drain.drained.len() != recorded && !opts.dry_run {
        state_dir.write_drain(&drain).context("writing the drain state")?;
    }
    let drained = cfg
        .uplinks
        .iter()
        .filter(|u| drain.drained.contains(&u.name))
        .map(|u| u.id)
        .collect();

    // Subscribe before the first dump; notifications received meanwhile
    // stay queued and are applied after it (§12.2).
    let subscription = Subscription::new(&groups::ALL, RECEIVE_BUFFER).context("netlink subscription")?;
    let client = Client::new().context("netlink socket")?;
    let dumper = Client::new().context("netlink socket")?;
    let layout = Layout::of(&cfg);
    let scope = Scope {
        polywan_tables: layout.tables(),
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
    let mut manifest = manifest;
    if !opts.dry_run {
        // Write-ahead (IMPL-5, FR-REC-1 step 1): before any mutation.
        manifest.bind(&cfg);
        state_dir.write_manifest(&manifest).context("writing the manifest")?;
    }
    let io = Io::start().context("starting the I/O thread")?;
    let (lanes, done_rx) = Lanes::start(&io, state_dir.clone(), manifest.clone());
    // The notifiers and the API run on the I/O runtime too.
    let io_handle = io.handle().clone();
    let mut d = Daemon {
        config_path: opts.config.clone(),
        io: Some(io),
        lanes,
        seq: 0,
        nft_flight: None,
        inspection: None,
        sysctls_flight: BTreeMap::new(),
        sysctls_applied: BTreeMap::new(),
        installing: true,
        hand_back: None,
        reload: None,
        reload_again: false,
        applied_ops: 0,
        fatal: None,
        desired_generation: 0,
        applied_generation: 0,
        last_desired: None,
        bus: Bus::new(events::instance_id()),
        pending_events: Vec::new(),
        status: watch::channel(Arc::new(Status::default())).0,
        status_dirty: true,
        started: std::time::SystemTime::now(),
        repairs: BTreeSet::new(),
        totals: Arc::default(),
        api: None,
        notify_config: watch::channel(Arc::new(cfg.notify.clone())).0,
        mail: None,
        orders: VecDeque::new(),
        command: None,
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
        drained,
        route_failed: BTreeMap::new(),
        nft_transaction: nft::transaction(&cfg).into(),
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
    // The API sockets (FR-API-1), served on the I/O runtime.
    let endpoints = crate::api::endpoints(&d.cfg).map_err(|e| anyhow::anyhow!("api: {e}"))?;
    let (orders, orders_rx) = mpsc::channel(crate::api::ORDER_QUEUE);
    let runtime_dir = opts.lock.parent().unwrap_or(Path::new("/run/polywan")).to_owned();
    // FR-HOOK-4: the hooks read their own bounded queue of the bus.
    let hook_events = d.bus.add_notifier("hooks", crate::hooks::QUEUE, usize::MAX);
    // FR-MET-2: failed notifications, counted by the notifiers.
    let failures = Arc::new(crate::metrics::Failures::default());
    // FR-HOOK-3: one concurrency limit for hooks and their tests.
    let hook_slots = Arc::new(tokio::sync::Semaphore::new(crate::hooks::CONCURRENCY));
    io_handle.spawn(crate::hooks::notifier(
        hook_events,
        d.notify_config.subscribe(),
        Arc::clone(&hook_slots),
        Arc::clone(&failures),
    ));
    // FR-MAIL-2: the email queue receives the selected types only.
    let mail_events = d
        .bus
        .add_notifier("email", crate::mail::QUEUE, crate::mail::QUEUE_BYTES);
    d.bus.select("email", Some(email_selection(&d.cfg)));
    d.totals().events_dropped = d.bus.dropped();
    // A flush and a test at most (tests run one at a time).
    let (mail, mail_requests) = mpsc::channel(2);
    io_handle.spawn(crate::mail::notifier(
        mail_events,
        d.notify_config.subscribe(),
        mail_requests,
        d.bus.instance().to_owned(),
        Arc::clone(&failures),
    ));
    let shared = crate::api::Shared {
        status: d.status.subscribe(),
        ring: d.bus.ring(),
        latest: d.bus.subscribe(),
        started: std::time::Instant::now(),
        orders,
        tester: Arc::new(crate::notifytest::Tester::new(
            d.notify_config.subscribe(),
            mail.clone(),
            hook_slots,
            d.bus.instance().to_owned(),
            crate::test_hooks::mail_times(crate::mail::Times::default()),
        )),
        failures,
        totals: Arc::clone(&d.totals),
    };
    d.mail = Some(mail);
    let api = crate::api::Api::start(&io_handle, endpoints, runtime_dir, shared)
        .await
        .map_err(|e| anyhow::anyhow!("api: {e}"))?;
    d.api = Some(api);
    // Applied by the first pass, with the failure handling of any other
    // (FR-REC-3, FR-REC-5).
    d.sysctls_pending.extend(d.sysctl_scopes());
    d.load_checkpoint();
    if d.cfg.firewall.mode == FirewallMode::Managed
        && let Ok(Some(listing)) = nftctl::table(&d.cfg.firewall.nft_path).await
    {
        // The assignments the table has.
        let mask = d.cfg.routing.fwmark_mask;
        d.nft_adopted = Some(
            d.assignments()
                .into_iter()
                .filter(|(k, interface)| {
                    nftctl::assigns(
                        &listing,
                        k.family.key(),
                        interface,
                        mask.encode(FieldValue::path(k.uplink)),
                    )
                })
                .collect(),
        );
    }
    let listing = nftctl::table(&d.cfg.firewall.nft_path).await;
    d.check_nft(listing);
    info!(
        uplinks = d.cfg.uplinks.len(),
        mode = ?d.cfg.firewall.mode,
        "polywan {} started",
        env!("CARGO_PKG_VERSION")
    );
    d.pending_events.push(NewEvent::new(
        "daemon_started",
        format!("polywan {} started", env!("CARGO_PKG_VERSION")),
    ));
    if d.cfg.firewall.mode == FirewallMode::External {
        info!("external firewall mode: marking and NAT are the administrator's responsibility (export-nft)");
    }
    d.event_loop(subscription, probe_rx, done_rx, orders_rx).await
}

/// The event types the email queue admits: none without email (FR-MAIL-2).
fn email_selection(cfg: &Config) -> Vec<String> {
    cfg.notify.email.as_ref().map(|e| e.events.clone()).unwrap_or_default()
}

/// The system checks of `check-config` without `--offline` (§9).
pub async fn check_system(path: &Path, cfg: &Config) -> Result<checks::Findings> {
    // FR-CFG-5: nothing configured runs before its ownership is verified.
    let mut f = checks::trusted(path, cfg);
    if !f.errors.is_empty() {
        return Ok(f);
    }
    f.extend(checks::identities(cfg));
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
        polywan_tables: layout.tables(),
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

    /// IMPL-6: an unreadable checkpoint is ignored and every path starts
    /// cold (FR-HEALTH-1).
    fn load_checkpoint(&mut self) {
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

    /// The comparisons of PolyWAN's table listed by an inspection
    /// (FR-REC-6, FR-FW-2).
    fn check_nft(&mut self, listing: std::result::Result<Option<serde_json::Value>, String>) {
        if self.cfg.firewall.mode == FirewallMode::External {
            match listing {
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
        match listing {
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
            self.pending_events.push(
                NewEvent::new("status_degraded", format!("status degraded ({reason})"))
                    .change("ok", "degraded")
                    .reason(reason),
            );
        }
        self.status_dirty = true;
    }

    /// Clears a degradation reason; `status_recovered` only when no other
    /// reason remains.
    fn recover(&mut self, reason: &'static str) {
        if self.degraded.remove(reason) && self.degraded.is_empty() {
            info!(reason, "status_recovered");
            self.pending_events.push(
                NewEvent::new("status_recovered", format!("status ok ({reason} cleared)"))
                    .change("degraded", "ok")
                    .reason(reason),
            );
        }
        self.status_dirty = true;
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
        self.repairs.insert(kind);
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
            "the only default routes on {} use a nexthop group, which PolyWAN does not use: the path is not ready; configure a static gateway (FR-DISC-3)",
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
                    Some(r) if deleted && crate::test_hooks::hidden_deletion(r.family, r.table) => Change::None,
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
        if let Change::Link(i) = &change {
            debug!(ifindex = i, "link changed");
        }
        let third_party = port != 0 && port != self.client.port();
        if third_party && let Some(r) = removed_rule {
            warn!(
                kind = "rules",
                port,
                priority = r.priority,
                "PolyWAN artifact removed by a third party"
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
                "PolyWAN artifact removed by a third party"
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
                        let scope = SysctlScope::Interface(up.interface.clone());
                        self.sysctls_applied.remove(&scope);
                        self.sysctls_pending.insert(scope);
                        self.sysctl_retries.remove(&up.interface);
                    }
                }
                self.dirty = true;
            }
            Change::Route { .. } | Change::Rule { .. } | Change::Nexthop { .. } => self.dirty = true,
            Change::None => {}
        }
    }

    /// Router Advertisements arrived on an interface (the listener of
    /// `ra.rs`, which sees every one; `RTM_NEWPREFIX` would cover only those
    /// with prefix information). FR-DISC-5: they may have refreshed or shortened
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
                let Some(health) = self.cfg.uplink(r.path.uplink).map(|u| &u.health) else {
                    return;
                };
                self.status_dirty = true;
                {
                    let mut totals = self.totals();
                    for sample in &r.samples {
                        let result = if sample.rtt.is_some() { "ok" } else { "lost" };
                        let key = (r.path.uplink, r.path.family, sample.target, result);
                        crate::metrics::Totals::count(&mut totals.probe_samples, key);
                    }
                }
                let p = self.paths.get_mut(&r.path).expect("checked above");
                p.window.push(r.samples, usize::from(health.quality_window));
                p.stats = p.window.stats();
                let violations = quality::violations(&p.stats, &health.quality, health.quality_min_samples);
                if violations.is_empty() == p.violating {
                    p.violating = !violations.is_empty();
                    let list: Vec<String> = violations.iter().map(ToString::to_string).collect();
                    if p.violating {
                        info!(uplink = r.path.uplink.get(), family = %r.path.family, violations = %list.join(", "), "quality gate violated");
                    } else {
                        info!(uplink = r.path.uplink.get(), family = %r.path.family, "quality gates met");
                    }
                }
                let round = match (r.passed, violations.is_empty()) {
                    (false, _) => Round::Failed,
                    (true, true) => Round::Passed,
                    (true, false) => Round::Degraded,
                };
                debug!(uplink = r.path.uplink.get(), family = %r.path.family, passed = r.passed, reachable = r.reachable, loss = ?p.stats.loss, rtt = ?p.stats.rtt, jitter = ?p.stats.jitter, "probe round");
                if let Some(t) = p.machine.round(round, h) {
                    self.transitioned(r.path, t);
                    self.dirty = true;
                    self.write_checkpoint();
                }
            }
        }
    }

    fn write_checkpoint(&mut self) {
        let c = self.checkpoint();
        // Best effort: a full queue drops it, the next one supersedes it.
        if self.lanes.persist(PersistJob::Checkpoint(Box::new(c))) == Err(Lost::Closed) {
            self.lost();
        }
        self.last_checkpoint = Instant::now();
    }

    /// At shutdown, once the lanes have stopped.
    fn write_checkpoint_now(&mut self) {
        if let Err(e) = self.state_dir.write_checkpoint(&self.checkpoint()) {
            warn!("health checkpoint: {e}");
        }
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
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
        }
    }

    /// Starts the next command if none is in progress.
    fn next_order(&mut self) {
        while self.command.is_none() {
            let Some(Order { action: request, reply }) = self.orders.pop_front() else {
                return;
            };
            match request {
                Action::Drain { uplink, force } => self.start_drain(&uplink, true, force, reply),
                Action::Undrain { uplink } => self.start_drain(&uplink, false, false, reply),
                Action::Reload => {
                    self.command = Some(Active::Reloading { reply });
                    self.start_reload();
                }
                Action::Forget { uplink } => self.start_forget(uplink, reply),
            }
        }
    }

    /// The candidates of a family (§2): eligible (a priority, not drained)
    /// and ready.
    fn candidates(&self, family: Family) -> Vec<UplinkId> {
        self.cfg
            .uplinks
            .iter()
            .filter(|u| u.priority.is_some() && !self.drained.contains(&u.id))
            .filter(|u| {
                self.paths
                    .get(&PathKey { uplink: u.id, family })
                    .is_some_and(|p| p.machine.is_ready())
            })
            .map(|u| u.id)
            .collect()
    }

    /// FR-SEL-3, FR-SEL-4: drain or undrain, persisted before it applies.
    fn start_drain(&mut self, name: &str, drain: bool, force: bool, reply: oneshot::Sender<Answer>) {
        let Some(u) = self.cfg.uplinks.iter().find(|u| u.name == name) else {
            let _ = reply.send(Answer::error(
                StatusCode::NOT_FOUND,
                format!("no uplink is named {name:?}"),
            ));
            return;
        };
        let id = u.id;
        if drain && !force {
            for family in Family::ALL {
                if self.candidates(family) == [id] {
                    let _ = reply.send(Answer::error(
                        StatusCode::CONFLICT,
                        format!("{name} is the last {family} candidate; draining it needs force (FR-SEL-4)"),
                    ));
                    return;
                }
            }
        }
        let mut drained = self.drained.clone();
        if drain {
            drained.insert(id);
        } else {
            drained.remove(&id);
        }
        let names = drained
            .iter()
            .filter_map(|i| self.cfg.uplink(*i))
            .map(|u| u.name.clone());
        let state = state::DrainState::of(names);
        let seq = self.next_seq();
        match self.lanes.persist(PersistJob::Drain { seq, state }) {
            Ok(()) => {
                self.command = Some(Active::Persisting {
                    seq,
                    uplink: id,
                    drain,
                    reply,
                })
            }
            Err(Lost::Full) => {
                let _ = reply.send(Answer::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the state directory is busy",
                ));
            }
            Err(Lost::Closed) => self.lost(),
        }
    }

    /// FR-MARK-4: releases the binding of an uplink no longer configured.
    fn start_forget(&mut self, uplink: String, reply: oneshot::Sender<Answer>) {
        if self.cfg.uplinks.iter().any(|u| u.name == uplink) {
            let _ = reply.send(Answer::error(
                StatusCode::CONFLICT,
                format!("uplink {uplink:?} is still in the configuration; remove it and reload first"),
            ));
            return;
        }
        let seq = self.next_seq();
        match self.lanes.persist(PersistJob::Forget {
            seq,
            uplink: uplink.clone(),
        }) {
            Ok(()) => self.command = Some(Active::Forgetting { seq, uplink, reply }),
            Err(Lost::Full) => {
                let _ = reply.send(Answer::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the state directory is busy",
                ));
            }
            Err(Lost::Closed) => self.lost(),
        }
    }

    fn forgotten(&mut self, seq: u64, result: std::result::Result<u8, String>) {
        let Some(Active::Forgetting { uplink, reply, .. }) = self
            .command
            .take_if(|c| matches!(c, Active::Forgetting { seq: s, .. } if *s == seq))
        else {
            return;
        };
        let answer = match result {
            Ok(id) => {
                info!(uplink = %uplink, id, "uplink forgotten");
                Answer::new(StatusCode::OK, serde_json::json!({ "uplink": uplink, "id": id }))
            }
            Err(e) => Answer::error(StatusCode::CONFLICT, e),
        };
        let _ = reply.send(answer);
        self.next_order();
    }

    /// The drain intent is durable: it applies now, and the command waits
    /// for the applied generation that includes it.
    fn drained(&mut self, seq: u64, result: std::result::Result<(), String>) {
        let Some(Active::Persisting {
            uplink, drain, reply, ..
        }) = self
            .command
            .take_if(|c| matches!(c, Active::Persisting { seq: s, .. } if *s == seq))
        else {
            return;
        };
        let name = self.cfg.uplink(uplink).map(|u| u.name.clone()).unwrap_or_default();
        if let Err(e) = result {
            error!(uplink = %name, "drain state not written: {e}");
            let _ = reply.send(Answer::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the drain state could not be written; nothing changed",
            ));
            return self.next_order();
        }
        let (kind, verb) = if drain {
            self.drained.insert(uplink);
            ("uplink_drained", "drained")
        } else {
            self.drained.remove(&uplink);
            ("uplink_undrained", "undrained")
        };
        info!(uplink = %name, "{kind}");
        self.pending_events
            .push(NewEvent::new(kind, format!("uplink {name} {verb}")).uplink(&name));
        self.dirty = true;
        self.command = Some(Active::Applying {
            target: None,
            since: Instant::now(),
            step: if drain { "respond drain" } else { "respond undrain" },
            answer: serde_json::json!({ "uplink": name, "drained": drain }),
            reply,
        });
    }

    /// Answers the command in progress once applied, or once it waited too
    /// long.
    fn check_command(&mut self) {
        let Some(Active::Applying { target, since, .. }) = &self.command else {
            return;
        };
        let applied = target.is_some_and(|t| self.applied_generation >= t);
        if !applied && since.elapsed() < COMMAND_WAIT {
            return;
        }
        let Some(Active::Applying {
            target,
            step,
            answer,
            reply,
            ..
        }) = self.command.take()
        else {
            return;
        };
        let answer = if applied {
            // AS-46: a crash can be injected right before the answer.
            let _ = crate::test_hooks::step(step);
            let mut body = answer;
            body["generation"] = target.unwrap_or_default().into();
            Answer::new(StatusCode::OK, body)
        } else {
            Answer::new(
                StatusCode::ACCEPTED,
                serde_json::json!({
                    "error": "not yet applied; PolyWAN keeps applying it",
                    "generation": target,
                }),
            )
        };
        let _ = reply.send(answer);
        self.next_order();
    }

    /// A health transition of a path: its since, the log line, the event and
    /// its total (FR-MET-2).
    fn transitioned(&mut self, key: PathKey, t: health::Transition) {
        if let Some(p) = self.paths.get_mut(&key) {
            p.since_ms = now_ms();
        }
        info!(uplink = key.uplink.get(), family = %key.family, from = ?t.from, to = ?t.to, reason = %t.reason, "path state changed");
        crate::metrics::Totals::count(
            &mut self.totals().transitions,
            (key.uplink, key.family, state_name(t.to)),
        );
        if let Some(u) = self.cfg.uplink(key.uplink) {
            self.pending_events.push(path_event(&u.name, key.family, t));
        }
    }

    /// Emits the events of the step in order, then publishes the status.
    fn flush_events(&mut self) {
        if !self.pending_events.is_empty() {
            for e in std::mem::take(&mut self.pending_events) {
                self.bus.emit(e);
            }
            self.totals().events_dropped = self.bus.dropped();
            self.status_dirty = true;
        }
        if std::mem::take(&mut self.status_dirty) {
            let s = Arc::new(self.snapshot());
            self.status.send_replace(s);
        }
    }

    /// The status of FR-API-2.
    fn snapshot(&self) -> Status {
        let wall = std::time::SystemTime::now();
        let boot_now = now_ms();
        let since = |ms: u64| events::rfc3339(wall - Duration::from_millis(boot_now.saturating_sub(ms)));
        let mut active = BTreeMap::new();
        for (family, set) in &self.active {
            active.insert(
                family.key(),
                set.iter()
                    .filter_map(|id| self.cfg.uplink(*id).map(|u| u.name.clone()))
                    .collect(),
            );
        }
        Status {
            version: env!("CARGO_PKG_VERSION"),
            instance: self.bus.instance().to_owned(),
            started: events::rfc3339(self.started),
            config_digest: self.cfg.digest.clone(),
            generation: status::Generations {
                desired: self.desired_generation,
                applied: self.applied_generation,
            },
            status: if self.degraded.is_empty() { "ok" } else { "degraded" },
            reasons: self.degraded.iter().copied().collect(),
            uplinks: self
                .cfg
                .uplinks
                .iter()
                .map(|u| status::UplinkStatus {
                    name: u.name.clone(),
                    id: u.id.get(),
                    interface: u.interface.clone(),
                    drained: self.drained.contains(&u.id),
                })
                .collect(),
            paths: self
                .paths
                .iter()
                .filter_map(|(k, p)| {
                    let u = self.cfg.uplink(k.uplink)?;
                    let d = p.discovered.as_ref();
                    let ready = d.and_then(|d| d.ready.as_ref().ok());
                    Some(status::PathStatus {
                        uplink: u.name.clone(),
                        family: k.family.key(),
                        state: state_name(p.machine.state()),
                        ready: p.machine.is_ready(),
                        reason: p.machine.reason().as_str(),
                        since: since(p.since_ms),
                        source: ready.map(|r| r.source),
                        gateway: ready.and_then(|r| r.gateway),
                        addresses: d
                            .map(|d| d.local_addresses.iter().copied().collect())
                            .unwrap_or_default(),
                        statistics: (&p.stats).into(),
                    })
                })
                .collect(),
            active,
        }
    }

    /// The totals, held briefly: a scrape only reads them.
    fn totals(&self) -> std::sync::MutexGuard<'_, crate::metrics::Totals> {
        self.totals.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A lane is gone (FR-REC-7).
    fn lost(&mut self) {
        self.fatal = Some("an internal I/O lane stopped".into());
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
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
            // a path is not ready until those of its family are applied, nor
            // while they fail.
            if let Some(u) = self.cfg.uplink(key.uplink)
                && self.sysctls_unapplied(&SysctlScope::Interface(u.interface.clone()), Some(key.family))
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
                    // The causes come from the interface's settings, read
                    // outside the State task (IMPL-4).
                    let job = PersistJob::GatewayWarning {
                        uplink: u.name.clone(),
                        interface: u.interface.clone(),
                        delay,
                    };
                    if self.lanes.persist(job) == Err(Lost::Closed) {
                        self.fatal = Some("an internal I/O lane stopped".into());
                    }
                }
            } else {
                p.gateway_wait = None;
            }
            if !unchanged {
                info!(uplink = key.uplink.get(), family = %key.family, ready = ?raw.ready.as_ref().map(|r| (r.source, r.gateway, r.ifindex)), "path discovery changed");
                // FR-EV-1: address and gateway changes of an observed path.
                if let (Some(prev), Some(u)) = (p.discovered.as_ref(), self.cfg.uplink(key.uplink)) {
                    let was = prev.ready.as_ref().ok();
                    let now = raw.ready.as_ref().ok();
                    let (old, new) = (was.map(|r| r.source), now.map(|r| r.source));
                    if old != new {
                        self.pending_events.push(change_event(
                            "path_address_changed",
                            "source",
                            &u.name,
                            key.family,
                            old,
                            new,
                        ));
                    }
                    let (old, new) = (was.and_then(|r| r.gateway), now.and_then(|r| r.gateway));
                    if old != new {
                        self.pending_events.push(change_event(
                            "path_gateway_changed",
                            "gateway",
                            &u.name,
                            key.family,
                            old,
                            new,
                        ));
                    }
                }
            }
            let reason = d.ready.as_ref().err().copied().unwrap_or(Reason::Startup);
            let transition = p.machine.set_ready(d.ready.is_ok(), reason);
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
            if let Some(t) = transition {
                self.transitioned(key, t);
            }
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
                let names = |s: &BTreeSet<UplinkId>| -> Vec<String> {
                    s.iter()
                        .filter_map(|id| self.cfg.uplink(*id).map(|u| u.name.clone()))
                        .collect()
                };
                let (old, new) = (names(&previous), names(&set));
                self.pending_events.push(
                    NewEvent::new(
                        "active_set_changed",
                        format!("{family} active set: [{}] -> [{}]", old.join(", "), new.join(", ")),
                    )
                    .family(family.key())
                    .change(old, new),
                );
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
            // FR-PROBE-5: a new probing generation, or a path no longer
            // ready, starts an empty window.
            p.window.clear();
            p.stats = quality::Stats::default();
            p.violating = false;
            if let Some(mut spec) = wanted {
                spec.generation = p.generation;
                let handle = probe::spawn(spec.clone(), self.probe_tx.clone());
                p.prober = Some((spec, handle));
            }
        }
    }

    /// The mark assignment of every configured path: its interface, which a
    /// reload may change while the uplink keeps its id.
    fn assignments(&self) -> BTreeSet<Assignment> {
        self.cfg
            .uplinks
            .iter()
            .flat_map(|u| {
                u.families()
                    .map(|family| (PathKey { uplink: u.id, family }, u.interface.clone()))
            })
            .collect()
    }

    /// Whether the settings of `scope` that matter to `family` (`None`: all
    /// of them) are pending without an earlier application: the
    /// prerequisite of readiness is not met (FR-DISC-7). Settings that are
    /// only checked (`manage_sysctls = false`) are never a prerequisite.
    fn sysctls_unapplied(&self, scope: &SysctlScope, family: Option<Family>) -> bool {
        if !self.cfg.routing.manage_sysctls || !self.sysctls_pending.contains(scope) {
            return false;
        }
        let Some((applied, true)) = self.sysctls_applied.get(scope) else {
            return true;
        };
        let wanted = self.wanted_sysctls_of(scope).map(|j| j.0).unwrap_or_default();
        !wanted
            .iter()
            .filter(|s| family.is_none() || s.family.is_none() || s.family == family)
            .all(|s| applied.contains(s))
    }

    /// The wanted settings of every scope, and whether they are managed.
    fn wanted_sysctls(&self) -> BTreeMap<SysctlScope, SysctlJob> {
        let manage = self.cfg.routing.manage_sysctls;
        let mut m: BTreeMap<SysctlScope, SysctlJob> = self
            .sysctl_scopes()
            .into_iter()
            .map(|s| (s, (Vec::new(), manage)))
            .collect();
        for s in sysctl::desired(&self.cfg) {
            m.entry(sysctl_scope(&s))
                .or_insert_with(|| (Vec::new(), manage))
                .0
                .push(s);
        }
        m
    }

    /// The entry of `scope` in [`Self::wanted_sysctls`], without building
    /// the others.
    fn wanted_sysctls_of(&self, scope: &SysctlScope) -> Option<SysctlJob> {
        let interface = match scope {
            SysctlScope::Global => None,
            SysctlScope::Interface(i) => Some(i.as_str()),
        };
        let settings: Vec<sysctl::Setting> = sysctl::desired(&self.cfg)
            .into_iter()
            .filter(|s| s.interface.as_deref() == interface)
            .collect();
        (*scope == SysctlScope::Global || !settings.is_empty()).then_some((settings, self.cfg.routing.manage_sysctls))
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

    /// Gives the pending sysctls to the persistence lane, before the routes
    /// and rules that rely on them (FR-REC-3): the interfaces' first, then
    /// the global ones unless `global` is false (their retry waits for its
    /// backoff). An interface whose settings are pending or failed keeps its
    /// paths not ready; it is retried with its own backoff, and no other
    /// interface waits for it (FR-DISC-7).
    fn dispatch_sysctls(&mut self, global: bool) {
        let mut scopes: Vec<SysctlScope> = self.sysctls_pending.iter().cloned().collect();
        // Interfaces first: a failure of the global settings does not keep
        // them from their own.
        scopes.sort_by_key(|s| *s == SysctlScope::Global);
        for scope in scopes {
            if self.sysctls_flight.contains_key(&scope) {
                continue;
            }
            match &scope {
                SysctlScope::Interface(i) if self.sysctl_retries.get(i).is_some_and(|r| Instant::now() < r.at) => {
                    continue;
                }
                SysctlScope::Global if !global => continue,
                _ => {}
            }
            let wanted = self.wanted_sysctls_of(&scope).unwrap_or_default();
            let seq = self.next_seq();
            let job = PersistJob::Sysctls {
                seq,
                scope: scope.clone(),
                settings: wanted.0.clone(),
                manage: wanted.1,
            };
            match self.lanes.persist(job) {
                Ok(()) => {
                    self.sysctls_flight.insert(scope, (seq, wanted));
                }
                // Retried by the next pass.
                Err(Lost::Full) => self.dirty = true,
                Err(Lost::Closed) => self.lost(),
            }
        }
    }

    /// A completed sysctl application (FR-REC-5, FR-DISC-7).
    fn sysctls_done(&mut self, seq: u64, scope: SysctlScope, result: std::result::Result<(), String>) {
        if !matches!(self.sysctls_flight.get(&scope), Some((s, _)) if *s == seq) {
            // Superseded by a reload: applied again if still wanted.
            return;
        }
        let Some((_, job)) = self.sysctls_flight.remove(&scope) else {
            return;
        };
        self.dirty = true;
        match (result, &scope) {
            (Ok(()), _) => {
                self.sysctls_pending.remove(&scope);
                self.sysctls_applied.insert(scope.clone(), job);
                if let SysctlScope::Interface(i) = &scope {
                    self.sysctl_retries.remove(i);
                    self.sysctls_failed.remove(i);
                }
            }
            (Err(e), SysctlScope::Interface(i)) => {
                let i = i.clone();
                self.sysctls_applied.remove(&scope);
                crate::metrics::Totals::count(&mut self.totals().apply_failures, FailureKind::Sysctl);
                error!(interface = %i, kind = "sysctl", "apply_failed: set sysctls: {e}");
                self.pending_events.push(failure_event(
                    &format!("set sysctls of {i}"),
                    FailureKind::Sysctl,
                    None,
                    None,
                ));
                self.sysctls_failed.insert(i.clone(), e);
                self.degrade("apply_failed");
                let backoff = self
                    .sysctl_retries
                    .get(&i)
                    .map_or(Duration::from_secs(1), |r| (r.backoff * 2).min(Duration::from_secs(60)));
                self.sysctl_retries.insert(
                    i,
                    Retry {
                        at: Instant::now() + backoff,
                        backoff,
                        attempt: SYSCTL_ATTEMPT.to_owned(),
                    },
                );
            }
            (Err(e), SysctlScope::Global) => {
                self.sysctls_applied.remove(&scope);
                self.failed(
                    Failure::new("set sysctls", FailureKind::Sysctl, e),
                    SYSCTL_ATTEMPT.to_owned(),
                )
            }
        }
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
            self.dispatch_sysctls(global);
        }
        if self.installing {
            if !self.sysctls_flight.is_empty() {
                return;
            }
            self.installing = false;
        }
        if !self.sysctls_pending.is_empty() {
            // Everything depends on the global settings.
            if self.sysctls_unapplied(&SysctlScope::Global, None) {
                self.evaluate();
                return;
            }
        }
        self.reread_expired();
        if !self.reread.is_empty() {
            let tables: Vec<_> = std::mem::take(&mut self.reread).into_iter().collect();
            debug!(?tables, "re-reading tables");
            if let Err(e) = observer::reread(&self.dumper, &self.scope, &mut self.system, &tables).await {
                warn!("re-reading tables: {e}");
            }
        }
        let input = self.evaluate();
        let managed = self.cfg.firewall.mode == FirewallMode::Managed;
        let transaction = Arc::clone(&self.nft_transaction);
        let configured = self.assignments();
        let nft_pending =
            managed && (self.nft_missing || self.nft_applied.as_ref().map(|(t, _)| t) != Some(&transaction));
        let new_paths = if managed {
            unassigned(
                &configured,
                self.nft_applied.as_ref().map(|(_, a)| a).or(self.nft_adopted.as_ref()),
            )
        } else {
            BTreeSet::new()
        };
        let desired = plan::plan(&self.cfg, &input);
        if self
            .last_desired
            .as_ref()
            .is_none_or(|(d, t, digest)| *d != desired || *t != transaction || *digest != self.cfg.digest)
        {
            self.desired_generation += 1;
            self.last_desired = Some((desired.clone(), Arc::clone(&transaction), self.cfg.digest.clone()));
        }
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
        // IMPL-4: while the nftables lane applies a transaction, the
        // operations before the nftables step still run (withdrawals among
        // them); those after it wait for the application's completion.
        let ops: Vec<Op> = if self.nft_flight.is_some() {
            ops.into_iter().take_while(|o| !matches!(o, Op::ApplyNft)).collect()
        } else {
            ops
        };
        if ops.is_empty() {
            if self.nft_flight.is_some() || self.hand_back.is_some() {
                return;
            }
            // Routing and nftables no longer hold a departed family's
            // artifacts: its settings go back last (FR-REC-9 step 4).
            let departed = sysctl::departed(&self.manifest, &self.cfg);
            if !departed.is_empty() && self.cfg.routing.manage_sysctls {
                let seq = self.next_seq();
                match self.lanes.persist(PersistJob::HandBack {
                    seq,
                    families: departed,
                }) {
                    Ok(()) => self.hand_back = Some((seq, attempt)),
                    Err(Lost::Full) => self.dirty = true,
                    Err(Lost::Closed) => self.lost(),
                }
                return;
            }
            if self.sysctls_pending.is_empty() {
                self.applied_generation = self.desired_generation;
            }
            for kind in std::mem::take(&mut self.repairs) {
                crate::metrics::Totals::count(&mut self.totals().repairs, kind);
                self.pending_events.push(
                    NewEvent::new(
                        "artifact_repaired",
                        format!("PolyWAN's {kind} removed by a third party are restored"),
                    )
                    .reason(kind),
                );
            }
            if self.applied_ops > 0 {
                info!(
                    operations = std::mem::take(&mut self.applied_ops),
                    generation = self.applied_generation,
                    "applied"
                );
            }
            self.applied();
            return;
        }
        for op in &ops {
            debug!("{op}");
        }
        let count = ops.len();
        let result = reconcile::execute(&self.client, &mut self.system, &self.scope, self.protocol, ops).await;
        match result {
            Ok(nft_due) => {
                if nft_due {
                    // The operations before it are applied: the table goes
                    // to the nftables lane, the rest waits for it.
                    self.applied_ops += count - 1;
                    let seq = self.next_seq();
                    let job = NftJob::Apply {
                        seq,
                        nft: self.cfg.firewall.nft_path.clone(),
                        transaction: Arc::clone(&transaction),
                    };
                    match self.lanes.nft(job) {
                        Ok(()) => {
                            self.nft_flight = Some(NftFlight {
                                seq,
                                transaction,
                                configured,
                                attempt,
                            })
                        }
                        Err(Lost::Full) => self.dirty = true,
                        Err(Lost::Closed) => self.lost(),
                    }
                    return;
                }
                self.applied_ops += count;
                // Routes of uplinks whose assignments were just installed
                // and paths whose routes failed are reconsidered; the pass
                // that finds nothing to do reports the application.
                self.dirty = true;
            }
            Err(f) => self.failed(f, attempt),
        }
    }

    /// The nftables lane applied a transaction, or failed to (FR-REC-5).
    fn nft_applied(&mut self, seq: u64, result: std::result::Result<Option<serde_json::Value>, String>) {
        let Some(flight) = self.nft_flight.take_if(|f| f.seq == seq) else {
            return;
        };
        self.dirty = true;
        match result {
            Ok(listing) => {
                // The kernel holds this table, whatever the configuration
                // became meanwhile: the next pass compares against it.
                self.nft_applied = Some((flight.transaction, flight.configured));
                self.nft_missing = false;
                self.nft_listing = listing;
                self.applied_ops += 1;
            }
            Err(error) => self.failed(
                Failure::new(Op::ApplyNft.to_string(), FailureKind::Nftables, error),
                flight.attempt,
            ),
        }
    }

    /// The persistence lane handed families back (FR-REC-9 step 4).
    fn handed_back(&mut self, seq: u64, result: std::result::Result<(), String>) {
        let Some((_, attempt)) = self.hand_back.take_if(|(s, _)| *s == seq) else {
            return;
        };
        self.dirty = true;
        if let Err(error) = result {
            self.failed(
                Failure::new("restore sysctls of a handed-back family", FailureKind::Sysctl, error),
                attempt,
            );
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
        let count = crate::metrics::Totals::count(&mut self.totals().apply_failures, f.kind);
        error!(operation = %f.op, kind = f.kind.as_str(), errno = ?f.errno, extack = ?f.extack, failures = count, "apply_failed: {}", f.error);
        self.pending_events
            .push(failure_event(&f.op, f.kind, f.errno, f.extack.as_deref()));
        self.degrade("apply_failed");
        // FR-REC-5: a command not yet applied reports the failed step.
        if let Some(Active::Applying { reply, .. }) = self.command.take_if(|c| matches!(c, Active::Applying { .. })) {
            let _ = reply.send(Answer::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "error": "not applied: a step failed; PolyWAN keeps retrying",
                    "failed_steps": [{ "operation": f.op, "kind": f.kind.as_str(), "errno": f.errno }],
                }),
            ));
            self.next_order();
        }
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
        // The table and the flowtables are listed by the nftables lane,
        // after any application already queued there (IMPL-4).
        if self.inspection.is_none() {
            let seq = self.next_seq();
            let job = NftJob::Inspect {
                seq,
                nft: self.cfg.firewall.nft_path.clone(),
            };
            match self.lanes.nft(job) {
                Ok(()) => self.inspection = Some(seq),
                Err(Lost::Full) => {}
                Err(Lost::Closed) => self.lost(),
            }
        }
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

    /// SIGHUP: a reload starts, or follows the one in progress (FR-CFG-3).
    fn start_reload(&mut self) {
        if self.reload.is_some() {
            self.reload_again = true;
            return;
        }
        let seq = self.next_seq();
        let context = worker::ReloadContext {
            structural: self.cfg.structural(),
            state_dir: self.cfg.state_dir.clone(),
            nft_path: self.cfg.firewall.nft_path.clone(),
        };
        self.lanes.validate_reload(seq, self.config_path.clone(), context);
        self.reload = Some(ReloadPhase::Validating(seq));
    }

    fn reload_failed(&mut self, errors: &[String]) {
        for e in errors {
            error!("reload_failed: {e}");
        }
        // A reload requested through the control socket gets the
        // diagnostics (FR-API-3, IMPL-11), unless another reload follows.
        let mut answered = false;
        if !self.reload_again
            && let Some(Active::Reloading { reply }) = self.command.take_if(|c| matches!(c, Active::Reloading { .. }))
        {
            let _ = reply.send(Answer::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({
                    "error": "the configuration was not reloaded; the running configuration is kept",
                    "errors": errors,
                }),
            ));
            answered = true;
        }
        // Diagnostics stay in the log (FR-API-2, IMPL-11).
        self.pending_events.push(NewEvent::new(
            "reload_failed",
            "the configuration was not reloaded; the running configuration is kept",
        ));
        self.end_reload();
        // The next command starts once the reload state is clear.
        if answered {
            self.next_order();
        }
    }

    fn end_reload(&mut self) {
        self.reload = None;
        if std::mem::take(&mut self.reload_again) {
            self.start_reload();
        }
    }

    /// The validation of a reload: rejected, or bound in the manifest next,
    /// with the drain intent of removed uplinks pruned (FR-SEL-3), by the
    /// persistence lane.
    fn reload_validated(&mut self, outcome: worker::ReloadOutcome) {
        if !matches!(self.reload, Some(ReloadPhase::Validating(seq)) if seq == outcome.seq) {
            return;
        }
        if let Some(listing) = &outcome.running_flowtables {
            self.record_flowtables(listing);
        }
        let (new, endpoints) = match outcome.result {
            Ok((new, endpoints)) => (Arc::new(*new), endpoints),
            Err(errors) => return self.reload_failed(&errors),
        };
        // FR-API-1, FR-MET-1: the listeners are prepared before the commit.
        let Some(api) = self.api.clone() else {
            return self.reload_failed(&["the API is not running".to_owned()]);
        };
        let seq = self.next_seq();
        self.lanes.prepare_api(seq, api, endpoints);
        self.reload = Some(ReloadPhase::Preparing { seq, config: new });
    }

    /// The API listeners are prepared: the manifest binding follows.
    fn api_prepared(&mut self, seq: u64, result: std::result::Result<(), String>) {
        let Some(ReloadPhase::Preparing { config: new, .. }) = self
            .reload
            .take_if(|r| matches!(r, ReloadPhase::Preparing { seq: s, .. } if *s == seq))
        else {
            return;
        };
        if let Err(e) = result {
            return self.reload_failed(&[e]);
        }
        let drained: BTreeSet<UplinkId> = self
            .drained
            .iter()
            .copied()
            .filter(|id| new.uplink(*id).is_some())
            .collect();
        let drain = (drained != self.drained)
            .then(|| state::DrainState::of(drained.iter().filter_map(|id| new.uplink(*id)).map(|u| u.name.clone())));
        let seq = self.next_seq();
        let job = PersistJob::Bind {
            seq,
            config: Arc::clone(&new),
            drain,
        };
        match self.lanes.persist(job) {
            Ok(()) => {
                self.reload = Some(ReloadPhase::Binding {
                    seq,
                    config: new,
                    drained,
                })
            }
            Err(Lost::Full) => {
                self.api_command(crate::api::Command::Rollback);
                self.reload_failed(&["the persistence queue is full".to_owned()])
            }
            Err(Lost::Closed) => self.lost(),
        }
    }

    fn api_command(&mut self, c: crate::api::Command) {
        if let Some(api) = &self.api
            && !api.send(c)
        {
            warn!("the API manager did not take a command");
        }
    }

    /// The manifest and the drain intent are written: the reload commits.
    fn reload_bound(&mut self, seq: u64, result: std::result::Result<(), Vec<String>>) {
        let Some(ReloadPhase::Binding { config, drained, .. }) = self
            .reload
            .take_if(|r| matches!(r, ReloadPhase::Binding { seq: s, .. } if *s == seq))
        else {
            return;
        };
        if let Err(errors) = result {
            self.api_command(crate::api::Command::Rollback);
            return self.reload_failed(&errors);
        }
        self.api_command(crate::api::Command::Commit);
        let new = Arc::unwrap_or_clone(config);
        self.drained = drained;
        self.cfg = new;
        self.nft_transaction = nft::transaction(&self.cfg).into();
        // Paths exist only for configured uplinks: those of removed uplinks
        // go at once, with their probers, and so do their metrics' totals
        // (an id names one uplink until it is forgotten, FR-MARK-4).
        let configured: BTreeSet<UplinkId> = self.cfg.uplinks.iter().map(|u| u.id).collect();
        self.totals().retain_uplinks(|id| configured.contains(&id));
        self.prune_paths(|k| configured.contains(&k.uplink));
        self.scope.discovery_tables = self.cfg.routing.discovery_tables.clone();
        // The settings of removed uplinks' interfaces are no longer PolyWAN's
        // to apply, nor their retries to keep: re-added, they start afresh.
        // Every scope is checked again; settings applied earlier keep their
        // paths ready meanwhile (only new ones are a prerequisite).
        let wanted = self.wanted_sysctls();
        self.sysctls_applied.retain(|s, _| wanted.contains_key(s));
        self.sysctls_pending = wanted.into_keys().collect();
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
        // Settings of the previous configuration still being applied are
        // forgotten: their completions only update the manifest.
        self.sysctls_flight.clear();
        self.bus.select("email", Some(email_selection(&self.cfg)));
        self.notify_config.send_replace(Arc::new(self.cfg.notify.clone()));
        info!("config_reloaded");
        self.pending_events
            .push(NewEvent::new("config_reloaded", "the configuration was reloaded"));
        // Committed: the API's reload completes when applied.
        if !self.reload_again
            && let Some(Active::Reloading { reply }) = self.command.take_if(|c| matches!(c, Active::Reloading { .. }))
        {
            self.command = Some(Active::Applying {
                target: None,
                since: Instant::now(),
                step: "respond reload",
                answer: serde_json::json!({ "reloaded": true }),
                reply,
            });
        }
        self.dirty = true;
        self.end_reload();
    }

    /// A completion of a lane.
    fn completion(&mut self, done: Done) {
        match done {
            Done::NftApplied { seq, result } => self.nft_applied(seq, result),
            Done::NftInspected { seq, table, flowtables } => {
                if self.inspection.take_if(|s| *s == seq).is_some() {
                    self.check_nft(table);
                    self.record_flowtables(&flowtables);
                    self.dirty = true;
                }
            }
            Done::Sysctls {
                seq,
                scope,
                result,
                manifest,
            } => {
                self.manifest = manifest;
                self.sysctls_done(seq, scope, result);
            }
            Done::Bound { seq, result, manifest } => {
                self.manifest = manifest;
                self.reload_bound(seq, result);
            }
            Done::HandedBack { seq, result, manifest } => {
                self.manifest = manifest;
                self.handed_back(seq, result);
            }
            Done::Reload(outcome) => self.reload_validated(outcome),
            Done::ApiPrepared { seq, result } => self.api_prepared(seq, result),
            Done::Drained { seq, result } => self.drained(seq, result),
            Done::Forgotten { seq, result, manifest } => {
                self.manifest = manifest;
                self.forgotten(seq, result);
            }
        }
    }

    async fn event_loop(
        &mut self,
        mut subscription: Subscription,
        mut probe_rx: mpsc::Receiver<probe::Report>,
        mut done_rx: mpsc::Receiver<Done>,
        mut orders_rx: mpsc::Receiver<Order>,
    ) -> Result<()> {
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        let mut hup = signal(SignalKind::hangup())?;
        let mut next_full = Instant::now() + self.cfg.routing.reconcile_interval;
        let (ra_tx, mut ra_rx) = mpsc::unbounded_channel();
        // A raw socket, as the ICMP probes need anyway.
        let listener = crate::ra::spawn(ra_tx).context("listening to Router Advertisements")?;
        loop {
            if self.dirty {
                self.dirty = false;
                self.step().await;
                self.status_dirty = true;
                if let Some(Active::Applying {
                    target: target @ None, ..
                }) = &mut self.command
                {
                    *target = Some(self.desired_generation);
                }
            }
            self.check_command();
            if let Some(e) = self.fatal.take() {
                bail!("{e}");
            }
            self.flush_events();
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
                .chain(match &self.command {
                    Some(Active::Applying { since, .. }) => Some(*since + COMMAND_WAIT),
                    _ => None,
                })
                .fold(next_full, Instant::min);
            let checkpoint_due = self.last_checkpoint + Duration::from_secs(30);
            tokio::select! {
                n = subscription.next() => {
                    let Some(first) = n else {
                        bail!("the netlink subscription closed");
                    };
                    // A burst is handled in one pass: the notifications
                    // already queued first.
                    let queued = batch(first, || subscription.queued(), NOTIFICATION_BATCH, |n| {
                        matches!(n, Notification::Overrun)
                    });
                    for n in queued {
                        match n {
                            Notification::Message { message, port, flags } => self.notification(message, port, flags),
                            Notification::Overrun => {
                                warn!("netlink notifications were lost (ENOBUFS): full resynchronisation");
                                self.full_reconciliation().await;
                            }
                        }
                    }
                }
                r = probe_rx.recv() => if let Some(r) = r { self.probe_report(r) },
                Some(o) = orders_rx.recv() => {
                    self.orders.push_back(o);
                    self.next_order();
                }
                d = done_rx.recv() => match d {
                    Some(d) => self.completion(d),
                    None => bail!("the I/O lanes stopped"),
                },
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
                _ = hup.recv() => self.start_reload(),
                _ = term.recv() => break,
                _ = int.recv() => break,
            }
        }
        info!("daemon_stopping");
        self.pending_events
            .push(NewEvent::new("daemon_stopping", "polywan is stopping"));
        self.flush_events();
        // The batch holding `daemon_stopping` and the email still waiting
        // get their last attempt (bounded by mail::SHUTDOWN).
        if let Some(mail) = self.mail.take() {
            let (done, wait) = tokio::sync::oneshot::channel();
            if mail.send(crate::mail::Request::Flush(done)).await.is_ok() {
                let _ = tokio::time::timeout(crate::mail::SHUTDOWN + Duration::from_secs(1), wait).await;
            }
        }
        listener.abort();
        for p in self.paths.values_mut() {
            if let Some((_, h)) = p.prober.take() {
                h.abort();
            }
        }
        // The API sockets go first, then the lanes (a running write
        // completes), so that the last checkpoint is not overwritten by an
        // older one.
        if let Some(api) = self.api.take() {
            api.shutdown().await;
        }
        drop(self.io.take());
        self.write_checkpoint_now();
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
                    drained: self.drained.contains(&key.uplink),
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
                    (p.ready.is_some() && !p.drained).then_some(Candidate {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_takes_nothing_beyond_its_bound_or_its_end() {
        let mut source = 2..=1001;
        let items = batch(1, || source.next(), 1000, |_| false);
        assert_eq!(items, (1..=1000).collect::<Vec<_>>());
        assert_eq!(source.next(), Some(1001), "left for the next batch");
        // An overrun ends its batch; what follows waits.
        let mut source = 2..=10;
        assert_eq!(batch(1, || source.next(), 1000, |n| *n == 5), [1, 2, 3, 4, 5]);
        assert_eq!(source.next(), Some(6));
        let mut empty = std::iter::empty::<u32>();
        assert_eq!(batch(7, || empty.next(), 1000, |_| false), [7]);
    }

    #[test]
    fn paths_without_their_assignment_wait_for_the_replacement() {
        let path = |uplink: u8, family| PathKey {
            uplink: UplinkId::new(uplink).expect("an uplink id"),
            family,
        };
        let a4 = (path(1, Family::V4), "wana".to_owned());
        let a6 = (path(1, Family::V6), "wana".to_owned());
        let b4 = (path(2, Family::V4), "wanb".to_owned());
        let applied: BTreeSet<Assignment> = [a4.clone(), b4.clone()].into();
        // Nothing known: nothing held back.
        assert!(unassigned(&applied, None).is_empty());
        assert!(unassigned(&applied, Some(&applied)).is_empty());
        // A family added to an uplink.
        let added: BTreeSet<Assignment> = [a4.clone(), a6, b4.clone()].into();
        assert_eq!(unassigned(&added, Some(&applied)), [path(1, Family::V6)].into());
        // An uplink moved to another interface by a reload.
        let moved: BTreeSet<Assignment> = [a4, (path(2, Family::V4), "wanc".to_owned())].into();
        assert_eq!(unassigned(&moved, Some(&applied)), [path(2, Family::V4)].into());
    }
}
