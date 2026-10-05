//! Work outside the routing executor (SPEC.md IMPL-4): a second runtime on
//! its own thread runs the `nft` subprocesses, the state-directory writes,
//! sysctl access and the validation of reloads, and reports completions to
//! the State task, which keeps handling discovery, probe results and
//! routing deadlines meanwhile.
//!
//! Two lanes keep their own orders: the nftables lane applies transactions
//! and inspects the ruleset one at a time, so that an inspection never
//! races an application; the persistence lane owns the manifest (every
//! change of it is a job of the lane, so that no write can overwrite a newer
//! one) and runs its jobs one at a time, health checkpoints after every
//! administrative job and only the latest of them.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::checks;
use crate::config::{self, Config, Structural};
use crate::model::Family;
use crate::nftctl;
use crate::state::{Checkpoint, DrainState, Manifest, StateDir};
use crate::sysctl::{self, Setting};

/// The I/O thread and its runtime.
pub struct Io {
    handle: Handle,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Io {
    pub fn start() -> std::io::Result<Io> {
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new().name("polywan-io".into()).spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = handle_tx.send(Err(e));
                    return;
                }
            };
            let _ = handle_tx.send(Ok(rt.handle().clone()));
            rt.block_on(async {
                let _ = stopped.await;
            });
        })?;
        let handle = handle_rx
            .recv()
            .map_err(|_| std::io::Error::other("the I/O thread did not start"))??;
        Ok(Io {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}

impl Drop for Io {
    /// Stops the runtime, which cancels its tasks (an `nft` child is
    /// killed with its task), and waits for the thread.
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A set of sysctls applied together.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SysctlScope {
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

/// Jobs of the nftables lane.
pub enum NftJob {
    /// Applies a transaction, then lists the table for the comparisons of
    /// full reconciliations (FR-REC-6).
    Apply {
        seq: u64,
        nft: PathBuf,
        transaction: String,
    },
    /// Lists PolyWAN's table and the flowtables (FR-REC-6, FR-CT-2).
    Inspect { seq: u64, nft: PathBuf },
}

/// Jobs of the persistence lane.
pub enum PersistJob {
    /// Records the baselines write-ahead and applies the settings of a
    /// scope (FR-REC-3, FR-DISC-7); only checks them without management.
    Sysctls {
        seq: u64,
        scope: SysctlScope,
        settings: Vec<Setting>,
        manage: bool,
    },
    /// Validates a reloaded configuration against the manifest, binds its
    /// uplinks write-ahead and prunes the drain intent (FR-SEL-3).
    Bind {
        seq: u64,
        config: Arc<Config>,
        drain: Option<DrainState>,
    },
    /// Restores the settings of families no longer managed (FR-REC-9).
    HandBack { seq: u64, families: Vec<Family> },
    /// The drain intent, durably before it is applied (FR-SEL-3).
    Drain { seq: u64, state: DrainState },
    /// Releases the id binding of a removed uplink (FR-MARK-4).
    Forget { seq: u64, uplink: String },
    /// A health checkpoint; only the latest waiting one is written.
    Checkpoint(Box<Checkpoint>),
    /// Logs the FR-SYS-3 warning about a missing IPv6 gateway, with the
    /// causes read from the interface's settings.
    GatewayWarning {
        uplink: String,
        interface: String,
        delay: String,
    },
}

/// What a lane reports to the State task.
pub enum Done {
    NftApplied {
        seq: u64,
        /// The table listed after the application, or the failure.
        result: Result<Option<Value>, String>,
    },
    NftInspected {
        seq: u64,
        table: Result<Option<Value>, String>,
        flowtables: Result<Value, String>,
    },
    Sysctls {
        seq: u64,
        scope: SysctlScope,
        result: Result<(), String>,
        manifest: Manifest,
    },
    /// The manifest as written, or the conflicts and errors that rejected
    /// the reload; `manifest` is the lane's manifest either way.
    Bound {
        seq: u64,
        result: Result<(), Vec<String>>,
        manifest: Manifest,
    },
    HandedBack {
        seq: u64,
        result: Result<(), String>,
        manifest: Manifest,
    },
    Drained {
        seq: u64,
        result: Result<(), String>,
    },
    /// The id released, or why not; the lane's manifest either way.
    Forgotten {
        seq: u64,
        result: Result<u8, String>,
        manifest: Manifest,
    },
    Reload(ReloadOutcome),
    /// The API listeners of a reloaded configuration are bound (FR-API-1).
    ApiPrepared {
        seq: u64,
        result: Result<(), String>,
    },
}

/// A validated reload, or why it was rejected; the flowtable inspection
/// of the running configuration either way (FR-CT-2).
pub struct ReloadOutcome {
    pub seq: u64,
    pub result: Result<(Box<Config>, Vec<crate::api::Endpoint>), Vec<String>>,
    pub running_flowtables: Option<Result<Value, String>>,
}

/// Senders of the lanes.
#[derive(Clone)]
pub struct Lanes {
    handle: Handle,
    nft: mpsc::Sender<NftJob>,
    persist: mpsc::Sender<PersistJob>,
    done: mpsc::Sender<Done>,
}

/// A job that could not be queued: the queue was full, or the lane is gone
/// (an internal task ended, FR-REC-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lost {
    Full,
    Closed,
}

impl<T> From<mpsc::error::TrySendError<T>> for Lost {
    fn from(e: mpsc::error::TrySendError<T>) -> Lost {
        match e {
            mpsc::error::TrySendError::Full(_) => Lost::Full,
            mpsc::error::TrySendError::Closed(_) => Lost::Closed,
        }
    }
}

/// Bound of each lane's queue: the State task keeps at most one job of a
/// kind in flight, so the queues stay short.
const LANE_QUEUE: usize = 64;

impl Lanes {
    /// Starts both lanes on the I/O runtime; completions arrive on the
    /// returned receiver.
    pub fn start(io: &Io, state_dir: StateDir, manifest: Manifest) -> (Lanes, mpsc::Receiver<Done>) {
        let (done, done_rx) = mpsc::channel(LANE_QUEUE);
        let (nft, nft_rx) = mpsc::channel(LANE_QUEUE);
        let (persist, persist_rx) = mpsc::channel(LANE_QUEUE);
        io.handle().spawn(nft_lane(nft_rx, done.clone()));
        io.handle()
            .spawn(persist_lane(persist_rx, done.clone(), state_dir, manifest));
        (
            Lanes {
                handle: io.handle().clone(),
                nft,
                persist,
                done,
            },
            done_rx,
        )
    }

    /// Queues a job of the nftables lane.
    pub fn nft(&self, job: NftJob) -> Result<(), Lost> {
        self.nft.try_send(job).map_err(Lost::from)
    }

    /// Queues a job of the persistence lane.
    pub fn persist(&self, job: PersistJob) -> Result<(), Lost> {
        self.persist.try_send(job).map_err(Lost::from)
    }

    /// Prepares the API listeners of a reloaded configuration.
    pub fn prepare_api(&self, seq: u64, api: crate::api::Api, endpoints: Vec<crate::api::Endpoint>) {
        let done = self.done.clone();
        self.handle.spawn(async move {
            let result = api.prepare(endpoints).await;
            let _ = done.send(Done::ApiPrepared { seq, result }).await;
        });
    }

    /// Validates a reload on the I/O runtime: reading and checking the file,
    /// the trust of the binaries and the accounts, the inspection of the
    /// flowtables against the running and the proposed configuration.
    pub fn validate_reload(&self, seq: u64, path: PathBuf, running: ReloadContext) {
        let done = self.done.clone();
        self.handle.spawn(async move {
            let outcome = validate(seq, &path, running).await;
            let _ = done.send(Done::Reload(outcome)).await;
        });
    }
}

/// What reload validation needs of the running configuration.
pub struct ReloadContext {
    pub structural: Structural,
    pub state_dir: PathBuf,
    pub nft_path: PathBuf,
}

async fn validate(seq: u64, path: &std::path::Path, running: ReloadContext) -> ReloadOutcome {
    let reject = |errors: Vec<String>, running_flowtables| ReloadOutcome {
        seq,
        result: Err(errors),
        running_flowtables,
    };
    let path_owned = path.to_owned();
    let loaded = tokio::task::spawn_blocking(move || {
        let new = config::load(&path_owned).map_err(|e| vec![e.to_string()])?;
        if new.structural() != running.structural {
            return Err(vec![
                "structural settings cannot change on reload (FR-CFG-4)".to_owned(),
            ]);
        }
        // The state directory holds the bindings and the sysctl baselines.
        if new.state_dir != running.state_dir {
            return Err(vec![
                "state_dir cannot change on reload; stop, move the state directory, then start".to_owned(),
            ]);
        }
        // FR-CFG-5: nothing configured runs before its ownership is verified.
        let mut trust = checks::trusted(&path_owned, &new);
        trust.extend(checks::identities(&new));
        if !trust.errors.is_empty() {
            return Err(trust.errors);
        }
        let unsupported = new.unsupported_features();
        if !unsupported.is_empty() {
            return Err(vec![format!(
                "not supported by this development build: {}",
                unsupported.join(", ")
            )]);
        }
        let endpoints = crate::api::endpoints(&new.api).map_err(|e| vec![e])?;
        Ok((new, endpoints))
    })
    .await;
    let (new, endpoints) = match loaded {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return reject(e, None),
        Err(e) => return reject(vec![format!("validation task failed: {e}")], None),
    };
    // FR-CT-2: inspect against the running configuration, and refuse a
    // proposed configuration that would match.
    let listing = nftctl::flowtables(&running.nft_path).await;
    let proposed = if new.firewall.nft_path == running.nft_path {
        listing.clone()
    } else {
        nftctl::flowtables(&new.firewall.nft_path).await
    };
    match proposed {
        Ok(r) => {
            let found = checks::flowtables(&r, &new);
            if !found.is_empty() {
                return reject(found, Some(listing));
            }
        }
        Err(e) => return reject(vec![format!("cannot inspect the flowtables: {e}")], Some(listing)),
    }
    ReloadOutcome {
        seq,
        result: Ok((Box::new(new), endpoints)),
        running_flowtables: Some(listing),
    }
}

async fn nft_lane(mut jobs: mpsc::Receiver<NftJob>, done: mpsc::Sender<Done>) {
    while let Some(job) = jobs.recv().await {
        let report = match job {
            NftJob::Apply { seq, nft, transaction } => {
                let result = match nftctl::apply(&nft, &transaction).await {
                    Ok(()) => Ok(nftctl::table(&nft).await.ok().flatten()),
                    Err(e) => Err(e),
                };
                Done::NftApplied { seq, result }
            }
            NftJob::Inspect { seq, nft } => Done::NftInspected {
                seq,
                table: nftctl::table(&nft).await,
                flowtables: nftctl::flowtables(&nft).await,
            },
        };
        if done.send(report).await.is_err() {
            return;
        }
    }
}

async fn persist_lane(
    mut jobs: mpsc::Receiver<PersistJob>,
    done: mpsc::Sender<Done>,
    dir: StateDir,
    mut manifest: Manifest,
) {
    let mut queue: VecDeque<PersistJob> = VecDeque::new();
    let mut checkpoint: Option<Box<Checkpoint>> = None;
    loop {
        // Everything already queued, sorted: administrative jobs in order,
        // checkpoints only the latest, after them.
        while let Ok(job) = jobs.try_recv() {
            match job {
                PersistJob::Checkpoint(c) => checkpoint = Some(c),
                job => queue.push_back(job),
            }
        }
        let job = match queue.pop_front() {
            Some(job) => job,
            None => match checkpoint.take() {
                Some(c) => PersistJob::Checkpoint(c),
                None => match jobs.recv().await {
                    Some(job) => job,
                    None => return,
                },
            },
        };
        let dir2 = dir.clone();
        let m = manifest.clone();
        let run = tokio::task::spawn_blocking(move || persist(job, &dir2, m)).await;
        let (report, m) = match run {
            Ok(r) => r,
            Err(e) => {
                warn!("persistence job failed: {e}");
                continue;
            }
        };
        if let Some(m) = m {
            manifest = m;
        }
        if let Some(report) = report
            && done.send(report).await.is_err()
        {
            return;
        }
    }
}

/// Runs one job on the blocking pool; returns its report and the lane's new
/// manifest, if the job changed it.
fn persist(job: PersistJob, dir: &StateDir, mut manifest: Manifest) -> (Option<Done>, Option<Manifest>) {
    crate::test_hooks::slow_persistence();
    match job {
        PersistJob::Sysctls {
            seq,
            scope,
            settings,
            manage,
        } => {
            let result = apply_sysctls(&scope, &settings, manage, dir, &mut manifest);
            (
                Some(Done::Sysctls {
                    seq,
                    scope,
                    result,
                    manifest: manifest.clone(),
                }),
                Some(manifest),
            )
        }
        PersistJob::Bind { seq, config, drain } => {
            let conflicts: Vec<String> = manifest.check(&config).iter().map(ToString::to_string).collect();
            if !conflicts.is_empty() {
                return (
                    Some(Done::Bound {
                        seq,
                        result: Err(conflicts),
                        manifest: manifest.clone(),
                    }),
                    None,
                );
            }
            let mut bound = manifest.clone();
            bound.bind(&config);
            if let Err(e) = dir.write_manifest(&bound) {
                return (
                    Some(Done::Bound {
                        seq,
                        result: Err(vec![e.to_string()]),
                        manifest,
                    }),
                    None,
                );
            }
            // The bindings are recorded (write-ahead) whatever follows.
            let result = match drain.map(|d| dir.write_drain(&d)) {
                Some(Err(e)) => Err(vec![e.to_string()]),
                _ => Ok(()),
            };
            (
                Some(Done::Bound {
                    seq,
                    result,
                    manifest: bound.clone(),
                }),
                Some(bound),
            )
        }
        PersistJob::HandBack { seq, families } => {
            let mut failures = Vec::new();
            for family in families {
                let h = sysctl::hand_back(&mut manifest, family, sysctl::read, sysctl::write);
                for k in &h.restored {
                    info!("restored {} (family {family} handed back)", sysctl::dotted(k));
                }
                for k in &h.released {
                    info!(
                        "{} left as it is: changed since PolyWAN set it, or gone",
                        sysctl::dotted(k)
                    );
                }
                for (k, e) in h.failed {
                    failures.push(format!("{}: {e}", sysctl::dotted(k)));
                }
            }
            if let Err(e) = dir.write_manifest(&manifest) {
                failures.push(format!("manifest: {e}"));
            }
            let result = if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; "))
            };
            (
                Some(Done::HandedBack {
                    seq,
                    result,
                    manifest: manifest.clone(),
                }),
                Some(manifest),
            )
        }
        PersistJob::Drain { seq, state } => {
            let result = crate::test_hooks::step("persist drain")
                .map_err(|e| e.to_string())
                .and_then(|()| dir.write_drain(&state).map_err(|e| e.to_string()));
            (Some(Done::Drained { seq, result }), None)
        }
        PersistJob::Forget { seq, uplink } => {
            let mut released = manifest.clone();
            let result = released.forget(&uplink).and_then(|id| {
                dir.write_manifest(&released)
                    .map(|()| id.get())
                    .map_err(|e| e.to_string())
            });
            let changed = result.is_ok();
            let report = Done::Forgotten {
                seq,
                result,
                manifest: if changed { released.clone() } else { manifest },
            };
            (Some(report), changed.then_some(released))
        }
        PersistJob::Checkpoint(c) => {
            if let Err(e) = dir.write_checkpoint(&c) {
                warn!("health checkpoint: {e}");
            }
            (None, None)
        }
        PersistJob::GatewayWarning {
            uplink,
            interface,
            delay,
        } => {
            warn!(
                uplink = %uplink,
                "no IPv6 default route discovered on {interface} {delay} after startup or after its link came up: {}; a static gateway avoids depending on Router Advertisements (FR-SYS-3)",
                checks::gateway_causes(&interface, sysctl::read)
            );
            (None, None)
        }
    }
}

/// The settings of one scope: baselines recorded and written before the
/// values (write-ahead, IMPL-5); without management, differences are
/// warnings only (§4.6).
fn apply_sysctls(
    scope: &SysctlScope,
    settings: &[Setting],
    manage: bool,
    dir: &StateDir,
    manifest: &mut Manifest,
) -> Result<(), String> {
    let diffs = match sysctl::differences(settings, sysctl::read) {
        Ok(diffs) => diffs,
        // Only checked, never a prerequisite of readiness.
        Err(e) if !manage => {
            warn!("checking sysctls: {e} (manage_sysctls = false)");
            return Ok(());
        }
        Err(e) => return Err(e.to_string()),
    };
    if diffs.is_empty() {
        return Ok(());
    }
    if !manage {
        for d in diffs {
            warn!(
                "{} is {}, PolyWAN needs {} (manage_sysctls = false)",
                d.setting.display(),
                d.current,
                d.setting.value
            );
        }
        return Ok(());
    }
    let mut recorded = manifest.clone();
    sysctl::record(&mut recorded, &diffs);
    if recorded != *manifest {
        dir.write_manifest(&recorded).map_err(|e| e.to_string())?;
        *manifest = recorded;
    }
    crate::test_hooks::step(format_args!("set sysctls ({scope})")).map_err(|e| e.to_string())?;
    for d in diffs {
        sysctl::write(&d.setting.key, d.setting.value).map_err(|e| format!("{}: {e}", d.setting.display()))?;
        info!("set {} = {} (was {})", d.setting.display(), d.setting.value, d.current);
    }
    Ok(())
}
