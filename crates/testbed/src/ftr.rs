//! Running the daemon under test (fault-tolerant-router) in the router
//! namespace.
//!
//! The configuration lives under `/run/ftr-tests/<run>`: the daemon refuses
//! configuration files whose parent directories are writable by group or
//! others (FR-CFG-5), which excludes `/tmp`. Every run has its own lock,
//! state directory and log.

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::inject::Daemon;
use crate::plan::Uplink;
use crate::topology::Topology;

/// `FTR_DAEMON_BIN`: the `fault-tolerant-router` executable under test.
pub fn daemon_bin() -> Result<PathBuf> {
    std::env::var_os("FTR_DAEMON_BIN")
        .map(PathBuf::from)
        .context("FTR_DAEMON_BIN must name the fault-tolerant-router executable")
}

/// One configured uplink of a test configuration.
#[derive(Clone, Copy, Debug)]
pub struct UplinkSpec {
    pub uplink: Uplink,
    pub id: u8,
    pub priority: Option<u16>,
    pub weight: u16,
}

impl UplinkSpec {
    pub fn new(uplink: Uplink, id: u8) -> UplinkSpec {
        UplinkSpec {
            uplink,
            id,
            priority: Some(1),
            weight: 1,
        }
    }

    pub fn priority(mut self, p: Option<u16>) -> UplinkSpec {
        self.priority = p;
        self
    }

    pub fn weight(mut self, w: u16) -> UplinkSpec {
        self.weight = w;
        self
    }
}

/// Health settings for tests: fast unless a scenario needs the defaults.
#[derive(Clone, Debug)]
pub struct HealthSpec {
    pub text: String,
}

impl HealthSpec {
    /// Rounds every second, two attempts of 300 ms, default fall and rise.
    pub fn fast() -> HealthSpec {
        HealthSpec {
            text: "interval = \"1s\"\ntimeout = \"300ms\"\nattempts = 2\n".into(),
        }
    }

    /// The defaults of SPEC.md §11.2 (detection bounds of FR-HEALTH-5).
    pub fn defaults() -> HealthSpec {
        HealthSpec { text: String::new() }
    }
}

/// An IPv4 configuration over the given uplinks, with `lan` as downlink.
/// `extra` is appended verbatim (other tables, routing settings).
pub fn ipv4_config(uplinks: &[UplinkSpec], health: &HealthSpec, routing: &str, extra: &str) -> String {
    let mut s = String::from("version = 2\n");
    if !routing.is_empty() {
        let _ = writeln!(s, "[routing]\n{routing}");
    }
    s += "[[downlink]]\ninterface = \"lan\"\n";
    for u in uplinks {
        let _ = writeln!(
            s,
            "[[uplink]]\nid = {}\nname = \"{}\"\ninterface = \"{}\"",
            u.id,
            u.uplink.to_string().to_lowercase(),
            u.uplink.l3_iface()
        );
        if let Some(p) = u.priority {
            let _ = writeln!(s, "priority = {p}");
        }
        let _ = writeln!(s, "weight = {}\n[uplink.ipv4]", u.weight);
    }
    let _ = writeln!(s, "[health]\n{}", health.text);
    s + extra
}

/// The daemon under test and its files.
pub struct Ftr {
    daemon: Option<Daemon>,
    /// Length of the log when the daemon was last started.
    log_start: usize,
    pub dir: PathBuf,
    pub config: PathBuf,
    pub lock: PathBuf,
    pub log: PathBuf,
    bin: PathBuf,
    router_ns: String,
}

impl Topology {
    /// The directory for the daemon's configuration and state of this run.
    pub fn ftr_dir(&self) -> PathBuf {
        PathBuf::from("/run/ftr-tests").join(self.run_id())
    }

    /// Writes `config` (with this run's `state_dir`) and starts the daemon.
    pub fn start_ftr(&self, config: &str) -> Result<Ftr> {
        let mut f = self.prepare_ftr(config)?;
        f.start(self)?;
        Ok(f)
    }

    /// Writes the configuration without starting the daemon (CLI tests).
    pub fn prepare_ftr(&self, config: &str) -> Result<Ftr> {
        let dir = self.ftr_dir();
        fs::create_dir_all(&dir)?;
        for d in [Path::new("/run/ftr-tests"), dir.as_path()] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o755))?;
        }
        let f = Ftr {
            daemon: None,
            log_start: 0,
            config: dir.join("config.toml"),
            lock: dir.join("lock"),
            log: self.dir().join("daemon.log"),
            dir,
            bin: daemon_bin()?,
            router_ns: self.router().name().to_owned(),
        };
        f.write_config(config)?;
        Ok(f)
    }
}

impl Ftr {
    /// Replaces the configuration file (a reload needs [`Ftr::reload`]).
    pub fn write_config(&self, config: &str) -> Result<()> {
        let state = self.dir.join("state");
        let text = config.replacen(
            "version = 2\n",
            &format!("version = 2\nstate_dir = \"{}\"\n", state.display()),
            1,
        );
        fs::write(&self.config, text)?;
        fs::set_permissions(&self.config, fs::Permissions::from_mode(0o644))?;
        Ok(())
    }

    fn args<'a>(&'a self, rest: &[&'a str]) -> Vec<String> {
        let mut v = vec!["--lock".to_owned(), self.lock.display().to_string()];
        v.extend(rest.iter().map(|s| (*s).to_owned()));
        v
    }

    /// Starts `run --config` (again, after a stop).
    pub fn start(&mut self, t: &Topology) -> Result<()> {
        let config = self.config.display().to_string();
        let args = self.args(&["run", "--config", &config]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.log_start = fs::metadata(&self.log).map(|m| m.len() as usize).unwrap_or(0);
        self.daemon = Some(t.start_daemon(&self.bin, &args)?);
        Ok(())
    }

    /// Runs a CLI command in the router namespace (with this run's lock).
    pub fn cli(&self, rest: &[&str]) -> Result<Output> {
        let args = self.args(rest);
        Ok(std::process::Command::new("ip")
            .args(["netns", "exec", &self.router_ns])
            .arg(&self.bin)
            .args(&args)
            .output()?)
    }

    /// The log of the daemon since its last start.
    pub fn log(&self) -> String {
        let all = fs::read(&self.log).unwrap_or_default();
        String::from_utf8_lossy(all.get(self.log_start..).unwrap_or_default()).into_owned()
    }

    /// Waits until the log contains `needle` `count` times or more.
    pub fn wait_log(&self, t: &Topology, needle: &str, count: usize, timeout: Duration) -> Result<Duration> {
        t.wait_for(&format!("{count}× {needle:?} in the daemon log"), timeout, || {
            if self.daemon.as_ref().is_some_and(Daemon::exited) {
                anyhow::bail!("the daemon exited:\n{}", self.log());
            }
            Ok(self.log().matches(needle).count() >= count)
        })
    }

    /// Waits until the daemon has exited (a refused startup).
    pub fn wait_exit(&self, t: &Topology, timeout: Duration) -> Result<()> {
        t.wait_for("the daemon to exit", timeout, || {
            Ok(self.daemon.as_ref().is_none_or(Daemon::exited))
        })
        .map(|_| ())
    }

    /// Waits for the first complete application of the desired state.
    pub fn wait_installed(&self, t: &Topology) -> Result<()> {
        self.wait_log(t, "applied", 1, Duration::from_secs(20)).map(|_| ())
    }

    pub fn signal(&self, sig: &str) -> Result<()> {
        self.daemon.as_ref().context("not running")?.signal(sig)
    }

    pub fn reload(&self) -> Result<()> {
        self.signal("HUP")
    }

    /// SIGTERM and the exit status.
    pub fn stop(&mut self) -> Result<std::process::ExitStatus> {
        self.daemon.take().context("not running")?.stop()
    }

    /// SIGKILL, as a crash.
    pub fn kill(&mut self) -> Result<()> {
        if let Some(d) = self.daemon.take() {
            d.signal("KILL")?;
            drop(d);
        }
        Ok(())
    }
}

impl Drop for Ftr {
    fn drop(&mut self) {
        drop(self.daemon.take());
        let _ = fs::remove_dir_all(&self.dir);
    }
}
