//! Running the daemon under test (polywan) in the router
//! namespace.
//!
//! The configuration lives under `/run/polywan-tests/<run>`: the daemon refuses
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
use crate::netns::Ns;
use crate::plan::{Family, Uplink};
use crate::topology::Topology;

/// `POLYWAN_DAEMON_BIN`: the `polywan` executable under test.
pub fn daemon_bin() -> Result<PathBuf> {
    std::env::var_os("POLYWAN_DAEMON_BIN")
        .map(PathBuf::from)
        .context("POLYWAN_DAEMON_BIN must name the polywan executable")
}

/// One configured uplink of a test configuration.
#[derive(Clone, Debug)]
pub struct UplinkSpec {
    pub uplink: Uplink,
    pub id: u8,
    pub priority: Option<u16>,
    pub weight: u16,
    /// The `nat` of the IPv6 section; `None` leaves it out.
    pub ipv6_nat: Option<&'static str>,
    /// Settings appended to the IPv4 section and to the IPv6 section.
    ipv4_settings: String,
    ipv6_settings: String,
}

impl UplinkSpec {
    /// Priority 1, weight 1, and IPv6 paths that masquerade: IPv6 has no
    /// NAT default (FR-NAT-1) and the LAN prefix is routed by no provider.
    pub fn new(uplink: Uplink, id: u8) -> UplinkSpec {
        UplinkSpec {
            uplink,
            id,
            priority: Some(1),
            weight: 1,
            ipv6_nat: Some("masquerade"),
            ipv4_settings: String::new(),
            ipv6_settings: String::new(),
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

    /// The `nat` of the IPv6 path (`None`: no `nat`, an invalid section).
    pub fn ipv6_nat(mut self, nat: Option<&'static str>) -> UplinkSpec {
        self.ipv6_nat = nat;
        self
    }

    /// Appends settings (TOML lines, for example `gateway = "10.99.0.1"`)
    /// to the section of the path of `family`.
    pub fn path(mut self, family: Family, settings: &str) -> UplinkSpec {
        let text = match family {
            Family::V4 => &mut self.ipv4_settings,
            Family::V6 => &mut self.ipv6_settings,
        };
        text.push_str(settings);
        if !settings.ends_with('\n') {
            text.push('\n');
        }
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

    /// These settings with `extra` (TOML lines of `[health]`, then
    /// possibly `[health.quality]`) appended.
    pub fn with(mut self, extra: &str) -> HealthSpec {
        self.text.push_str(extra);
        self
    }
}

/// The `fwmark_mask` the scenarios run with: `POLYWAN_TEST_FWMARK_MASK` (for
/// example `0xff`, `0x00ff0000`, `0xff000000`, AS-43), the default otherwise.
pub fn mask() -> u32 {
    std::env::var("POLYWAN_TEST_FWMARK_MASK")
        .ok()
        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x00ff_0000)
}

/// A field value placed in the PolyWAN field of the mark (FR-MARK-3).
pub fn encode(value: u8) -> u32 {
    u32::from(value) << mask().trailing_zeros()
}

/// A bit outside the PolyWAN field, for foreign-mark checks (AS-24).
pub fn foreign_bit(n: u32) -> u32 {
    (0..32)
        .map(|b| 1u32 << b)
        .filter(|b| b & mask() == 0)
        .nth(n as usize)
        .unwrap_or(0)
}

/// [`config`] for IPv4 with fast health settings and nothing else.
pub fn ipv4(uplinks: &[UplinkSpec]) -> String {
    family(uplinks, Family::V4)
}

/// [`config`] for one family with fast health settings and nothing else.
pub fn family(uplinks: &[UplinkSpec], family: Family) -> String {
    config(uplinks, &[family], &HealthSpec::fast(), "", "")
}

/// [`config`] for both families with fast health settings and nothing else.
pub fn dual(uplinks: &[UplinkSpec]) -> String {
    config(uplinks, &Family::ALL, &HealthSpec::fast(), "", "")
}

/// A configuration of `families` over the given uplinks, with `lan` as
/// downlink, and the per-path settings of each [`UplinkSpec`]. `routing`
/// goes into the `[routing]` table; `extra` is appended verbatim (other
/// tables).
pub fn config(uplinks: &[UplinkSpec], families: &[Family], health: &HealthSpec, routing: &str, extra: &str) -> String {
    let mut s = String::new();
    let mut routing = routing.to_owned();
    if mask() != 0x00ff_0000 {
        routing = format!("fwmark_mask = {:#x}\n{routing}", mask());
    }
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
        let _ = writeln!(s, "weight = {}", u.weight);
        for f in families {
            match f {
                Family::V4 => {
                    s += "[uplink.ipv4]\n";
                    s += &u.ipv4_settings;
                }
                Family::V6 => {
                    s += "[uplink.ipv6]\n";
                    if let Some(nat) = u.ipv6_nat {
                        let _ = writeln!(s, "nat = \"{nat}\"");
                    }
                    s += &u.ipv6_settings;
                }
            }
        }
    }
    let _ = writeln!(s, "[health]\n{}", health.text);
    s + extra
}

/// The daemon under test and its files.
pub struct Polywan {
    daemon: Option<Daemon>,
    /// Length of the log when the daemon was last started.
    log_start: usize,
    pub dir: PathBuf,
    /// The `state_dir` that [`Polywan::write_config`] writes.
    pub state: PathBuf,
    pub config: PathBuf,
    pub lock: PathBuf,
    pub log: PathBuf,
    bin: PathBuf,
    router_ns: String,
    /// Environment of the next starts (test hooks of the daemon).
    env: Vec<(String, String)>,
    /// The shipped unit file the daemon starts as (`POLYWAN_TEST_UNIT`),
    /// or `None` to start it as a child of the test.
    unit: Option<PathBuf>,
    unit_options: crate::unit::UnitOptions,
}

impl Topology {
    /// The directory for the daemon's configuration and state of this run.
    pub fn polywan_dir(&self) -> PathBuf {
        PathBuf::from(crate::topology::POLYWAN_ROOT).join(self.run_id())
    }

    /// Writes `config` (with this run's `state_dir`) and starts the daemon.
    pub fn start_polywan(&self, config: &str) -> Result<Polywan> {
        let mut f = self.prepare_polywan(config)?;
        f.start(self)?;
        Ok(f)
    }

    /// Writes the configuration without starting the daemon (CLI tests).
    pub fn prepare_polywan(&self, config: &str) -> Result<Polywan> {
        let dir = self.polywan_dir();
        fs::create_dir_all(&dir)?;
        for d in [Path::new(crate::topology::POLYWAN_ROOT), dir.as_path()] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o755))?;
        }
        let f = Polywan {
            daemon: None,
            log_start: 0,
            config: dir.join("config.toml"),
            lock: dir.join("lock"),
            log: self.dir().join("daemon.log"),
            state: dir.join("state"),
            dir,
            bin: daemon_bin()?,
            router_ns: self.router().name().to_owned(),
            env: Vec::new(),
            unit: crate::unit::shipped_unit(),
            unit_options: Default::default(),
        };
        f.write_config(config)?;
        Ok(f)
    }
}

impl Polywan {
    /// Replaces the configuration file (a reload needs [`Polywan::reload`]).
    /// The run's sockets and an existing group replace the API defaults
    /// (`/run/polywan`, group `polywan`) unless the configuration has its own
    /// `[api]` table: parallel runs must not share sockets.
    pub fn write_config(&self, config: &str) -> Result<()> {
        // The run's state directory, a top-level key: before any table.
        let mut text = format!("state_dir = \"{}\"\n{config}", self.state.display());
        if !text.contains("\n[api]") {
            let _ = write!(
                text,
                "\n[api]\nsocket = \"{}\"\nstatus_socket = \"{}\"\ngroup = \"root\"\n",
                self.dir.join("api.sock").display(),
                self.dir.join("status.sock").display()
            );
        }
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
        self.start_with(t, &[])
    }

    /// Starts `run --config` with more `run` options (`--reset-state`).
    pub fn start_with(&mut self, t: &Topology, options: &[&str]) -> Result<()> {
        let config = self.config.display().to_string();
        let mut run = vec!["run", "--config", &config];
        run.extend_from_slice(options);
        let args = self.args(&run);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.log_start = fs::metadata(&self.log).map(|m| m.len() as usize).unwrap_or(0);
        self.daemon = Some(match &self.unit {
            Some(unit) => {
                let socket = self.control_socket().display().to_string();
                let reload = self.args(&["reload", "--socket", &socket]);
                let reload: Vec<&str> = reload.iter().map(String::as_str).collect();
                t.start_daemon_unit(unit, &self.bin, &args, &reload, &self.env, &self.unit_options)?
            }
            None => t.start_daemon(&self.bin, &args, &self.env)?,
        });
        Ok(())
    }

    /// Starts the daemon as a child of the test also when the suite runs
    /// under the unit: scenarios about running without systemd.
    pub fn direct(&mut self) {
        self.unit = None;
    }

    /// The drop-in and start options of the next starts under the unit.
    pub fn set_unit_options(&mut self, options: crate::unit::UnitOptions) {
        self.unit_options = options;
    }

    /// The unit the daemon runs as, if it was started under one.
    pub fn unit(&self) -> Option<&crate::unit::Unit> {
        self.daemon.as_ref()?.unit()
    }

    /// Sets an environment variable for the next starts, for the daemon's
    /// test hooks (built with the `test-hooks` feature by `run-suite.sh`).
    pub fn set_env(&mut self, key: &str, value: &str) {
        self.env.retain(|(k, _)| k != key);
        self.env.push((key.to_owned(), value.to_owned()));
    }

    /// Runs a CLI command in the router namespace (with this run's lock and
    /// the environment set by [`Polywan::set_env`]).
    pub fn cli(&self, rest: &[&str]) -> Result<Output> {
        Ok(Ns::new(self.router_ns.as_str())
            .command(&self.bin)
            .args(self.args(rest))
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .output()?)
    }

    /// Runs `run --config` with more `run` options in the foreground until
    /// it exits, killed after 30 s: a startup that must be refused, with
    /// its exit status (§9) and diagnostics.
    pub fn run_refused(&self, options: &[&str]) -> Result<Output> {
        let config = self.config.display().to_string();
        let mut run = vec!["run", "--config", &config];
        run.extend_from_slice(options);
        Ok(Ns::new(self.router_ns.as_str())
            .command("timeout")
            .args(["--signal=KILL", "30"])
            .arg(&self.bin)
            .args(self.args(&run))
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .output()?)
    }

    /// This run's status socket ([`Polywan::write_config`]).
    pub fn status_socket(&self) -> PathBuf {
        self.dir.join("status.sock")
    }

    /// This run's control socket.
    pub fn control_socket(&self) -> PathBuf {
        self.dir.join("api.sock")
    }

    /// `GET /v1/status` through `polywan status --json` on the status
    /// socket.
    pub fn status(&self) -> Result<serde_json::Value> {
        let socket = self.status_socket().display().to_string();
        let out = self.cli(&["status", "--json", "--socket", &socket])?;
        anyhow::ensure!(out.status.success(), "status: {}", output_text(&out));
        Ok(serde_json::from_slice(&out.stdout)?)
    }

    /// `GET path` on the status socket, from the test process: a Unix
    /// socket needs no network namespace.
    fn get(&self, path: &str) -> Result<serde_json::Value> {
        let (code, body) = crate::agent::http(&self.status_socket(), "GET", path, "")?;
        anyhow::ensure!(code == 200, "GET {path}: {code} {body}");
        Ok(serde_json::from_str(&body)?)
    }

    /// Waits until `/v1/status` satisfies `cond`; fails if the daemon exits.
    /// Before the daemon serves its status socket, nothing satisfies it.
    fn wait_status(
        &self,
        t: &Topology,
        what: &str,
        timeout: Duration,
        mut cond: impl FnMut(&serde_json::Value) -> bool,
    ) -> Result<Duration> {
        t.wait_for(what, timeout, || {
            if self.daemon.as_ref().is_some_and(Daemon::exited) {
                anyhow::bail!("the daemon exited:\n{}", self.log());
            }
            Ok(self.get("/v1/status").is_ok_and(|s| cond(&s)))
        })
    }

    /// Waits until the desired state is applied, interface settings
    /// included (`generation.applied == generation.desired > 0`): unlike
    /// [`Polywan::wait_installed`], not while a setting keeps failing.
    pub fn wait_settled(&self, t: &Topology) -> Result<()> {
        self.wait_status(t, "the desired state applied", Duration::from_secs(20), |s| {
            let g = &s["generation"];
            g["desired"].as_u64().is_some_and(|d| d > 0) && g["applied"] == g["desired"]
        })
        .map(|_| ())
    }

    /// Waits until the status of `uplink`'s path of `family` ([`path`])
    /// satisfies `cond`, for example `up` and ready.
    pub fn wait_path_where(
        &self,
        t: &Topology,
        uplink: &str,
        family: Family,
        what: &str,
        timeout: Duration,
        cond: impl Fn(&serde_json::Value) -> bool,
    ) -> Result<Duration> {
        self.wait_status(t, &format!("{what} on {uplink} {family}"), timeout, |s| {
            cond(path(s, uplink, family))
        })
    }

    /// Waits until the quality window of `uplink`'s path of `family` holds
    /// `n` samples or more.
    pub fn wait_samples(&self, t: &Topology, uplink: &str, family: Family, n: u64, timeout: Duration) -> Result<()> {
        let what = format!("{n} samples");
        self.wait_path_where(t, uplink, family, &what, timeout, |p| {
            p["statistics"]["samples"].as_u64().is_some_and(|s| s >= n)
        })
        .map(|_| ())
    }

    /// The events so far through `polywan events`: (sequence, type, line).
    pub fn events(&self) -> Result<Vec<(u64, String, String)>> {
        let socket = self.status_socket().display().to_string();
        let out = self.cli(&["events", "--socket", &socket])?;
        anyhow::ensure!(out.status.success(), "events: {}", output_text(&out));
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                // TIMESTAMP #SEQ TYPE MESSAGE
                let mut w = l.split_whitespace().skip(1);
                let seq = w.next()?.strip_prefix('#')?.parse().ok()?;
                Some((seq, w.next()?.to_owned(), l.to_owned()))
            })
            .collect())
    }

    /// The sequence number of the latest event, a cursor for
    /// [`Polywan::wait_event`].
    pub fn latest_event(&self) -> Result<u64> {
        Ok(self.events()?.last().map_or(0, |e| e.0))
    }

    /// Waits until `count` events of type `kind` whose message contains
    /// `needle` exist after sequence number `after` (0: all of them; a
    /// cursor from [`Polywan::latest_event`] keeps an earlier event, a
    /// startup flap for example, from satisfying the wait), through long
    /// polls of `/v1/events` (FR-API-2) that the next event answers.
    pub fn wait_event(
        &self,
        after: u64,
        kind: &str,
        needle: &str,
        count: usize,
        timeout: Duration,
    ) -> Result<Duration> {
        let start = std::time::Instant::now();
        let (mut instance, mut after, mut found) = (None::<String>, Some(after).filter(|a| *a > 0), 0);
        loop {
            let mut query = Vec::new();
            if let Some(i) = &instance {
                query.push(format!("instance={i}"));
            }
            if let Some(a) = after {
                query.push(format!("after={a}"));
            }
            // Whole seconds within the agent's 15 s read timeout.
            let left = timeout.saturating_sub(start.elapsed());
            query.push(format!("wait={}", left.as_secs().clamp(1, 10)));
            let page = self.get(&format!("/v1/events?{}", query.join("&")))?;
            if page["reset"] == true {
                found = 0;
            }
            instance = page["instance"].as_str().map(str::to_owned);
            for e in page["events"].as_array().into_iter().flatten() {
                after = e["seq"].as_u64().or(after);
                if e["type"] == kind && e["message"].as_str().is_some_and(|m| m.contains(needle)) {
                    found += 1;
                }
            }
            if found >= count {
                return Ok(start.elapsed());
            }
            if start.elapsed() > timeout {
                anyhow::bail!("timed out after {timeout:?} waiting for {count} {kind} events with {needle:?}");
            }
        }
    }

    /// `polywan drain NAME [--force]` or `undrain NAME` on the control
    /// socket.
    pub fn drain(&self, name: &str, drain: bool, force: bool) -> Result<Output> {
        let socket = self.control_socket().display().to_string();
        let mut args = vec![if drain { "drain" } else { "undrain" }, name, "--socket", &socket];
        if force {
            args.push("--force");
        }
        self.cli(&args)
    }

    /// `polywan reload` on the control socket.
    pub fn reload_cli(&self) -> Result<Output> {
        let socket = self.control_socket().display().to_string();
        self.cli(&["reload", "--socket", &socket])
    }

    /// Replaces the configuration with `config` and reloads it through the
    /// control socket, which must succeed.
    pub fn reload_with(&self, config: &str) -> Result<Output> {
        self.write_config(config)?;
        succeeded(self.reload_cli()?)
    }

    /// `polywan notify-test` on the control socket.
    pub fn notify_test(&self) -> Result<Output> {
        let socket = self.control_socket().display().to_string();
        self.cli(&["notify-test", "--socket", &socket])
    }

    /// Runs a CLI command with this run's configuration (`--config`).
    pub fn cli_config(&self, args: &[&str]) -> Result<Output> {
        let config = self.config.display().to_string();
        let mut v = args.to_vec();
        v.extend(["--config", &config]);
        self.cli(&v)
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

    /// Waits for the first application of the desired state (its
    /// `applied` log line), also while an interface setting keeps failing
    /// (AS-27); [`Polywan::wait_settled`] waits for the settings too.
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

impl Drop for Polywan {
    fn drop(&mut self) {
        drop(self.daemon.take());
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Standard error then standard output of a command, as text.
pub fn output_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout)
}

/// The output of a command that must have succeeded; otherwise an error
/// with its [`output_text`].
pub fn succeeded(out: Output) -> Result<Output> {
    anyhow::ensure!(out.status.success(), "{}", output_text(&out));
    Ok(out)
}

/// The status (`GET /v1/status`) of `uplink`'s path of `family`; null if
/// there is none.
pub fn path<'a>(status: &'a serde_json::Value, uplink: &str, family: Family) -> &'a serde_json::Value {
    static NONE: serde_json::Value = serde_json::Value::Null;
    status["paths"]
        .as_array()
        .and_then(|p| {
            p.iter()
                .find(|p| p["uplink"] == uplink && p["family"] == family.to_string())
        })
        .unwrap_or(&NONE)
}
