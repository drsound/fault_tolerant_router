//! The daemon under test as the packaged systemd unit (AS-34: every other
//! scenario passes under it).
//!
//! With `POLYWAN_TEST_UNIT` naming the shipped `packaging/polywan.service`,
//! each start installs a copy of it under a new name in
//! `/run/systemd/system`, with a drop-in that systemd parses (the harness has
//! no unit parser) and that overrides only what a run needs: the command
//! line, the run's directories in place of the packaged ones, the router
//! namespace, the binary under test, the test hooks' environment, the log,
//! and no restart. Every unit is new, so systemd loads it on first use
//! without a `daemon-reload`. `systemctl start` returns once the daemon has
//! sent `READY=1` (or failed), so every scenario exercises the readiness of
//! IMPL-10. The drop-ins of a run are recorded in its `units.log`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use anyhow::{Context, Result};

use crate::netns;
use crate::topology::{EXEC_ROOT, POLYWAN_ROOT, Topology};

/// Where the units of the runs are installed: removed at reboot.
const UNIT_DIR: &str = "/run/systemd/system";

/// `POLYWAN_TEST_UNIT`: the shipped unit file, when the suite runs under it.
pub fn shipped_unit() -> Option<PathBuf> {
    std::env::var_os("POLYWAN_TEST_UNIT")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// What a scenario of AS-34 changes in the drop-in and the start.
#[derive(Clone, Debug, Default)]
pub struct UnitOptions {
    /// Keeps the packaged `Restart=always`: the main process changes.
    pub restart: bool,
    /// More `[Service]` settings, one per line (`TimeoutStopSec=3s`).
    pub extra: String,
    /// `systemctl start --no-block`: returns before the readiness.
    pub no_block: bool,
}

/// A started unit of a run: its name and the main process it started.
pub struct Unit {
    name: String,
    /// The main process as of the start or the last [`Unit::systemctl`]
    /// (0: none).
    pid: AtomicU32,
    /// The main process is read from systemd each time: it can restart,
    /// or not have started yet.
    live: bool,
    /// The mount point of the binary, created by systemd.
    bound: PathBuf,
}

impl Topology {
    /// Starts `binary args...` as a copy of the shipped `unit` in the router
    /// namespace, with `env` (test hooks), `reload` (the arguments of
    /// `ExecReload=`), its output appended to `daemon.log`. A daemon that
    /// fails to start is no error: its unit has no main process.
    pub fn start_unit(
        &self,
        unit: &Path,
        binary: &Path,
        args: &[&str],
        reload: &[&str],
        env: &[(String, String)],
        options: &UnitOptions,
    ) -> Result<Unit> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let name = format!("polywan-tb-{}-{seq}.service", self.run_id());
        let path = Path::new(UNIT_DIR).join(&name);
        // The binary, bound read-only (ProtectHome= hides build directories
        // under /root and /home) at a new path of the run: systemd looks the
        // executable up again inside the namespace only when it does not
        // exist outside (a file there without the execute bit fails the
        // start), and creates it as the mount point.
        let bound = self.exec_dir()?.join(format!("polywan-{seq}"));
        let dropin = self.dropin(binary, &bound, args, reload, env, options)?;
        fs::copy(unit, &path).with_context(|| format!("installing {}", path.display()))?;
        let dir = dropin_dir(&name);
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("harness.conf"), &dropin)?;
        let start = std::process::Command::new("systemctl")
            .arg("start")
            .args(options.no_block.then_some("--no-block"))
            .arg(&name)
            .stdin(std::process::Stdio::null())
            .output()
            .context("systemctl start")?;
        let unit = Unit {
            name,
            pid: AtomicU32::new(0),
            live: options.restart || options.no_block,
            bound,
        };
        unit.pid.store(unit.main_pid()?.unwrap_or(0), Ordering::Relaxed);
        let mut record = format!("== {}\n{dropin}", unit.name);
        let _ = writeln!(
            record,
            "start: {} {}{}",
            start.status,
            String::from_utf8_lossy(&start.stderr).trim(),
            unit.state()
        );
        append(&self.dir().join("units.log"), &record);
        Ok(unit)
    }

    /// The drop-in of a run's unit; each override says why.
    fn dropin(
        &self,
        binary: &Path,
        bound: &Path,
        args: &[&str],
        reload: &[&str],
        env: &[(String, String)],
        options: &UnitOptions,
    ) -> Result<String> {
        let run = self.run_id();
        let exec = |args: &[&str]| {
            std::iter::once(bound.to_string_lossy().into_owned())
                .chain(args.iter().map(|a| (*a).to_owned()))
                .map(|a| quote(&a.replace('$', "$$")))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let log = plain(&self.dir().join("daemon.log"))?;
        let mut s = String::from("# polywan-testbed: the packaged unit, overridden for one run.\n[Service]\n");
        let _ = writeln!(s, "# The run's configuration, lock and options.");
        let _ = writeln!(s, "ExecStart=\nExecStart={}", exec(args));
        let _ = writeln!(s, "ExecReload=\nExecReload={}", exec(reload));
        let _ = writeln!(
            s,
            "# The run's directories ({POLYWAN_ROOT}/{run}: configuration, state, sockets, lock;\n# {EXEC_ROOT}/{run}: executables and their records) in place of the packaged ones."
        );
        let _ = writeln!(s, "RuntimeDirectory=\nRuntimeDirectory=polywan-tests/{run}");
        let _ = writeln!(
            s,
            "StateDirectory=\nStateDirectory=polywan-tests/{run}\nStateDirectoryMode=0755"
        );
        let _ = writeln!(s, "NetworkNamespacePath=/run/netns/{}", self.router().name());
        let _ = writeln!(s, "BindReadOnlyPaths={}:{}", plain(binary)?, plain(bound)?);
        // What `ip netns exec` mounts over /etc (an entry with a target).
        let etc = self.netns_etc(crate::plan::Node::Router);
        if let Ok(entries) = fs::read_dir(&etc) {
            let _ = writeln!(s, "# The router's /etc entries, as `ip netns exec` mounts them.");
            for e in entries.flatten() {
                let target = Path::new("/etc").join(e.file_name());
                if target.exists() {
                    let _ = writeln!(s, "BindReadOnlyPaths={}:{}", plain(&e.path())?, plain(&target)?);
                }
            }
        }
        if !env.is_empty() {
            let _ = writeln!(s, "# Test hooks.");
            for (k, v) in env {
                let _ = writeln!(s, "Environment={}", quote(&format!("{k}={v}")));
            }
        }
        let _ = writeln!(s, "StandardOutput=append:{log}\nStandardError=append:{log}");
        if !options.restart {
            let _ = writeln!(
                s,
                "# Scenarios end the daemon on purpose (refused startups, SIGKILL, the crash hook)\n# and start it themselves; restarts are a subject of AS-34 alone."
            );
            let _ = writeln!(s, "Restart=no");
        }
        if !options.extra.is_empty() {
            let _ = writeln!(s, "# The scenario's settings.\n{}", options.extra.trim_end());
        }
        Ok(s)
    }
}

impl Unit {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn pid(&self) -> Option<u32> {
        if self.live {
            self.main_pid().ok().flatten()
        } else {
            Some(self.pid.load(Ordering::Relaxed)).filter(|p| *p != 0)
        }
    }

    /// Its main process according to systemd.
    pub fn main_pid(&self) -> Result<Option<u32>> {
        Ok(self.property("MainPID")?.parse().ok().filter(|p| *p != 0))
    }

    /// Whether its main process has ended.
    pub fn exited(&self) -> bool {
        self.pid().is_none_or(netns::exited)
    }

    /// `systemctl VERB... NAME`, for example `reload` or `restart`; the
    /// main process is read again afterwards.
    pub fn systemctl(&self, verb: &[&str]) -> Result<std::process::Output> {
        let out = std::process::Command::new("systemctl")
            .args(verb)
            .arg(&self.name)
            .stdin(std::process::Stdio::null())
            .output()?;
        self.pid.store(self.main_pid()?.unwrap_or(0), Ordering::Relaxed);
        Ok(out)
    }

    /// `ActiveState/SubState`, for example `active/running`.
    pub fn active_state(&self) -> Result<String> {
        Ok(format!(
            "{}/{}",
            self.property("ActiveState")?,
            self.property("SubState")?
        ))
    }

    /// `systemctl stop` (SIGTERM to the main process, IMPL-10's
    /// `KillMode=mixed`) and the main process's exit status.
    pub fn stop(&self) -> Result<ExitStatus> {
        netns::host("systemctl", ["stop", &self.name])?;
        use std::os::unix::process::ExitStatusExt;
        let status: i32 = self.property("ExecMainStatus")?.parse()?;
        // CLD_EXITED, CLD_KILLED, CLD_DUMPED (waitid(2)).
        Ok(match self.property("ExecMainCode")?.as_str() {
            "2" => ExitStatus::from_raw(status),
            "3" => ExitStatus::from_raw(status | 0x80),
            _ => ExitStatus::from_raw((status & 0xff) << 8),
        })
    }

    /// A property, as `systemctl show --value` prints it.
    pub fn property(&self, name: &str) -> Result<String> {
        Ok(netns::host("systemctl", ["show", "--value", "-p", name, &self.name])?
            .trim()
            .to_owned())
    }

    /// Its state, for the record.
    fn state(&self) -> String {
        netns::host(
            "systemctl",
            [
                "show",
                "-p",
                "ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,NRestarts",
                &self.name,
            ],
        )
        .map(|s| format!("\n{}", s.trim_end()))
        .unwrap_or_default()
    }
}

impl Drop for Unit {
    /// Kills whatever runs (as the direct mode kills its child), then
    /// removes the unit.
    fn drop(&mut self) {
        let _ = netns::host("systemctl", ["kill", "--signal=KILL", &self.name]);
        let _ = netns::host("systemctl", ["stop", &self.name]);
        let _ = netns::host("systemctl", ["reset-failed", &self.name]);
        let _ = fs::remove_file(Path::new(UNIT_DIR).join(&self.name));
        let _ = fs::remove_dir_all(dropin_dir(&self.name));
        let _ = fs::remove_file(&self.bound);
    }
}

fn dropin_dir(name: &str) -> PathBuf {
    Path::new(UNIT_DIR).join(format!("{name}.d"))
}

/// One word of a unit file setting: double-quoted, with specifiers (`%`)
/// escaped (systemd.unit(5)); command lines also escape `$`
/// (systemd.service(5)), which other settings take literally.
fn quote(word: &str) -> String {
    let mut s = String::from("\"");
    for c in word.chars() {
        match c {
            '"' | '\\' => {
                s.push('\\');
                s.push(c);
            }
            '%' => s.push_str("%%"),
            _ => s.push(c),
        }
    }
    s.push('"');
    s
}

/// A path for settings that take it literally (`StandardOutput=`, and
/// `BindReadOnlyPaths=`, which fails with a quoted path on systemd 257).
fn plain(path: &Path) -> Result<String> {
    let s = path.display().to_string();
    anyhow::ensure!(
        !s.contains(|c: char| c.is_whitespace() || matches!(c, ':' | '%' | '"' | '\\' | '\'')),
        "a path for a unit setting has a special character: {s}"
    );
    Ok(s)
}

fn append(path: &Path, text: &str) {
    use std::io::Write;
    if let Ok(mut f) = fs::File::options().create(true).append(true).open(path) {
        let _ = f.write_all(text.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn quoting() {
        assert_eq!(quote("/run/x y"), "\"/run/x y\"");
        assert_eq!(quote("a%b$c\"d\\"), "\"a%%b$c\\\"d\\\\\"");
    }
}
