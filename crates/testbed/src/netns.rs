//! Running commands inside network namespaces.
//!
//! Every command goes through `ip netns exec`, so the harness itself never
//! changes namespace and needs no unsafe code.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

use anyhow::{Context, Result, bail};

/// A network namespace, addressed by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ns {
    name: String,
}

impl Ns {
    pub fn new(name: impl Into<String>) -> Ns {
        Ns { name: name.into() }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// A command that runs `program` inside the namespace.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut c = Command::new("ip");
        c.args(["netns", "exec", &self.name]).arg(program);
        c
    }

    /// Runs `program args...` and returns its standard output; fails on a
    /// non-zero exit status, with the command and its standard error.
    pub fn run<I, S>(&self, program: &str, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut c = self.command(program);
        c.args(args);
        checked(c)
    }

    /// Like [`Ns::run`], splitting `args` on whitespace (for literal commands).
    pub fn cmd(&self, program: &str, args: &str) -> Result<String> {
        self.run(program, args.split_whitespace())
    }

    /// Runs an `ip` command given as one whitespace-separated string.
    pub fn ip(&self, args: &str) -> Result<String> {
        self.cmd("ip", args)
    }

    /// Runs `ip -j ...` and parses the JSON output (an empty output is `[]`).
    pub fn ip_json(&self, args: &str) -> Result<serde_json::Value> {
        let out = self.run("ip", std::iter::once("-j").chain(args.split_whitespace()))?;
        if out.trim().is_empty() {
            return Ok(serde_json::Value::Array(Vec::new()));
        }
        serde_json::from_str(&out).with_context(|| format!("parsing `ip -j {args}` in {}", self.name))
    }

    /// Runs a shell script with `sh -c`.
    pub fn sh(&self, script: &str) -> Result<String> {
        self.run("sh", ["-c", script])
    }

    /// Runs a command and returns its output whatever the exit status.
    pub fn output<I, S>(&self, program: &str, args: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut c = self.command(program);
        c.args(args).stdin(Stdio::null());
        c.output()
            .with_context(|| format!("spawning {program} in {}", self.name))
    }

    /// Applies an nftables ruleset given as text (`nft -f -`).
    pub fn nft(&self, ruleset: &str) -> Result<()> {
        let mut c = self.command("nft");
        c.args(["-f", "-"]);
        with_stdin(c, ruleset.as_bytes()).with_context(|| format!("nft ruleset in {}:\n{ruleset}", self.name))?;
        Ok(())
    }

    /// Sets sysctls (`key=value` pairs) inside the namespace.
    pub fn sysctl(&self, settings: &[&str]) -> Result<()> {
        self.run("sysctl", std::iter::once("-qw").chain(settings.iter().copied()))?;
        Ok(())
    }

    /// The value of a sysctl inside the namespace (`net.ipv4.ip_forward`).
    pub fn sysctl_get(&self, key: &str) -> Result<String> {
        Ok(self.run("sysctl", ["-n", key])?.trim().to_owned())
    }

    /// The packets of a named nftables counter in the namespace.
    pub fn counter(&self, family: &str, table: &str, name: &str) -> Result<u64> {
        let out = self.run("nft", ["-j", "list", "counter", family, table, name])?;
        let v: serde_json::Value = serde_json::from_str(&out)?;
        v["nftables"]
            .as_array()
            .into_iter()
            .flatten()
            .find_map(|o| o["counter"]["packets"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("counter {name} not found in {family} {table}"))
    }

    /// Spawns a long-running process with stdout and stderr appended to `log`.
    pub fn spawn<I, S>(&self, program: &str, args: I, log: &Path) -> Result<Child>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.spawn_env(program, args, &[], log)
    }

    /// [`Ns::spawn`] with environment variables.
    pub fn spawn_env<I, S>(&self, program: &str, args: I, env: &[(String, String)], log: &Path) -> Result<Child>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let out = File::options()
            .create(true)
            .append(true)
            .open(log)
            .with_context(|| format!("opening {}", log.display()))?;
        let err = out.try_clone()?;
        let mut c = self.command(program);
        c.args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err);
        c.spawn()
            .with_context(|| format!("spawning {program} in {}", self.name))
    }

    /// Process ids of every process running in the namespace.
    pub fn pids(&self) -> Result<Vec<u32>> {
        let out = host("ip", ["netns", "pids", &self.name])?;
        Ok(out.split_whitespace().filter_map(|p| p.parse().ok()).collect())
    }
}

/// Whether a process has ended. A zombie counts as ended: a daemon that
/// detached itself is reaped by PID 1, which some minimal inits (virtme-ng's)
/// never do.
pub fn exited(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |s| s.contains(") Z "))
}

/// Runs a command in the host namespace and returns its standard output.
pub fn host<I, S>(program: &str, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut c = Command::new(program);
    c.args(args);
    checked(c)
}

/// Names of all network namespaces of the host.
pub fn list() -> Result<Vec<String>> {
    let out = host("ip", ["netns", "list"])?;
    Ok(out
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_owned)
        .collect())
}

fn describe(c: &Command) -> String {
    std::iter::once(c.get_program())
        .chain(c.get_args())
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn checked(mut c: Command) -> Result<String> {
    c.stdin(Stdio::null());
    let what = describe(&c);
    let out = c.output().with_context(|| format!("spawning `{what}`"))?;
    if !out.status.success() {
        bail!(
            "`{what}` failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Runs a command feeding `input` on its standard input.
pub fn with_stdin(mut c: Command, input: &[u8]) -> Result<String> {
    let what = describe(&c);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().with_context(|| format!("spawning `{what}`"))?;
    child.stdin.take().context("stdin")?.write_all(input)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "`{what}` failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
