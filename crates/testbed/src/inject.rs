//! Failure injection (SPEC.md §14.2): links, deterministic nftables drop
//! patterns in the providers, `tc netem`, PPPoE session resets, and the
//! daemon under test.

use std::path::Path;
use std::process::Child;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::netns;
use crate::plan::{self, Family, Node, Uplink};
use crate::topology::Topology;

impl Topology {
    /// Carrier loss on the router's uplink interface: the provider side of
    /// the link goes down (the router keeps its interface administratively up).
    pub fn carrier_down(&self, uplink: Uplink) -> Result<()> {
        self.ns(uplink.provider()).ip("link set wan down")?;
        Ok(())
    }

    pub fn carrier_up(&self, uplink: Uplink) -> Result<()> {
        self.ns(uplink.provider()).ip("link set wan up")?;
        Ok(())
    }

    /// The router's own uplink interface goes administratively down or up.
    pub fn router_link(&self, uplink: Uplink, up: bool) -> Result<()> {
        self.router().run(
            "ip",
            ["link", "set", uplink.carrier_iface(), if up { "up" } else { "down" }],
        )?;
        Ok(())
    }

    /// The provider loses its own upstream while the customer link stays up
    /// ("link up but provider disconnected from the internet").
    pub fn upstream_down(&self, uplink: Uplink) -> Result<()> {
        self.ns(uplink.provider()).ip("link set core down")?;
        Ok(())
    }

    pub fn upstream_up(&self, uplink: Uplink) -> Result<()> {
        let ns = self.ns(uplink.provider());
        ns.ip("link set core up")?;
        // The kernel deleted the default routes when the link went down.
        let (v4, v6) = match uplink {
            Uplink::A => ("198.18.0.1", Some("2001:db8:fff0:a::1")),
            Uplink::B => ("198.18.0.5", Some("2001:db8:fff0:b::1")),
            Uplink::C => ("198.18.0.9", Some("2001:db8:fff0:c::1")),
        };
        ns.ip(&format!("route replace default via {v4}"))?;
        if let Some(v6) = v6 {
            ns.ip(&format!("-6 route replace default via {v6}"))?;
        }
        Ok(())
    }

    /// Installs forwarding rules in the provider (table `inet tb_inject`,
    /// replaced as a whole). Each entry is an nftables rule for the forward
    /// hook, for example `ip daddr 1.1.1.1 drop`.
    pub fn provider_rules(&self, uplink: Uplink, rules: &[String]) -> Result<()> {
        let ns = self.ns(uplink.provider());
        let mut text = String::from(
            "table inet tb_inject {}\ndelete table inet tb_inject\ntable inet tb_inject {\n  chain forward {\n    type filter hook forward priority 0; policy accept;\n",
        );
        for r in rules {
            text.push_str("    ");
            text.push_str(r);
            text.push('\n');
        }
        text.push_str("  }\n}\n");
        ns.nft(&text)
    }

    /// Drops echo requests from the customer towards the default probe
    /// targets: every `every`-th one per family (deterministic), or all of
    /// them with `every = 1`.
    pub fn drop_probe_echoes(&self, uplink: Uplink, every: u32) -> Result<()> {
        let v4: Vec<String> = plan::PROBE_TARGETS_V4.iter().map(|a| a.to_string()).collect();
        let v6: Vec<String> = plan::PROBE_TARGETS_V6.iter().map(|a| a.to_string()).collect();
        let pick = if every <= 1 {
            String::new()
        } else {
            format!("numgen inc mod {every} 0 ")
        };
        let mut rules = vec![format!(
            "iifname != \"core\" ip daddr {{ {} }} icmp type echo-request {pick}counter drop",
            v4.join(", ")
        )];
        if uplink.families().contains(&Family::V6) {
            rules.push(format!(
                "iifname != \"core\" ip6 daddr {{ {} }} icmpv6 type echo-request {pick}counter drop",
                v6.join(", ")
            ));
        }
        self.provider_rules(uplink, &rules)
    }

    /// Removes the provider's injected rules.
    pub fn clear_provider_rules(&self, uplink: Uplink) -> Result<()> {
        let _ = self
            .ns(uplink.provider())
            .output("nft", ["delete", "table", "inet", "tb_inject"])?;
        Ok(())
    }

    /// Applies `tc netem` parameters (for example `delay 50ms loss 10%`) on
    /// the provider's side of the customer link, that is to traffic towards
    /// the router. Statistical scenarios only.
    pub fn netem(&self, uplink: Uplink, params: &str) -> Result<()> {
        self.ns(uplink.provider()).run(
            "tc",
            ["qdisc", "replace", "dev", "wan", "root", "netem"]
                .into_iter()
                .chain(params.split_whitespace()),
        )?;
        Ok(())
    }

    pub fn clear_netem(&self, uplink: Uplink) -> Result<()> {
        let _ = self
            .ns(uplink.provider())
            .output("tc", ["qdisc", "del", "dev", "wan", "root"])?;
        Ok(())
    }

    /// Terminates the PPPoE session from the provider side; the router's
    /// `pppd` reconnects (new `ppp0` ifindex) after its holdoff.
    pub fn pppoe_reset(&self) -> Result<()> {
        let ns = self.ns(Node::IspC);
        for pid in ns.pids()? {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            if comm.trim() == "pppd" {
                let _ = netns::host("kill", ["-TERM", &pid.to_string()]);
            }
        }
        Ok(())
    }

    /// Restarts provider C's PPPoE server with remote addresses from `first`
    /// and ends the session: the router's `pppd` reconnects with a new
    /// `ppp0` and an address of the new range.
    pub fn pppoe_renumber(&self, first: &str) -> Result<()> {
        let ns = self.ns(Node::IspC);
        for pid in ns.pids()? {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            if matches!(comm.trim(), "pppoe-server" | "pppd") {
                let _ = netns::host("kill", ["-TERM", &pid.to_string()]);
            }
        }
        self.wait_for("provider C's PPPoE server to stop", Duration::from_secs(5), || {
            Ok(ns.pids()?.iter().all(|pid| {
                std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|c| c.trim() != "pppoe-server")
                    .unwrap_or(true)
            }))
        })?;
        self.start_pppoe_server(first)
    }

    /// Forces DHCPv4 renewal on an uplink (SIGUSR1 to its `udhcpc`).
    pub fn dhcp_renew(&self, uplink: Uplink) -> Result<()> {
        let pidfile = self.dir().join(format!("udhcpc-{}.pid", uplink.carrier_iface()));
        let pid = std::fs::read_to_string(&pidfile).with_context(|| format!("reading {}", pidfile.display()))?;
        netns::host("kill", ["-USR1", pid.trim()])?;
        Ok(())
    }

    /// Starts the daemon under test in the router namespace with `args`
    /// (for example `run --config PATH`) and environment variables (its test
    /// hooks), logging to `daemon.log` in the run directory.
    pub fn start_daemon(&self, binary: &Path, args: &[&str], env: &[(String, String)]) -> Result<Daemon> {
        let log = self.dir().join("daemon.log");
        let child = self.router().spawn_env(&binary.to_string_lossy(), args, env, &log)?;
        Ok(Daemon { child: Some(child) })
    }

    /// Waits until `cond` holds, polling every 100 ms, or fails after `timeout`.
    pub fn wait_for(&self, what: &str, timeout: Duration, mut cond: impl FnMut() -> Result<bool>) -> Result<Duration> {
        let start = std::time::Instant::now();
        loop {
            if cond()? {
                return Ok(start.elapsed());
            }
            if start.elapsed() > timeout {
                anyhow::bail!("timed out after {timeout:?} waiting for {what}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The daemon process under test; killed when dropped.
pub struct Daemon {
    child: Option<Child>,
}

impl Daemon {
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Sends a signal by name (`TERM`, `HUP`, `KILL`, ...).
    pub fn signal(&self, sig: &str) -> Result<()> {
        if let Some(pid) = self.pid() {
            netns::host("kill", [format!("-{sig}"), pid.to_string()])?;
        }
        Ok(())
    }

    /// Whether the process has ended (a zombie counts as ended).
    pub fn exited(&self) -> bool {
        self.child.as_ref().is_some_and(|c| {
            std::fs::read_to_string(format!("/proc/{}/stat", c.id())).map_or(true, |s| s.contains(") Z "))
        })
    }

    /// Sends SIGTERM and waits for the exit status.
    pub fn stop(mut self) -> Result<std::process::ExitStatus> {
        self.signal("TERM")?;
        let mut child = self.child.take().context("daemon already stopped")?;
        Ok(child.wait()?)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
