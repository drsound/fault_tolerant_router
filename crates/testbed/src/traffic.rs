//! Traffic generation, uplink attribution and leak counters.

use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::process::{Child, ChildStdin, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::plan::{self, Family, Node, Uplink};
use crate::topology::{Topology, counter_name};

/// How a connection attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Connected and got the server's answer.
    Ok,
    /// ICMP destination unreachable (`ENETUNREACH` or `EHOSTUNREACH`).
    Unreachable,
    /// Connection refused (TCP RST or ICMP port unreachable).
    Refused,
    /// No answer before the timeout.
    Timeout,
    /// Any other error.
    Error,
}

/// One connection opened by the `connect` agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnResult {
    pub dst: SocketAddr,
    pub local: Option<SocketAddr>,
    /// Source address and port as seen by the server.
    pub observed: Option<SocketAddr>,
    pub outcome: Outcome,
    pub errno: Option<i32>,
    pub millis: u64,
}

impl ConnResult {
    /// The uplink the connection left through, from the address the server saw.
    pub fn uplink(&self) -> Option<Uplink> {
        self.observed.and_then(|o| plan::attribute(o.ip()))
    }
}

/// Result of a long-lived flow.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FlowReport {
    pub local: Option<SocketAddr>,
    pub observed: Option<SocketAddr>,
    pub sent: u64,
    pub received: u64,
    /// Longest interval between two consecutive echoed messages.
    pub max_gap_ms: u64,
    pub error: Option<String>,
    pub errno: Option<i32>,
    pub millis: u64,
}

impl FlowReport {
    pub fn uplink(&self) -> Option<Uplink> {
        self.observed.and_then(|o| plan::attribute(o.ip()))
    }

    /// The flow ran without errors and never stalled longer than `max_gap`.
    pub fn continuous(&self, max_gap: Duration) -> bool {
        self.error.is_none() && self.received > 0 && u128::from(self.max_gap_ms) <= max_gap.as_millis()
    }
}

/// A connection or datagram logged by the test servers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerEvent {
    pub proto: String,
    pub port: u16,
    pub peer: SocketAddr,
    pub local: Option<SocketAddr>,
    pub bytes: usize,
}

impl ServerEvent {
    pub fn uplink(&self) -> Option<Uplink> {
        plan::attribute(self.peer.ip())
    }
}

/// Result of a single ping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PingOutcome {
    Reply,
    Unreachable,
    Timeout,
}

/// Connections counted by egress uplink (`None`: failed or unattributable).
pub fn tally(results: &[ConnResult]) -> BTreeMap<Option<Uplink>, usize> {
    let mut m = BTreeMap::new();
    for r in results {
        *m.entry(r.uplink()).or_insert(0) += 1;
    }
    m
}

/// A running long-lived flow; [`Flow::stop`] ends it and returns the report.
pub struct Flow {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}

impl Flow {
    /// Closes the agent's standard input, which ends the flow, and returns its report.
    pub fn stop(mut self) -> Result<FlowReport> {
        drop(self.stdin.take());
        let child = self.child.take().context("flow already stopped")?;
        let out = child.wait_with_output()?;
        serde_json::from_slice(&out.stdout)
            .with_context(|| format!("flow agent output: {}", String::from_utf8_lossy(&out.stderr)))
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Topology {
    /// Opens `count` TCP (or UDP) connections from `node` to `destinations`
    /// distinct test servers, cycling over them, and reports each one.
    pub fn connect_many(
        &self,
        node: Node,
        family: Family,
        destinations: u8,
        count: usize,
        udp: bool,
    ) -> Result<Vec<ConnResult>> {
        let port = if udp { plan::UDP_PORT } else { plan::TCP_PORT };
        let dsts: Vec<String> = plan::servers(family, destinations)
            .into_iter()
            .map(|a| SocketAddr::new(a, port).to_string())
            .collect();
        self.connect_to(node, &dsts, count, udp, Duration::from_secs(2))
    }

    /// Opens `count` connections from `node`, cycling over `dsts` (`ip:port`).
    pub fn connect_to(
        &self,
        node: Node,
        dsts: &[String],
        count: usize,
        udp: bool,
        timeout: Duration,
    ) -> Result<Vec<ConnResult>> {
        self.connect_bound(node, dsts, count, udp, timeout, &crate::agent::Binding::default())
    }

    /// Like [`Topology::connect_to`], with sockets bound to a source address
    /// and/or an interface.
    pub fn connect_bound(
        &self,
        node: Node,
        dsts: &[String],
        count: usize,
        udp: bool,
        timeout: Duration,
        binding: &crate::agent::Binding,
    ) -> Result<Vec<ConnResult>> {
        let mut args = vec![
            "agent".to_owned(),
            "connect".into(),
            "--count".into(),
            count.to_string(),
            "--timeout-ms".into(),
            timeout.as_millis().to_string(),
        ];
        if udp {
            args.push("--udp".into());
        }
        if let Some(a) = binding.source {
            args.extend(["--bind".to_owned(), a.to_string()]);
        }
        if let Some(d) = &binding.device {
            args.extend(["--device".to_owned(), d.clone()]);
        }
        args.extend(dsts.iter().cloned());
        let out = self.ns(node).run(&self.agent_bin().to_string_lossy(), &args)?;
        serde_json::from_str(&out).context("parsing connect agent output")
    }

    /// Transfers `bytes` bytes to a test server and back (`agent bulk`).
    pub fn bulk(&self, node: Node, dst: IpAddr, bytes: usize, timeout: Duration) -> Result<FlowReport> {
        let out = self.ns(node).run(
            &self.agent_bin().to_string_lossy(),
            [
                "agent".to_owned(),
                "bulk".into(),
                "--bytes".into(),
                bytes.to_string(),
                "--timeout-ms".into(),
                timeout.as_millis().to_string(),
                SocketAddr::new(dst, plan::TCP_PORT).to_string(),
            ],
        )?;
        serde_json::from_str(&out).context("parsing bulk agent output")
    }

    /// Starts a long-lived TCP flow from `node` to `dst`.
    pub fn start_flow(&self, node: Node, dst: IpAddr, interval: Duration) -> Result<Flow> {
        let mut c = self.ns(node).command(self.agent_bin());
        c.args(["agent", "flow", "--interval-ms", &interval.as_millis().to_string()])
            .arg(SocketAddr::new(dst, plan::TCP_PORT).to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().context("spawning flow agent")?;
        let stdin = child.stdin.take();
        Ok(Flow {
            child: Some(child),
            stdin,
        })
    }

    /// Sends a one-way UDP flow from `node` (fixed source port) to the UDP sink at `dst`.
    pub fn udp_send(&self, node: Node, dst: IpAddr, src_port: u16, count: u32, interval: Duration) -> Result<()> {
        self.ns(node).run(
            &self.agent_bin().to_string_lossy(),
            [
                "agent".to_owned(),
                "udp-send".into(),
                "--src-port".into(),
                src_port.to_string(),
                "--count".into(),
                count.to_string(),
                "--interval-ms".into(),
                interval.as_millis().to_string(),
                SocketAddr::new(dst, plan::UDP_SINK_PORT).to_string(),
            ],
        )?;
        Ok(())
    }

    /// Everything the test servers logged so far.
    pub fn server_events(&self) -> Result<Vec<ServerEvent>> {
        let p = self.dir().join("server-events.jsonl");
        let text = match fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).context("server event"))
            .collect()
    }

    /// One ping from `node` to `dst` (1 s timeout).
    pub fn ping(&self, node: Node, dst: IpAddr) -> Result<PingOutcome> {
        let out = self
            .ns(node)
            .output("ping", ["-n", "-c", "1", "-W", "1", &dst.to_string()])?;
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(if out.status.success() {
            PingOutcome::Reply
        } else if text.contains("Unreachable") || text.contains("unreachable") {
            PingOutcome::Unreachable
        } else {
            PingOutcome::Timeout
        })
    }

    fn named_counter(&self, family: &str, table: &str, name: &str) -> Result<u64> {
        let out = self
            .router()
            .run("nft", ["-j", "list", "counter", family, table, name])?;
        let v: serde_json::Value = serde_json::from_str(&out)?;
        v["nftables"]
            .as_array()
            .into_iter()
            .flatten()
            .find_map(|o| o["counter"]["packets"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("counter {name} not found"))
    }

    /// IPv4 packets routed by an operating-system default route of the router
    /// (realm match) since the last [`Topology::reset_counters`]. Any non-zero
    /// value while FTR is installed is a leak (INV-3).
    pub fn ipv4_leaks(&self) -> Result<u64> {
        self.named_counter("ip", "tb_observe", "leak4")
    }

    /// Packets of `family` that left the router through `uplink` since the last reset.
    pub fn egress_packets(&self, uplink: Uplink, family: Family) -> Result<u64> {
        if !uplink.families().contains(&family) {
            bail!("uplink {uplink} has no {family}");
        }
        self.named_counter("inet", "tb_egress", &counter_name(uplink, family))
    }

    /// Resets the harness counters of the router.
    pub fn reset_counters(&self) -> Result<()> {
        self.router().cmd("nft", "reset counters table ip tb_observe")?;
        self.router().cmd("nft", "reset counters table inet tb_egress")?;
        Ok(())
    }
}
