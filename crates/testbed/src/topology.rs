//! The reference topology (SPEC.md §14.2).
//!
//! ```text
//!                         inet (probe targets, test servers)
//!                  isp-a /        | isp-b         \ isp-c
//!                ispa            ispb              ispc
//!     DHCPv4/v6 + RA |   CGNAT + RA |       PPPoE    |
//!                wana            wanb              wanc (ppp0)
//!                    \            |               /
//!                             router  (under test)
//!                                | lan
//!                              client
//! ```
//!
//! The router gets its uplink configuration the way an operating system
//! would: DHCPv4 leases through `udhcpc`, IPv6 addresses and default routes
//! from Router Advertisements (kernel SLAAC, `accept_ra = 2`), and a PPPoE
//! session through `pppd`. Its main table therefore holds operating-system
//! default routes for every uplink (metrics 100, 200 and 300, realm
//! [`OS_ROUTE_REALM`]), as the acceptance scenarios require.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::netns::{self, Ns};
use crate::plan::{self, Family, Node, OS_ROUTE_REALM, Uplink};

/// Build options.
#[derive(Clone, Debug)]
pub struct Options {
    /// Run identifier; random when absent. Namespaces are `tb-<run>-<node>`.
    pub run_id: Option<String>,
    /// Parent of the run's working directory (configuration files, logs, leases).
    pub work_root: PathBuf,
    /// The `ftr-testbed` executable, used to run test agents inside namespaces.
    pub agent_bin: PathBuf,
    /// Configure IPv6 (RA, SLAAC, DHCPv6) on providers A and B.
    pub ipv6: bool,
    /// Bring up provider C (PPPoE).
    pub pppoe: bool,
    /// Start the router's uplink clients (`udhcpc`, `pppd`) and wait for
    /// their configuration while building. When false, the router has no
    /// lease, no global address and no default route on its uplinks until
    /// [`Topology::start_uplink_clients`] (AS-44).
    pub uplink_clients: bool,
    /// How long to wait for leases, addresses and default routes.
    pub ready_timeout: Duration,
    /// Value of `net.ipv4.conf.default.rp_filter` in the router namespace
    /// before its interfaces are created (2 is the systemd default).
    pub router_default_rp_filter: u8,
    /// Keep the kernel's ICMP rate limits. Disabled by default, so that every
    /// rejected packet produces its ICMP error and tests stay deterministic.
    pub icmp_ratelimit: bool,
    /// Egress delay of the client's LAN interface. Without it the round trip
    /// through the namespaces takes microseconds, and an ICMP error can reach
    /// a connecting TCP socket while `connect()` still owns it; the kernel
    /// then records only a soft error and waits for the SYN retransmission
    /// (observed with IPv6). One millisecond is enough.
    pub lan_delay: Option<Duration>,
    /// Keep namespaces and files when the topology is dropped (debugging).
    pub keep: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            run_id: None,
            work_root: std::env::var_os("FTR_TESTBED_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp/ftr-testbed")),
            agent_bin: default_agent_bin(),
            ipv6: true,
            pppoe: true,
            uplink_clients: true,
            ready_timeout: Duration::from_secs(45),
            router_default_rp_filter: 2,
            icmp_ratelimit: false,
            lan_delay: Some(Duration::from_millis(1)),
            keep: std::env::var_os("FTR_TESTBED_KEEP").is_some_and(|v| v == "1"),
        }
    }
}

/// `FTR_TESTBED_BIN`, or the current executable when it is `ftr-testbed`.
fn default_agent_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("FTR_TESTBED_BIN") {
        return PathBuf::from(p);
    }
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ftr-testbed"))
}

/// A running topology. Dropping it tears everything down unless `keep` is set.
pub struct Topology {
    run_id: String,
    dir: PathBuf,
    opts: Options,
    server: Option<Child>,
    torn_down: bool,
}

/// Namespace name prefix of a run.
pub fn prefix(run_id: &str) -> String {
    format!("tb-{run_id}-")
}

fn random_run_id() -> String {
    // Parallel tests can read the same clock value (a coarse clock source
    // in a virtual machine): a per-process sequence number tells them apart.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mixed = (nanos as u64)
        ^ (u64::from(std::process::id()) << 32)
        ^ (nanos >> 64) as u64
        ^ seq.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    // Fold to 24 bits: short names keep `ip netns list` readable.
    format!("{:06x}", (mixed ^ (mixed >> 24) ^ (mixed >> 48)) & 0xff_ffff)
}

impl Topology {
    /// Builds the topology and waits until the router has leases, addresses
    /// and operating-system default routes on every configured uplink.
    pub fn build(opts: Options) -> Result<Topology> {
        if !crate::is_root() {
            bail!("the test harness needs root (network namespaces, nftables, PPPoE)");
        }
        let run_id = opts.run_id.clone().unwrap_or_else(random_run_id);
        if !run_id.chars().all(|c| c.is_ascii_alphanumeric()) || run_id.is_empty() || run_id.len() > 12 {
            bail!("run id must be 1-12 alphanumeric characters");
        }
        if netns::list()?.iter().any(|n| n.starts_with(&prefix(&run_id))) {
            bail!("run {run_id} already exists");
        }
        let dir = opts.work_root.join(&run_id);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut topo = Topology {
            run_id,
            dir,
            opts,
            server: None,
            torn_down: false,
        };
        if let Err(e) = topo.setup() {
            let diag = topo.diagnostics();
            if !topo.opts.keep {
                let _ = topo.teardown();
            }
            return Err(e.context(format!("building topology {}\n{diag}", topo.run_id)));
        }
        Ok(topo)
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The run's working directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn options(&self) -> &Options {
        &self.opts
    }

    /// The namespace of a node.
    pub fn ns(&self, node: Node) -> Ns {
        Ns::new(format!("{}{}", prefix(&self.run_id), node.short()))
    }

    pub fn router(&self) -> Ns {
        self.ns(Node::Router)
    }

    pub fn client(&self) -> Ns {
        self.ns(Node::Client)
    }

    pub fn inet(&self) -> Ns {
        self.ns(Node::Inet)
    }

    /// Uplinks brought up by this run.
    pub fn uplinks(&self) -> Vec<Uplink> {
        Uplink::ALL
            .into_iter()
            .filter(|u| *u != Uplink::C || self.opts.pppoe)
            .collect()
    }

    /// Families configured on an uplink by this run.
    pub fn families(&self, uplink: Uplink) -> Vec<Family> {
        uplink
            .families()
            .iter()
            .copied()
            .filter(|f| *f == Family::V4 || self.opts.ipv6)
            .collect()
    }

    /// The per-namespace configuration directory of a node: `ip netns exec`
    /// bind-mounts each entry over the one with the same name in `/etc`
    /// (for example `systemd` over `/etc/systemd`). Removed with the run.
    pub fn netns_etc(&self, node: Node) -> PathBuf {
        Path::new("/etc/netns").join(self.ns(node).name())
    }

    /// Path of the agent executable.
    pub fn agent_bin(&self) -> &Path {
        &self.opts.agent_bin
    }

    /// Disarms teardown on drop and returns the run identifier.
    pub fn keep(mut self) -> String {
        self.torn_down = true;
        if let Some(mut s) = self.server.take() {
            // The server keeps running inside the namespace; just forget the handle.
            let _ = s.try_wait();
        }
        self.run_id.clone()
    }

    fn setup(&mut self) -> Result<()> {
        for m in ["veth", "dummy", "pppoe", "sch_netem", "nf_tables", "nft_masq", "nf_nat"] {
            // Best effort: the module may be built in, or loaded already.
            let _ = netns::host("modprobe", [m]);
        }
        for node in Node::ALL {
            netns::host("ip", ["netns", "add", self.ns(node).name()])?;
        }
        self.sysctls()?;
        self.links()?;
        self.internet()?;
        self.provider_a()?;
        self.provider_b()?;
        if self.opts.pppoe {
            self.provider_c()?;
        }
        self.lan()?;
        self.router_uplink_settings()?;
        self.observability()?;
        if self.opts.uplink_clients {
            self.start_uplink_clients()?;
            self.wait_ready()?;
        }
        self.warm_up()?;
        Ok(())
    }

    fn sysctls(&self) -> Result<()> {
        for node in Node::ALL {
            let ns = self.ns(node);
            ns.ip("link set lo up")?;
            let fwd = if matches!(node, Node::Client) { "0" } else { "1" };
            ns.sysctl(&[
                &format!("net.ipv4.ip_forward={fwd}"),
                &format!("net.ipv6.conf.all.forwarding={fwd}"),
            ])?;
            if !self.opts.icmp_ratelimit {
                ns.sysctl(&["net.ipv4.icmp_ratelimit=0", "net.ipv6.icmp.ratelimit=0"])?;
                // Per-namespace only on recent kernels.
                let _ = ns.sysctl(&["net.ipv4.icmp_msgs_per_sec=1000000", "net.ipv4.icmp_msgs_burst=1000000"]);
            }
            if node == Node::Router {
                let rp = self.opts.router_default_rp_filter;
                ns.sysctl(&[
                    "net.ipv4.conf.all.rp_filter=0",
                    &format!("net.ipv4.conf.default.rp_filter={rp}"),
                ])?;
            } else {
                // Only the router performs duplicate address detection: it
                // keeps the other nodes quick to start.
                ns.sysctl(&[
                    "net.ipv6.conf.all.keep_addr_on_down=1",
                    "net.ipv6.conf.default.keep_addr_on_down=1",
                    "net.ipv4.ip_nonlocal_bind=1",
                    "net.ipv6.ip_nonlocal_bind=1",
                    "net.ipv6.conf.all.accept_dad=0",
                    "net.ipv6.conf.default.accept_dad=0",
                    "net.ipv4.conf.all.rp_filter=0",
                    "net.ipv4.conf.default.rp_filter=0",
                ])?;
            }
        }
        Ok(())
    }

    fn veth(&self, a: Node, a_if: &str, b: Node, b_if: &str) -> Result<()> {
        self.ns(a).run(
            "ip",
            [
                "link",
                "add",
                a_if,
                "type",
                "veth",
                "peer",
                "name",
                b_if,
                "netns",
                self.ns(b).name(),
            ],
        )?;
        self.ns(a).run("ip", ["link", "set", a_if, "up"])?;
        self.ns(b).run("ip", ["link", "set", b_if, "up"])?;
        Ok(())
    }

    fn links(&self) -> Result<()> {
        self.veth(Node::Inet, "isp-a", Node::IspA, "core")?;
        self.veth(Node::Inet, "isp-b", Node::IspB, "core")?;
        self.veth(Node::Router, "wana", Node::IspA, "wan")?;
        self.veth(Node::Router, "wanb", Node::IspB, "wan")?;
        if self.opts.pppoe {
            self.veth(Node::Inet, "isp-c", Node::IspC, "core")?;
            self.veth(Node::Router, "wanc", Node::IspC, "wan")?;
        }
        self.veth(Node::Router, "lan", Node::Client, "lan")?;
        Ok(())
    }

    fn internet(&mut self) -> Result<()> {
        let ns = self.inet();
        ns.ip("addr add 198.18.0.1/30 dev isp-a")?;
        ns.ip("addr add 198.18.0.5/30 dev isp-b")?;
        ns.ip("route add 192.0.2.0/24 via 198.18.0.2")?;
        if self.opts.pppoe {
            ns.ip("addr add 198.18.0.9/30 dev isp-c")?;
            ns.ip("route add 203.0.113.0/24 via 198.18.0.10")?;
        }
        ns.ip("addr add 2001:db8:fff0:a::1/64 dev isp-a nodad")?;
        ns.ip("addr add 2001:db8:fff0:b::1/64 dev isp-b nodad")?;
        ns.ip("-6 route add 2001:db8:a::/48 via 2001:db8:fff0:a::2")?;
        ns.ip("-6 route add 2001:db8:b::/48 via 2001:db8:fff0:b::2")?;
        ns.ip("link add targets type dummy")?;
        ns.ip("link set targets up")?;
        for a in plan::PROBE_TARGETS_V4 {
            ns.ip(&format!("addr add {a}/32 dev targets"))?;
        }
        for a in plan::PROBE_TARGETS_V6 {
            ns.ip(&format!("addr add {a}/128 dev targets nodad"))?;
        }
        ns.ip(&format!("route add local {} dev lo", plan::SERVERS_V4))?;
        ns.ip(&format!("-6 route add local {} dev lo", plan::SERVERS_V6))?;
        let log = self.dir.join("server.log");
        let events = self.dir.join("server-events.jsonl");
        let bin = self.opts.agent_bin.clone();
        let child = ns.spawn(
            &bin.to_string_lossy(),
            ["agent", "serve", "--log", &events.to_string_lossy()],
            &log,
        )?;
        self.server = Some(child);
        Ok(())
    }

    fn dnsmasq(&self, node: Node, name: &str, extra: &[&str]) -> Result<()> {
        let d = &self.dir;
        let mut args: Vec<String> = vec![
            "--conf-file=/dev/null".into(),
            "--no-resolv".into(),
            "--no-hosts".into(),
            "--port=0".into(),
            "--user=root".into(),
            "--interface=wan".into(),
            "--bind-interfaces".into(),
            "--log-dhcp".into(),
            format!("--pid-file={}", d.join(format!("dnsmasq-{name}.pid")).display()),
            format!(
                "--dhcp-leasefile={}",
                d.join(format!("dnsmasq-{name}.leases")).display()
            ),
            format!("--log-facility={}", d.join(format!("dnsmasq-{name}.log")).display()),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        self.ns(node).run("dnsmasq", &args)?;
        Ok(())
    }

    fn provider_a(&self) -> Result<()> {
        let ns = self.ns(Node::IspA);
        ns.ip("addr add 198.18.0.2/30 dev core")?;
        ns.ip("route add default via 198.18.0.1")?;
        ns.ip("addr add 2001:db8:fff0:a::2/64 dev core nodad")?;
        ns.ip("-6 route add default via 2001:db8:fff0:a::1")?;
        ns.ip("addr add 192.0.2.1/24 dev wan")?;
        let mut extra = vec![
            "--dhcp-range=192.0.2.100,192.0.2.199,255.255.255.0,2m",
            "--dhcp-option=option:router,192.0.2.1",
        ];
        if self.opts.ipv6 {
            ns.ip("addr add 2001:db8:a:ffff::1/64 dev wan nodad")?;
            extra.extend([
                "--enable-ra",
                "--dhcp-range=2001:db8:a:ffff::1000,2001:db8:a:ffff::1fff,slaac,64,2m",
                "--ra-param=wan,4,1800",
            ]);
        }
        self.dnsmasq(Node::IspA, "a", &extra)
    }

    fn provider_b(&self) -> Result<()> {
        let ns = self.ns(Node::IspB);
        ns.ip("addr add 198.18.0.6/30 dev core")?;
        ns.ip("route add default via 198.18.0.5")?;
        ns.ip("addr add 2001:db8:fff0:b::2/64 dev core nodad")?;
        ns.ip("-6 route add default via 2001:db8:fff0:b::1")?;
        ns.ip("addr add 100.64.0.1/24 dev wan")?;
        ns.nft(
            "table ip tb_cgnat {\n  chain post {\n    type nat hook postrouting priority 100;\n    oifname \"core\" ip saddr 100.64.0.0/10 masquerade\n  }\n}\n",
        )?;
        let mut extra = vec![
            "--dhcp-range=100.64.0.100,100.64.0.199,255.255.255.0,2m",
            "--dhcp-option=option:router,100.64.0.1",
        ];
        if self.opts.ipv6 {
            ns.ip("addr add 2001:db8:b:ffff::1/64 dev wan nodad")?;
            extra.extend([
                "--enable-ra",
                "--dhcp-range=2001:db8:b:ffff::,ra-only,64",
                "--ra-param=wan,4,1800",
            ]);
        }
        self.dnsmasq(Node::IspB, "b", &extra)
    }

    fn provider_c(&self) -> Result<()> {
        let ns = self.ns(Node::IspC);
        ns.ip("addr add 198.18.0.10/30 dev core")?;
        ns.ip("route add default via 198.18.0.9")?;
        ns.sysctl(&["net.ipv6.conf.wan.disable_ipv6=1"])?;
        let opts = self.dir.join("pppoe-server.options");
        fs::write(
            &opts,
            "noauth\nnoipv6\nmtu 1492\nmru 1492\nlcp-echo-interval 1\nlcp-echo-failure 3\nip-up-script /bin/true\nip-down-script /bin/true\n",
        )?;
        // User-mode PPPoE on the server side: the kernel-mode plugin path is
        // hard-coded differently across rp-pppoe versions.
        ns.run(
            "pppoe-server",
            [
                "-I",
                "wan",
                "-L",
                "203.0.113.1",
                "-R",
                "203.0.113.10",
                "-N",
                "10",
                "-O",
                &opts.to_string_lossy(),
                "-X",
                &self.dir.join("pppoe-server.pid").to_string_lossy(),
            ],
        )?;
        Ok(())
    }

    fn lan(&self) -> Result<()> {
        let r = self.router();
        r.ip(&format!("addr add {}/24 dev lan", plan::LAN_ROUTER_V4))?;
        r.ip(&format!("addr add {}/64 dev lan nodad", plan::LAN_ROUTER_V6))?;
        let c = self.client();
        c.ip(&format!("addr add {}/24 dev lan", plan::LAN_CLIENT_V4))?;
        c.ip(&format!("addr add {}/64 dev lan nodad", plan::LAN_CLIENT_V6))?;
        c.ip(&format!("route add default via {}", plan::LAN_ROUTER_V4))?;
        c.ip(&format!("-6 route add default via {}", plan::LAN_ROUTER_V6))?;
        if let Some(d) = self.opts.lan_delay {
            c.run(
                "tc",
                [
                    "qdisc",
                    "add",
                    "dev",
                    "lan",
                    "root",
                    "netem",
                    "delay",
                    &format!("{}us", d.as_micros()),
                ],
            )?;
        }
        Ok(())
    }

    fn router_uplink_settings(&self) -> Result<()> {
        let r = self.router();
        for u in [Uplink::A, Uplink::B] {
            let ifc = u.carrier_iface();
            if self.opts.ipv6 {
                r.sysctl(&[&format!("net.ipv6.conf.{ifc}.accept_ra=2")])?;
            } else {
                r.sysctl(&[
                    &format!("net.ipv6.conf.{ifc}.accept_ra=0"),
                    &format!("net.ipv6.conf.{ifc}.autoconf=0"),
                ])?;
            }
        }
        if self.opts.pppoe {
            r.sysctl(&["net.ipv6.conf.wanc.disable_ipv6=1"])?;
        }
        Ok(())
    }

    /// Starts the router's DHCPv4 clients and, with provider C, `pppd`; the
    /// build does it unless [`Options::uplink_clients`] is false. Use
    /// [`Topology::wait_ready`] to wait for their configuration.
    pub fn start_uplink_clients(&self) -> Result<()> {
        let r = self.router();
        let script = self.dir.join("udhcpc-script");
        fs::write(&script, udhcpc_script())?;
        chmod_x(&script)?;
        for u in [Uplink::A, Uplink::B] {
            let ifc = u.carrier_iface();
            let mut c = r.command("env");
            c.arg(format!("TB_METRIC={}", u.os_metric()))
                .arg(format!("TB_REALM={OS_ROUTE_REALM}"))
                .arg("udhcpc")
                .args(["-i", ifc, "-s"])
                .arg(&script)
                .arg("-p")
                .arg(self.dir.join(format!("udhcpc-{ifc}.pid")))
                .args(["-t", "10", "-T", "1", "-A", "2", "-b", "-S"]);
            let out = c.output().context("spawning udhcpc")?;
            if !out.status.success() {
                bail!("udhcpc on {ifc} failed: {}", String::from_utf8_lossy(&out.stderr));
            }
        }
        if self.opts.pppoe {
            let up = self.dir.join("pppd-ip-up");
            fs::write(&up, ppp_ip_up_script(Uplink::C.os_metric()))?;
            chmod_x(&up)?;
            r.run(
                "pppd",
                [
                    "plugin",
                    "pppoe.so",
                    "nic-wanc",
                    "noauth",
                    "noipv6",
                    "persist",
                    "maxfail",
                    "0",
                    "holdoff",
                    "1",
                    "unit",
                    "0",
                    "linkname",
                    &self.ppp_linkname(),
                    "user",
                    "testbed",
                    "noipdefault",
                    "nodefaultroute",
                    "mtu",
                    "1492",
                    "mru",
                    "1492",
                    "lcp-echo-interval",
                    "1",
                    "lcp-echo-failure",
                    "3",
                    "ip-up-script",
                    &up.to_string_lossy(),
                    "ip-down-script",
                    "/bin/true",
                    "logfile",
                    &self.dir.join("pppd.log").to_string_lossy(),
                ],
            )?;
        }
        Ok(())
    }

    fn ppp_linkname(&self) -> String {
        format!("tb-{}-c", self.run_id)
    }

    /// Counters installed in the router namespace (table `tb_observe`, owned
    /// by the harness, never by the daemon under test):
    ///
    /// - `leak4`: IPv4 packets routed by an operating-system default route
    ///   (matched by realm, see [`OS_ROUTE_REALM`]);
    /// - `<uplink><family>` (for example `a4`, `c4`, `b6`): packets leaving
    ///   through each uplink, by family.
    fn observability(&self) -> Result<()> {
        let mut rules = String::from(
            "table ip tb_observe {\n  counter leak4 {}\n  chain post {\n    type filter hook postrouting priority 400; policy accept;\n",
        );
        rules.push_str(&format!(
            "    meta rtclassid {OS_ROUTE_REALM} counter name \"leak4\"\n  }}\n}}\n"
        ));
        rules.push_str("table inet tb_egress {\n");
        for u in Uplink::ALL {
            for f in u.families() {
                rules.push_str(&format!("  counter {} {{}}\n", counter_name(u, *f)));
            }
        }
        rules.push_str("  chain post {\n    type filter hook postrouting priority 400; policy accept;\n");
        for u in Uplink::ALL {
            for f in u.families() {
                let proto = if *f == Family::V4 { "ipv4" } else { "ipv6" };
                rules.push_str(&format!(
                    "    oifname \"{}\" meta nfproto {proto} counter name \"{}\"\n",
                    u.l3_iface(),
                    counter_name(u, *f)
                ));
            }
        }
        rules.push_str("  }\n}\n");
        self.router().nft(&rules)
    }

    /// Resolves the neighbours between client and router in both directions,
    /// so that the first test packets are not queued behind address resolution.
    fn warm_up(&self) -> Result<()> {
        let c = self.client();
        c.run("ping", ["-n", "-c", "1", "-W", "2", &plan::LAN_ROUTER_V4.to_string()])?;
        if self.opts.ipv6 {
            c.run("ping", ["-n", "-c", "1", "-W", "2", &plan::LAN_ROUTER_V6.to_string()])?;
        }
        Ok(())
    }

    /// Waits until every configured uplink has its addresses and default routes.
    pub fn wait_ready(&self) -> Result<()> {
        let deadline = Instant::now() + self.opts.ready_timeout;
        loop {
            let missing = self.missing()?;
            if missing.is_empty() {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!(
                    "router not ready after {:?}: missing {}",
                    self.opts.ready_timeout,
                    missing.join(", ")
                );
            }
            sleep(Duration::from_millis(200));
        }
    }

    fn missing(&self) -> Result<Vec<String>> {
        let mut missing = Vec::new();
        for u in self.uplinks() {
            for f in self.families(u) {
                if self.uplink_address(u, f)?.is_none() {
                    missing.push(format!("{u} {f} address"));
                }
                if self.os_default_route(u, f)?.is_none() {
                    missing.push(format!("{u} {f} default route"));
                }
            }
        }
        Ok(missing)
    }

    /// First global, non-tentative address of an uplink, if any.
    pub fn uplink_address(&self, uplink: Uplink, family: Family) -> Result<Option<IpAddr>> {
        let ifc = uplink.l3_iface();
        let r = self.router();
        if !iface_exists(&r, ifc)? {
            return Ok(None);
        }
        let v = r.ip_json(&format!(
            "{} addr show dev {ifc} scope global -tentative",
            family.flag()
        ))?;
        Ok(v.as_array()
            .into_iter()
            .flatten()
            .flat_map(|l| l["addr_info"].as_array().cloned().unwrap_or_default())
            .filter(|a| a["dadfailed"].as_bool() != Some(true))
            .find_map(|a| a["local"].as_str().and_then(|s| s.parse().ok())))
    }

    /// The operating-system default route of an uplink in the router's main
    /// table, as `Some(gateway)` (`None` inside for a device-only route).
    pub fn os_default_route(&self, uplink: Uplink, family: Family) -> Result<Option<Option<IpAddr>>> {
        let ifc = uplink.l3_iface();
        let r = self.router();
        if !iface_exists(&r, ifc)? {
            return Ok(None);
        }
        let v = r.ip_json(&format!("{} route show table main default dev {ifc}", family.flag()))?;
        Ok(v.as_array()
            .and_then(|a| a.first())
            .map(|route| route["gateway"].as_str().and_then(|g| g.parse().ok())))
    }

    /// Collected state of the router and process logs, for error messages.
    pub fn diagnostics(&self) -> String {
        let mut out = String::new();
        let r = self.router();
        for cmd in [
            "-br addr",
            "route show table all",
            "-6 route show table all",
            "rule",
            "-6 rule",
        ] {
            out.push_str(&format!("--- router: ip {cmd}\n"));
            out.push_str(&r.ip(cmd).unwrap_or_else(|e| format!("{e:#}\n")));
        }
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "log") {
                    let text = fs::read_to_string(&p).unwrap_or_default();
                    let tail: Vec<&str> = text.lines().rev().take(15).collect();
                    out.push_str(&format!("--- {} (tail)\n", p.display()));
                    for l in tail.into_iter().rev() {
                        out.push_str(l);
                        out.push('\n');
                    }
                }
            }
        }
        out
    }

    /// Removes every namespace, process and file of the run.
    pub fn teardown(&mut self) -> Result<()> {
        if self.torn_down {
            return Ok(());
        }
        self.torn_down = true;
        let res = destroy(&self.run_id, &self.opts.work_root);
        if let Some(mut s) = self.server.take() {
            let _ = s.kill();
            let _ = s.wait();
        }
        res
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        if self.opts.keep && !self.torn_down {
            eprintln!(
                "ftr-testbed: keeping run {} (FTR_TESTBED_KEEP=1); remove it with `ftr-testbed down {}`",
                self.run_id, self.run_id
            );
            return;
        }
        if let Err(e) = self.teardown() {
            eprintln!("ftr-testbed: teardown of run {} failed: {e:#}", self.run_id);
        }
    }
}

/// Name of the egress counter of an uplink and family in table `inet tb_egress`.
pub fn counter_name(uplink: Uplink, family: Family) -> String {
    let u = uplink.to_string().to_ascii_lowercase();
    match family {
        Family::V4 => format!("{u}4"),
        Family::V6 => format!("{u}6"),
    }
}

fn iface_exists(ns: &Ns, ifc: &str) -> Result<bool> {
    Ok(ns.output("ip", ["link", "show", "dev", ifc])?.status.success())
}

/// Run identifiers present on the host (from namespace names).
pub fn runs() -> Result<Vec<String>> {
    let mut ids: Vec<String> = netns::list()?
        .into_iter()
        .filter_map(|n| {
            n.strip_prefix("tb-")
                .and_then(|r| r.split_once('-'))
                .map(|(id, _)| id.to_owned())
        })
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Destroys a run: kills its processes, deletes its namespaces, removes its files.
pub fn destroy(run_id: &str, work_root: &Path) -> Result<()> {
    let pre = prefix(run_id);
    let names: Vec<String> = netns::list()?.into_iter().filter(|n| n.starts_with(&pre)).collect();
    let spaces: Vec<Ns> = names.iter().map(Ns::new).collect();
    for signal in ["-TERM", "-KILL"] {
        let mut any = false;
        for ns in &spaces {
            let pids = ns.pids().unwrap_or_default();
            for pid in pids {
                any = true;
                let _ = netns::host("kill", [signal, &pid.to_string()]);
            }
        }
        if any && signal == "-TERM" {
            sleep(Duration::from_millis(500));
        }
    }
    let mut errors = Vec::new();
    for ns in &spaces {
        if let Err(e) = netns::host("ip", ["netns", "del", ns.name()]) {
            errors.push(format!("{e:#}"));
        }
        let etc = Path::new("/etc/netns").join(ns.name());
        if etc.exists() {
            let _ = fs::remove_dir_all(etc);
        }
    }
    let _ = fs::remove_file(format!("/run/ppp-tb-{run_id}-c.pid"));
    let _ = fs::remove_file(format!("/var/run/ppp-tb-{run_id}-c.pid"));
    let dir = work_root.join(run_id);
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("; "))
    }
}

fn chmod_x(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// The DHCPv4 client script: what a distribution's DHCP client does with a
/// lease (address plus default route with a per-interface metric), with the
/// harness realm on the route.
fn udhcpc_script() -> &'static str {
    r#"#!/bin/sh
# ftr-testbed udhcpc script: address and default route with a per-interface
# metric (TB_METRIC) and realm (TB_REALM).
metric=${TB_METRIC:-100}
realm=${TB_REALM:-99}
case "$1" in
  deconfig)
    ip -4 addr flush dev "$interface" scope global
    ;;
  bound|renew)
    for c in $(ip -4 -o addr show dev "$interface" scope global | awk '{print $4}'); do
      [ "${c%/*}" = "$ip" ] || ip -4 addr del "$c" dev "$interface"
    done
    ip -4 addr replace "$ip/$mask" dev "$interface" valid_lft "${lease:-forever}" preferred_lft "${lease:-forever}"
    for r in $router; do
      ip -4 route replace default via "$r" dev "$interface" metric "$metric" realm "$realm" proto dhcp
      break
    done
    ;;
esac
exit 0
"#
}

fn ppp_ip_up_script(metric: u32) -> String {
    format!(
        "#!/bin/sh\n# ftr-testbed pppd ip-up: $1 is the interface.\nip -4 route replace default dev \"$1\" metric {metric} realm {OS_ROUTE_REALM} proto static\n"
    )
}
