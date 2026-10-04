//! `polywan-testbed`: manual control of the namespace test topology, and the
//! agents that the harness runs inside namespaces.

#![forbid(unsafe_code)]

use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use testbed::{Node, Options, Topology, agent, topology};

#[derive(Parser)]
#[command(
    name = "polywan-testbed",
    version,
    about = "Network namespace test topology for PolyWAN 2.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a topology and leave it running; prints the run identifier.
    Up {
        /// Run identifier (1-12 alphanumeric characters); random by default.
        #[arg(long)]
        run_id: Option<String>,
        /// Skip IPv6 on the providers.
        #[arg(long)]
        no_ipv6: bool,
        /// Skip provider C (PPPoE).
        #[arg(long)]
        no_pppoe: bool,
        /// Working directory root (default /tmp/polywan-testbed or POLYWAN_TESTBED_DIR).
        #[arg(long)]
        work_root: Option<PathBuf>,
    },
    /// Destroy one run, or every run with --all.
    Down {
        run_id: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        work_root: Option<PathBuf>,
    },
    /// List the runs present on this host.
    List,
    /// Run a command in a node of a run (inet, ispa, ispb, ispc, router, client).
    Exec {
        run_id: String,
        node: Node,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Test agents (used by the harness inside namespaces).
    #[command(hide = true)]
    Agent {
        #[command(subcommand)]
        agent: AgentCommand,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    Serve {
        #[arg(long)]
        log: Option<String>,
    },
    Connect {
        #[arg(long, default_value_t = 1)]
        count: usize,
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 32)]
        parallel: usize,
        #[arg(long)]
        udp: bool,
        /// Source address to bind.
        #[arg(long)]
        bind: Option<std::net::IpAddr>,
        /// Interface to bind (SO_BINDTODEVICE).
        #[arg(long)]
        device: Option<String>,
        #[arg(required = true)]
        dst: Vec<SocketAddr>,
    },
    Flow {
        #[arg(long, default_value_t = 50)]
        interval_ms: u64,
        #[arg(long)]
        duration_ms: Option<u64>,
        dst: SocketAddr,
    },
    Bulk {
        #[arg(long, default_value_t = 300_000)]
        bytes: usize,
        #[arg(long, default_value_t = 10_000)]
        timeout_ms: u64,
        dst: SocketAddr,
    },
    /// One Router Advertisement without options (RFC 4861 §4.2) to all
    /// nodes, from the interface's link-local address.
    SendRa {
        #[arg(long)]
        device: String,
        /// Router lifetime in seconds.
        #[arg(long)]
        lifetime: u16,
        /// The flags byte (managed 0x80, other configuration 0x40).
        #[arg(long, default_value_t = 0)]
        flags: u8,
        /// A /64 announced for SLAAC (prefix information, on-link and
        /// autonomous, 120 s lifetimes).
        #[arg(long)]
        prefix: Option<Ipv6Addr>,
        /// Advertisements to send (a flood), `interval_us` apart.
        #[arg(long, default_value_t = 1)]
        count: u32,
        #[arg(long, default_value_t = 0)]
        interval_us: u64,
    },
    UdpSend {
        #[arg(long)]
        src_port: u16,
        #[arg(long, default_value_t = 10)]
        count: u32,
        #[arg(long, default_value_t = 100)]
        interval_ms: u64,
        dst: SocketAddr,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("polywan-testbed: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn work_root(o: Option<PathBuf>) -> PathBuf {
    o.unwrap_or_else(|| Options::default().work_root)
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Up {
            run_id,
            no_ipv6,
            no_pppoe,
            work_root: root,
        } => {
            let opts = Options {
                run_id,
                ipv6: !no_ipv6,
                pppoe: !no_pppoe,
                work_root: work_root(root),
                ..Options::default()
            };
            let topo = Topology::build(opts)?;
            let dir = topo.dir().display().to_string();
            let id = topo.keep();
            println!("{id}");
            eprintln!("run {id} is up; namespaces {}*, files in {dir}", topology::prefix(&id));
        }
        Command::Down {
            run_id,
            all,
            work_root: root,
        } => {
            let root = work_root(root);
            let ids = match (run_id, all) {
                (Some(id), false) => vec![id],
                (None, true) => topology::runs()?,
                _ => bail!("give either a run identifier or --all"),
            };
            for id in ids {
                topology::destroy(&id, &root)?;
                eprintln!("run {id} destroyed");
            }
        }
        Command::List => {
            for id in topology::runs()? {
                println!("{id}");
            }
        }
        Command::Exec { run_id, node, command } => {
            let ns = testbed::Ns::new(format!("{}{}", topology::prefix(&run_id), node.short()));
            let status = ns
                .command(&command[0])
                .args(&command[1..])
                .status()
                .context("spawning command")?;
            if !status.success() {
                bail!("command exited with {status}");
            }
        }
        Command::Agent { agent: a } => match a {
            AgentCommand::Serve { log } => agent::serve(log.as_deref())?,
            AgentCommand::Connect {
                count,
                timeout_ms,
                parallel,
                udp,
                bind,
                device,
                dst,
            } => {
                let binding = agent::Binding { source: bind, device };
                let r = agent::connect(&dst, count, udp, Duration::from_millis(timeout_ms), parallel, &binding);
                println!("{}", serde_json::to_string(&r)?);
            }
            AgentCommand::Flow {
                interval_ms,
                duration_ms,
                dst,
            } => {
                let r = agent::flow(
                    dst,
                    Duration::from_millis(interval_ms),
                    duration_ms.map(Duration::from_millis),
                );
                println!("{}", serde_json::to_string(&r)?);
            }
            AgentCommand::Bulk { bytes, timeout_ms, dst } => {
                let r = agent::bulk(dst, bytes, Duration::from_millis(timeout_ms));
                println!("{}", serde_json::to_string(&r)?);
            }
            AgentCommand::SendRa {
                device,
                lifetime,
                flags,
                prefix,
                count,
                interval_us,
            } => agent::send_ra(
                &device,
                &agent::Advertisement {
                    lifetime,
                    flags,
                    prefix,
                },
                count,
                Duration::from_micros(interval_us),
            )?,
            AgentCommand::UdpSend {
                src_port,
                count,
                interval_ms,
                dst,
            } => {
                let sent = agent::udp_send(dst, src_port, count, Duration::from_millis(interval_ms))?;
                println!("{sent}");
            }
        },
    }
    Ok(())
}
