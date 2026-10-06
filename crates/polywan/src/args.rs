//! The command line of SPEC.md §9, also read by the man page and shell
//! completion generator (`xtask`).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::{config, state};

/// `polywan --version`; a build with the test hooks says so, which the
/// release workflow checks (they are never released).
#[cfg(not(feature = "test-hooks"))]
const VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(feature = "test-hooks")]
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (test hooks)");

#[derive(Parser)]
#[command(
    name = "polywan",
    version = VERSION,
    about = "Multi-uplink policy routing daemon for Linux routers"
)]
pub struct Cli {
    /// Instance lock (tests run several daemons on one host).
    #[arg(long, global = true, hide = true, default_value = state::LOCK_PATH)]
    pub lock: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the daemon in the foreground.
    Run {
        /// The configuration file.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_PATH)]
        config: PathBuf,
        /// Compute and log every artifact change without applying it, then exit.
        #[arg(long)]
        dry_run: bool,
        /// Discard the drain state and health checkpoints, and a corrupt or
        /// unknown-version manifest (never a valid one).
        #[arg(long)]
        reset_state: bool,
    },
    /// Validate the configuration and, without --offline, the system prerequisites.
    CheckConfig {
        /// The configuration file.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_PATH)]
        config: PathBuf,
        /// Only validate the file.
        #[arg(long)]
        offline: bool,
    },
    /// Print the commented example configuration that the packages install.
    GenerateConfig,
    /// Print the nftables ruleset that the managed firewall mode installs.
    ExportNft {
        /// The configuration file.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
    /// Remove every PolyWAN artifact listed in the manifest and the
    /// configuration (refused while the daemon runs).
    Cleanup {
        /// The configuration file.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
    /// Show the daemon's status (through the status socket by default).
    Status {
        /// Print the raw JSON of GET /v1/status.
        #[arg(long)]
        json: bool,
        /// The API socket to use: the status socket by default, the control
        /// socket when the status socket is disabled.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_STATUS_SOCKET)]
        socket: PathBuf,
    },
    /// Show recent events (through the status socket by default).
    Events {
        /// Keep waiting for new events, also while the daemon stops or
        /// restarts.
        #[arg(long)]
        follow: bool,
        /// One JSON object per line.
        #[arg(long)]
        json: bool,
        /// The API socket to use: the status socket by default, the control
        /// socket when the status socket is disabled.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_STATUS_SOCKET)]
        socket: PathBuf,
    },
    /// Drain an uplink: no new connections through it (through the
    /// control socket).
    Drain {
        /// The uplink's name.
        #[arg(value_name = "NAME")]
        name: String,
        /// Drain even the last candidate of a family.
        #[arg(long)]
        force: bool,
        /// The control socket.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_API_SOCKET)]
        socket: PathBuf,
    },
    /// Undrain an uplink.
    Undrain {
        /// The uplink's name.
        #[arg(value_name = "NAME")]
        name: String,
        /// The control socket.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_API_SOCKET)]
        socket: PathBuf,
    },
    /// Reload the configuration (through the control socket).
    Reload {
        /// The control socket.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_API_SOCKET)]
        socket: PathBuf,
    },
    /// Test every configured notification channel through the daemon;
    /// --offline tests them here, as root, outside the service's sandbox.
    NotifyTest {
        /// The control socket.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_API_SOCKET, conflicts_with = "offline")]
        socket: PathBuf,
        /// Test locally while the daemon is stopped (holds the instance lock).
        #[arg(long)]
        offline: bool,
        /// The configuration file (with --offline).
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_PATH, requires = "offline")]
        config: PathBuf,
    },
    /// Release the persisted id binding of a removed uplink: through the
    /// control socket while the daemon runs, offline otherwise.
    ForgetUplink {
        /// The removed uplink's name.
        #[arg(value_name = "NAME")]
        name: String,
        /// The control socket.
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_API_SOCKET)]
        socket: PathBuf,
        /// The configuration file (offline).
        #[arg(long, value_name = "PATH", default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
}
