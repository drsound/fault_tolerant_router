//! Command-line interface (SPEC.md §9).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use polywan::{cleanup, config, daemon, nft, state};
use tracing::error;

#[derive(Parser)]
#[command(
    name = "polywan",
    version,
    about = "Multi-uplink policy routing daemon for Linux routers"
)]
struct Cli {
    /// Instance lock (tests run several daemons on one host).
    #[arg(long, global = true, hide = true, default_value = state::LOCK_PATH)]
    lock: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon in the foreground.
    Run {
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
        /// Compute and log every artifact change without applying it.
        #[arg(long)]
        dry_run: bool,
        /// Discard the drain state and health checkpoints (never the manifest).
        #[arg(long)]
        reset_state: bool,
    },
    /// Validate the configuration and, without --offline, the system prerequisites.
    CheckConfig {
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
        /// Only validate the file.
        #[arg(long)]
        offline: bool,
    },
    /// Print a commented example configuration.
    GenerateConfig,
    /// Print the nftables ruleset that the managed firewall mode installs.
    ExportNft {
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
    /// Remove every PolyWAN artifact (refused while the daemon runs).
    Cleanup {
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
    /// Show the daemon's status (through the status socket by default).
    Status {
        /// The raw JSON of `GET /v1/status`.
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = polywan::config::DEFAULT_STATUS_SOCKET)]
        socket: PathBuf,
    },
    /// Show recent events (through the status socket by default).
    Events {
        /// Keep waiting for new events.
        #[arg(long)]
        follow: bool,
        #[arg(long, default_value = polywan::config::DEFAULT_STATUS_SOCKET)]
        socket: PathBuf,
    },
    /// Drain an uplink: no new connections through it (through the
    /// control socket).
    Drain {
        name: String,
        /// Drain even the last candidate of a family.
        #[arg(long)]
        force: bool,
        #[arg(long, default_value = polywan::config::DEFAULT_API_SOCKET)]
        socket: PathBuf,
    },
    /// Undrain an uplink.
    Undrain {
        name: String,
        #[arg(long, default_value = polywan::config::DEFAULT_API_SOCKET)]
        socket: PathBuf,
    },
    /// Reload the configuration (through the control socket).
    Reload {
        #[arg(long, default_value = polywan::config::DEFAULT_API_SOCKET)]
        socket: PathBuf,
    },
    /// Test every configured notification channel through the daemon;
    /// --offline tests them here, as root, outside the service's sandbox.
    NotifyTest {
        #[arg(long, default_value = polywan::config::DEFAULT_API_SOCKET, conflicts_with = "offline")]
        socket: PathBuf,
        /// Test locally while the daemon is stopped (holds the instance lock).
        #[arg(long)]
        offline: bool,
        #[arg(long, default_value = config::DEFAULT_PATH, requires = "offline")]
        config: PathBuf,
    },
    /// Release the persisted id binding of a removed uplink: through the
    /// control socket while the daemon runs, offline otherwise.
    ForgetUplink {
        name: String,
        #[arg(long, default_value = polywan::config::DEFAULT_API_SOCKET)]
        socket: PathBuf,
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
}

fn init_logging() {
    let level = match std::env::var("POLYWAN_LOG").as_deref() {
        Ok("trace") => tracing::Level::TRACE,
        Ok("debug") => tracing::Level::DEBUG,
        Ok("warn") => tracing::Level::WARN,
        Ok("error") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_max_level(level)
        .with_target(false)
        .init();
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            error!("cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        match cli.command {
            Command::Run {
                config,
                dry_run,
                reset_state,
            } => {
                daemon::run(daemon::Options {
                    config,
                    dry_run,
                    reset_state,
                    lock: cli.lock,
                })
                .await
            }
            Command::CheckConfig { config, offline } => check_config(&config, offline).await,
            Command::GenerateConfig => {
                print!("{}", config::EXAMPLE);
                Ok(())
            }
            Command::ExportNft { config } => {
                let cfg = load(&config)?;
                print!("{}", nft::ruleset(&cfg));
                Ok(())
            }
            Command::Cleanup { config } => {
                let cfg = load(&config)?;
                let _lock = state::InstanceLock::acquire(&cli.lock)?;
                let dir = state::StateDir {
                    path: cfg.state_dir.clone(),
                };
                cleanup::run(&cfg, &dir).await
            }
            Command::ForgetUplink { name, socket, config } => {
                polywan::cli::forget(&socket, &name, &config, &cli.lock).await
            }
            Command::Reload { socket } => polywan::cli::reload(&socket).await,
            Command::NotifyTest {
                socket,
                offline,
                config,
            } => {
                if offline {
                    polywan::cli::notify_test_offline(&config, &cli.lock).await
                } else {
                    polywan::cli::notify_test(&socket).await
                }
            }
            Command::Status { json, socket } => polywan::cli::status(&socket, json).await,
            Command::Drain { name, force, socket } => polywan::cli::drain(&socket, &name, true, force).await,
            Command::Undrain { name, socket } => polywan::cli::drain(&socket, &name, false, false).await,
            Command::Events { follow, socket } => polywan::cli::events(&socket, follow).await,
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn load(path: &Path) -> anyhow::Result<config::Config> {
    config::load(path).map_err(|e| anyhow::anyhow!("{e}"))
}

async fn check_config(path: &Path, offline: bool) -> anyhow::Result<()> {
    let cfg = load(path)?;
    if !offline {
        let f = daemon::check_system(path, &cfg).await?;
        for w in &f.warnings {
            tracing::warn!("{w}");
        }
        if !f.errors.is_empty() {
            anyhow::bail!("{}", f.errors.join("\n"));
        }
    }
    println!("{}: valid", path.display());
    Ok(())
}
