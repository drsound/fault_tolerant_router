//! Command-line interface (SPEC.md §9).

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use polywan::args::{Cli, Command};
use polywan::{cleanup, config, daemon, nft, state};
use tracing::error;

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
                polywan::cli::write_stdout(format_args!("{}", config::EXAMPLE), false);
                Ok(())
            }
            Command::ExportNft { config } => {
                let cfg = polywan::cli::load(&config)?;
                polywan::cli::write_stdout(format_args!("{}", nft::ruleset(&cfg)), false);
                Ok(())
            }
            Command::Cleanup { config } => {
                let cfg = polywan::cli::load(&config)?;
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
            Command::Events { follow, json, socket } => polywan::cli::events(&socket, follow, json).await,
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            // §9: only `run` refuses a configuration with its own status.
            if e.downcast_ref::<daemon::ConfigRefused>().is_some() {
                ExitCode::from(78)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

async fn check_config(path: &Path, offline: bool) -> anyhow::Result<()> {
    let cfg = polywan::cli::load(path)?;
    if !offline {
        let f = daemon::check_system(path, &cfg).await?;
        for w in &f.warnings {
            tracing::warn!("{w}");
        }
        if !f.errors.is_empty() {
            anyhow::bail!("{}", f.errors.join("\n"));
        }
    }
    polywan::say!("{}: valid", path.display());
    Ok(())
}
