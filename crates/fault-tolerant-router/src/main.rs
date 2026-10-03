//! Command-line interface (SPEC.md §9).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use fault_tolerant_router::{config, nft};

#[derive(Parser)]
#[command(
    name = "fault-tolerant-router",
    version,
    about = "Multi-uplink policy routing daemon for Linux routers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckConfig { config: path, offline } => check_config(&path, offline),
        Command::GenerateConfig => {
            print!("{}", config::EXAMPLE);
            ExitCode::SUCCESS
        }
        Command::ExportNft { config: path } => match config::load(&path) {
            Ok(cfg) => {
                print!("{}", nft::ruleset(&cfg));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn check_config(path: &std::path::Path, offline: bool) -> ExitCode {
    let cfg = match config::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let unsupported = cfg.unsupported_features();
    if !unsupported.is_empty() {
        for f in unsupported {
            eprintln!("{}: {f} not supported by this development build", path.display());
        }
        return ExitCode::FAILURE;
    }
    if !offline {
        eprintln!("system prerequisite checks are not implemented yet; use --offline");
        return ExitCode::FAILURE;
    }
    println!("{}: valid", path.display());
    ExitCode::SUCCESS
}
