//! Build-time tools: the man page and the shell completions of the
//! packages (DIST-1), generated from the command line definitions so that
//! they cannot drift from the CLI. Never part of a release binary.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Arg, ArgAction, CommandFactory, Parser};
use clap_complete::Shell;
use polywan::args::Cli;
use roff::{Roff, bold, italic, roman};

#[derive(Parser)]
enum Task {
    /// Write polywan.8 into DIR.
    Man { dir: PathBuf },
    /// Write the bash, zsh and fish completions into DIR.
    Completions { dir: PathBuf },
}

fn main() -> anyhow::Result<()> {
    match Task::parse() {
        Task::Man { dir } => write(&dir, "polywan.8", man_page().as_bytes()),
        Task::Completions { dir } => {
            for (shell, name) in [
                (Shell::Bash, "polywan"),
                (Shell::Zsh, "_polywan"),
                (Shell::Fish, "polywan.fish"),
            ] {
                let mut out = Vec::new();
                clap_complete::generate(shell, &mut Cli::command(), "polywan", &mut out);
                write(&dir, name, &out)?;
            }
            Ok(())
        }
    }
}

fn write(dir: &Path, name: &str, content: &[u8]) -> anyhow::Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("{}", dir.display()))?;
    let path = dir.join(name);
    fs::write(&path, content).with_context(|| format!("{}", path.display()))
}

/// polywan(8): one page with every command (SPEC.md §9).
fn man_page() -> String {
    let mut cmd = Cli::command();
    cmd.build();
    let version = cmd.get_version().unwrap_or_default().to_owned();
    let commands: Vec<_> = cmd
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect();
    let mut r = Roff::new();
    r.control(
        "TH",
        [
            "POLYWAN",
            "8",
            &date(),
            &format!("polywan {version}"),
            "System Administration",
        ],
    );

    r.control("SH", ["NAME"]);
    r.text([roman(format!("polywan - {}", cmd.get_about().unwrap_or_default()))]);

    r.control("SH", ["SYNOPSIS"]);
    for (i, c) in commands.iter().enumerate() {
        if i > 0 {
            r.control("br", []);
        }
        r.text(synopsis(c));
    }

    r.control("SH", ["DESCRIPTION"]);
    for p in DESCRIPTION {
        paragraph(&mut r, p);
    }

    r.control("SH", ["COMMANDS"]);
    for c in &commands {
        r.control("SS", [c.get_name()]);
        r.text(synopsis(c));
        let about = c.get_long_about().or_else(|| c.get_about());
        if let Some(about) = about {
            r.control("PP", []);
            r.text([roman(sentence(&about.to_string()))]);
        }
        for a in visible(c) {
            r.control("TP", []);
            r.text(argument(a));
            let help = a.get_long_help().or_else(|| a.get_help());
            let mut help = sentence(&help.map(|h| h.to_string()).unwrap_or_default());
            let defaults: Vec<_> = a.get_default_values().iter().map(|v| v.to_string_lossy()).collect();
            if !defaults.is_empty() && takes_value(a) {
                help += &format!(" Default: {}.", defaults.join(", "));
            }
            r.text([roman(help)]);
        }
    }

    for (section, items) in SECTIONS {
        r.control("SH", [*section]);
        for (term, text) in *items {
            r.control("TP", []);
            r.text([bold(*term)]);
            r.text([roman(*text)]);
        }
    }

    r.control("SH", ["SEE ALSO"]);
    r.text([roman(SEE_ALSO)]);
    r.render()
}

/// clap drops the final period of a doc comment.
fn sentence(text: &str) -> String {
    match text.chars().last() {
        Some(c) if c.is_alphanumeric() || c == ')' => format!("{text}."),
        _ => text.to_owned(),
    }
}

/// The page's date: SOURCE_DATE_EPOCH for reproducible package builds,
/// the current time otherwise.
fn date() -> String {
    let secs = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
            now.map(|d| d.as_secs()).unwrap_or_default()
        });
    // Days since 1970-01-01 to a Gregorian date (civil_from_days of Howard
    // Hinnant's date algorithms).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn paragraph(r: &mut Roff, text: &str) {
    r.control("PP", []);
    r.text([roman(text)]);
}

fn visible(c: &clap::Command) -> impl Iterator<Item = &Arg> {
    c.get_arguments().filter(|a| !a.is_hide_set() && a.get_id() != "help")
}

fn takes_value(a: &Arg) -> bool {
    matches!(a.get_action(), ArgAction::Set | ArgAction::Append)
}

/// `--config PATH` or `NAME`.
fn argument(a: &Arg) -> Vec<roff::Inline> {
    let value = a
        .get_value_names()
        .map(|v| v.join(" "))
        .unwrap_or_else(|| a.get_id().as_str().to_uppercase());
    match a.get_long() {
        Some(long) if takes_value(a) => vec![bold(format!("--{long}")), roman(" "), italic(value)],
        Some(long) => vec![bold(format!("--{long}"))],
        None => vec![italic(value)],
    }
}

/// `polywan run [--config PATH] [--dry-run] [--reset-state]`.
fn synopsis(c: &clap::Command) -> Vec<roff::Inline> {
    let mut line = vec![bold(format!("polywan {}", c.get_name()))];
    for a in visible(c) {
        line.push(roman(" "));
        if a.is_required_set() {
            line.extend(argument(a));
        } else {
            line.push(roman("["));
            line.extend(argument(a));
            line.push(roman("]"));
        }
    }
    line
}

const DESCRIPTION: &[&str] = &[
    "PolyWAN runs on a Linux router with several internet uplinks. It balances new outgoing connections across the healthy uplinks of the preferred priority group with the kernel's hash-based multipath routing, keeps every connection on the uplink it started on with connection marks and policy routing, and answers inbound connections through the uplink they arrived on. It probes the internet through every uplink, for IPv4 and IPv6 independently, and can apply policies that route selected traffic through a chosen uplink. Uplinks may use static, DHCP, SLAAC or PPP addressing; PolyWAN discovers their addresses and gateways and coexists with the default routes of the operating system.",
    "The daemon (polywan run) manages routing rules and routes in its own ranges, the sysctls it needs, and, in the managed firewall mode, its own nftables table. It normally runs as the systemd service polywan.service, which waits for its readiness and reloads it with systemctl reload polywan. The configuration is /etc/polywan/config.toml; the packages install a commented example, which polywan generate-config also prints.",
    "The other commands talk to the running daemon through its API sockets, or act offline while it is stopped. status and events use the status socket, readable by every local user unless api.status_group restricts it; drain, undrain, reload, notify-test and forget-uplink use the control socket, which root and the members of the polywan group (api.group) can use: membership of that group grants full control. The commands never read the configuration to find a socket; --socket selects another path.",
];

const SECTIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "FILES",
        &[
            (
                "/etc/polywan/config.toml",
                "The configuration, owned by root and writable by no one else.",
            ),
            (
                "/usr/share/doc/polywan/examples/config.toml",
                "The commented example configuration, the text of polywan generate-config.",
            ),
            (
                "/var/lib/polywan",
                "The state directory (state_dir): the manifest of the installed artifacts, the drain state and the health checkpoints; mode 0700.",
            ),
            (
                "/run/polywan/api.sock",
                "The control socket (api.socket), owned by root and the polywan group, mode 0660.",
            ),
            (
                "/run/polywan/status.sock",
                "The status socket (api.status_socket), mode 0666, or 0660 with api.status_group.",
            ),
            (
                "/run/polywan/lock",
                "The instance lock, held by the daemon and by the offline commands (cleanup, notify-test --offline, forget-uplink without a running daemon).",
            ),
        ],
    ),
    (
        "ENVIRONMENT",
        &[
            (
                "POLYWAN_LOG",
                "The log level: error, warn, info (the default), debug or trace. Logs go to standard error.",
            ),
            (
                "NOTIFY_SOCKET",
                "Set by systemd: the daemon reports READY=1 once its API sockets are open and its first reconciliation attempt has completed or reported a failure, STATUS= with a one-line summary, and STOPPING=1 at shutdown; never with --dry-run.",
            ),
        ],
    ),
    (
        "SIGNALS",
        &[
            ("SIGHUP", "Reload the configuration, like polywan reload."),
            (
                "SIGTERM, SIGINT",
                "Stop the daemon. With routing.on_shutdown = \"keep\" (the default) the routing stays in place; with \"cleanup\" every artifact is removed first.",
            ),
        ],
    ),
    (
        "EXIT STATUS",
        &[
            (
                "0",
                "Success; for status, the status was retrieved, also while the daemon is degraded.",
            ),
            ("1", "Failure."),
            ("2", "A usage error."),
            (
                "78",
                "polywan run only: the configuration refused startup. It cannot be read, parsed or validated, a configured path fails the ownership and permission checks, a configured account is absent or prohibited, or it conflicts with the structural settings or uplink identities recorded in the manifest. The service does not restart after this status.",
            ),
        ],
    ),
];

const SEE_ALSO: &str = "nft(8), ip-rule(8), ip-route(8), systemctl(1), systemd.service(5), msmtp(1). The documentation: https://github.com/drsound/polywan/tree/main/docs";
