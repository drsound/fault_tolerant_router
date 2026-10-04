//! Configuration file (SPEC.md §11): TOML parsing, validation with precise
//! messages (file, line, key) and the resolved configuration used by every
//! other component.

mod raw;
mod validate;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;

use crate::model::{Family, FwMask, UplinkId};

pub use raw::{AllDownPolicy, Fallback, FirewallMode, Nat, OnShutdown, Protocol, Security};
pub use validate::parse_target;

/// Default location of the configuration file (FR-CFG-1).
pub const DEFAULT_PATH: &str = "/etc/fault-tolerant-router/config.toml";

/// The validated configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub routing: Routing,
    pub firewall: Firewall,
    pub downlinks: Vec<String>,
    pub uplinks: Vec<Uplink>,
    pub policies: Vec<Policy>,
    pub notify: Notify,
    pub api: Api,
    pub metrics_listen: Option<SocketAddr>,
    pub state_dir: PathBuf,
    /// SHA-256 of the configuration text, in hexadecimal (IMPL-5, FR-API-2).
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Routing {
    pub table_base: u32,
    pub rule_priority_base: u32,
    pub route_protocol: u8,
    pub fwmark_mask: FwMask,
    pub all_down_policy: AllDownPolicy,
    pub discovery_tables: Vec<u32>,
    pub manage_sysctls: bool,
    pub reconcile_interval: Duration,
    pub on_shutdown: OnShutdown,
}

/// Structural settings, which cannot change on reload (FR-CFG-4) and are
/// recorded in the manifest (IMPL-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Structural {
    pub fwmark_mask: FwMask,
    pub table_base: u32,
    pub rule_priority_base: u32,
    pub route_protocol: u8,
    pub firewall_mode: FirewallMode,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Firewall {
    pub mode: FirewallMode,
    pub nat_priority: i32,
    pub nft_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Uplink {
    pub id: UplinkId,
    pub name: String,
    pub description: String,
    pub interface: String,
    /// `None`: never a candidate (FR-SEL-2).
    pub priority: Option<u16>,
    pub weight: u16,
    pub ipv4: Option<PathSettings>,
    pub ipv6: Option<PathSettings>,
    pub health: Health,
}

impl Uplink {
    pub fn path(&self, family: Family) -> Option<&PathSettings> {
        match family {
            Family::V4 => self.ipv4.as_ref(),
            Family::V6 => self.ipv6.as_ref(),
        }
    }

    pub fn families(&self) -> impl Iterator<Item = Family> + '_ {
        Family::ALL.into_iter().filter(|f| self.path(*f).is_some())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoOr<T> {
    Auto,
    Static(T),
}

#[derive(Clone, Debug, PartialEq)]
pub struct PathSettings {
    pub source: AutoOr<IpAddr>,
    pub gateway: AutoOr<IpAddr>,
    pub gateway_onlink: bool,
    pub nat: Nat,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Health {
    pub interval: Duration,
    pub timeout: Duration,
    pub attempts: u8,
    pub required_reachable: u8,
    pub fall: u8,
    pub rise: u8,
    pub targets_v4: Vec<Target>,
    pub targets_v6: Vec<Target>,
    pub quality: Quality,
    pub quality_window: u8,
    pub quality_min_samples: u16,
}

impl Health {
    pub fn targets(&self, family: Family) -> &[Target] {
        match family {
            Family::V4 => &self.targets_v4,
            Family::V6 => &self.targets_v6,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Quality {
    pub max_rtt: Option<Duration>,
    pub max_jitter: Option<Duration>,
    pub max_loss: Option<f64>,
}

impl Quality {
    pub fn enabled(&self) -> bool {
        self.max_rtt.is_some() || self.max_jitter.is_some() || self.max_loss.is_some()
    }
}

/// A probe target (FR-PROBE-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Icmp(IpAddr),
    Tcp(SocketAddr),
}

impl Target {
    pub fn addr(&self) -> IpAddr {
        match self {
            Target::Icmp(a) => *a,
            Target::Tcp(s) => s.ip(),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Icmp(a) => write!(f, "icmp:{a}"),
            Target::Tcp(s) => write!(f, "tcp:{s}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub name: String,
    pub family: Family,
    /// `None`: any downlink.
    pub input_interface: Option<String>,
    pub source: Option<IpNet>,
    pub destination: Option<IpNet>,
    pub protocol: Option<Protocol>,
    pub destination_port: Option<(u16, u16)>,
    pub uplink: UplinkId,
    pub fallback: Fallback,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Notify {
    pub coalesce: Duration,
    pub email: Option<Email>,
    pub hooks: Vec<Hook>,
    pub hook_user: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Email {
    pub from: String,
    pub to: Vec<String>,
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    pub max_per_hour: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hook {
    pub command: Vec<String>,
    /// `None`: every event type.
    pub events: Option<Vec<String>>,
    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Api {
    pub socket: PathBuf,
    pub group: String,
}

impl Config {
    pub fn structural(&self) -> Structural {
        Structural {
            fwmark_mask: self.routing.fwmark_mask,
            table_base: self.routing.table_base,
            rule_priority_base: self.routing.rule_priority_base,
            route_protocol: self.routing.route_protocol,
            firewall_mode: self.firewall.mode,
        }
    }

    /// Whether at least one uplink enables the family (§4.3).
    pub fn manages(&self, family: Family) -> bool {
        self.uplinks.iter().any(|u| u.path(family).is_some())
    }

    pub fn uplink(&self, id: UplinkId) -> Option<&Uplink> {
        self.uplinks.iter().find(|u| u.id == id)
    }

    /// Features that this build does not implement yet. The daemon refuses
    /// to run a configuration that uses them rather than ignore them.
    pub fn unsupported_features(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.policies.is_empty() {
            v.push("policies ([[policy]])");
        }
        if self.notify.email.is_some() {
            v.push("email notifications ([notify.email])");
        }
        if !self.notify.hooks.is_empty() {
            v.push("hooks ([[notify.hook]])");
        }
        if self.metrics_listen.is_some() {
            v.push("metrics (metrics.listen)");
        }
        if self.uplinks.iter().any(|u| u.health.quality.enabled()) {
            v.push("quality gates (health.quality)");
        }
        v
    }
}

/// One validation problem.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Diagnostic {
    pub line: Option<usize>,
    pub key: String,
    pub message: String,
}

/// Every problem found in a configuration file.
#[derive(Debug)]
pub struct ConfigError {
    pub file: PathBuf,
    pub diagnostics: Vec<Diagnostic>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, d) in self.diagnostics.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{}", self.file.display())?;
            if let Some(line) = d.line {
                write!(f, ":{line}")?;
            }
            if d.key.is_empty() {
                write!(f, ": {}", d.message)?;
            } else {
                write!(f, ": {}: {}", d.key, d.message)?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// Reads and validates a configuration file.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError {
        file: path.to_owned(),
        diagnostics: vec![Diagnostic {
            line: None,
            key: String::new(),
            message: format!("cannot read: {e}"),
        }],
    })?;
    parse(&text).map_err(|diagnostics| ConfigError {
        file: path.to_owned(),
        diagnostics,
    })
}

/// Validates configuration text.
pub fn parse(text: &str) -> Result<Config, Vec<Diagnostic>> {
    check_version(text)?;
    let raw: raw::Config = toml::from_str(text).map_err(|e| {
        vec![Diagnostic {
            line: e.span().map(|s| line_of(text, s.start)),
            key: String::new(),
            message: e.message().trim_end().to_owned(),
        }]
    })?;
    let mut config = validate::validate(text, raw)?;
    config.digest = digest(text);
    Ok(config)
}

/// SHA-256 of a text, in hexadecimal.
pub fn digest(text: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// FR-CFG-1: the file starts with `version = 2`.
fn check_version(text: &str) -> Result<(), Vec<Diagnostic>> {
    let first = text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .find(|(_, l)| !l.is_empty() && !l.starts_with('#'));
    let fail = |line, message: String| {
        Err(vec![Diagnostic {
            line,
            key: "version".into(),
            message,
        }])
    };
    let Some((line, first)) = first else {
        return fail(None, "the file must start with `version = 2`".into());
    };
    let Some((key, value)) = first.split_once('=') else {
        return fail(Some(line), "the file must start with `version = 2`".into());
    };
    if key.trim() != "version" {
        return fail(Some(line), "the file must start with `version = 2`".into());
    }
    let value = value.split('#').next().unwrap_or("").trim();
    if value != "2" {
        return fail(
            Some(line),
            format!("unsupported configuration version {value} (this release reads version 2)"),
        );
    }
    Ok(())
}

pub(crate) fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].bytes().filter(|b| *b == b'\n').count() + 1
}

/// A commented example configuration (`generate-config`).
pub const EXAMPLE: &str = include_str!("example.toml");

#[cfg(test)]
mod tests;
