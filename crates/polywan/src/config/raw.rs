//! Serde image of the configuration file (SPEC.md §11.2). Every table rejects
//! unknown keys (FR-CFG-1); values are checked in [`super::validate`].

use std::path::PathBuf;

use serde::Deserialize;
use toml::Spanned;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    // Checked before deserialization (super::check_version).
    #[allow(dead_code)]
    pub version: toml::Value,
    pub routing: Option<Spanned<Routing>>,
    pub firewall: Option<Spanned<Firewall>>,
    #[serde(default)]
    pub downlink: Vec<Spanned<Downlink>>,
    #[serde(default)]
    pub uplink: Vec<Spanned<Uplink>>,
    pub health: Option<Spanned<Health>>,
    #[serde(default)]
    pub policy: Vec<Spanned<Policy>>,
    pub notify: Option<Spanned<Notify>>,
    pub api: Option<Spanned<Api>>,
    pub metrics: Option<Spanned<Metrics>>,
    pub state_dir: Option<Spanned<PathBuf>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    pub table_base: Option<i64>,
    pub rule_priority_base: Option<i64>,
    pub route_protocol: Option<i64>,
    pub fwmark_mask: Option<i64>,
    pub all_down_policy: Option<AllDownPolicy>,
    pub discovery_tables: Option<Vec<TableRef>>,
    pub manage_sysctls: Option<bool>,
    pub reconcile_interval: Option<String>,
    pub on_shutdown: Option<OnShutdown>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AllDownPolicy {
    Ready,
    Keep,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OnShutdown {
    Keep,
    Cleanup,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum TableRef {
    Id(i64),
    Name(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    pub mode: Option<FirewallMode>,
    pub nat_priority: Option<i64>,
    pub nft_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallMode {
    Managed,
    External,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Downlink {
    pub interface: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Uplink {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub interface: String,
    pub priority: Option<i64>,
    pub weight: Option<i64>,
    pub ipv4: Option<Spanned<Path>>,
    pub ipv6: Option<Spanned<Path>>,
    pub health: Option<Spanned<Health>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Path {
    pub source: Option<String>,
    pub gateway: Option<String>,
    pub gateway_onlink: Option<bool>,
    pub nat: Option<Nat>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Nat {
    Masquerade,
    Snat,
    None,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub attempts: Option<i64>,
    pub required_reachable: Option<i64>,
    pub fall: Option<i64>,
    pub rise: Option<i64>,
    pub ipv4: Option<Targets>,
    pub ipv6: Option<Targets>,
    pub quality: Option<Quality>,
    pub quality_window: Option<i64>,
    pub quality_min_samples: Option<i64>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub targets: Vec<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quality {
    pub max_rtt: Option<String>,
    pub max_jitter: Option<String>,
    pub max_loss: Option<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    pub family: PolicyFamily,
    pub input_interface: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Option<Protocol>,
    pub destination_port: Option<PortSpec>,
    pub uplink: String,
    pub fallback: Option<Fallback>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    Icmp,
    Icmpv6,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Port(i64),
    Range(String),
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    Balance,
    Block,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notify {
    pub coalesce: Option<String>,
    pub email: Option<Spanned<Email>>,
    #[serde(default)]
    pub hook: Vec<Spanned<Hook>>,
    pub hook_user: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Email {
    pub from: String,
    pub to: Vec<String>,
    pub sendmail: Option<PathBuf>,
    pub max_per_hour: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    pub command: Vec<String>,
    pub events: Option<Vec<String>>,
    pub timeout: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    pub socket: Option<PathBuf>,
    pub group: Option<String>,
    pub status_socket: Option<PathBuf>,
    pub status_group: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    pub listen: Option<String>,
}
