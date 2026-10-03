//! Prerequisite checks of startup and `check-config` (SPEC.md PLAT-1,
//! PLAT-2, FR-CFG-5, FR-ROUTE-6, FR-COEX-1, FR-CT-1, FR-CT-2, FR-NAT-4,
//! FR-DISC-8). Errors refuse startup; warnings are logged.

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::Config;
use crate::netlink::msg::{ObservedAction, TABLE_MAIN};
use crate::nftctl;
use crate::plan::Layout;
use crate::system::System;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Findings {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl Findings {
    pub fn extend(&mut self, other: Findings) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }
}

/// Parses the leading `major.minor` of a version string.
pub fn version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// PLAT-1: Linux 6.1 or later.
pub fn kernel(osrelease: &str) -> Findings {
    let mut f = Findings::default();
    match version(osrelease) {
        Some((ma, mi, _)) if (ma, mi) >= (6, 1) => {}
        _ => f.errors.push(format!(
            "Linux {osrelease} is not supported: Linux 6.1 or later is required (PLAT-1)"
        )),
    }
    f
}

/// PLAT-2: nftables 1.0.6 or later (`nft --version` output).
pub fn nftables(version_output: &str) -> Findings {
    let mut f = Findings::default();
    let v = version_output
        .split_whitespace()
        .find(|w| w.starts_with('v'))
        .and_then(|w| version(&w[1..]));
    match v {
        Some(v) if v >= (1, 0, 6) => {}
        _ => f.errors.push(format!(
            "nftables {:?} is not supported: 1.0.6 or later is required for the managed firewall mode (PLAT-2)",
            version_output.trim()
        )),
    }
    f
}

/// FR-CFG-5 and `firewall.nft_path`: owned by root, not writable by group or
/// others, for the file and every parent directory.
pub fn ownership(path: &Path, what: &str) -> Findings {
    let mut f = Findings::default();
    let mut p = Some(path);
    while let Some(cur) = p {
        match fs::metadata(cur) {
            Ok(m) if m.uid() != 0 => f
                .errors
                .push(format!("{what}: {} is not owned by root (FR-CFG-5)", cur.display())),
            Ok(m) if m.mode() & 0o022 != 0 => f.errors.push(format!(
                "{what}: {} is writable by group or others (mode {:o}, FR-CFG-5)",
                cur.display(),
                m.mode() & 0o7777
            )),
            Ok(_) => {}
            Err(e) => f.errors.push(format!("{what}: {}: {e}", cur.display())),
        }
        p = cur.parent().filter(|x| !x.as_os_str().is_empty());
    }
    f
}

/// FR-ROUTE-6: collisions in FTR's ranges, the local rule, and foreign rules
/// that precede FTR.
pub fn routing(system: &System, layout: Layout, protocol: u8, families: &[crate::model::Family]) -> Findings {
    let mut f = Findings::default();
    for family in families {
        let rules: Vec<_> = system.rules.iter().filter(|r| r.family == *family).collect();
        if !rules.iter().any(|r| {
            r.priority == 0
                && r.action
                    == ObservedAction::Lookup {
                        table: 255,
                        suppress_prefixlen: None,
                    }
        }) {
            f.errors.push(format!(
                "{family}: the local-table rule at priority 0 is missing (FR-ROUTE-6)"
            ));
        }
        for r in &rules {
            if layout.priorities().contains(&r.priority) && r.protocol != protocol && !r.l3mdev {
                f.errors.push(format!(
                    "{family}: a rule at priority {} with protocol {} collides with FTR's priority range {}–{} (FR-ROUTE-6)",
                    r.priority,
                    r.protocol,
                    layout.priorities().start(),
                    layout.priorities().end()
                ));
            } else if r.l3mdev || (r.priority > 0 && r.priority < layout.priority_base) {
                let what = if r.l3mdev {
                    " (VRF l3mdev rule: it matches only traffic of VRF devices)"
                } else {
                    ""
                };
                f.warnings.push(format!(
                    "{family}: the rule at priority {} precedes FTR's rules; FTR's invariants do not cover the traffic it matches{what}",
                    r.priority
                ));
            }
        }
        for r in system
            .routes
            .values()
            .filter(|r| r.family == *family && layout.tables().contains(&r.table))
        {
            if r.protocol != protocol {
                f.errors.push(format!(
                    "{family}: table {} contains a route with protocol {} that FTR did not install (FR-ROUTE-6)",
                    r.table, r.protocol
                ));
            }
        }
    }
    f
}

/// FR-DISC-8: connected prefixes of the downlinks must be in main.
pub fn downlinks(system: &System, config: &Config) -> Findings {
    let mut f = Findings::default();
    for d in &config.downlinks {
        let Some(link) = system.link_by_name(d) else {
            f.warnings.push(format!("downlink {d}: the interface does not exist"));
            continue;
        };
        for a in system
            .addresses
            .values()
            .filter(|a| a.index == link.index && a.global())
        {
            let net = network(a.address, a.prefix_len);
            let covered = system.routes_in(a.family, TABLE_MAIN).any(|r| {
                r.destination == Some((net, a.prefix_len)) && r.nexthops.iter().any(|h| h.ifindex == link.index)
            });
            if !covered && a.prefix_len < if a.address.is_ipv4() { 32 } else { 128 } {
                f.warnings.push(format!(
                    "downlink {d}: the prefix {net}/{} is not in the main table; replies towards it would follow a path table to a provider (FR-DISC-8)",
                    a.prefix_len
                ));
            }
        }
    }
    f
}

fn network(a: IpAddr, len: u8) -> IpAddr {
    match a {
        IpAddr::V4(v) => {
            let m = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len.min(32)))
            };
            IpAddr::V4((u32::from(v) & m).into())
        }
        IpAddr::V6(v) => {
            let m = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len.min(128)))
            };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

/// Flowtables whose device selectors match a configured uplink or downlink
/// (FR-CT-2): by name, also for interfaces that do not exist, a trailing `*`
/// treated as a possible prefix selector. Software and hardware offload
/// alike. Returns the diagnostics.
pub fn flowtables(ruleset: &Value, config: &Config) -> Vec<String> {
    let interfaces = config
        .uplinks
        .iter()
        .map(|u| (u.interface.as_str(), "uplink"))
        .chain(config.downlinks.iter().map(|d| (d.as_str(), "downlink")));
    let interfaces: Vec<(&str, &str)> = interfaces.collect();
    let mut v = Vec::new();
    for (ft, selector) in nftctl::flowtable_devices(ruleset) {
        for (name, role) in &interfaces {
            let matches = match selector.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => selector == *name,
            };
            if matches {
                v.push(format!(
                    "flowtable {ft}: device selector {selector:?} matches the {role} {name}; flow offload between downlinks and uplinks bypasses FTR's marking and is not supported (FR-CT-2)"
                ));
            }
        }
    }
    v
}

/// FR-CT-1, FR-CT-2, FR-NAT-4 from the JSON ruleset.
pub fn ruleset(ruleset: &Value, config: &Config) -> Findings {
    let mut f = Findings::default();
    f.errors.extend(flowtables(ruleset, config));
    for c in nftctl::notrack_chains(ruleset) {
        f.warnings.push(format!(
            "chain {c} contains notrack statements: untracked data traffic is not pinned (FR-CT-1)"
        ));
    }
    for c in nftctl::source_nat_chains(ruleset) {
        f.warnings.push(format!(
            "chain {c} performs source NAT; if it applies to uplink interfaces, set nat = \"none\" on those paths (FR-NAT-4)"
        ));
    }
    f
}

const CONF_DIRS: [&str; 4] = ["etc", "run", "usr/local/lib", "usr/lib"];

/// The effective `[Network]` settings of systemd-networkd: the first main
/// file found in /etc, /run, /usr/local/lib, /usr/lib, then the drop-ins of
/// `networkd.conf.d` in those directories, sorted by file name, a name in an
/// earlier directory hiding the same name in later ones.
pub fn networkd_settings(root: &Path) -> BTreeMap<String, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(main) = CONF_DIRS
        .iter()
        .map(|d| root.join(d).join("systemd/networkd.conf"))
        .find(|p| p.is_file())
    {
        files.push(main);
    }
    let mut dropins: BTreeMap<String, PathBuf> = BTreeMap::new();
    for d in CONF_DIRS {
        let Ok(entries) = fs::read_dir(root.join(d).join("systemd/networkd.conf.d")) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".conf") {
                dropins.entry(name).or_insert_with(|| e.path());
            }
        }
    }
    files.extend(dropins.into_values());
    let mut settings = BTreeMap::new();
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else { continue };
        let mut section = String::new();
        for line in text.lines().map(str::trim) {
            if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                continue;
            }
            if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = s.to_owned();
            } else if let Some((k, v)) = line.split_once('=')
                && section == "Network"
            {
                settings.insert(k.trim().to_owned(), v.trim().to_owned());
            }
        }
    }
    settings
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

/// FR-COEX-1 for a running systemd-networkd.
pub fn networkd(root: &Path) -> Findings {
    let mut f = Findings::default();
    let s = networkd_settings(root);
    for key in ["ManageForeignRoutingPolicyRules", "ManageForeignRoutes"] {
        // Both default to yes.
        if s.get(key).and_then(|v| parse_bool(v)).unwrap_or(true) {
            f.errors.push(format!(
                "systemd-networkd is active with {key} enabled: it deletes FTR's rules and routes on link reconfiguration and restart. Set {key}=no in [Network] of a drop-in such as /etc/systemd/networkd.conf.d/fault-tolerant-router.conf and restart systemd-networkd (FR-COEX-1)"
            ));
        }
    }
    f
}

/// Whether systemd-networkd runs in this network namespace (by process
/// name; an instance in another namespace manages other interfaces).
pub fn networkd_running() -> bool {
    let own = fs::read_link("/proc/self/ns/net").ok();
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit())
            && fs::read_to_string(e.path().join("comm")).is_ok_and(|c| c.trim() == "systemd-network")
            && fs::read_link(e.path().join("ns/net")).ok() == own
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(kernel("6.1.0-53-amd64").errors.is_empty());
        assert!(kernel("7.1.13+deb13-amd64").errors.is_empty());
        assert!(!kernel("5.15.0-100-generic").errors.is_empty());
        assert!(nftables("nftables v1.0.6 (Lester Gooch #5)\n").errors.is_empty());
        assert!(!nftables("nftables v1.0.5 (Lester Gooch #4)").errors.is_empty());
        assert!(nftables("nftables v1.1.7 (Commodore Bullmoose #8)").errors.is_empty());
    }

    #[test]
    fn networkd_precedence_and_defaults() {
        let root = std::env::temp_dir().join(format!("ftr-networkd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let w = |p: &str, t: &str| {
            let p = root.join(p);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, t).unwrap();
        };
        // Defaults: both enabled.
        assert_eq!(networkd(&root).errors.len(), 2);
        w("usr/lib/systemd/networkd.conf", "[Network]\n#ManageForeignRoutes=yes\n");
        w(
            "etc/systemd/networkd.conf.d/50-ftr.conf",
            "[Network]\nManageForeignRoutingPolicyRules=no\nManageForeignRoutes=no\n",
        );
        assert!(networkd(&root).errors.is_empty());
        // A later drop-in re-enables one; a same-named file in /usr/lib is hidden.
        w(
            "usr/lib/systemd/networkd.conf.d/50-ftr.conf",
            "[Network]\nManageForeignRoutes=yes\n",
        );
        assert!(networkd(&root).errors.is_empty());
        w(
            "run/systemd/networkd.conf.d/90-other.conf",
            "[Network]\nManageForeignRoutes=yes\n",
        );
        let e = networkd(&root).errors;
        assert_eq!(e.len(), 1);
        assert!(e[0].contains("ManageForeignRoutes enabled"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn flowtables_on_uplinks_are_refused() {
        let cfg = crate::config::parse(
            "version = 2\n[[downlink]]\ninterface = \"lan\"\n[[uplink]]\nid = 1\nname = \"a\"\ninterface = \"wana\"\n[uplink.ipv4]\n",
        )
        .unwrap();
        let r: Value = serde_json::from_str(
            r#"{"nftables":[{"flowtable":{"family":"inet","table":"f","name":"ft","dev":["lan","wana"]}}]}"#,
        )
        .unwrap();
        assert_eq!(ruleset(&r, &cfg).errors.len(), 2, "uplink and downlink");
        let r: Value = serde_json::from_str(
            r#"{"nftables":[{"flowtable":{"family":"inet","table":"f","name":"ft","dev":"wan*"}},{"flowtable":{"family":"ip","table":"g","name":"other","dev":"eth9"}}]}"#,
        )
        .unwrap();
        let e = flowtables(&r, &cfg);
        assert_eq!(
            e.len(),
            1,
            "a trailing * is a possible prefix; unrelated devices are fine: {e:?}"
        );
        assert!(e[0].contains("inet f ft") && e[0].contains("\"wan*\"") && e[0].contains("uplink wana"));
    }
}
