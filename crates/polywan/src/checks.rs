//! Prerequisite checks of startup and `check-config` (SPEC.md PLAT-1,
//! PLAT-2, FR-CFG-5, FR-ROUTE-6, FR-COEX-1, FR-CT-1, FR-CT-2, FR-NAT-4,
//! FR-DISC-8). Errors refuse startup; warnings are logged.

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::{AutoOr, Config};
use crate::model::{Family, UplinkId};
use crate::netlink::msg::{ObservedAction, TABLE_MAIN};
use crate::nftctl;
use crate::plan::{Layout, RuleKind};
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

/// What must hold before PolyWAN runs configured programs, each stage only
/// once the previous one passed: the trust of the configuration and of its
/// executables (FR-CFG-5), the accounts, and no descriptor that hooks and
/// sendmail would inherit (FR-HOOK-3; `inherited` comes from
/// [`crate::subprocess::inherited_descriptors`]).
pub fn runnable(config_path: &Path, config: &Config, inherited: &[i32]) -> Runnable {
    let mut r = Runnable {
        refused: trusted(config_path, config).errors,
        failed: Vec::new(),
    };
    if r.refused.is_empty() {
        (r.refused, r.failed) = accounts(config);
    }
    if r.refused.is_empty() && r.failed.is_empty() {
        r.failed = crate::subprocess::descriptor_errors(config, inherited);
    }
    r
}

/// The errors of [`runnable`] by what resolves them (§9): `refused` only a
/// change of the configuration or of what it names (FR-CFG-5, an absent or
/// prohibited account), `failed` anything else (a failed account lookup,
/// inherited descriptors).
#[derive(Debug, Default)]
pub struct Runnable {
    pub refused: Vec<String>,
    pub failed: Vec<String>,
}

impl Runnable {
    pub fn errors(self) -> Vec<String> {
        let mut v = self.refused;
        v.extend(self.failed);
        v
    }
}

/// FR-CFG-5 for the configuration file and the binaries PolyWAN runs as
/// root, `firewall.nft_path` and, with email, `notify.email.sendmail`:
/// checked before anything configured runs.
pub fn trusted(config_path: &Path, config: &Config) -> Findings {
    let mut f = ownership(config_path, "configuration");
    f.extend(executable(&config.firewall.nft_path, "firewall.nft_path"));
    if let Some(e) = &config.notify.email {
        f.extend(executable(&e.sendmail, "notify.email.sendmail"));
    }
    f
}

/// FR-CFG-5 for a binary PolyWAN runs: trusted like the configuration, and
/// resolving to an executable regular file. Checked again right before
/// every execution.
pub fn executable(path: &Path, what: &str) -> Findings {
    let mut f = ownership(path, what);
    if f.errors.is_empty() {
        match fs::metadata(path) {
            Ok(m) if !m.is_file() => f
                .errors
                .push(format!("{what}: {} is not a regular file (FR-CFG-5)", path.display())),
            Ok(m) if m.mode() & 0o111 == 0 => f
                .errors
                .push(format!("{what}: {} is not executable (FR-CFG-5)", path.display())),
            Ok(_) => {}
            Err(e) => f.errors.push(format!("{what}: {}: {e}", path.display())),
        }
    }
    f
}

/// §11.2: the groups of the API sockets and, with hooks, the hook user
/// exist in the account databases.
pub fn identities(config: &Config) -> Findings {
    let (mut errors, failed) = accounts(config);
    errors.extend(failed);
    Findings {
        errors,
        warnings: Vec::new(),
    }
}

/// [`identities`], absent or prohibited accounts apart from failed lookups.
fn accounts(config: &Config) -> (Vec<String>, Vec<String>) {
    let (mut refused, mut failed) = (Vec::new(), Vec::new());
    let mut group = |name: &str, key: &str| match crate::identity::group(name) {
        Ok(Some(_)) => {}
        Ok(None) => refused.push(format!("{key}: group {name:?} does not exist")),
        Err(e) => failed.push(format!("{key}: cannot look up group {name:?}: {e}")),
    };
    group(&config.api.group, "api.group");
    if config.api.status_socket.is_some()
        && let Some(g) = &config.api.status_group
    {
        group(g, "api.status_group");
    }
    if !config.notify.hooks.is_empty() {
        match crate::identity::user(&config.notify.hook_user) {
            Ok(Some(u)) if u.uid == 0 => refused.push(format!(
                "notify.hook_user: {}",
                crate::hooks::uid_zero(&config.notify.hook_user)
            )),
            Ok(Some(_)) => {}
            Ok(None) => refused.push(format!(
                "notify.hook_user: user {:?} does not exist",
                config.notify.hook_user
            )),
            Err(e) => failed.push(format!("notify.hook_user: cannot look up the user: {e}")),
        }
    }
    (refused, failed)
}

/// FR-CFG-5 and `firewall.nft_path`: owned by root, not writable by group or
/// others, for the file and every directory its resolution traverses,
/// through symbolic links too.
pub fn ownership(path: &Path, what: &str) -> Findings {
    let mut f = Findings::default();
    // A relative path is the working directory's, as the configuration
    // loader reads it.
    let traversed = match std::path::absolute(path).and_then(|path| {
        traversed(&path, |p| {
            fs::symlink_metadata(p)?
                .file_type()
                .is_symlink()
                .then(|| fs::read_link(p))
                .transpose()
        })
    }) {
        Ok(t) => t,
        Err(e) => {
            f.errors.push(format!("{what}: {}: {e}", path.display()));
            return f;
        }
    };
    for cur in traversed {
        match fs::metadata(&cur) {
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
    }
    f
}

/// The directories and the file that resolving the absolute `path` goes
/// through, root first: each one's owner can replace what follows. `link` returns the
/// target of a symbolic link, `None` for anything else. Symbolic links
/// themselves are left out: their directory decides who can replace them.
fn traversed(path: &Path, link: impl Fn(&Path) -> std::io::Result<Option<PathBuf>>) -> std::io::Result<Vec<PathBuf>> {
    use std::path::Component;

    // The components still to resolve, next last; `/` restarts from the
    // root.
    fn push(rest: &mut Vec<PathBuf>, p: &Path) {
        rest.extend(p.components().rev().filter_map(|c| match c {
            Component::RootDir => Some(PathBuf::from("/")),
            Component::ParentDir => Some(PathBuf::from("..")),
            Component::Normal(n) => Some(PathBuf::from(n)),
            Component::CurDir | Component::Prefix(_) => None,
        }));
    }
    let root = PathBuf::from("/");
    let mut out = vec![root.clone()];
    let mut cur = root.clone();
    let mut rest = Vec::new();
    push(&mut rest, path);
    let mut links = 0;
    while let Some(c) = rest.pop() {
        if c == root {
            cur = root.clone();
        } else if c.as_os_str() == ".." {
            cur.pop();
        } else {
            let next = cur.join(&c);
            if let Some(target) = link(&next)? {
                links += 1;
                if links > 40 {
                    return Err(std::io::Error::other("too many levels of symbolic links"));
                }
                // A relative target resolves from the link's directory.
                push(&mut rest, &target);
                continue;
            }
            cur = next;
            if !out.contains(&cur) {
                out.push(cur.clone());
            }
        }
    }
    Ok(out)
}

/// IMPL-6 without a manifest: PolyWAN-tagged rules in the configured range are
/// adopted only if this configuration's layout produces them (same marks,
/// masks and tables); a different `fwmark_mask` or `table_base` installed
/// them otherwise.
pub fn adoptable(system: &System, layout: Layout, protocol: u8) -> Findings {
    let mut f = Findings::default();
    let ids: Vec<UplinkId> = (1..=63).filter_map(UplinkId::new).collect();
    for family in Family::ALL {
        let planned = layout.static_rules(family, &ids);
        for r in system
            .rules
            .iter()
            .filter(|r| r.family == family && r.protocol == protocol && layout.priorities().contains(&r.priority))
        {
            let consistent = match (r.source, crate::reconcile::classify(layout, r.priority)) {
                (Some((a, _)), Some(RuleKind::SourceLookup(id))) => {
                    r.is(&layout.source_rules(family, id, a)[0], protocol)
                }
                (Some((a, _)), Some(RuleKind::SourceGuard)) => {
                    r.is(&layout.source_rules(family, ids[0], a)[1], protocol)
                }
                _ => planned.iter().any(|p| r.is(p, protocol)),
            };
            if !consistent {
                f.errors.push(format!(
                    "{family}: PolyWAN's rule at priority {} does not match this configuration (another fwmark_mask or table_base installed it?) and there is no manifest to clean it up with: run `cleanup` with this configuration, then start (IMPL-6)",
                    r.priority
                ));
            }
        }
    }
    f
}

/// FR-ROUTE-6: collisions in PolyWAN's ranges, the local rule, and foreign rules
/// that precede PolyWAN.
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
                    "{family}: a rule at priority {} with protocol {} collides with PolyWAN's priority range {}–{} (FR-ROUTE-6)",
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
                    "{family}: the rule at priority {} precedes PolyWAN's rules; PolyWAN's invariants do not cover the traffic it matches{what}",
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
                    "{family}: table {} contains a route with protocol {} that PolyWAN did not install (FR-ROUTE-6)",
                    r.table, r.protocol
                ));
            }
        }
    }
    f
}

/// FR-SYS-3: the diagnosis of `accept_ra = 1` on an interface, shared by
/// the startup check and the warning about a missing gateway.
fn accept_ra_one(interface: &str, polywan_enables_forwarding: bool) -> String {
    format!(
        "{interface} has accept_ra = 1, and the kernel ignores Router Advertisements there while IPv6 forwarding is enabled{}; set accept_ra = 2, or let a user-space client (systemd-networkd, NetworkManager) handle Router Advertisements with accept_ra = 0",
        if polywan_enables_forwarding {
            ", which PolyWAN enables"
        } else {
            ""
        }
    )
}

/// FR-SYS-3: with IPv6 forwarding, the kernel ignores Router Advertisements
/// on interfaces with `accept_ra = 1`, so an IPv6 path with `gateway =
/// "auto"` there would never get its default route. `read` reads a key
/// below `/proc/sys`; absent interfaces are skipped.
pub fn accept_ra(config: &Config, read: impl Fn(&str) -> std::io::Result<String>) -> Findings {
    let mut f = Findings::default();
    for u in &config.uplinks {
        if !u.path(Family::V6).is_some_and(|p| p.gateway == AutoOr::Auto) {
            continue;
        }
        if read(&format!("net/ipv6/conf/{}/accept_ra", u.interface))
            .ok()
            .as_deref()
            != Some("1")
        {
            continue;
        }
        let enabled = read(&format!("net/ipv6/conf/{}/forwarding", u.interface)).is_ok_and(|v| v == "1");
        if config.routing.manage_sysctls || enabled {
            f.warnings.push(format!(
                "uplink {}: the IPv6 path with gateway = \"auto\" would get no default route: {} (FR-SYS-3)",
                u.name,
                accept_ra_one(&u.interface, !enabled)
            ));
        }
    }
    f
}

/// FR-SYS-3: the likely causes of a missing IPv6 gateway on an interface,
/// from its Router Advertisement settings. `read` reads a key below
/// `/proc/sys`.
pub fn gateway_causes(interface: &str, read: impl Fn(&str) -> std::io::Result<String>) -> String {
    let setting = |name: &str| read(&format!("net/ipv6/conf/{interface}/{name}")).unwrap_or_default();
    match (setting("accept_ra").as_str(), setting("forwarding").as_str()) {
        ("1", "1") => accept_ra_one(interface, false),
        ("0", _) => "accept_ra = 0: the kernel does not process Router Advertisements, so a user-space client (systemd-networkd, NetworkManager) must install the default route; check that it runs and accepts them".into(),
        _ => "no Router Advertisement with a non-zero router lifetime arrived: the provider may send none, or they are filtered on the link".into(),
    }
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
                    "flowtable {ft}: device selector {selector:?} matches the {role} {name}; flow offload between downlinks and uplinks bypasses PolyWAN's marking and is not supported (FR-CT-2)"
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
                "systemd-networkd is active with {key} enabled: it deletes PolyWAN's rules and routes on link reconfiguration and restart. Set {key}=no in [Network] of a drop-in such as /etc/systemd/networkd.conf.d/polywan.conf and restart systemd-networkd (FR-COEX-1)"
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
    fn ownership_follows_symbolic_links_and_their_directories() {
        // /usr/sbin/nft -> ../lib/nft/bin -> /opt/nft/nft; /opt/nft -> v1.
        let links: BTreeMap<&str, &str> = [
            ("/usr/sbin/nft", "../lib/nft/bin"),
            ("/usr/lib/nft/bin", "/opt/nft/nft"),
            ("/opt/nft", "v1"),
        ]
        .into_iter()
        .collect();
        let link = |p: &Path| Ok(links.get(p.to_str().unwrap()).map(PathBuf::from));
        let t = traversed(Path::new("/usr/sbin/nft"), link).unwrap();
        let t: Vec<&str> = t.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(
            t,
            [
                "/",
                "/usr",
                "/usr/sbin",
                "/usr/lib",
                "/usr/lib/nft",
                "/opt",
                "/opt/v1",
                "/opt/v1/nft"
            ]
        );
        let lp = |_: &Path| Ok(Some(PathBuf::from("/loop")));
        assert!(traversed(Path::new("/loop"), lp).is_err(), "a link loop ends");
    }

    #[test]
    fn hooks_never_run_with_uid_0() {
        let mut cfg = crate::config::parse(
            "[[downlink]]\ninterface = \"lan\"\n[[uplink]]\nid = 1\nname = \"a\"\ninterface = \"wana\"\n[uplink.ipv4]\n[[notify.hook]]\ncommand = [\"/bin/true\"]\n",
        )
        .unwrap();
        cfg.notify.hook_user = "root".into();
        let errors = identities(&cfg).errors;
        assert!(errors.iter().any(|e| e.contains("UID 0")), "{errors:?}");
    }

    #[test]
    fn a_relative_path_is_checked_where_it_is_read() {
        // `etc/passwd` from the crate directory, not the trusted /etc/passwd.
        assert!(!Path::new("etc/passwd").exists());
        assert!(!ownership(Path::new("etc/passwd"), "configuration").errors.is_empty());
    }

    #[test]
    fn adoption_without_a_manifest_needs_the_same_layout() {
        use netlink_packet_route::RouteNetlinkMessage;

        let layout = Layout {
            table_base: 1000,
            priority_base: 1000,
            mask: crate::model::FwMask::DEFAULT,
        };
        let id = UplinkId::new(2).unwrap();
        let mut rules = layout.static_rules(Family::V4, &[id]);
        rules.extend(layout.source_rules(Family::V4, id, "192.0.2.2".parse().unwrap()));
        let scope = crate::system::Scope {
            polywan_tables: layout.tables(),
            discovery_tables: Vec::new(),
        };
        let mut s = System::default();
        for r in &rules {
            s.apply(
                &scope,
                &RouteNetlinkMessage::NewRule(crate::netlink::msg::rule_message(r, 249)),
            );
        }
        assert!(adoptable(&s, layout, 249).errors.is_empty());
        let other_mask = Layout {
            mask: crate::model::FwMask::new(0xff).unwrap(),
            ..layout
        };
        assert!(!adoptable(&s, other_mask, 249).errors.is_empty());
        let other_tables = Layout {
            table_base: 2000,
            ..layout
        };
        assert!(!adoptable(&s, other_tables, 249).errors.is_empty());
    }

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
        let root = std::env::temp_dir().join(format!("polywan-networkd-{}", std::process::id()));
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
            "etc/systemd/networkd.conf.d/50-polywan.conf",
            "[Network]\nManageForeignRoutingPolicyRules=no\nManageForeignRoutes=no\n",
        );
        assert!(networkd(&root).errors.is_empty());
        // A later drop-in re-enables one; a same-named file in /usr/lib is hidden.
        w(
            "usr/lib/systemd/networkd.conf.d/50-polywan.conf",
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
            "[[downlink]]\ninterface = \"lan\"\n[[uplink]]\nid = 1\nname = \"a\"\ninterface = \"wana\"\n[uplink.ipv4]\n",
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

    #[test]
    fn accept_ra_one_with_forwarding_is_reported() {
        let text = "[[downlink]]\ninterface = \"lan\"\n[[uplink]]\nid = 1\nname = \"a\"\ninterface = \"wana\"\n[uplink.ipv6]\nnat = \"masquerade\"\n[[uplink]]\nid = 2\nname = \"b\"\ninterface = \"wanb\"\n[uplink.ipv6]\nnat = \"masquerade\"\ngateway = \"fe80::1\"\n";
        let cfg = crate::config::parse(text).unwrap();
        let values = |accept_ra: &'static str, forwarding: &'static str| {
            move |k: &str| -> std::io::Result<String> {
                match k {
                    k if k.ends_with("/accept_ra") => Ok(accept_ra.to_owned()),
                    k if k.ends_with("/forwarding") => Ok(forwarding.to_owned()),
                    _ => Err(std::io::ErrorKind::NotFound.into()),
                }
            }
        };
        // Only the automatic gateway is concerned; PolyWAN enables forwarding.
        let f = accept_ra(&cfg, values("1", "0"));
        assert_eq!(f.warnings.len(), 1, "{f:?}");
        assert!(f.warnings[0].contains("wana has accept_ra = 1") && f.warnings[0].contains("which PolyWAN enables"));
        assert!(accept_ra(&cfg, values("2", "1")).warnings.is_empty());
        assert!(accept_ra(&cfg, values("0", "1")).warnings.is_empty());
        let mut unmanaged = cfg.clone();
        unmanaged.routing.manage_sysctls = false;
        assert!(accept_ra(&unmanaged, values("1", "0")).warnings.is_empty());
        assert_eq!(accept_ra(&unmanaged, values("1", "1")).warnings.len(), 1);
    }

    #[test]
    fn gateway_causes_follow_the_router_advertisement_settings() {
        let values = |accept_ra: &'static str, forwarding: &'static str| {
            move |k: &str| -> std::io::Result<String> {
                match k {
                    "net/ipv6/conf/wana/accept_ra" => Ok(accept_ra.to_owned()),
                    "net/ipv6/conf/wana/forwarding" => Ok(forwarding.to_owned()),
                    _ => Err(std::io::ErrorKind::NotFound.into()),
                }
            }
        };
        let one = gateway_causes("wana", values("1", "1"));
        assert!(
            one.starts_with("wana has accept_ra = 1") && !one.contains("which PolyWAN enables"),
            "{one}"
        );
        assert!(gateway_causes("wana", values("0", "1")).starts_with("accept_ra = 0: the kernel does not process"));
        let none = "no Router Advertisement with a non-zero router lifetime arrived";
        assert!(gateway_causes("wana", values("2", "1")).starts_with(none));
        assert!(gateway_causes("wana", values("1", "0")).starts_with(none));
        assert!(
            gateway_causes("wanb", values("1", "1")).starts_with(none),
            "unreadable settings"
        );
    }
}
