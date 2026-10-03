//! System settings (SPEC.md §4.6). Keys are paths below `/proc/sys`
//! (`net/ipv4/conf/wan0.100/rp_filter`), never dotted names, because
//! interface names can contain dots.

use std::fs;
use std::io;
use std::path::PathBuf;

use crate::config::Config;
use crate::model::Family;
use crate::state::Manifest;

/// One setting FTR wants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting {
    pub key: String,
    pub value: &'static str,
    /// The interface the key belongs to, if any (absent interfaces are
    /// skipped and the setting applied when the interface appears).
    pub interface: Option<String>,
    pub family: Option<Family>,
}

impl Setting {
    pub fn path(&self) -> PathBuf {
        PathBuf::from("/proc/sys").join(&self.key)
    }

    /// The conventional dotted name, for messages.
    pub fn display(&self) -> String {
        self.key.replace('/', ".")
    }
}

fn global(key: &str, value: &'static str, family: Family) -> Setting {
    Setting {
        key: key.to_owned(),
        value,
        interface: None,
        family: Some(family),
    }
}

fn per_interface(family: Family, interface: &str, name: &str, value: &'static str) -> Setting {
    let dir = if family == Family::V4 { "ipv4" } else { "ipv6" };
    Setting {
        key: format!("net/{dir}/conf/{interface}/{name}"),
        value,
        interface: Some(interface.to_owned()),
        family: Some(family),
    }
}

/// FR-SYS-1, FR-SYS-2, FR-SYS-4 (FR-ROUTE-5), for the managed families.
pub fn desired(config: &Config) -> Vec<Setting> {
    let mut v = Vec::new();
    let v4 = config.manages(Family::V4);
    let v6 = config.manages(Family::V6);
    if v4 {
        v.push(global("net/ipv4/ip_forward", "1", Family::V4));
        v.push(global("net/ipv4/fib_multipath_hash_policy", "1", Family::V4));
    }
    if v6 {
        v.push(global("net/ipv6/conf/all/forwarding", "1", Family::V6));
        v.push(global("net/ipv6/fib_multipath_hash_policy", "1", Family::V6));
    }
    for u in &config.uplinks {
        if v4 {
            // rp_filter and src_valid_mark exist only for IPv4.
            v.push(per_interface(Family::V4, &u.interface, "rp_filter", "2"));
            v.push(per_interface(Family::V4, &u.interface, "src_valid_mark", "1"));
            v.push(per_interface(
                Family::V4,
                &u.interface,
                "ignore_routes_with_linkdown",
                "1",
            ));
        }
        if v6 {
            v.push(per_interface(
                Family::V6,
                &u.interface,
                "ignore_routes_with_linkdown",
                "1",
            ));
        }
    }
    v
}

pub fn read(key: &str) -> io::Result<String> {
    Ok(fs::read_to_string(PathBuf::from("/proc/sys").join(key))?
        .trim()
        .to_owned())
}

pub fn write(key: &str, value: &str) -> io::Result<()> {
    fs::write(PathBuf::from("/proc/sys").join(key), value)
}

/// A setting that differs from what FTR wants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    pub setting: Setting,
    pub current: String,
}

/// Settings whose current value differs; settings of absent interfaces are
/// skipped.
pub fn differences(settings: &[Setting], read: impl Fn(&str) -> io::Result<String>) -> io::Result<Vec<Difference>> {
    let mut v = Vec::new();
    for s in settings {
        match read(&s.key) {
            Ok(current) if current == s.value => {}
            Ok(current) => v.push(Difference {
                setting: s.clone(),
                current,
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound && s.interface.is_some() => {}
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", s.display()))),
        }
    }
    Ok(v)
}

/// Records the baselines in the manifest (to be written before applying,
/// write-ahead) and returns the keys to write.
pub fn record(manifest: &mut Manifest, diffs: &[Difference]) {
    for d in diffs {
        manifest.record_sysctl(&d.setting.key, &d.current, d.setting.value);
    }
}

/// Restores the baselines of the given keys whose current value is still
/// the one FTR set (§4.6, FR-REC-4). Returns the keys restored.
pub fn restore(manifest: &Manifest, keys: impl Fn(&str) -> bool) -> Vec<(String, io::Result<()>)> {
    let mut v = Vec::new();
    for (key, set) in &manifest.sysctl_set {
        if !keys(key) {
            continue;
        }
        let Some(baseline) = manifest.sysctl_baseline.get(key) else {
            continue;
        };
        if read(key).ok().as_deref() == Some(set.as_str()) && baseline != set {
            v.push((key.clone(), write(key, baseline)));
        }
    }
    v
}

/// The family a recorded key belongs to.
pub fn family_of(key: &str) -> Option<Family> {
    if key.starts_with("net/ipv4/") {
        Some(Family::V4)
    } else if key.starts_with("net/ipv6/") {
        Some(Family::V6)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::config;

    const CONFIG: &str = r#"version = 2
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "wan0.100"
[uplink.ipv4]
"#;

    #[test]
    fn ipv4_only_configurations_change_no_ipv6_setting() {
        let cfg = config::parse(CONFIG).unwrap();
        let d = desired(&cfg);
        assert!(d.iter().all(|s| s.family == Some(Family::V4)));
        let keys: Vec<&str> = d.iter().map(|s| s.key.as_str()).collect();
        assert!(keys.contains(&"net/ipv4/conf/wan0.100/rp_filter"));
        assert!(keys.contains(&"net/ipv4/conf/wan0.100/src_valid_mark"));
        assert!(keys.contains(&"net/ipv4/fib_multipath_hash_policy"));
        assert!(!keys.iter().any(|k| k.contains("conf/all/rp_filter")), "FR-SYS-2");
    }

    #[test]
    fn differences_skip_absent_interfaces_and_baselines_are_kept() {
        let cfg = config::parse(CONFIG).unwrap();
        let values: HashMap<&str, &str> = [
            ("net/ipv4/ip_forward", "0"),
            ("net/ipv4/fib_multipath_hash_policy", "1"),
        ]
        .into();
        let read = |k: &str| {
            values
                .get(k)
                .map(|v| (*v).to_owned())
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        };
        let d = differences(&desired(&cfg), read).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(
            (d[0].setting.key.as_str(), d[0].current.as_str()),
            ("net/ipv4/ip_forward", "0")
        );
        let mut m = Manifest::new(&cfg);
        record(&mut m, &d);
        assert_eq!(m.sysctl_baseline["net/ipv4/ip_forward"], "0");
        assert_eq!(family_of("net/ipv6/conf/all/forwarding"), Some(Family::V6));
    }
}
