//! System settings (SPEC.md §4.6). Keys are paths below `/proc/sys`
//! (`net/ipv4/conf/wan0.100/rp_filter`), never dotted names, because
//! interface names can contain dots.

use std::fs;
use std::io;
use std::path::PathBuf;

use crate::config::Config;
use crate::model::Family;
use crate::state::Manifest;

/// One setting PolyWAN wants.
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
        dotted(&self.key)
    }
}

/// A `/proc/sys` key (`net/ipv4/ip_forward`) in the dotted form of
/// `sysctl(8)`.
pub fn dotted(key: impl AsRef<str>) -> String {
    key.as_ref().replace('/', ".")
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

/// Whether `key` can name a setting PolyWAN manages: a path below
/// `/proc/sys/net` of plain components. Keys also come from the manifest,
/// and a key must never name a file elsewhere.
pub fn valid_key(key: &str) -> bool {
    key.strip_prefix("net/")
        .is_some_and(|rest| rest.split('/').all(|c| !c.is_empty() && c != "." && c != ".."))
}

fn path(key: &str) -> io::Result<PathBuf> {
    if valid_key(key) {
        Ok(PathBuf::from("/proc/sys").join(key))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{key:?} is not a network setting"),
        ))
    }
}

pub fn read(key: &str) -> io::Result<String> {
    Ok(fs::read_to_string(path(key)?)?.trim().to_owned())
}

pub fn write(key: &str, value: &str) -> io::Result<()> {
    fs::write(path(key)?, value)
}

/// A setting that differs from what PolyWAN wants.
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
/// the one PolyWAN set (§4.6, FR-REC-4). Returns the keys restored or that
/// could not be read or written; a key of an interface that is gone has
/// nothing left to restore.
pub fn restore(
    manifest: &Manifest,
    keys: impl Fn(&str) -> bool,
    read: impl Fn(&str) -> io::Result<String>,
    write: impl Fn(&str, &str) -> io::Result<()>,
) -> Vec<(String, io::Result<()>)> {
    let mut v = Vec::new();
    for (key, set) in &manifest.sysctl_set {
        if !keys(key) {
            continue;
        }
        let Some(baseline) = manifest.sysctl_baseline.get(key) else {
            continue;
        };
        match read(key) {
            Ok(current) if current == *set && baseline != set => v.push((key.clone(), write(key, baseline))),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => v.push((key.clone(), Err(e))),
        }
    }
    v
}

/// Outcome of handing a family's settings back (FR-REC-9 step 4).
#[derive(Debug, Default)]
pub struct Handoff {
    /// Restored to the baseline.
    pub restored: Vec<String>,
    /// Changed by someone else since PolyWAN set them: left as they are.
    pub released: Vec<String>,
    /// Not restored; kept in the manifest and retried (FR-REC-5).
    pub failed: Vec<(String, io::Error)>,
}

/// Restores the recorded settings of a family that is no longer managed,
/// only where the current value is still the one PolyWAN set, and forgets them
/// in the manifest; failures stay recorded for a retry.
pub fn hand_back(
    manifest: &mut Manifest,
    family: Family,
    read: impl Fn(&str) -> io::Result<String>,
    write: impl Fn(&str, &str) -> io::Result<()>,
) -> Handoff {
    let mut h = Handoff::default();
    let keys: Vec<String> = manifest
        .sysctl_set
        .keys()
        .filter(|k| family_of(k) == Some(family))
        .cloned()
        .collect();
    for key in keys {
        let set = manifest.sysctl_set[&key].clone();
        let baseline = manifest.sysctl_baseline.get(&key).cloned();
        let outcome = match read(&key) {
            // The interface is gone: nothing left to restore.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
            Ok(current) if current != set => Ok(false),
            Ok(_) => match baseline {
                Some(b) if b != set => write(&key, &b).map(|()| true),
                _ => Ok(true),
            },
        };
        match outcome {
            Ok(restored) => {
                manifest.sysctl_set.remove(&key);
                manifest.sysctl_baseline.remove(&key);
                if restored {
                    h.restored.push(key)
                } else {
                    h.released.push(key)
                }
            }
            Err(e) => h.failed.push((key, e)),
        }
    }
    h
}

/// Families whose settings are recorded but that the configuration no
/// longer manages.
pub fn departed(manifest: &Manifest, config: &Config) -> Vec<Family> {
    Family::ALL
        .into_iter()
        .filter(|f| !config.manages(*f) && manifest.sysctl_set.keys().any(|k| family_of(k) == Some(*f)))
        .collect()
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

    #[test]
    fn keys_stay_below_proc_sys_net() {
        for key in [
            "net/ipv4/ip_forward",
            "net/ipv4/conf/wan0.100/rp_filter",
            "net/ipv6/conf/all/forwarding",
        ] {
            assert!(valid_key(key), "{key}");
        }
        for key in [
            "/etc/passwd",
            "kernel/core_pattern",
            "net/../kernel/core_pattern",
            "net/ipv4/conf/./rp_filter",
            "net//ipv4",
            "net/",
            "net",
        ] {
            assert!(!valid_key(key), "{key}");
            assert_eq!(read(key).unwrap_err().kind(), io::ErrorKind::InvalidInput, "{key}");
            assert_eq!(
                write(key, "1").unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{key}"
            );
        }
    }
    use crate::config;

    const CONFIG: &str = r#"[[downlink]]
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

    #[test]
    fn restore_reports_read_and_write_failures_but_not_vanished_interfaces() {
        let cfg = config::parse(CONFIG).unwrap();
        let mut m = Manifest::new(&cfg);
        m.record_sysctl("net/ipv4/ip_forward", "0", "1");
        m.record_sysctl("net/ipv4/conf/gone/rp_filter", "2", "0");
        m.record_sysctl("net/ipv4/conf/wana/src_valid_mark", "0", "1");
        m.record_sysctl("net/ipv4/fib_multipath_hash_policy", "0", "1");
        m.record_sysctl("net/ipv4/conf/wanb/rp_filter", "2", "0");
        let read = |k: &str| match k {
            "net/ipv4/conf/gone/rp_filter" => Err(io::Error::from(io::ErrorKind::NotFound)),
            "net/ipv4/fib_multipath_hash_policy" => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            // Changed by the administrator since PolyWAN set it.
            "net/ipv4/conf/wanb/rp_filter" => Ok("1".to_owned()),
            _ => Ok("1".to_owned()),
        };
        let write = |k: &str, _: &str| {
            if k.contains("src_valid_mark") {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(())
        };
        let r = restore(&m, |_| true, read, write);
        let ok: Vec<&str> = r.iter().filter(|(_, e)| e.is_ok()).map(|(k, _)| k.as_str()).collect();
        let mut failed: Vec<&str> = r.iter().filter(|(_, e)| e.is_err()).map(|(k, _)| k.as_str()).collect();
        failed.sort_unstable();
        assert_eq!(ok, ["net/ipv4/ip_forward"]);
        assert_eq!(
            failed,
            [
                "net/ipv4/conf/wana/src_valid_mark",
                "net/ipv4/fib_multipath_hash_policy"
            ]
        );
    }

    #[test]
    fn hand_back_restores_only_untouched_settings_of_the_family() {
        use std::cell::RefCell;
        let cfg = config::parse(CONFIG).unwrap();
        let mut m = Manifest::new(&cfg);
        m.record_sysctl("net/ipv4/ip_forward", "0", "1");
        m.record_sysctl("net/ipv6/conf/all/forwarding", "0", "1");
        m.record_sysctl("net/ipv6/conf/wana/ignore_routes_with_linkdown", "0", "1");
        m.record_sysctl("net/ipv6/fib_multipath_hash_policy", "0", "1");
        m.record_sysctl("net/ipv6/conf/gone/ignore_routes_with_linkdown", "0", "1");
        let current: RefCell<HashMap<String, String>> = RefCell::new(
            [
                ("net/ipv4/ip_forward", "1"),
                ("net/ipv6/conf/all/forwarding", "1"),
                // Changed by the administrator since PolyWAN set it.
                ("net/ipv6/conf/wana/ignore_routes_with_linkdown", "2"),
                ("net/ipv6/fib_multipath_hash_policy", "1"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
        );
        let read = |k: &str| {
            current
                .borrow()
                .get(k)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        };
        let fail_hash = |k: &str, v: &str| {
            if k.contains("hash") {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            current.borrow_mut().insert(k.to_owned(), v.to_owned());
            Ok(())
        };
        let h = hand_back(&mut m, Family::V6, read, fail_hash);
        assert_eq!(h.restored, ["net/ipv6/conf/all/forwarding"]);
        assert_eq!(h.released.len(), 2, "administrator change and vanished interface");
        assert_eq!(h.failed.len(), 1);
        assert_eq!(current.borrow()["net/ipv6/conf/all/forwarding"], "0");
        assert_eq!(current.borrow()["net/ipv6/conf/wana/ignore_routes_with_linkdown"], "2");
        // The failure stays recorded for a retry; IPv4 is untouched.
        assert!(m.sysctl_set.contains_key("net/ipv6/fib_multipath_hash_policy"));
        assert_eq!(m.sysctl_baseline["net/ipv4/ip_forward"], "0");
        assert_eq!(departed(&m, &cfg), [Family::V6]);
        // A retry that succeeds empties the family.
        let h = hand_back(&mut m, Family::V6, read, |k: &str, v: &str| {
            current.borrow_mut().insert(k.to_owned(), v.to_owned());
            Ok(())
        });
        assert_eq!(h.restored, ["net/ipv6/fib_multipath_hash_policy"]);
        assert!(departed(&m, &cfg).is_empty());
        assert_eq!(current.borrow()["net/ipv4/ip_forward"], "1");
    }
}
