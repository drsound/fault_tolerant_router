//! State directory (SPEC.md §12.3): the manifest, the drain state and the
//! health checkpoint, each a versioned JSON file written atomically
//! (IMPL-5), and the instance lock (IMPL-6).

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{Config, FirewallMode, Structural};
use crate::model::{Family, FwMask, UplinkId};

pub const MANIFEST: &str = "manifest.json";
pub const DRAIN: &str = "drain.json";
pub const CHECKPOINT: &str = "health.json";
pub const LOCK_PATH: &str = "/run/polywan/lock";
const VERSION: u32 = 1;

#[derive(Debug)]
pub enum StateError {
    Io {
        path: PathBuf,
        error: io::Error,
    },
    /// Unknown version or unparsable content (IMPL-6: startup fails unless
    /// `--reset-state`).
    Corrupt {
        path: PathBuf,
        message: String,
    },
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Io { path, error } => write!(f, "{}: {error}", path.display()),
            StateError::Corrupt { path, message } => write!(f, "{}: {message}", path.display()),
        }
    }
}

impl std::error::Error for StateError {}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StateError + '_ {
    move |error| StateError::Io {
        path: path.to_owned(),
        error,
    }
}

/// Writes a file atomically: temporary file, fsync, rename, fsync of the
/// directory (IMPL-5).
pub fn write_atomic(path: &Path, content: &[u8]) -> Result<(), StateError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(io_err(&tmp))?;
    f.write_all(content).map_err(io_err(&tmp))?;
    f.sync_all().map_err(io_err(&tmp))?;
    drop(f);
    fs::rename(&tmp, path).map_err(io_err(path))?;
    File::open(dir).and_then(|d| d.sync_all()).map_err(io_err(dir))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, StateError> {
    let text = match fs::read(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(StateError::Io {
                path: path.to_owned(),
                error: e,
            });
        }
    };
    #[derive(Deserialize)]
    struct Versioned {
        version: u32,
    }
    let corrupt = |message: String| StateError::Corrupt {
        path: path.to_owned(),
        message,
    };
    let v: Versioned = serde_json::from_slice(&text).map_err(|e| corrupt(e.to_string()))?;
    if v.version != VERSION {
        return Err(corrupt(format!("unknown state file version {}", v.version)));
    }
    serde_json::from_slice(&text)
        .map(Some)
        .map_err(|e| corrupt(e.to_string()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), StateError> {
    let mut text = serde_json::to_vec_pretty(value).map_err(|e| StateError::Corrupt {
        path: path.to_owned(),
        message: e.to_string(),
    })?;
    text.push(b'\n');
    write_atomic(path, &text)
}

/// The state directory.
#[derive(Clone, Debug)]
pub struct StateDir {
    pub path: PathBuf,
}

impl StateDir {
    /// Creates the directory (mode 0700) if needed.
    pub fn open(path: &Path) -> Result<StateDir, StateError> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(io_err(path))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_err(path))?;
        Ok(StateDir { path: path.to_owned() })
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn manifest(&self) -> Result<Option<Manifest>, StateError> {
        read_json(&self.file(MANIFEST))
    }

    pub fn write_manifest(&self, m: &Manifest) -> Result<(), StateError> {
        write_json(&self.file(MANIFEST), m)
    }

    pub fn drain(&self) -> Result<DrainState, StateError> {
        Ok(read_json(&self.file(DRAIN))?.unwrap_or_default())
    }

    pub fn write_drain(&self, d: &DrainState) -> Result<(), StateError> {
        write_json(&self.file(DRAIN), d)
    }

    pub fn checkpoint(&self) -> Result<Option<Checkpoint>, StateError> {
        read_json(&self.file(CHECKPOINT))
    }

    pub fn write_checkpoint(&self, c: &Checkpoint) -> Result<(), StateError> {
        write_json(&self.file(CHECKPOINT), c)
    }

    /// `run --reset-state`: discards drain state and checkpoints, never the
    /// manifest (IMPL-6).
    pub fn reset(&self) -> Result<(), StateError> {
        for name in [DRAIN, CHECKPOINT] {
            let p = self.file(name);
            match fs::remove_file(&p) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(StateError::Io { path: p, error: e }),
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Managed,
    External,
}

/// Structural settings as recorded in the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedStructure {
    pub fwmark_mask: u32,
    pub table_base: u32,
    pub rule_priority_base: u32,
    pub route_protocol: u8,
    pub firewall_mode: Mode,
}

impl From<Structural> for RecordedStructure {
    fn from(s: Structural) -> Self {
        RecordedStructure {
            fwmark_mask: s.fwmark_mask.mask(),
            table_base: s.table_base,
            rule_priority_base: s.rule_priority_base,
            route_protocol: s.route_protocol,
            firewall_mode: match s.firewall_mode {
                FirewallMode::Managed => Mode::Managed,
                FirewallMode::External => Mode::External,
            },
        }
    }
}

impl RecordedStructure {
    pub fn mask(&self) -> Option<FwMask> {
        FwMask::new(self.fwmark_mask)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub id: u8,
    pub name: String,
    /// Removed from the configuration; the id stays reserved until
    /// `forget-uplink` (FR-MARK-4).
    pub removed: bool,
}

/// The manifest (IMPL-5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub structure: RecordedStructure,
    pub tables: (u32, u32),
    pub priorities: (u32, u32),
    pub nft_table: String,
    /// Families that have PolyWAN artifacts (§4.3).
    pub families: Vec<String>,
    pub uplinks: Vec<Binding>,
    /// Value of each sysctl before PolyWAN first changed it (FR-SYS, FR-REC-4).
    pub sysctl_baseline: BTreeMap<String, String>,
    /// The value PolyWAN set, so that cleanup restores only untouched values.
    pub sysctl_set: BTreeMap<String, String>,
}

/// A configuration that conflicts with the manifest.
#[derive(Debug, PartialEq, Eq)]
pub enum ManifestConflict {
    Structure {
        recorded: RecordedStructure,
        configured: RecordedStructure,
    },
    IdReused {
        id: u8,
        recorded: String,
        configured: String,
    },
    IdChanged {
        name: String,
        recorded: u8,
        configured: u8,
    },
}

impl std::fmt::Display for ManifestConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestConflict::Structure { recorded, configured } => write!(
                f,
                "structural settings differ from the installed ones ({recorded:?} installed, {configured:?} configured): run `polywan cleanup` with the old settings, then start with the new ones (FR-CFG-4)"
            ),
            ManifestConflict::IdReused {
                id,
                recorded,
                configured,
            } => write!(
                f,
                "uplink id {id} is bound to {recorded:?}; it cannot be reused for {configured:?} until `polywan forget-uplink {recorded}` (FR-MARK-4)"
            ),
            ManifestConflict::IdChanged {
                name,
                recorded,
                configured,
            } => write!(
                f,
                "uplink {name:?} has id {recorded}; changing it to {configured} is not allowed while the old binding is recorded (FR-MARK-4)"
            ),
        }
    }
}

impl Manifest {
    pub fn new(config: &Config) -> Manifest {
        let s = config.structural();
        let mut m = Manifest {
            version: VERSION,
            structure: s.into(),
            tables: (s.table_base, s.table_base + 191),
            priorities: (s.rule_priority_base, s.rule_priority_base + 699),
            nft_table: format!("inet {}", crate::nft::TABLE),
            families: Vec::new(),
            uplinks: Vec::new(),
            sysctl_baseline: BTreeMap::new(),
            sysctl_set: BTreeMap::new(),
        };
        m.bind(config);
        m
    }

    /// Checks the configuration against the recorded structure and bindings.
    pub fn check(&self, config: &Config) -> Vec<ManifestConflict> {
        let mut v = Vec::new();
        let configured: RecordedStructure = config.structural().into();
        if configured != self.structure {
            v.push(ManifestConflict::Structure {
                recorded: self.structure,
                configured,
            });
        }
        for u in &config.uplinks {
            for b in &self.uplinks {
                if b.id == u.id.get() && b.name != u.name {
                    v.push(ManifestConflict::IdReused {
                        id: b.id,
                        recorded: b.name.clone(),
                        configured: u.name.clone(),
                    });
                } else if b.name == u.name && b.id != u.id.get() {
                    v.push(ManifestConflict::IdChanged {
                        name: u.name.clone(),
                        recorded: b.id,
                        configured: u.id.get(),
                    });
                }
            }
        }
        v
    }

    /// Records the bindings of the configuration (call after `check`):
    /// configured uplinks are bound, the others are marked removed.
    pub fn bind(&mut self, config: &Config) {
        for b in &mut self.uplinks {
            b.removed = !config.uplinks.iter().any(|u| u.id.get() == b.id);
        }
        for u in &config.uplinks {
            if !self.uplinks.iter().any(|b| b.id == u.id.get()) {
                self.uplinks.push(Binding {
                    id: u.id.get(),
                    name: u.name.clone(),
                    removed: false,
                });
            }
        }
        self.uplinks.sort_by_key(|b| b.id);
        self.families = Family::ALL
            .into_iter()
            .filter(|f| config.manages(*f))
            .map(|f| f.key().to_owned())
            .collect();
    }

    /// `forget-uplink NAME`: refused while the uplink is configured.
    pub fn forget(&mut self, name: &str) -> Result<UplinkId, String> {
        let pos = self
            .uplinks
            .iter()
            .position(|b| b.name == name)
            .ok_or_else(|| format!("no uplink {name:?} is recorded"))?;
        if !self.uplinks[pos].removed {
            return Err(format!(
                "uplink {name:?} is still configured; remove it from the configuration first"
            ));
        }
        let b = self.uplinks.remove(pos);
        UplinkId::new(b.id).ok_or_else(|| format!("invalid recorded id {}", b.id))
    }

    /// Records the baseline of a sysctl the first time PolyWAN changes it.
    pub fn record_sysctl(&mut self, key: &str, previous: &str, set: &str) {
        self.sysctl_baseline
            .entry(key.to_owned())
            .or_insert_with(|| previous.to_owned());
        self.sysctl_set.insert(key.to_owned(), set.to_owned());
    }
}

/// Persisted drain intent (FR-SEL-3), by uplink name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainState {
    pub version: u32,
    pub drained: Vec<String>,
}

impl DrainState {
    pub fn of(drained: impl IntoIterator<Item = String>) -> DrainState {
        DrainState {
            version: VERSION,
            drained: drained.into_iter().collect(),
        }
    }
}

impl Default for DrainState {
    fn default() -> DrainState {
        DrainState::of([])
    }
}

/// Health checkpoint (IMPL-5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub boot_id: String,
    /// `CLOCK_BOOTTIME` in milliseconds when written.
    pub boottime_ms: u64,
    pub config_digest: String,
    pub structure: RecordedStructure,
    pub paths: Vec<PathCheckpoint>,
    pub active_v4: Vec<u8>,
    pub active_v6: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathCheckpoint {
    pub uplink: u8,
    pub family: String,
    pub ifindex: Option<u32>,
    pub source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub up: bool,
    pub since_ms: u64,
    pub passes: u8,
    pub failures: u8,
}

/// Maximum age of a usable checkpoint (FR-HEALTH-1).
pub const CHECKPOINT_MAX_AGE_MS: u64 = 10 * 60 * 1000;

impl Checkpoint {
    /// Valid: same boot, younger than 10 minutes, same structural settings.
    pub fn valid(&self, boot_id: &str, now_ms: u64, structure: &RecordedStructure) -> bool {
        self.boot_id == boot_id
            && now_ms >= self.boottime_ms
            && now_ms - self.boottime_ms < CHECKPOINT_MAX_AGE_MS
            && self.structure == *structure
    }
}

/// `/proc/sys/kernel/random/boot_id`.
pub fn boot_id() -> io::Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().to_owned())
}

/// `CLOCK_BOOTTIME` in milliseconds, from `/proc/uptime` (which reports it,
/// suspend included, with centisecond resolution).
pub fn boottime_ms() -> io::Result<u64> {
    let text = fs::read_to_string("/proc/uptime")?;
    let secs = text.split_whitespace().next().unwrap_or("");
    let (int, frac) = secs.split_once('.').unwrap_or((secs, "0"));
    let int: u64 = int.parse().map_err(|_| io::Error::other("bad /proc/uptime"))?;
    let frac: u64 = format!("{frac:0<3}")[..3]
        .parse()
        .map_err(|_| io::Error::other("bad /proc/uptime"))?;
    Ok(int * 1000 + frac + crate::test_hooks::boottime_shift_ms())
}

/// The exclusive instance lock (IMPL-6), held while the value lives.
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// IMPL-6: the lock is a regular file of the daemon's user (root) with
    /// mode 0600, created so from the outset, never opened through a
    /// symbolic link, never replaced or unlinked. Its directory is created
    /// with mode 0755 when missing (IMPL-10).
    pub fn acquire(path: &Path) -> io::Result<InstanceLock> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

        if let Some(dir) = path.parent()
            && !dir.exists()
        {
            fs::DirBuilder::new().recursive(true).mode(0o755).create(dir)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)?;
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != nix::unistd::geteuid().as_raw() || m.mode() & 0o077 != 0 {
            return Err(io::Error::other(format!(
                "{}: the instance lock must be a regular file owned by root with mode 0600 (IMPL-6)",
                path.display()
            )));
        }
        match file.try_lock() {
            Ok(()) => Ok(InstanceLock { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "{} is held by another instance (daemon, cleanup or forget-uplink)",
                    path.display()
                ),
            )),
            Err(fs::TryLockError::Error(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    const CONFIG: &str = r#"[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "wana"
[uplink.ipv4]
[[uplink]]
id = 2
name = "b"
interface = "wanb"
[uplink.ipv4]
"#;

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "polywan-state-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn files_round_trip_atomically() {
        let dir = StateDir::open(&tempdir()).unwrap();
        let cfg = config::parse(CONFIG).unwrap();
        assert_eq!(dir.manifest().unwrap(), None);
        let mut m = Manifest::new(&cfg);
        m.record_sysctl("net.ipv4.ip_forward", "0", "1");
        m.record_sysctl("net.ipv4.ip_forward", "1", "1");
        dir.write_manifest(&m).unwrap();
        let back = dir.manifest().unwrap().unwrap();
        assert_eq!(back, m);
        assert_eq!(
            back.sysctl_baseline["net.ipv4.ip_forward"], "0",
            "the first baseline is kept"
        );
        assert_eq!(back.families, ["ipv4"]);
        let drain = DrainState::of(["b".to_owned()]);
        dir.write_drain(&drain).unwrap();
        assert_eq!(dir.drain().unwrap(), drain);
        assert!(!dir.path.join("drain.tmp").exists());
        dir.reset().unwrap();
        assert_eq!(dir.drain().unwrap(), DrainState::default());
        // What a default writes, the reader accepts.
        dir.write_drain(&DrainState::default()).unwrap();
        assert_eq!(dir.drain().unwrap(), DrainState::default());
        assert!(dir.manifest().unwrap().is_some(), "reset never discards the manifest");
        fs::remove_dir_all(&dir.path).unwrap();
    }

    #[test]
    fn unknown_versions_and_garbage_are_corrupt() {
        let dir = StateDir::open(&tempdir()).unwrap();
        fs::write(dir.path.join(DRAIN), "{\"version\": 9, \"drained\": []}").unwrap();
        assert!(matches!(dir.drain(), Err(StateError::Corrupt { .. })));
        fs::write(dir.path.join(CHECKPOINT), "not json").unwrap();
        assert!(matches!(dir.checkpoint(), Err(StateError::Corrupt { .. })));
        fs::remove_dir_all(&dir.path).unwrap();
    }

    #[test]
    fn bindings_follow_fr_mark_4() {
        let cfg = config::parse(CONFIG).unwrap();
        let mut m = Manifest::new(&cfg);
        assert!(m.check(&cfg).is_empty());
        // Reusing id 2 for another name, and changing a's id.
        let other = config::parse(
            &CONFIG
                .replace("name = \"b\"", "name = \"c\"")
                .replace("id = 1", "id = 3"),
        )
        .unwrap();
        let c = m.check(&other);
        assert!(c.contains(&ManifestConflict::IdReused {
            id: 2,
            recorded: "b".into(),
            configured: "c".into()
        }));
        assert!(c.contains(&ManifestConflict::IdChanged {
            name: "a".into(),
            recorded: 1,
            configured: 3
        }));
        // Removing b keeps its id reserved until forget.
        let only_a = config::parse(&CONFIG[..CONFIG.find("[[uplink]]\nid = 2").unwrap()]).unwrap();
        assert!(m.check(&only_a).is_empty());
        m.bind(&only_a);
        assert!(m.uplinks.iter().any(|b| b.name == "b" && b.removed));
        assert!(m.forget("a").is_err(), "a is configured");
        assert_eq!(m.forget("b").unwrap().get(), 2);
        assert!(
            m.check(&other)
                .iter()
                .all(|c| !matches!(c, ManifestConflict::IdReused { .. }))
        );
        // Structural changes are refused.
        let moved = config::parse(&format!("[routing]\ntable_base = 2000\n{}", CONFIG)).unwrap();
        assert!(matches!(m.check(&moved)[0], ManifestConflict::Structure { .. }));
    }

    #[test]
    fn checkpoint_validity() {
        let s: RecordedStructure = config::parse(CONFIG).unwrap().structural().into();
        let c = Checkpoint {
            version: VERSION,
            boot_id: "b1".into(),
            boottime_ms: 1_000_000,
            config_digest: String::new(),
            structure: s,
            paths: Vec::new(),
            active_v4: vec![1],
            active_v6: Vec::new(),
        };
        assert!(c.valid("b1", 1_000_000 + 599_999, &s));
        assert!(!c.valid("b1", 1_000_000 + 600_000, &s), "10 minutes old");
        assert!(!c.valid("b2", 1_000_001, &s), "another boot");
        let mut other = s;
        other.table_base = 2000;
        assert!(!c.valid("b1", 1_000_001, &other));
    }

    #[test]
    fn the_lock_is_exclusive() {
        let dir = tempdir();
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("lock");
        let held = InstanceLock::acquire(&p).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            InstanceLock::acquire(&p).err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        drop(held);
        assert!(InstanceLock::acquire(&p).is_ok());
        // Never through a symbolic link, never a permissive file (IMPL-6).
        let link = dir.join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(InstanceLock::acquire(&link).is_err());
        let open = dir.join("open");
        fs::write(&open, "").unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(InstanceLock::acquire(&open).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn uptime_is_parsed() {
        assert!(boottime_ms().unwrap() > 0);
    }
}
