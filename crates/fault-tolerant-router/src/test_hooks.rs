//! Hooks for the acceptance scenarios. They act only in builds with the
//! `test-hooks` feature, which `tests/vm/run-suite.sh` enables and release
//! builds never do; otherwise they do nothing.

use std::time::Duration;

use crate::model::Family;

/// `FTR_TEST_BOOTTIME_SHIFT_MS`: milliseconds added to `CLOCK_BOOTTIME`, so
/// that a scenario can age the health checkpoint past its maximum age on a
/// host that booted less than that age ago (AS-47).
#[cfg(feature = "test-hooks")]
pub fn boottime_shift_ms() -> u64 {
    static SHIFT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SHIFT.get_or_init(|| {
        std::env::var("FTR_TEST_BOOTTIME_SHIFT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    })
}

/// `FTR_TEST_GATEWAY_WARNING_MS`: the delay of the FR-SYS-3 warning about a
/// missing IPv6 gateway, in milliseconds, instead of `default`, so that a
/// scenario need not wait for it.
#[cfg(feature = "test-hooks")]
pub fn gateway_warning(default: Duration) -> Duration {
    static DELAY: std::sync::OnceLock<Option<Duration>> = std::sync::OnceLock::new();
    let delay = *DELAY.get_or_init(|| {
        std::env::var("FTR_TEST_GATEWAY_WARNING_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_millis)
    });
    delay.unwrap_or(default)
}

/// A failure injected before a step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Injected {
    pub message: String,
    /// Injected by `empty:TEXT`: a failing route replacement also removes
    /// the route it replaces first, the empty-table outcome of an IPv6
    /// multipath replacement that fails after the first insertion
    /// (FR-ROUTE-2, AS-36).
    pub removes_route: bool,
}

impl std::fmt::Display for Injected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Injected {}

/// `FTR_TEST_FAULTS`: a control file for failure injection (AS-27, AS-36).
/// Every step of the reconciler and of cleanup calls this before acting.
/// While the file holds a number N greater than 0, the step proceeds and the
/// file is rewritten with N - 1; while it holds 0, the step fails with an
/// injected error, until the file is removed or rewritten. While it holds
/// `match:TEXT`, the steps whose name contains TEXT fail and the others
/// proceed; `empty:TEXT` is the same, and the failure also removes the
/// route ([`Injected::removes_route`]). Every step is appended to
/// `<file>.steps`, followed by ` failed` when it failed.
#[cfg(feature = "test-hooks")]
pub fn step(name: impl std::fmt::Display) -> Result<(), Injected> {
    use std::io::Write;

    let Some(path) = std::env::var_os("FTR_TEST_FAULTS").map(std::path::PathBuf::from) else {
        return Ok(());
    };
    let name = name.to_string();
    let control = std::fs::read_to_string(&path).unwrap_or_default();
    let control = control.trim();
    let failure = |removes_route| {
        Err(Injected {
            message: format!("failure injected before {name}"),
            removes_route,
        })
    };
    let selective = control
        .strip_prefix("match:")
        .map(|text| (text, false))
        .or_else(|| control.strip_prefix("empty:").map(|text| (text, true)));
    let result = if let Some((text, removes_route)) = selective {
        if name.contains(text) {
            failure(removes_route)
        } else {
            Ok(())
        }
    } else {
        match control.parse::<u64>().ok() {
            Some(0) => failure(false),
            Some(n) => {
                let _ = std::fs::write(&path, (n - 1).to_string());
                Ok(())
            }
            None => Ok(()),
        }
    };
    let mut steps = path.into_os_string();
    steps.push(".steps");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(steps) {
        let _ = writeln!(f, "{name}{}", if result.is_err() { " failed" } else { "" });
    }
    result
}

/// The table whose route an `empty:` failure removed: the daemon ignores
/// the deletion's notification, as a kernel failure need not send one, so
/// that only the re-read of the table corrects its view (AS-36).
#[cfg(feature = "test-hooks")]
static HIDDEN: std::sync::Mutex<Option<(Family, u32)>> = std::sync::Mutex::new(None);

/// Records the deletion that the simulated failure performs next.
#[cfg(feature = "test-hooks")]
pub fn hide_deletion(family: Family, table: u32) {
    *HIDDEN.lock().unwrap_or_else(|e| e.into_inner()) = Some((family, table));
}

/// Whether a deletion notification is the hidden one; it is consumed.
#[cfg(feature = "test-hooks")]
pub fn hidden_deletion(family: Family, table: u32) -> bool {
    let mut hidden = HIDDEN.lock().unwrap_or_else(|e| e.into_inner());
    if *hidden == Some((family, table)) {
        *hidden = None;
        return true;
    }
    false
}

#[cfg(not(feature = "test-hooks"))]
pub fn boottime_shift_ms() -> u64 {
    0
}

#[cfg(not(feature = "test-hooks"))]
pub fn gateway_warning(default: Duration) -> Duration {
    default
}

#[cfg(not(feature = "test-hooks"))]
pub fn step(_name: impl std::fmt::Display) -> Result<(), Injected> {
    Ok(())
}

#[cfg(not(feature = "test-hooks"))]
pub fn hide_deletion(_family: Family, _table: u32) {}

#[cfg(not(feature = "test-hooks"))]
pub fn hidden_deletion(_family: Family, _table: u32) -> bool {
    false
}
