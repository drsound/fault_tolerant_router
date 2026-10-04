//! Hooks for the acceptance scenarios. They act only in builds with the
//! `test-hooks` feature, which `tests/vm/run-suite.sh` enables and release
//! builds never do; otherwise they do nothing.

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

/// `FTR_TEST_FAULTS`: a control file for failure injection (AS-27, AS-36).
/// Every step of the reconciler and of cleanup calls this before acting.
/// While the file holds a number N greater than 0, the step proceeds and the
/// file is rewritten with N - 1; while it holds 0, the step fails with an
/// injected error, until the file is removed or rewritten. While it holds
/// `match:TEXT`, the steps whose name contains TEXT fail and the others
/// proceed; `empty:TEXT` is the same, and a failing route replacement also
/// removes the route first ([`empties`]). Every step is appended to
/// `<file>.steps`, followed by ` failed` when it failed.
#[cfg(feature = "test-hooks")]
pub fn step(name: impl std::fmt::Display) -> Result<(), String> {
    use std::io::Write;

    let Some(path) = std::env::var_os("FTR_TEST_FAULTS").map(std::path::PathBuf::from) else {
        return Ok(());
    };
    let control = std::fs::read_to_string(&path).unwrap_or_default();
    let control = control.trim();
    let failure = || Err(format!("failure injected before {name}"));
    let result = if let Some(text) = control
        .strip_prefix("match:")
        .or_else(|| control.strip_prefix("empty:"))
    {
        if name.to_string().contains(text) {
            failure()
        } else {
            Ok(())
        }
    } else {
        match control.parse::<u64>().ok() {
            Some(0) => failure(),
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

/// Whether a failing step, injected by `empty:TEXT`, also removes the route
/// it replaces: the empty-table outcome of an IPv6 multipath replacement
/// that fails after the first insertion (FR-ROUTE-2, AS-36).
#[cfg(feature = "test-hooks")]
pub fn empties(name: impl std::fmt::Display) -> bool {
    let Some(path) = std::env::var_os("FTR_TEST_FAULTS") else {
        return false;
    };
    let control = std::fs::read_to_string(path).unwrap_or_default();
    control
        .trim()
        .strip_prefix("empty:")
        .is_some_and(|text| name.to_string().contains(text))
}

#[cfg(not(feature = "test-hooks"))]
pub fn empties(_name: impl std::fmt::Display) -> bool {
    false
}

#[cfg(not(feature = "test-hooks"))]
pub fn boottime_shift_ms() -> u64 {
    0
}

#[cfg(not(feature = "test-hooks"))]
pub fn step(_name: impl std::fmt::Display) -> Result<(), String> {
    Ok(())
}
