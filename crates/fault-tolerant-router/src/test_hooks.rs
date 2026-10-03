//! Hooks for the acceptance scenarios, compiled only with the `test-hooks`
//! feature: `tests/vm/run-suite.sh` enables it, release builds never do.

use std::sync::OnceLock;

/// `FTR_TEST_BOOTTIME_SHIFT_MS`: milliseconds added to `CLOCK_BOOTTIME`, so
/// that a scenario can age the health checkpoint past its maximum age on a
/// host that booted less than that age ago (AS-47).
pub fn boottime_shift_ms() -> u64 {
    static SHIFT: OnceLock<u64> = OnceLock::new();
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
/// injected error, until the file is removed or rewritten. Every step is
/// appended to `<file>.steps`, followed by ` failed` when it failed.
pub fn step(name: &str) -> Result<(), String> {
    use std::io::Write;

    let Some(path) = std::env::var_os("FTR_TEST_FAULTS").map(std::path::PathBuf::from) else {
        return Ok(());
    };
    let armed = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    let result = match armed {
        Some(0) => Err(format!("failure injected before {name}")),
        Some(n) => {
            let _ = std::fs::write(&path, (n - 1).to_string());
            Ok(())
        }
        None => Ok(()),
    };
    let mut steps = path.into_os_string();
    steps.push(".steps");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(steps) {
        let _ = writeln!(f, "{name}{}", if result.is_err() { " failed" } else { "" });
    }
    result
}
