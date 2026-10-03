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
