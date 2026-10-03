//! Helpers shared by the kernel tests, which run under `unshare -n`.

// Each test binary uses part of them.
#![allow(dead_code)]

use std::process::Command;

/// Refuses to run in the initial network namespace.
pub fn private_netns() {
    let own = std::fs::read_link("/proc/self/ns/net").expect("own netns");
    let init = std::fs::read_link("/proc/1/ns/net").expect("netns of pid 1 (needs root)");
    assert_ne!(
        own, init,
        "refusing to change the initial network namespace; run under `unshare -n`"
    );
}

/// Runs a shell command and asserts that it succeeds.
pub fn sh(cmd: &str) {
    let ok = Command::new("sh").args(["-c", cmd]).status().expect("sh").success();
    assert!(ok, "{cmd}");
}
