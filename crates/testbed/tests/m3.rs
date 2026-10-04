//! M3 acceptance scenarios (SPEC.md §14.3, §17): operations (API and CLI,
//! drain, policies, events, email, hooks, metrics, quality gates), with the
//! daemon under test (`POLYWAN_DAEMON_BIN`) in the router namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use anyhow::Result;
use testbed::Outcome;
use testbed::plan::{Family, Node};
use testbed::polywan::{self, HealthSpec};
use testbed::traffic::tally;

mod common;
use common::*;

/// An IPv4 configuration over A and B with `extra` appended.
fn with(extra: &str) -> String {
    polywan::config(&ab(), &[Family::V4], &HealthSpec::fast(), "", extra)
}

/// AS-20, email variants: the SMTP keys of earlier drafts, malformed
/// addresses and header injection attempts are refused by offline
/// `check-config`, on reload (the running configuration stays) and at
/// startup (FR-MAIL-1, FR-CFG-1, FR-CFG-3).
#[test]
#[ignore = "needs root and network namespaces"]
fn as20_invalid_email_settings_are_refused() -> Result<()> {
    let t = build();
    let mut f = t.start_polywan(&polywan::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let email =
        |from: &str, to: &str, more: &str| with(&format!("[notify.email]\nfrom = \"{from}\"\nto = [\"{to}\"]\n{more}"));
    let cases = [
        (
            email(
                "router@example.com",
                "admin@example.com",
                "host = \"smtp.example.com\"\nport = 587\n",
            ),
            "unknown field `host`",
        ),
        (
            email("Router <router@example.com>", "admin@example.com", ""),
            "notify.email.from: \"Router <router@example.com>\" is not a single address",
        ),
        (
            email(
                "router@example.com",
                "admin@example.com\\r\\nBcc: victim@example.com",
                "",
            ),
            "notify.email.to[0]",
        ),
        (
            email("router@example.com", "-oQ/tmp/x@example.com", ""),
            "must not start with '-'",
        ),
    ];
    for (i, (config, needle)) in cases.iter().enumerate() {
        f.write_config(config)?;
        let out = f.cli_config(&["check-config", "--offline"])?;
        let text = polywan::output_text(&out);
        assert!(!out.status.success() && text.contains(needle), "{needle}: {text}");
        f.reload()?;
        f.wait_log(&t, "reload_failed", i + 1, Duration::from_secs(5))?;
        assert!(f.log().contains(needle), "{needle}: {}", f.log());
    }
    let r = t.connect_many(Node::Client, Family::V4, 10, 20, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    f.stop()?;
    f.start(&t)?;
    f.wait_exit(&t, Duration::from_secs(5))?;
    assert!(f.log().contains(cases[3].1), "{}", f.log());
    Ok(())
}

/// AS-20, `notify.email.sendmail` (FR-CFG-5): a sendmail reached through a
/// symbolic link whose target directory is writable by others, and one
/// that is not executable, are refused by online `check-config`, at startup
/// and on reload, and never run; the rejected reload keeps the running
/// configuration.
#[test]
#[ignore = "needs root and network namespaces"]
fn as20_an_untrusted_sendmail_never_runs() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    let open = f.dir.join("open");
    std::fs::create_dir(&open)?;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))?;
    let ran = f.dir.join("ran");
    let sendmail = open.join("sendmail");
    std::fs::write(
        &sendmail,
        format!("#!/bin/sh\ntouch {}\ncat >/dev/null\n", ran.display()),
    )?;
    std::fs::set_permissions(&sendmail, std::fs::Permissions::from_mode(0o755))?;
    let link = f.dir.join("sendmail");
    std::os::unix::fs::symlink(&sendmail, &link)?;
    let email = |path: &std::path::Path| {
        with(&format!(
            "[notify.email]\nfrom = \"router@example.com\"\nto = [\"admin@example.com\"]\nsendmail = \"{}\"\n",
            path.display()
        ))
    };
    let refusal = format!("{} is writable by group or others", open.display());
    let plain = t.exec_dir()?.join("sendmail");
    std::fs::write(&plain, "#!/bin/sh\nexit 0\n")?;
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644))?;
    for (config, needle) in [
        (email(&link), refusal.clone()),
        (email(&plain), format!("{} is not executable", plain.display())),
    ] {
        f.write_config(&config)?;
        let out = f.cli_config(&["check-config"])?;
        let text = polywan::output_text(&out);
        assert!(!out.status.success() && text.contains(&needle), "{text}");
        f.start(&t)?;
        f.wait_exit(&t, Duration::from_secs(5))?;
        assert!(f.log().contains(&needle), "{}", f.log());
    }
    f.write_config(&polywan::ipv4(&ab()))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    f.write_config(&email(&link))?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains(&refusal), "{}", f.log());
    let r = t.connect_many(Node::Client, Family::V4, 10, 20, false)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    assert!(!ran.exists(), "the untrusted sendmail never ran");
    f.stop()?;
    Ok(())
}

/// IMPL-6 and FR-SEL-3: unreadable drain state refuses startup until
/// `--reset-state`; an unreadable health checkpoint is ignored (cold
/// start); the drain intent of an uplink that is no longer configured is
/// pruned at startup and on reload, and a re-added uplink is not drained.
#[test]
#[ignore = "needs root and network namespaces"]
fn impl6_unreadable_state_and_drain_pruning() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    std::fs::create_dir_all(&f.state)?;
    std::fs::set_permissions(&f.state, std::fs::Permissions::from_mode(0o700))?;
    let drain = f.state.join("drain.json");
    let checkpoint = f.state.join("health.json");
    std::fs::write(&drain, "{")?;
    std::fs::write(&checkpoint, "{")?;
    f.start(&t)?;
    f.wait_exit(&t, Duration::from_secs(5))?;
    assert!(
        f.log().contains("drain state:") && f.log().contains("--reset-state"),
        "{}",
        f.log()
    );
    // A drained, plus a name no longer configured.
    std::fs::write(&drain, "{\"version\": 1, \"drained\": [\"a\", \"gone\"]}\n")?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    assert!(f.log().contains("health checkpoint ignored"), "{}", f.log());
    wait_members(&t, Family::V4, &["wanb"], Duration::from_secs(10))?;
    let names = |p: &std::path::Path| -> Result<Vec<String>> {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p)?)?;
        Ok(v["drained"]
            .as_array()
            .map(|a| a.iter().filter_map(|n| n.as_str().map(str::to_owned)).collect())
            .unwrap_or_default())
    };
    assert_eq!(names(&drain)?, ["a"], "pruned at startup");
    // Removing A clears its intent; re-added, it is not drained.
    f.write_config(&polywan::ipv4(&ab()[1..]))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    assert!(names(&drain)?.is_empty(), "pruned on reload");
    f.write_config(&polywan::ipv4(&ab()))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 2, Duration::from_secs(5))?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(15))?;
    f.stop()?;
    std::fs::write(&drain, "{\"version\": 7, \"drained\": []}\n")?;
    f.start_with(&t, &["--reset-state"])?;
    f.wait_installed(&t)?;
    assert!(!drain.exists() || names(&drain)?.is_empty());
    f.stop()?;
    Ok(())
}
