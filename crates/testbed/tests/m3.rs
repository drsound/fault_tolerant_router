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
