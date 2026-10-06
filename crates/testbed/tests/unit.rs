//! Acceptance scenarios that need the packaged unit (SPEC.md AS-34,
//! IMPL-6 and IMPL-10 under systemd): msmtp through the sandboxed unit,
//! unit states, restarts and the instance lock across failed starts. Run by
//! `tests/vm/run-suite.sh --unit` only, after the M1 to M4 scenarios; each
//! fails when `POLYWAN_TEST_UNIT` is not set.

use std::os::unix::fs::PermissionsExt;
use std::process::Output;
use std::time::Duration;

use anyhow::{Context, Result};
use testbed::plan::{Family, Uplink};
use testbed::polywan::{self, HealthSpec, UplinkSpec, succeeded};

#[macro_use]
mod common;
use common::*;

/// Every scenario here starts the daemon under the packaged unit: a run
/// without it is an error, never a pass.
fn require_unit() -> Result<()> {
    anyhow::ensure!(
        testbed::unit::shipped_unit().is_some(),
        "POLYWAN_TEST_UNIT is not set: these scenarios run under the packaged unit (run-suite.sh --unit)"
    );
    Ok(())
}

/// The numeric id of a group in `/etc/group`.
fn gid(name: &str) -> Result<u32> {
    let groups = std::fs::read_to_string("/etc/group")?;
    groups
        .lines()
        .find_map(|l| {
            let mut w = l.split(':');
            (w.next() == Some(name)).then(|| w.nth(1)?.parse().ok())?
        })
        .with_context(|| format!("group {name}"))
}

/// The processes of a unit's control group: (pid, comm).
fn unit_processes(unit: &testbed::unit::Unit) -> Result<Vec<(u32, String)>> {
    let cgroup = unit.property("ControlGroup")?;
    let procs = std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cgroup.procs")).unwrap_or_default();
    Ok(procs
        .lines()
        .filter_map(|p| p.parse().ok())
        .map(|p: u32| {
            let comm = std::fs::read_to_string(format!("/proc/{p}/comm")).unwrap_or_default();
            (p, comm.trim().to_owned())
        })
        .collect())
}

/// msmtp's AppArmor profile in enforce mode for the guard's lifetime,
/// unloaded afterwards unless it was loaded before. The profile is given
/// on standard input: `apparmor_parser` skips a file named in
/// `/etc/apparmor.d/disable` (Debian disables this one by default), which
/// the harness leaves as it is.
struct Enforced {
    loaded_before: bool,
}

const MSMTP_PROFILE: &str = "/etc/apparmor.d/usr.bin.msmtp";

/// `apparmor_parser OPTION` with msmtp's profile on standard input.
fn apparmor_parser(option: &str) -> Result<Output> {
    succeeded(
        std::process::Command::new("apparmor_parser")
            .arg(option)
            .stdin(std::fs::File::open(MSMTP_PROFILE)?)
            .output()?,
    )
}

/// The kernel's line of the msmtp profile, if loaded.
fn msmtp_profile() -> Option<String> {
    std::fs::read_to_string("/sys/kernel/security/apparmor/profiles")
        .ok()?
        .lines()
        .find(|l| l.starts_with("msmtp "))
        .map(str::to_owned)
}

impl Enforced {
    /// `None` without AppArmor.
    fn new() -> Result<Option<Enforced>> {
        let enabled = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled").unwrap_or_default();
        if enabled.trim() != "Y" || !std::path::Path::new(MSMTP_PROFILE).exists() {
            return Ok(None);
        }
        let guard = Enforced {
            loaded_before: msmtp_profile().is_some(),
        };
        apparmor_parser("-r")?;
        anyhow::ensure!(
            msmtp_profile().is_some_and(|p| p.contains("(enforce)")),
            "msmtp's profile not enforced"
        );
        Ok(Some(guard))
    }
}

impl Drop for Enforced {
    fn drop(&mut self) {
        if !self.loaded_before {
            let _ = apparmor_parser("-R");
        }
    }
}

/// The password of the router's account on the test SMTP server.
const SMTP_PASSWORD: &str = "polywan-secret-7c1e";

/// AS-34, email (FR-MAIL-1, FR-MAIL-4, IMPL-10, DIST-3) and access
/// (FR-API-1): under the packaged unit, with `/usr/bin/msmtp` and its
/// system configuration (STARTTLS with certificate checking against the
/// system's trusted certificates, AUTH PLAIN with the password in the
/// root-only `/etc/netrc`), `notify-test` reaches the test SMTP server with
/// the configured sender, recipients and content; a certificate of
/// another authority and a wrong password fail with msmtp's diagnostics,
/// which carry no credentials; a stop during a submission lets it
/// complete, then sends `daemon_stopping`; the same submission succeeds
/// with msmtp's AppArmor profile in enforce mode (the process's
/// confinement checked). The control socket has the group `adm`, the
/// status socket the group `sys`, both mode 0660.
#[test]
#[ignore = "needs root and network namespaces"]
fn as34_notifications_through_msmtp() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    require_unit()?;
    let t = build();
    let mut f = t.prepare_polywan("")?;
    anyhow::ensure!(
        std::path::Path::new("/usr/bin/msmtp").exists(),
        "AS-34 needs msmtp (/usr/bin/msmtp)"
    );
    let evidence = std::process::Command::new("dpkg-query")
        .args(["-W", "msmtp", "systemd"])
        .output()?;
    eprintln!(
        "AS-34 evidence: {}",
        polywan::output_text(&evidence).replace('\n', "; ")
    );
    let pki = testbed::smtp::Pki::new("PolyWAN test authority")?;
    let server = t.start_smtp_server(&pki, SMTP_PASSWORD)?;
    t.msmtp_system(&pki.ca, SMTP_PASSWORD)?;
    let to = ["admin@example.com", "noc@example.org"];
    let api = f.api_table("adm", Some("sys"));
    let email = format!(
        "[notify]\ncoalesce = \"1s\"\n[notify.email]\nfrom = \"router@example.com\"\nto = [\"{}\"]\nsendmail = \"/usr/bin/msmtp\"\nevents = [\"daemon_stopping\"]\n",
        to.join("\", \"")
    );
    f.write_config(&polywan::config(
        &ab(),
        &[Family::V4],
        &HealthSpec::fast(),
        "",
        &format!("{api}{email}"),
    ))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    for (socket, group) in [(f.control_socket(), "adm"), (f.status_socket(), "sys")] {
        let m = std::fs::metadata(&socket)?;
        assert_eq!(
            (m.mode() & 0o777, m.uid(), m.gid()),
            (0o660, 0, gid(group)?),
            "{}",
            socket.display()
        );
    }

    // Received with the envelope and the content.
    let test = |f: &polywan::Polywan| -> Result<(bool, String)> {
        let out = f.notify_test()?;
        Ok((out.status.success(), polywan::output_text(&out)))
    };
    let (ok, text) = test(&f)?;
    assert!(ok, "{text}");
    let messages = server.wait(&t, "message", 1, Duration::from_secs(10))?;
    let m = &messages[0];
    assert_eq!(m.from.as_deref(), Some("router@example.com"));
    assert_eq!(m.rcpt, to);
    let mail = testbed::sendmail::Mail::parse(m.data.as_deref().unwrap_or_default())?;
    assert!(
        mail.header("Subject")
            .is_some_and(|s| s.starts_with("PolyWAN notification test")),
        "{mail:?}"
    );
    assert_eq!(mail.header("To"), Some(to.join(",\n ").as_str()));
    assert_eq!(server.of("tls")?.len(), 1);
    assert_eq!(server.of("auth")?.len(), 1);

    // Diagnostics: an untrusted certificate, a wrong password.
    let secrets = |text: &str| !text.contains(SMTP_PASSWORD) && !text.contains("wrong-password-41");
    server.serve(&testbed::smtp::Pki::new("Another authority")?)?;
    let (ok, text) = test(&f)?;
    assert!(!ok && text.contains("email: failed, exit status"), "{text}");
    assert!(text.to_lowercase().contains("certificate"), "{text}");
    // With TLS 1.3 the client checks the certificate after the server's
    // side of the handshake: the session ends without authentication.
    server.wait(&t, "end", 2, Duration::from_secs(5))?;
    assert_eq!(server.of("auth")?.len(), 1);
    server.serve(&pki)?;
    server.password("wrong-password-41")?;
    let (ok, text) = test(&f)?;
    assert!(!ok && text.contains("authentication failed"), "{text}");
    assert!(secrets(&text), "{text}");
    server.wait(&t, "auth_failed", 1, Duration::from_secs(5))?;
    assert!(secrets(&f.log()), "{}", f.log());
    assert_eq!(server.of("message")?.len(), 1);

    // Enforced by AppArmor: msmtp runs confined and succeeds.
    server.password(SMTP_PASSWORD)?;
    server.delay(Duration::from_secs(2))?;
    match Enforced::new()? {
        None => eprintln!("AS-34: AppArmor unavailable, the enforced run skipped"),
        Some(_enforced) => {
            eprintln!("AS-34: AppArmor profile {:?}", msmtp_profile());
            let unit = f.unit()?;
            let (confinement, tested) = during_submission(
                &t,
                &server,
                || test(&f),
                || {
                    let (pid, _) = unit_processes(unit)?
                        .into_iter()
                        .find(|(_, comm)| comm == "msmtp")
                        .context("msmtp in the unit")?;
                    let label = std::fs::read_to_string(format!("/proc/{pid}/attr/current")).unwrap_or_default();
                    Ok(label.trim().to_owned())
                },
            )?;
            let (ok, text) = tested?;
            assert!(ok, "{text}");
            eprintln!("AS-34: msmtp confined as {confinement:?}");
            assert_eq!(confinement, "msmtp (enforce)");
            server.wait(&t, "message", 2, Duration::from_secs(10))?;
        }
    }

    // A stop while a submission runs: it completes, then daemon_stopping.
    let before = server.of("message")?.len();
    let (status, _) = during_submission(&t, &server, || test(&f), || f.unit()?.stop())?;
    assert!(status.success(), "{status:?}\n{}", f.log());
    let messages = server.wait(&t, "message", before + 2, Duration::from_secs(10))?;
    let subject = |e: &testbed::smtp::Event| {
        testbed::sendmail::Mail::parse(e.data.as_deref().unwrap_or_default())
            .ok()
            .and_then(|m| m.header("Subject").map(str::to_owned))
            .unwrap_or_default()
    };
    assert!(subject(&messages[before]).starts_with("PolyWAN notification test"));
    let stopping = testbed::sendmail::Mail::parse(messages[before + 1].data.as_deref().unwrap_or_default())?;
    assert!(stopping.body.contains("daemon_stopping"), "{stopping:?}");
    Ok(())
}

/// Runs `act` while `submit` (a `notify-test`) has a message in the SMTP
/// server's DATA phase; returns both results.
fn during_submission<T, S: Send>(
    t: &testbed::Topology,
    server: &testbed::smtp::Server,
    submit: impl FnOnce() -> Result<S> + Send,
    act: impl FnOnce() -> Result<T>,
) -> Result<(T, Result<S>)> {
    let datas = server.of("data")?.len();
    std::thread::scope(|s| {
        let h = s.spawn(submit);
        server.wait(t, "data", datas + 1, Duration::from_secs(10))?;
        let done = act()?;
        Ok((done, h.join().expect("notify-test")))
    })
}

/// Whether a process has ended (or never existed).
fn gone(pid: &str) -> bool {
    pid.trim().parse().is_ok_and(testbed::netns::exited)
}

/// AS-34, the unit's life (IMPL-10, FR-API-1, FR-HOOK-2): with
/// `--no-block`, the unit stays `activating` while an `nft` wrapper holds
/// the first application, becomes `active` with the daemon's summary as
/// `StatusText`; `systemctl reload` succeeds, fails on an invalid
/// configuration (the unit stays active) and fails with an unknown outcome
/// when the control socket's group changes, `config_reloaded` recording
/// the outcome; a stop during a hung hook leaves no process of it, an
/// escaped one included, and cleans up (`on_shutdown = "cleanup"`); a
/// restart replaces the main process; a stop whose cleanup outlasts
/// `TimeoutStopSec=` is `deactivating` until systemd kills the daemon,
/// keeps the manifest, and an offline `cleanup` then succeeds.
#[test]
#[ignore = "needs root and network namespaces"]
fn as34_unit_states_reload_and_stop() -> Result<()> {
    require_unit()?;
    let t = build();
    let mut f = t.prepare_polywan("")?;
    let (wrapper, flag) = nft_wrapper(&t, &f, &["-f"], "sleep 6")?;
    let out = t.exec_dir()?.join("hook");
    std::fs::create_dir_all(&out)?;
    // Hooks run as nobody.
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o777))?;
    let o = out.display();
    // The hook's shell, a child, and a child that leaves its process group.
    let script =
        format!("echo $$ > {o}/shell; sleep 300 & echo $! > {o}/child; setsid sleep 300 & echo $! > {o}/escaped; wait");
    let (root, adm) = (f.api_table("root", None), f.api_table("adm", None));
    let config = |api: &str, weight: u16| {
        let more = format!(
            "[firewall]\nnft_path = \"{}\"\n{api}[[notify.hook]]\ncommand = [\"/bin/sh\", \"-c\", {script:?}]\nevents = [\"uplink_drained\"]\ntimeout = \"120s\"\n",
            wrapper.display()
        );
        let uplinks = [
            UplinkSpec::new(Uplink::A, 1),
            UplinkSpec::new(Uplink::B, 2).weight(weight),
        ];
        polywan::config(
            &uplinks,
            &[Family::V4],
            &HealthSpec::fast(),
            "on_shutdown = \"cleanup\"\n",
            &more,
        )
    };
    f.write_config(&config(&root, 1))?;

    // Readiness as unit states.
    std::fs::write(&flag, "")?;
    f.set_unit_options(testbed::unit::UnitOptions {
        no_block: true,
        ..Default::default()
    });
    f.start(&t)?;
    let state = |f: &polywan::Polywan| f.unit()?.active_state();
    t.wait_for("activating", Duration::from_secs(10), || {
        Ok(state(&f)? == "activating/start")
    })?;
    t.wait_for("the status socket", Duration::from_secs(10), || Ok(f.status().is_ok()))?;
    assert_eq!(state(&f)?, "activating/start", "not ready while nft runs");
    t.wait_for("active", Duration::from_secs(30), || Ok(state(&f)? == "active/running"))?;
    std::fs::remove_file(&flag)?;
    assert!(f.log().contains("applied"), "{}", f.log());
    let unit = f.unit()?;
    t.wait_for("StatusText", Duration::from_secs(15), || {
        Ok(unit.property("StatusText")? == "status ok; active ipv4: a, b")
    })?;

    // systemctl reload: applied, refused, unknown.
    let reload = |config: &str| -> Result<Output> {
        f.write_config(config)?;
        f.unit()?.systemctl(&["reload"])
    };
    let cursor = f.latest_event()?;
    assert!(reload(&config(&root, 2))?.status.success(), "{}", f.log());
    f.wait_event(cursor, "config_reloaded", "", 1, Duration::from_secs(10))?;
    let cursor = f.latest_event()?;
    let failed = reload("[[uplink]\n")?;
    assert!(!failed.status.success());
    f.wait_event(cursor, "reload_failed", "", 1, Duration::from_secs(10))?;
    assert_eq!(state(&f)?, "active/running");
    let cursor = f.latest_event()?;
    let unknown = reload(&config(&adm, 2))?;
    assert!(!unknown.status.success());
    assert!(f.log().contains("the outcome of the reload is unknown"), "{}", f.log());
    f.wait_event(cursor, "config_reloaded", "", 1, Duration::from_secs(10))?;
    assert_eq!(state(&f)?, "active/running");

    // A stop during a hung hook.
    succeeded(f.drain("a", true, false)?)?;
    t.wait_for("the hook's processes", Duration::from_secs(10), || {
        Ok(out.join("escaped").exists())
    })?;
    let pids: Vec<String> = ["shell", "child", "escaped"]
        .iter()
        .map(|n| std::fs::read_to_string(out.join(n)))
        .collect::<std::io::Result<_>>()?;
    assert!(pids.iter().all(|p| !gone(p)), "{pids:?}");
    let status = f.unit()?.stop()?;
    assert!(status.success(), "{status:?}\n{}", f.log());
    assert!(
        pids.iter().all(|p| gone(p)),
        "no process of the hook survives: {pids:?}"
    );
    assert_eq!(tagged(&t, "249")?, 0, "on_shutdown = \"cleanup\"");
    assert!(!f.state.join("manifest.json").exists());

    // A restart, then a stop timeout during cleanup.
    f.set_unit_options(testbed::unit::UnitOptions {
        extra: "TimeoutStopSec=2s\n".into(),
        ..Default::default()
    });
    f.start(&t)?;
    f.wait_installed(&t)?;
    let unit = f.unit()?;
    let first = unit.main_pid()?;
    assert!(unit.systemctl(&["restart"])?.status.success(), "{}", f.log());
    assert_eq!(unit.active_state()?, "active/running");
    assert!(unit.main_pid()?.is_some() && unit.main_pid()? != first);
    f.wait_installed(&t)?;
    std::fs::write(&flag, "")?;
    let (status, states) = std::thread::scope(|s| -> Result<_> {
        let stop = s.spawn(|| unit.stop());
        let mut states = Vec::new();
        while !stop.is_finished() {
            let st = unit.active_state()?;
            if states.last() != Some(&st) {
                states.push(st);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok((stop.join().expect("stop")?, states))
    })?;
    std::fs::remove_file(&flag)?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9), "{status:?}");
    assert!(states.iter().any(|s| s == "deactivating/stop-sigterm"), "{states:?}");
    assert_eq!(unit.property("Result")?, "timeout");
    assert!(f.state.join("manifest.json").exists(), "kept until cleanup succeeds");
    succeeded(f.cli_config(&["cleanup"])?)?;
    assert_eq!(tagged(&t, "249")?, 0);
    assert!(!f.state.join("manifest.json").exists());
    Ok(())
}

/// AS-34, restarts (IMPL-10, §9): with the packaged `Restart=always`, a
/// daemon killed by SIGKILL is restarted after `RestartSec=`; one that
/// refuses its configuration (exit status 78) is not.
#[test]
#[ignore = "needs root and network namespaces"]
fn as34_unit_restarts() -> Result<()> {
    require_unit()?;
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    // The packaged restart policy, sooner: what is tested is which exits
    // restart, not the delay.
    f.set_unit_options(testbed::unit::UnitOptions {
        restart: true,
        extra: "RestartSec=1s\n".into(),
        ..Default::default()
    });
    f.start(&t)?;
    f.wait_installed(&t)?;
    let unit = f.unit()?;
    let kill = || -> Result<u32> {
        let pid = unit.main_pid()?.context("a main process")?;
        testbed::netns::host("kill", ["-KILL", &pid.to_string()])?;
        Ok(pid)
    };
    let killed = kill()?;
    t.wait_for("a restart", Duration::from_secs(20), || {
        Ok(unit.property("NRestarts")? == "1"
            && unit.active_state()? == "active/running"
            && unit.main_pid()?.is_some_and(|p| p != killed))
    })?;
    f.wait_installed(&t)?;
    f.write_config("[[uplink]\n")?;
    kill()?;
    t.wait_for("the refused restart", Duration::from_secs(20), || {
        Ok(unit.property("ActiveState")? == "failed")
    })?;
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(unit.property("ActiveState")?, "failed");
    assert_eq!(unit.property("NRestarts")?, "2");
    assert_eq!(unit.property("Result")?, "exit-code");
    assert_eq!(unit.property("ExecMainStatus")?, "78");
    Ok(())
}

/// The inode of `path`, which must exist.
fn inode(path: &std::path::Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::symlink_metadata(path)
        .with_context(|| path.display().to_string())?
        .ino())
}

/// IMPL-6 and IMPL-10 under the packaged unit: while an offline `cleanup`
/// holds the instance lock (an `nft` wrapper keeps it waiting), a start of
/// the service fails with 1 and leaves the lock file and its runtime
/// directory in place (`RuntimeDirectoryPreserve=yes`), so a second offline
/// command is still refused; the `cleanup` then completes. With the
/// packaged `Restart=always`, restarts fail likewise while the lock is held
/// and the service starts once it is released; its stop keeps the lock too.
#[test]
#[ignore = "needs root and network namespaces"]
fn impl6_lock_held_across_failed_starts_of_the_unit() -> Result<()> {
    require_unit()?;
    let t = build();
    let mut f = t.prepare_polywan("")?;
    // The wrapper's flag, also the condition of its wait.
    let armed = f.dir.join("nft-armed");
    let held = f.dir.join("nft-held");
    let wait = format!(
        "touch {}; while [ -e {} ]; do sleep 0.1; done",
        held.display(),
        armed.display()
    );
    let (wrapper, flag) = nft_wrapper(&t, &f, &["-f"], &wait)?;
    assert_eq!(flag, armed);
    let more = format!("[firewall]\nnft_path = \"{}\"\n", wrapper.display());
    f.write_config(&polywan::config(&ab(), &[Family::V4], &HealthSpec::fast(), "", &more))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    f.stop()?;
    assert!(f.state.join("manifest.json").exists());
    let identity = |f: &polywan::Polywan| -> Result<(u64, u64)> { Ok((inode(&f.lock)?, inode(&f.dir)?)) };
    let before = identity(&f)?;
    let config = f.config.display().to_string();
    // A `cleanup` in its nftables step, holding the lock.
    let hold = |f: &polywan::Polywan| -> Result<std::process::Child> {
        let _ = std::fs::remove_file(&held);
        std::fs::write(&flag, "")?;
        let child = f.cli_child(&["cleanup", "--config", &config])?;
        t.wait_for(
            "cleanup holding the lock",
            Duration::from_secs(10),
            || Ok(held.exists()),
        )?;
        Ok(child)
    };
    let release = |child: std::process::Child| -> Result<()> {
        std::fs::remove_file(&flag)?;
        let out = child.wait_with_output()?;
        anyhow::ensure!(out.status.success(), "cleanup: {}", polywan::output_text(&out));
        Ok(())
    };

    // A start without restarts fails; the lock stays and still excludes.
    let cleanup = hold(&f)?;
    f.start(&t)?;
    let unit = f.unit()?;
    assert_eq!(unit.active_state()?, "failed/failed", "{}", f.log());
    assert_eq!(unit.property("ExecMainStatus")?, "1");
    assert!(f.log().contains("instance lock"), "{}", f.log());
    assert_eq!(identity(&f)?, before, "the lock and its directory are kept");
    let second = f.cli_config(&["cleanup"])?;
    assert!(
        !second.status.success() && polywan::output_text(&second).contains("held by another instance"),
        "{}",
        polywan::output_text(&second)
    );
    release(cleanup)?;
    assert_eq!(tagged(&t, "249")?, 0, "the cleanup completed");
    assert!(!f.state.join("manifest.json").exists());
    assert_eq!(identity(&f)?, before);

    // The packaged restarts fail while the lock is held, then one starts
    // (sooner than `RestartSec=5s`: `cleanup` waits 10 s for nft).
    f.set_unit_options(testbed::unit::UnitOptions {
        restart: true,
        no_block: true,
        extra: "RestartSec=1s\n".into(),
    });
    let cleanup = hold(&f)?;
    f.start(&t)?;
    let unit = f.unit()?;
    t.wait_for("two failed restarts", Duration::from_secs(8), || {
        Ok(unit.property("NRestarts")?.parse::<u32>()? >= 2)
    })?;
    assert_eq!(identity(&f)?, before, "the lock and its directory are kept");
    release(cleanup)?;
    t.wait_for("the service started", Duration::from_secs(30), || {
        Ok(unit.active_state()? == "active/running")
    })?;
    f.wait_installed(&t)?;
    assert!(unit.stop()?.success(), "{}", f.log());
    assert_eq!(identity(&f)?, before, "kept by the stop");
    Ok(())
}
