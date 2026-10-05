//! M4 acceptance scenarios (SPEC.md §14.3, §17): the systemd integration
//! that the daemon provides by itself (IMPL-10: the configuration exit
//! status, readiness, status and stopping notifications), with the daemon
//! under test (`POLYWAN_DAEMON_BIN`) in the router namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::process::Output;
use std::time::Duration;

use anyhow::{Context, Result};
use testbed::plan::{Family, Uplink};
use testbed::polywan::{self, HealthSpec, UplinkSpec, succeeded};

#[macro_use]
mod common;
use common::*;

/// The exit status of a refused startup and its diagnostics, or a failure
/// naming both.
fn refused(out: &Output, status: i32, needle: &str) -> Result<()> {
    let text = polywan::output_text(out);
    anyhow::ensure!(
        out.status.code() == Some(status) && text.contains(needle),
        "expected exit status {status} with {needle:?}, got {:?}:\n{text}",
        out.status
    );
    Ok(())
}

/// §9 and IMPL-10: `run` exits with 78 when the configuration cannot be
/// read, parsed or validated, a configured path fails FR-CFG-5, a
/// configured account is absent or prohibited, or the configuration
/// conflicts with the manifest's structural settings or uplink identities;
/// with 1 for other startup failures (a held instance lock, corrupt drain
/// state or manifest, an unsupported nftables). `--reset-state` discards a
/// corrupt manifest (IMPL-6).
#[test]
#[ignore = "needs root and network namespaces"]
fn impl10_configuration_exit_status() -> Result<()> {
    let t = build();
    let config = polywan::ipv4(&ab());
    let mut f = t.prepare_polywan(&config)?;

    // Read, parse and validate (FR-CFG-1).
    let moved = f.config.with_extension("moved");
    std::fs::rename(&f.config, &moved)?;
    refused(&f.run_refused(&[])?, 78, "cannot read")?;
    std::fs::rename(&moved, &f.config)?;
    f.write_config("[[uplink]\n")?;
    refused(&f.run_refused(&[])?, 78, "config.toml")?;
    let reserved = "table_base = 100\n";
    f.write_config(&polywan::config(
        &ab(),
        &[Family::V4],
        &HealthSpec::fast(),
        reserved,
        "",
    ))?;
    refused(&f.run_refused(&[])?, 78, "reserved tables")?;
    // FR-CFG-5: the configuration writable by others.
    f.write_config(&config)?;
    std::fs::set_permissions(&f.config, std::fs::Permissions::from_mode(0o666))?;
    refused(&f.run_refused(&[])?, 78, "writable by group or others")?;
    // Accounts: an absent API group, a hook user with UID 0.
    let api = |group: &str| {
        format!(
            "\n[api]\nsocket = \"{}\"\nstatus_socket = \"{}\"\ngroup = \"{group}\"\n",
            f.dir.join("api.sock").display(),
            f.status_socket().display()
        )
    };
    f.write_config(&format!("{config}{}", api("polywan-no-such-group")))?;
    refused(
        &f.run_refused(&[])?,
        78,
        "group \"polywan-no-such-group\" does not exist",
    )?;
    f.write_config(&format!(
        "{config}[notify]\nhook_user = \"root\"\n[[notify.hook]]\ncommand = [\"/bin/true\"]\n{}",
        api("root")
    ))?;
    refused(&f.run_refused(&[])?, 78, "notify.hook_user")?;
    // An unsupported nftables (PLAT-2) is not a configuration failure.
    let nft = t.exec_dir()?.join("old-nft");
    std::fs::write(&nft, "#!/bin/sh\necho 'nftables v1.0.5 (Lester Gooch #4)'\n")?;
    std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755))?;
    f.write_config(&format!("{config}[firewall]\nnft_path = \"{}\"\n", nft.display()))?;
    refused(&f.run_refused(&[])?, 1, "1.0.6 or later is required")?;

    // A manifest: the instance lock held by a running daemon.
    f.write_config(&config)?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    refused(&f.run_refused(&[])?, 1, "instance lock")?;
    f.stop()?;
    // Conflicts with the manifest: structure, then identities.
    let routing = "table_base = 2000\n";
    f.write_config(&polywan::config(&ab(), &[Family::V4], &HealthSpec::fast(), routing, ""))?;
    refused(&f.run_refused(&[])?, 78, "structural settings differ")?;
    let swapped = [UplinkSpec::new(Uplink::A, 2), UplinkSpec::new(Uplink::B, 1)];
    f.write_config(&polywan::ipv4(&swapped))?;
    refused(&f.run_refused(&[])?, 78, "FR-MARK-4")?;
    // Corrupt state files fail startup with 1 (IMPL-6).
    f.write_config(&config)?;
    let drain = f.state.join("drain.json");
    std::fs::write(&drain, "{")?;
    refused(&f.run_refused(&[])?, 1, "drain state:")?;
    std::fs::remove_file(&drain)?;
    let manifest = f.state.join("manifest.json");
    let valid = std::fs::read(&manifest)?;
    std::fs::write(&manifest, "{\"version\": 7}\n")?;
    refused(&f.run_refused(&[])?, 1, "unknown state file version 7")?;
    // `--reset-state` discards it; the artifacts are adopted as without a
    // manifest, which is written again.
    f.start_with(&t, &["--reset-state"])?;
    f.wait_installed(&t)?;
    assert!(f.log().contains("unreadable manifest discarded"), "{}", f.log());
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&manifest)?)?["uplinks"],
        serde_json::from_slice::<serde_json::Value>(&valid)?["uplinks"]
    );
    f.stop()?;
    Ok(())
}

/// The notifications received on `socket` so far, one entry per datagram.
fn notifications(socket: &UnixDatagram) -> Vec<String> {
    let mut v = Vec::new();
    let mut buf = [0; 4096];
    while let Ok(n) = socket.recv(&mut buf) {
        v.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    v
}

/// IMPL-10 without systemd: with its own datagram socket as `NOTIFY_SOCKET`,
/// no `READY=1` before the initial attempt completed (a slow first nftables
/// application) although the status socket already answers; `STATUS=`
/// follows a carrier loss and its recovery; `STOPPING=1` at SIGTERM; `nft`
/// never inherits the variable, and a dry run sends nothing.
#[test]
#[ignore = "needs root and network namespaces"]
fn impl10_notifications_without_systemd() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan("")?;
    let path = f.dir.join("notify");
    let socket = UnixDatagram::bind(&path)?;
    socket.set_nonblocking(true)?;
    let env = f.dir.join("nft-env");
    let (wrapper, flag) = nft_wrapper(&t, &f, &["-f"], &format!("env > {}; sleep 3", env.display()))?;
    let firewall = format!("[firewall]\nnft_path = \"{}\"\n", wrapper.display());
    let config = polywan::config(&ab(), &[Family::V4], &HealthSpec::fast(), "", &firewall);
    f.write_config(&config)?;
    f.set_env("NOTIFY_SOCKET", &path.display().to_string());
    // A dry run is one-shot and never notifies.
    succeeded(f.cli_config(&["run", "--dry-run"])?)?;
    assert_eq!(notifications(&socket), Vec::<String>::new());

    std::fs::write(&flag, "")?;
    f.start(&t)?;
    let mut seen = Vec::new();
    t.wait_for("the status socket", Duration::from_secs(10), || Ok(f.status().is_ok()))?;
    t.wait_for("nft -f to start", Duration::from_secs(10), || Ok(env.exists()))?;
    seen.extend(notifications(&socket));
    assert!(!seen.iter().any(|n| n.contains("READY=1")), "{seen:?}");
    t.wait_for("READY=1", Duration::from_secs(20), || {
        seen.extend(notifications(&socket));
        Ok(seen.iter().any(|n| n.contains("READY=1")))
    })?;
    assert!(f.log().contains("applied"), "{}", f.log());
    std::fs::remove_file(&flag)?;
    assert!(!std::fs::read_to_string(&env)?.contains("NOTIFY_SOCKET"));
    // The latest `STATUS=` becomes `line`.
    let status = |seen: &mut Vec<String>, line: &str| {
        let line = format!("STATUS={line}");
        t.wait_for(&line, Duration::from_secs(15), || {
            seen.extend(notifications(&socket));
            let latest = seen.iter().flat_map(|n| n.lines()).rfind(|l| l.starts_with("STATUS="));
            Ok(latest == Some(line.as_str()))
        })
        .with_context(|| format!("received {seen:?}"))
    };
    status(&mut seen, "status ok; active ipv4: a, b")?;
    t.carrier_down(Uplink::A)?;
    status(&mut seen, "status ok; active ipv4: b")?;
    t.carrier_up(Uplink::A)?;
    status(&mut seen, "status ok; active ipv4: a, b")?;
    // Only changes are sent.
    let lines: Vec<&str> = seen
        .iter()
        .flat_map(|n| n.lines())
        .filter(|l| l.starts_with("STATUS="))
        .collect();
    assert!(lines.windows(2).all(|w| w[0] != w[1]), "{lines:?}");
    assert!(f.stop()?.success());
    assert!(notifications(&socket).iter().any(|n| n.contains("STOPPING=1")));
    Ok(())
}
