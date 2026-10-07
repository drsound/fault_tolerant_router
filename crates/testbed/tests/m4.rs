//! M4 acceptance scenarios (SPEC.md §14.3): the systemd integration
//! that the daemon provides by itself (IMPL-10: the configuration exit
//! status, readiness, status and stopping notifications) and `cleanup`
//! over the union of the manifest and the configuration (IMPL-7), with the
//! daemon under test (`POLYWAN_DAEMON_BIN`) in the router namespace.
//!
//! The scenarios that need the packaged unit are in `unit.rs`.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use anyhow::{Context, Result};
use testbed::Outcome;
use testbed::plan::{Family, Node, TCP_PORT, Uplink};
use testbed::polywan::{self, HealthSpec, UplinkSpec, succeeded};

#[macro_use]
mod common;
use common::*;

/// §9 and IMPL-10: `run` exits with 78 when the configuration cannot be
/// read, parsed or validated, a configured path fails FR-CFG-5 (also the
/// state directory, refused by the offline commands too), a
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
    // FR-CFG-5: the state directory writable by others, for startup and
    // for the offline commands that act on its manifest.
    f.write_config(&config)?;
    std::fs::create_dir_all(&f.state)?;
    std::fs::set_permissions(&f.state, std::fs::Permissions::from_mode(0o777))?;
    refused(&f.run_refused(&[])?, 78, "state_dir")?;
    for command in [&["cleanup"][..], &["forget-uplink", "gone"]] {
        let out = f.cli_config(command)?;
        let text = polywan::output_text(&out);
        assert!(
            !out.status.success() && text.contains("state_dir"),
            "{command:?}: {text}"
        );
    }
    std::fs::set_permissions(&f.state, std::fs::Permissions::from_mode(0o700))?;
    // Accounts: an absent API group, a hook user with UID 0.
    let api = |group: &str| f.api_table(group, None);
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
    // Without systemd also when the suite runs under the unit.
    f.direct();
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

/// IMPL-7 and FR-REC-4: artifacts of two layouts are installed (a run
/// with other table and priority ranges and route protocol whose manifest
/// was lost, then a run with the default layout); `cleanup` with the
/// first configuration, in external firewall mode, removes both layouts
/// and the managed nftables table that only the manifest records, keeps
/// objects of another protocol in both ranges, and removes the manifest.
/// The overlapping ranges are covered by the reconciler's unit tests: a
/// daemon refuses objects of another protocol in its ranges (FR-ROUTE-6).
#[test]
#[ignore = "needs root and network namespaces"]
fn impl7_cleanup_covers_the_installed_and_the_configured_layout() -> Result<()> {
    let t = build();
    let other = "table_base = 2000\nrule_priority_base = 3000\nroute_protocol = 250\n";
    let mut f = t.start_polywan(&polywan::config(&ab(), &Family::ALL, &HealthSpec::fast(), other, ""))?;
    f.wait_installed(&t)?;
    assert!(f.stop()?.success());
    std::fs::remove_file(f.state.join("manifest.json"))?;
    f.write_config(&polywan::dual(&ab()))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    wait_members(&t, Family::V6, &["wana", "wanb"], Duration::from_secs(15))?;
    assert!(f.stop()?.success());
    assert!(tagged(&t, "249")? > 0 && tagged(&t, "250")? > 0);
    // Another protocol in both layouts' ranges.
    let r = t.router();
    for family in ["-4", "-6"] {
        for (pref, table) in [(1650, 1150), (3650, 2150)] {
            r.ip(&format!("{family} rule add pref {pref} lookup {table} proto 251"))?;
            r.ip(&format!("{family} route add blackhole default table {table} proto 251"))?;
        }
    }
    let external = "[firewall]\nmode = \"external\"\n";
    f.write_config(&polywan::config(
        &ab(),
        &Family::ALL,
        &HealthSpec::fast(),
        other,
        external,
    ))?;
    succeeded(f.cli_config(&["cleanup"])?)?;
    assert_eq!(tagged(&t, "249")?, 0, "the installed layout is removed");
    assert_eq!(tagged(&t, "250")?, 0, "the configured layout is removed");
    assert_eq!(tagged(&t, "251")?, 8, "other protocols stay");
    assert!(
        r.sh("nft list table inet polywan").is_err(),
        "the managed table is removed"
    );
    assert!(!f.state.join("manifest.json").exists());
    for family in ["-4", "-6"] {
        for pref in [1650, 3650] {
            r.ip(&format!("{family} rule del pref {pref} proto 251"))?;
        }
    }
    Ok(())
}

/// `polywan events --follow --json` running in the background: its output
/// lines as JSON values (a string for a line that is not JSON) and its
/// standard error; killed on drop.
struct Follower {
    child: std::process::Child,
    lines: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    stderr: Option<std::thread::JoinHandle<String>>,
}

impl Follower {
    fn start(f: &polywan::Polywan) -> Result<Follower> {
        use std::io::{BufRead, Read};
        let socket = f.status_socket().display().to_string();
        let mut child = f.cli_child(&["events", "--follow", "--json", "--socket", &socket])?;
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stdout = std::io::BufReader::new(child.stdout.take().context("stdout")?);
        let sink = lines.clone();
        std::thread::spawn(move || {
            for line in stdout.lines().map_while(std::io::Result::ok) {
                let v = serde_json::from_str(&line).unwrap_or(serde_json::Value::String(line));
                sink.lock().expect("lines").push(v);
            }
        });
        let mut err = child.stderr.take().context("stderr")?;
        let stderr = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s);
            s
        });
        Ok(Follower {
            child,
            lines,
            stderr: Some(stderr),
        })
    }

    fn lines(&self) -> Vec<serde_json::Value> {
        self.lines.lock().expect("lines").clone()
    }

    /// The sequence number of the last event printed.
    fn last_seq(&self) -> Option<u64> {
        self.lines().iter().rev().find_map(|l| l["seq"].as_u64())
    }

    fn signal(&self, sig: &str) -> Result<()> {
        testbed::netns::host("kill", [sig, &self.child.id().to_string()]).map(|_| ())
    }

    /// Kills it and returns its standard error.
    fn finish(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stderr.take().and_then(|h| h.join().ok()).unwrap_or_default()
    }
}

impl Drop for Follower {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// FR-API-2 and §9, carried over from M3: `events --follow --json` keeps
/// following while the daemon stops and starts again, then prints a
/// `reset` notice with the new instance followed by the new history; and,
/// stopped (SIGSTOP) while drains and undrains emit more than the ring's
/// 1000 events, a `truncated` notice when it resumes, then the events that
/// remain, up to the latest.
#[test]
#[ignore = "needs root and network namespaces"]
fn api_events_follow_across_a_restart_and_an_eviction() -> Result<()> {
    let t = build();
    let mut f = t.start_polywan(&polywan::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    let follower = Follower::start(&f)?;
    let event = |l: &serde_json::Value, kind: &str| l["type"] == kind;
    t.wait_for("the history", Duration::from_secs(10), || {
        Ok(follower.lines().iter().any(|l| event(l, "daemon_started")))
    })?;
    let first = follower.lines()[0]["instance"]
        .as_str()
        .context("an instance")?
        .to_owned();

    // A restart: the follower waits, then reports the new instance.
    f.stop()?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    let reset = t.wait_for("the reset notice", Duration::from_secs(20), || {
        Ok(follower.lines().iter().any(|l| l["notice"] == "reset"))
    });
    let lines = follower.lines();
    reset.with_context(|| format!("{lines:#?}"))?;
    let at = lines.iter().position(|l| l["notice"] == "reset").context("reset")?;
    let second = lines[at]["instance"].as_str().context("its instance")?.to_owned();
    assert_ne!(second, first);
    assert!(
        lines[at + 1..]
            .iter()
            .any(|l| event(l, "daemon_started") && l["instance"] == second.as_str()),
        "{lines:#?}"
    );
    assert!(lines[at + 1..].iter().all(|l| l["instance"] == second.as_str()));

    // An eviction while the follower does not read.
    let latest = f.latest_event()?;
    t.wait_for("the follower at the latest event", Duration::from_secs(10), || {
        Ok(follower.last_seq() == Some(latest))
    })?;
    follower.signal("-STOP")?;
    let control = f.control_socket();
    let mut ops = 0;
    while f.latest_event()? < latest + 1100 {
        for _ in 0..100 {
            for action in ["drain", "undrain"] {
                let (code, body) = testbed::agent::http(&control, "POST", &format!("/v1/uplinks/b/{action}"), "")?;
                anyhow::ensure!(code == 200, "{action}: {code} {body}");
                ops += 1;
            }
        }
    }
    let before = follower.lines().len();
    follower.signal("-CONT")?;
    let end = f.latest_event()?;
    t.wait_for("the follower at the latest event", Duration::from_secs(20), || {
        Ok(follower.last_seq() == Some(end))
    })?;
    let lines = follower.lines()[before..].to_vec();
    let at = lines
        .iter()
        .position(|l| l["notice"] == "truncated")
        .with_context(|| format!("no truncated notice after {ops} drains and undrains: {lines:#?}"))?;
    let seqs: Vec<u64> = lines.iter().filter_map(|l| l["seq"].as_u64()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    let resumed = lines[at + 1]["seq"].as_u64().context("an event after the notice")?;
    assert!(resumed > latest + 1, "events were evicted: {resumed}");
    assert!(lines.iter().all(|l| l["notice"] != "reset"));
    let stderr = follower.finish();
    assert_eq!(stderr.matches("waiting for the daemon").count(), 1, "{stderr}");
    f.stop()?;
    Ok(())
}

per_family!(fr_probe_2_targets_of_the_router_or_a_downlink_network_are_refused);

/// FR-PROBE-2: a probe target that is an address of the router, or inside
/// the network of a downlink, makes online `check-config` fail and startup
/// refuse, and a reload that introduces one is rejected, the running
/// configuration kept.
fn fr_probe_2_targets_of_the_router_or_a_downlink_network_are_refused(fam: Family) -> Result<()> {
    let t = build();
    let local = address(&t, fam, Uplink::A)?;
    let (lan, public) = match fam {
        Family::V4 => ("198.51.100.77", "1.1.1.1"),
        Family::V6 => ("2001:db8:1::77", "2606:4700:4700::1111"),
    };
    let config = |target: &str| {
        let health = HealthSpec::fast().with(&format!(
            "required_reachable = 1\n[health.{fam}]\ntargets = [\"icmp:{target}\", \"icmp:{public}\"]\n"
        ));
        polywan::config(&ab(), &[fam], &health, "", "")
    };
    assert_refused(&t, &config(&local), "is an address of the router (wana)")?;
    assert_refused(&t, &config(lan), "the network of downlink lan")?;

    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    let digest = f.status()?["config_digest"].clone();
    for (target, needle) in [
        (local.as_str(), "is an address of the router"),
        (lan, "the network of downlink lan"),
    ] {
        f.write_config(&config(target))?;
        let out = f.reload_cli()?;
        let text = polywan::output_text(&out);
        assert!(!out.status.success() && text.contains(needle), "{text}");
        assert_eq!(
            f.status()?["config_digest"],
            digest,
            "the running configuration is kept"
        );
    }
    Ok(())
}

/// The recipes of the documentation that make packet-level claims (DIST-3):
/// their scenarios load the first `nft` block of the page as it is
/// published.
const PORT_FORWARDING: &str = include_str!("../../../docs/recipes/port-forwarding.md");
const REVERSE_PATH_FILTER: &str = include_str!("../../../docs/recipes/reverse-path-filtering.md");

/// Whether the running kernel is `major.minor` or later.
fn kernel_at_least(major: u32, minor: u32) -> Result<bool> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let mut parts = release.trim().split(['.', '-']).map(|p| p.parse::<u32>().unwrap_or(0));
    let found = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    Ok(found >= (major, minor))
}

fn nft_block(page: &str) -> String {
    nft_block_in(page, "")
}

/// The first nft block after `heading`.
fn nft_block_in(page: &str, heading: &str) -> String {
    let page = &page[page.find(heading).expect("the heading")..];
    let start = page.find("```nft\n").expect("an nft block") + "```nft\n".len();
    let end = page[start..].find("```").expect("a closing fence");
    page[start..start + end].to_owned()
}

per_family!(dist3_recipe_port_forwarding);

/// DIST-3: the port-forwarding recipe, with the topology's interface names,
/// LAN server and ports in place of the page's, forwards connections from
/// the internet through A and B to the LAN server, each answered through the
/// uplink it arrived on (INV-5), while its forward chain (policy drop) lets
/// the LAN's own connections through.
fn dist3_recipe_port_forwarding(fam: Family) -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    let _server = serve_in(&t, Node::Client)?;
    let mut ruleset = nft_block(PORT_FORWARDING);
    for (page, here) in [
        ("\"wan0\"", "\"wana\"".to_owned()),
        ("\"wan1\"", "\"wanb\"".to_owned()),
        ("\"lan0\"", "\"lan\"".to_owned()),
        ("dport 8080", "dport 8007".to_owned()),
        (
            "192.168.1.10:80",
            endpoint(&lan_client(Family::V4).to_string(), TCP_PORT),
        ),
        (
            "[fd00:1::10]:80",
            endpoint(&lan_client(Family::V6).to_string(), TCP_PORT),
        ),
    ] {
        anyhow::ensure!(ruleset.contains(page), "the recipe has no {page}");
        ruleset = ruleset.replace(page, &here);
    }
    t.router().nft(&ruleset)?;
    // Provider B (CGNAT) forwards its public IPv4 port to the router, as in
    // AS-09; its IPv6 addresses are public.
    if fam == Family::V4 {
        let b = address(&t, Family::V4, Uplink::B)?;
        t.ns(Node::IspB).nft(&format!(
            "table ip tb_in {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"core\" tcp dport 8007 dnat to {b}\n  }}\n}}\n"
        ))?;
    }
    for u in [Uplink::A, Uplink::B] {
        let iface = u.l3_iface();
        let public = if u == Uplink::B && fam == Family::V4 {
            "198.18.0.6".to_owned()
        } else {
            address(&t, fam, u)?
        };
        counter(
            &t,
            &format!("in{iface}"),
            &format!("oifname \"{iface}\" tcp sport 8007"),
        )?;
        counter(
            &t,
            &format!("out{iface}"),
            &format!("oifname != \"{iface}\" oifname != \"lan\" tcp sport 8007"),
        )?;
        let r = t.connect_to(
            Node::Inet,
            &[endpoint(&public, 8007)],
            10,
            false,
            Duration::from_secs(2),
        )?;
        assert!(
            r.iter().all(|c| c.outcome == Outcome::Ok),
            "{u}: {:?}",
            r.iter().map(|c| c.outcome).collect::<Vec<_>>()
        );
        assert!(
            counter_value(&t, &format!("in{iface}"))? >= 20,
            "{u}: replies leave through {iface}"
        );
        assert_eq!(
            counter_value(&t, &format!("out{iface}"))?,
            0,
            "{u}: no reply through another uplink"
        );
    }
    let r = t.connect_to(
        Node::Client,
        &servers(fam, 1, 10, TCP_PORT),
        20,
        false,
        Duration::from_secs(2),
    )?;
    assert!(
        r.iter().all(|c| c.outcome == Outcome::Ok),
        "the LAN's connections: {:?}",
        r.iter().map(|c| c.outcome).collect::<Vec<_>>()
    );
    Ok(())
}

/// DIST-3: the IPv4 rule of the reverse-path recipe, with the topology's
/// uplinks and LAN in place of the page's: a packet arriving on A with a LAN
/// source reaches the router despite loose mode, and the rule drops it.
#[test]
#[ignore = "needs root and network namespaces"]
fn dist3_recipe_ipv4_internal_sources() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    t.router().nft(
        "table inet t_spoof {\n  counter c {}\n  chain input {\n    type filter hook input priority 0; policy accept;\n    ip saddr 198.51.100.99 icmp type echo-request counter name c\n  }\n}\n",
    )?;
    let a = address(&t, Family::V4, Uplink::A)?;
    t.ns(Node::IspA).ip("addr add 198.51.100.99/32 dev wan")?;
    let spoof = || -> Result<u64> {
        let _ = t
            .ns(Node::IspA)
            .output("ping", ["-n", "-c", "2", "-W", "1", "-I", "198.51.100.99", &a])?;
        t.router().counter("inet", "t_spoof", "c")
    };
    assert!(
        spoof()? >= 2,
        "loose mode lets a LAN source arriving on an uplink through"
    );
    let mut ruleset = nft_block_in(REVERSE_PATH_FILTER, "## IPv4");
    for (page, here) in [
        ("\"wan0\"", "\"wana\""),
        ("\"wan1\"", "\"wanb\""),
        ("192.168.1.0/24", "198.51.100.0/24"),
    ] {
        anyhow::ensure!(ruleset.contains(page), "the recipe has no {page}");
        ruleset = ruleset.replace(page, here);
    }
    t.router().nft(&ruleset)?;
    let before = t.router().counter("inet", "t_spoof", "c")?;
    assert_eq!(spoof()?, before, "the rule drops a LAN source arriving on an uplink");
    Ok(())
}

/// DIST-3: the IPv6 reverse-path filter recipe, loaded as published, with an
/// empty active set and no operating-system default route, as AS-30: ICMP
/// and TCP probe replies, connections forwarded to the LAN server and to a
/// listener of the router through A pass; Router Advertisements bring A's
/// address back after its link went down; a provider's duplicate address
/// detection from the unspecified address reaches the router; a packet arriving on A with a LAN
/// source is dropped (it is not without the filter); the LAN's connections
/// pass once an uplink is active.
#[test]
#[ignore = "needs root and network namespaces"]
fn dist3_recipe_reverse_path_filter() -> Result<()> {
    let fam = Family::V6;
    let t = build();
    let (gwa, gwb) = (gateway(&t, fam, Uplink::A)?, gateway(&t, fam, Uplink::B)?);
    let ups = |priority: Option<u16>| {
        [
            UplinkSpec::new(Uplink::A, 1)
                .priority(priority)
                .path(fam, &format!("gateway = \"{gwa}\"")),
            UplinkSpec::new(Uplink::B, 2)
                .priority(priority)
                .path(fam, &format!("gateway = \"{gwb}\"")),
        ]
    };
    let health = HealthSpec {
        text: "interval = \"1s\"\ntimeout = \"300ms\"\nattempts = 2\nrequired_reachable = 3\n[health.ipv6]\ntargets = [\"icmp:2606:4700:4700::1111\", \"icmp:2001:4860:4860::8888\", \"tcp:[2620:fe::fe]:443\"]\n".into(),
    };
    let config = |priority| polywan::config(&ups(priority), &[fam], &health, "", "");
    t.router().sysctl(&[
        "net.ipv6.conf.wana.accept_ra_defrtr=0",
        "net.ipv6.conf.wanb.accept_ra_defrtr=0",
    ])?;
    for u in ["wana", "wanb"] {
        let _ = t.router().output("ip", ["-6", "route", "del", "default", "dev", u])?;
    }
    // Since Linux 7.1, nftables resolves IPv6 fib lookups through
    // fib6_lookup(), which ignores suppress_prefixlength, the main bypass:
    // an IPv6 default route of the main table then answers the filter's
    // lookups. The recipe's page requires none there on those kernels, so
    // the harness's leak6 route and provider C's go; older kernels keep
    // them, and pass with defaults in the main table.
    if kernel_at_least(7, 1)? {
        t.router().sysctl(&["net.ipv6.conf.ppp0.accept_ra_defrtr=0"])?;
        while t
            .router()
            .output("ip", ["-6", "route", "del", "default"])?
            .status
            .success()
        {}
    }

    // A packet from a LAN source arriving on A, counted at the router's input.
    t.router().nft(
        "table inet t_spoof {\n  counter c {}\n  chain input {\n    type filter hook input priority 0; policy accept;\n    ip6 saddr 2001:db8:1::99 icmpv6 type echo-request counter name c\n  }\n}\n",
    )?;
    let a = address(&t, fam, Uplink::A)?;
    t.ns(Node::IspA).ip("-6 addr add 2001:db8:1::99/128 dev wan nodad")?;
    let spoof = || -> Result<u64> {
        let _ = t
            .ns(Node::IspA)
            .output("ping", ["-6", "-n", "-c", "2", "-W", "1", "-I", "2001:db8:1::99", &a])?;
        t.router().counter("inet", "t_spoof", "c")
    };
    assert!(spoof()? >= 2, "without the filter, spoofed packets reach the router");

    let mut f = t.start_polywan(&config(None))?;
    f.wait_installed(&t)?;
    let recipe = nft_block_in(REVERSE_PATH_FILTER, "## IPv6");
    t.router().nft(&recipe)?;
    let before = t.router().counter("inet", "t_spoof", "c")?;
    assert_eq!(spoof()?, before, "the filter drops a LAN source arriving on an uplink");

    // Probe replies: ICMP and TCP targets, all of them required.
    assert!(balancing_members(&t, fam)?.is_empty());
    std::thread::sleep(Duration::from_secs(5));
    assert!(
        !f.log().contains("to=Down"),
        "probe replies pass the filter:\n{}",
        f.log()
    );

    // Forwarded and local inbound connections.
    let _client = serve_in(&t, Node::Client)?;
    let _router = serve_in(&t, Node::Router)?;
    t.router().nft(&format!(
        "table ip6 admin {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"wana\" tcp dport 8007 dnat to {}\n  }}\n}}\n",
        endpoint(&lan_client(fam).to_string(), TCP_PORT)
    ))?;
    for dst in [endpoint(&a, 8007), endpoint(&a, TCP_PORT)] {
        let r = t.connect_to(Node::Inet, std::slice::from_ref(&dst), 5, false, Duration::from_secs(2))?;
        assert!(
            r.iter().all(|c| c.outcome == Outcome::Ok),
            "{dst}: {:?}",
            r.iter().map(|c| c.outcome).collect::<Vec<_>>()
        );
    }

    // Router Advertisements: A's address comes back after its link went
    // down and up, and the path is up again.
    t.router().ip("link set wana down")?;
    t.router().ip("link set wana up")?;
    t.wait_for("A's address after the link came back", Duration::from_secs(20), || {
        Ok(address(&t, fam, Uplink::A)? == a)
    })?;
    f.wait_path_where(&t, "a", fam, "up and ready", Duration::from_secs(20), |p| {
        p["state"] == "up" && p["ready"] == true
    })?;

    // Duplicate address detection by the provider, from the unspecified
    // address: the router defends its address through the filter.
    // The harness's providers skip duplicate address detection.
    t.ns(Node::IspA).sysctl(&["net.ipv6.conf.wan.accept_dad=1"])?;
    t.ns(Node::IspA).ip(&format!("-6 addr add {a}/128 dev wan"))?;
    let defended = t
        .wait_for("dadfailed", Duration::from_secs(5), || {
            Ok(t.ns(Node::IspA).ip("-6 addr show dev wan")?.contains("dadfailed"))
        })
        .is_ok();
    t.ns(Node::IspA).ip(&format!("-6 addr del {a}/128 dev wan"))?;
    assert!(
        defended,
        "the provider's duplicate address detection reaches the router"
    );

    // The LAN's connections once an uplink is active.
    f.reload_with(&config(Some(1)))?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(20))?;
    let r = t.connect_to(
        Node::Client,
        &servers(fam, 1, 10, TCP_PORT),
        20,
        false,
        Duration::from_secs(2),
    )?;
    assert!(
        r.iter().all(|c| c.outcome == Outcome::Ok),
        "the LAN's connections: {:?}",
        r.iter().map(|c| c.outcome).collect::<Vec<_>>()
    );
    f.stop()?;
    Ok(())
}
