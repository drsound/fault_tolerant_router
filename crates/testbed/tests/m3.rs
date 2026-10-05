//! M3 acceptance scenarios (SPEC.md §14.3, §17): operations (API and CLI,
//! drain, policies, events, email, hooks, metrics, quality gates), with the
//! daemon under test (`POLYWAN_DAEMON_BIN`) in the router namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use testbed::agent::Held;
use testbed::netns::exited;
use testbed::plan::{Family, Node, TCP_PORT, TCP_PORT_HTTPS, Uplink};
use testbed::polywan::{self, HealthSpec, succeeded};
use testbed::sendmail::{Call, Mode, Stub};
use testbed::traffic::tally;
use testbed::{Outcome, Topology};

#[macro_use]
mod common;
use common::*;

/// An IPv4 configuration over A and B with `extra` appended.
fn with(extra: &str) -> String {
    polywan::config(&ab(), &[Family::V4], &HealthSpec::fast(), "", extra)
}

/// A `[notify.email]` table from `from` to `to`, with `more` keys.
fn email(from: &str, to: &[&str], more: &str) -> String {
    let to: Vec<String> = to.iter().map(|a| format!("\"{a}\"")).collect();
    format!("[notify.email]\nfrom = \"{from}\"\nto = [{}]\n{more}", to.join(", "))
}

/// `[notify]` with the `notify` keys, and email from router@example.com to
/// `to` through `sendmail` with `more` (keys of `[notify.email]`, then
/// other tables).
fn notify_email(sendmail: &std::path::Path, notify: &str, to: &[&str], more: &str) -> String {
    let more = format!("sendmail = \"{}\"\n{more}", sendmail.display());
    format!("[notify]\n{notify}{}", email("router@example.com", to, &more))
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
    let email = |from: &str, to: &str, more: &str| with(&email(from, &[to], more));
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
        let sendmail = format!("sendmail = \"{}\"\n", path.display());
        with(&email("router@example.com", &["admin@example.com"], &sendmail))
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

/// `[[policy]]` tables: (name, family, uplink, fallback, extra keys).
fn policies(list: &[(&str, Family, &str, &str, &str)]) -> String {
    list.iter()
        .map(|(name, fam, uplink, fallback, extra)| {
            format!(
                "[[policy]]\nname = \"{name}\"\nfamily = \"{fam}\"\nuplink = \"{uplink}\"\nfallback = \"{fallback}\"\n{extra}"
            )
        })
        .collect()
}

/// Connections rejected by a guard: none succeeds and at least one gets
/// the ICMP error; the kernel rate-limits these errors (more strictly on
/// Linux 6.1), so later attempts time out instead.
fn assert_rejected(r: &[testbed::traffic::ConnResult]) {
    let outcomes: Vec<Outcome> = r.iter().map(|c| c.outcome).collect();
    assert!(
        outcomes.contains(&Outcome::Unreachable) && !outcomes.contains(&Outcome::Ok),
        "rejected: {outcomes:?}"
    );
}

per_family!(as15_block_and_balance_policies_across_a_failure);

/// AS-15: a block policy (TCP 443) and a balance policy (TCP 7000) to A.
/// While A is healthy both go through A; while A is down, new block-policy
/// connections are rejected and new balance-policy connections use B;
/// connections opened before the failure stay on A, and those opened on B
/// stay on B after A recovers (INV-2).
fn as15_block_and_balance_policies_across_a_failure(fam: Family) -> Result<()> {
    let t = build();
    let rules = policies(&[
        (
            "https-on-a",
            fam,
            "a",
            "block",
            &format!("protocol = \"tcp\"\ndestination_port = {TCP_PORT_HTTPS}\n"),
        ),
        (
            "flows-on-a",
            fam,
            "a",
            "balance",
            &format!("protocol = \"tcp\"\ndestination_port = {TCP_PORT}\n"),
        ),
    ]);
    let config = polywan::config(&ab(), stack_families(fam), &HealthSpec::fast(), "", &rules);
    let f = t.start_polywan(&config)?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    let on = |port: u16| {
        t.connect_to(
            Node::Client,
            &servers(fam, 1, 20, port),
            20,
            false,
            Duration::from_secs(2),
        )
    };
    for port in [TCP_PORT, TCP_PORT_HTTPS] {
        let r = on(port)?;
        assert_eq!(tally(&r).get(&Some(Uplink::A)), Some(&20), "{port}: {:?}", tally(&r));
    }
    // Traffic that no policy matches is balanced.
    let r = t.connect_many(Node::Client, fam, 20, 40, true)?;
    assert!(r.iter().all(|c| c.outcome == Outcome::Ok), "{:?}", tally(&r));
    let before = start_flows(&t, fam, 30, 6)?;
    std::thread::sleep(Duration::from_millis(500));
    t.upstream_down(Uplink::A)?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(15))?;
    // The connections opened before the failure (servers 30 to 35) keep
    // sending through A, never through B: retransmissions while A is out,
    // with doubling intervals, so at least one within the rest of the
    // scenario, which lasts longer than the failure so far.
    let ipk = ip(fam);
    let before_servers: Vec<String> = (30..36).map(|n| testbed::plan::server(fam, n).to_string()).collect();
    for (name, iface) in [("before_a", "wana"), ("before_b", "wanb")] {
        counter(
            &t,
            name,
            &format!(
                "oifname \"{iface}\" ct original {ipk} daddr {{ {} }} tcp dport {TCP_PORT}",
                before_servers.join(", ")
            ),
        )?;
    }
    let r = on(TCP_PORT)?;
    assert_eq!(
        tally(&r).get(&Some(Uplink::B)),
        Some(&20),
        "balance fallback: {:?}",
        tally(&r)
    );
    // Rejected by the policy-block guard.
    counter(
        &t,
        "https",
        &format!("oifname {{ \"wana\", \"wanb\" }} tcp dport {TCP_PORT_HTTPS}"),
    )?;
    assert_rejected(&on(TCP_PORT_HTTPS)?);
    assert_eq!(counter_value(&t, "https")?, 0, "no block-policy packet leaves");
    let during = start_flows(&t, fam, 40, 6)?;
    std::thread::sleep(Duration::from_millis(500));
    t.upstream_up(Uplink::A)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(20))?;
    let r = on(TCP_PORT)?;
    assert_eq!(tally(&r).get(&Some(Uplink::A)), Some(&20), "{:?}", tally(&r));
    std::thread::sleep(Duration::from_secs(1));
    for r in before.into_iter().map(|f| f.stop()).collect::<Result<Vec<_>>>()? {
        assert!(
            r.uplink() == Some(Uplink::A) && r.received > 0,
            "opened before the failure: {r:?}"
        );
    }
    assert!(
        counter_value(&t, "before_a")? > 0 && counter_value(&t, "before_b")? == 0,
        "opened before the failure: through A, nothing through B"
    );
    for r in during.into_iter().map(|f| f.stop()).collect::<Result<Vec<_>>>()? {
        assert!(
            r.uplink() == Some(Uplink::B) && r.continuous(Duration::from_secs(1)),
            "opened on B: {r:?}"
        );
    }
    Ok(())
}

per_family!(as15_replies_of_unassigned_connections_are_not_policy_marked);

/// AS-15, §4.7 step 1.3: a block policy to A matching the LAN host's TCP
/// traffic does not catch the host's replies to a connection that arrived on
/// an interface PolyWAN does not manage (no path value): while A is down
/// they follow the balancing route through B instead of being rejected.
fn as15_replies_of_unassigned_connections_are_not_policy_marked(fam: Family) -> Result<()> {
    let t = build();
    let rules = policies(&[(
        "lan-host-on-a",
        fam,
        "a",
        "block",
        &format!("source = \"{}\"\nprotocol = \"tcp\"\n", lan_client(fam)),
    )]);
    let f = t.start_polywan(&polywan::config(&ab(), &[fam], &HealthSpec::fast(), "", &rules))?;
    f.wait_installed(&t)?;
    let _client = serve_in(&t, Node::Client)?;
    let remote = unmanaged_link(&t, fam)?;
    t.upstream_down(Uplink::A)?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(15))?;
    // The policy applies to the host's own new connections.
    let r = t.connect_to(
        Node::Client,
        &servers(fam, 1, 5, TCP_PORT),
        5,
        false,
        Duration::from_secs(2),
    )?;
    assert_rejected(&r);
    counter(&t, "b", &format!("oifname \"wanb\" {} daddr {remote}", ip(fam)))?;
    let flow = t.start_flow(Node::Inet, lan_client(fam), Duration::from_millis(50))?;
    std::thread::sleep(Duration::from_secs(2));
    let report = flow.stop()?;
    assert!(
        report.received > 0 && report.continuous(Duration::from_secs(1)),
        "{report:?}"
    );
    assert!(counter_value(&t, "b")? > 0, "replies balanced through B");
    t.upstream_up(Uplink::A)?;
    Ok(())
}

per_family!(as48_policy_marked_traffic_from_a_router_address_is_balanced);

/// AS-48: a forwarded connection whose source is A's address (a constructed
/// case: the LAN host uses it) matches a balance policy to A while A is
/// down: it is balanced through B, neither routed by A's source rule nor
/// rejected by the source guard (INV-4). IPv4 needs `accept_local = 1` on
/// the downlink, or the kernel drops the packet as a martian.
fn as48_policy_marked_traffic_from_a_router_address_is_balanced(fam: Family) -> Result<()> {
    let t = build();
    let a = t
        .uplink_address(Uplink::A, fam)?
        .ok_or_else(|| anyhow::anyhow!("A has no {fam} address"))?;
    let rules = policies(&[(
        "from-a",
        fam,
        "a",
        "balance",
        &format!("source = \"{a}\"\nprotocol = \"tcp\"\n"),
    )]);
    let f = t.start_polywan(&polywan::config(&ab(), &[fam], &HealthSpec::fast(), "", &rules))?;
    f.wait_installed(&t)?;
    match fam {
        Family::V4 => {
            t.router().sysctl(&["net.ipv4.conf.lan.accept_local=1"])?;
            t.client().ip(&format!("addr add {a}/32 dev lo"))?;
        }
        Family::V6 => {
            t.client().ip(&format!("addr add {a}/128 dev lo nodad"))?;
        }
    }
    t.upstream_down(Uplink::A)?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(15))?;
    // TCP only: A's probes have A's address too.
    let ipk = ip(fam);
    for (name, iface) in [("a", "wana"), ("b", "wanb")] {
        counter(
            &t,
            name,
            &format!("oifname \"{iface}\" ct original {ipk} saddr {a} tcp dport {TCP_PORT}"),
        )?;
    }
    // The replies go to A's address, which is the router's: the connections
    // cannot complete, only their first packets matter.
    let binding = testbed::agent::Binding {
        source: Some(a),
        device: None,
    };
    let connect = || {
        t.connect_bound(
            Node::Client,
            &servers(fam, 1, 5, TCP_PORT),
            5,
            false,
            Duration::from_secs(1),
            &binding,
        )
    };
    connect()?;
    let (via_a, via_b) = (counter_value(&t, "a")?, counter_value(&t, "b")?);
    assert!(via_a == 0 && via_b > 0, "balanced through B: a={via_a} b={via_b}");
    // Control: without the policy the same packets carry no PolyWAN value,
    // and A's source rule routes them through A's path table.
    f.write_config(&polywan::family(&ab(), fam))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    connect()?;
    assert!(counter_value(&t, "a")? > 0, "the source rule takes unmarked packets");
    t.upstream_up(Uplink::A)?;
    Ok(())
}

/// Fast health settings with the quality gates `gates` (TOML keys of
/// `[health.quality]`).
fn with_gates(gates: &str) -> HealthSpec {
    HealthSpec::fast().with(&format!("[health.quality]\n{gates}"))
}

/// The default `health.quality_window`, in rounds.
const QUALITY_WINDOW: u64 = 6;

/// Waits until A's and B's paths of `fam` forward steadily, before quality
/// gates are enabled: the first echoes after startup can be lost while
/// neighbours are resolved. Steady: a window of samples (a round has one
/// or more) without loss.
fn wait_steady(t: &Topology, f: &polywan::Polywan, fam: Family) -> Result<()> {
    for uplink in ["a", "b"] {
        f.wait_path_where(
            t,
            uplink,
            fam,
            "a window of samples without loss",
            Duration::from_secs(30),
            |p| {
                let s = &p["statistics"];
                s["samples"].as_u64().is_some_and(|n| n >= QUALITY_WINDOW) && s["loss"].as_f64() == Some(0.0)
            },
        )?;
    }
    Ok(())
}

per_family!(as06_deterministic_loss_violates_the_loss_gate);

/// AS-06: every third probe echo on A is lost, with `max_loss = 0.2`: A goes
/// down with reason `degraded` although its rounds pass reachability, and
/// comes back once the pattern stops, within `rise` rounds plus the
/// clearing of the window (FR-PROBE-5).
fn as06_deterministic_loss_violates_the_loss_gate(fam: Family) -> Result<()> {
    let t = build();
    // The gate is enabled once the topology forwards steadily (as AS-39).
    let f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    wait_steady(&t, &f, fam)?;
    let health = with_gates("max_loss = 0.2\n");
    f.write_config(&polywan::config(&ab(), &[fam], &health, "", ""))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    // Events before the gate (a startup flap) are not the scenario's.
    let gated = f.latest_event()?;
    t.drop_probe_echoes(Uplink::A, 3)?;
    let change = |change: &str| format!("uplink a {fam}: {change}");
    f.wait_event(
        gated,
        "path_state_changed",
        &change("up -> down (degraded)"),
        1,
        Duration::from_secs(20),
    )?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(2))?;
    let log = f.log();
    assert!(log.contains(&format!("uplink=1 family={fam} violations=loss")), "{log}");
    let events = f.events()?;
    assert!(
        !events
            .iter()
            .any(|(seq, k, l)| *seq > gated && k == "path_state_changed" && l.contains("(probe_failed)")),
        "reachability kept passing: {events:?}"
    );
    t.clear_provider_rules(Uplink::A)?;
    let cleared = Instant::now();
    f.wait_event(
        gated,
        "path_state_changed",
        &change("down -> up (probes_recovered)"),
        1,
        Duration::from_secs(15),
    )?;
    // rise (3) plus the window (6 rounds of 1 s), and a round of margin.
    let took = cleared.elapsed();
    assert!(took <= Duration::from_secs(10), "recovered after {took:?}");
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(2))?;
    Ok(())
}

per_family!(as39_quality_gates_with_unequal_target_rtts);

/// AS-39: probe targets with unequal RTTs (one 20 ms, one 150 ms away) and
/// no loss: with `max_loss = 0` no round loses a sample, since rounds run to
/// completion; the RTT gate is evaluated on the median (a 5 ms limit takes
/// A down, 100 ms brings it back at the next rounds). The IPv6 variant uses
/// the three default targets.
fn as39_quality_gates_with_unequal_target_rtts(fam: Family) -> Result<()> {
    let t = build();
    let targets = testbed::plan::probe_targets(fam);
    t.target_delays(
        Uplink::A,
        &[
            (targets[1], Duration::from_millis(20)),
            (targets[2], Duration::from_millis(150)),
        ],
    )?;
    let config = |max_rtt: &str| {
        let health = with_gates(&format!(
            "max_loss = 0.0\nmax_rtt = \"{max_rtt}\"\nmax_jitter = \"50ms\"\n"
        ));
        polywan::config(&ab(), &[fam], &health, "", "")
    };
    // Gates are enabled once the topology forwards steadily: the first
    // echoes after startup can be lost while neighbours are resolved. The
    // reload changes the sampling mode, so the window starts empty.
    let mut f = t.start_polywan(&polywan::family(&ab(), fam))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    wait_steady(&t, &f, fam)?;
    f.write_config(&config("100ms"))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    // Full windows: rounds run to completion, a sample per target, more
    // than quality_min_samples samples and five RTTs and differences.
    let full = QUALITY_WINDOW * targets.len() as u64;
    for uplink in ["a", "b"] {
        f.wait_samples(&t, uplink, fam, full, Duration::from_secs(30))?;
    }
    let log = f.log();
    let gated = log.split("config_reloaded").nth(1).unwrap_or_default();
    assert!(
        !gated.contains("quality gate violated") && !gated.contains("reason=degraded"),
        "{log}"
    );
    f.write_config(&config("5ms"))?;
    // Events before this gate (a startup flap) are not the scenario's.
    let gated = f.latest_event()?;
    f.reload()?;
    f.wait_event(
        gated,
        "path_state_changed",
        &format!("uplink a {fam}: up -> down (degraded)"),
        1,
        Duration::from_secs(10),
    )?;
    assert!(
        f.log().contains(&format!("uplink=1 family={fam} violations=rtt")),
        "{}",
        f.log()
    );
    f.write_config(&config("100ms"))?;
    f.reload()?;
    f.wait_event(
        gated,
        "path_state_changed",
        &format!("uplink a {fam}: down -> up (probes_recovered)"),
        1,
        Duration::from_secs(8),
    )?;
    f.wait_path_where(&t, "a", fam, "up and ready", Duration::from_secs(2), |p| {
        p["state"] == "up" && p["ready"] == true
    })?;
    t.clear_target_delays(Uplink::A)?;
    f.stop()?;
    Ok(())
}

/// IMPL-4 and FR-HEALTH-5: while the nftables lane applies a slow
/// transaction (a reload adding a policy, 5 s), and while the persistence
/// lane writes slowly (a reload adding C, 5 s per job), a carrier loss on B
/// still withdraws B within a second; both reloads complete afterwards.
#[test]
#[ignore = "needs root and network namespaces"]
fn impl4_slow_nft_and_persistence_do_not_delay_withdrawals() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    // Each slow branch leaves a marker once entered.
    let applying = f.dir.join("nft-applying");
    let (wrapper, slow) = nft_wrapper(&t, &f, &["-f"], &format!("touch {}; sleep 5", applying.display()))?;
    let writes = f.dir.join("slow-writes");
    let waiting = f.dir.join("slow-writes.waiting");
    f.set_env("POLYWAN_TEST_SLOW_WRITES", &writes.display().to_string());
    let firewall = format!("[firewall]\nnft_path = \"{}\"\n", wrapper.display());
    let policy = policies(&[("p", Family::V4, "a", "balance", "protocol = \"udp\"\n")]);
    let config = |uplinks: &[polywan::UplinkSpec], extra: &str| {
        polywan::config(
            uplinks,
            &[Family::V4],
            &HealthSpec::fast(),
            "",
            &format!("{firewall}{extra}"),
        )
    };
    f.write_config(&config(&ab(), ""))?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    // FR-HEALTH-5 counts from the kernel's notification, which the kernel
    // can delay under the load of parallel scenarios (Linux 6.1).
    let withdrawn = |f: &polywan::Polywan, what: &str| -> Result<()> {
        let monitor = t.router().monitor_links()?;
        t.carrier_down(Uplink::B)?;
        wait_members(&t, Family::V4, &["wana"], Duration::from_secs(5))?;
        let withdrawn = Instant::now();
        let notified = monitor
            .first(&["wanb", "NO-CARRIER"])
            .ok_or_else(|| anyhow::anyhow!("{what}: no carrier notification for wanb"))?;
        let took = withdrawn.duration_since(notified);
        assert!(
            took <= Duration::from_secs(1),
            "{what}: B withdrawn {took:?} after the notification\n{}",
            f.log()
        );
        t.carrier_up(Uplink::B)?;
        Ok(())
    };

    // A slow nftables application.
    std::fs::write(&slow, "")?;
    f.write_config(&config(&ab(), &policy))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    t.wait_for("the slow nftables application", Duration::from_secs(10), || {
        Ok(applying.exists())
    })?;
    withdrawn(&f, "slow nft")?;
    std::fs::remove_file(&slow)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(20))?;
    t.wait_for("the policy rule installed", Duration::from_secs(30), || {
        // `udp`, or 17 without /etc/protocols.
        Ok(t.router()
            .sh("nft list table inet polywan")?
            .contains("iifname \"lan\" ct direction original meta l4proto"))
    })
    .with_context(|| {
        format!(
            "ruleset:\n{}\ndaemon log:\n{}",
            t.router().sh("nft list table inet polywan").unwrap_or_default(),
            f.log()
        )
    })?;

    // Slow persistence: the reload's binding waits behind slow writes.
    std::fs::write(&writes, "5000")?;
    f.write_config(&config(&abc(), &policy))?;
    f.reload()?;
    t.wait_for("a slow persistence job", Duration::from_secs(10), || {
        Ok(waiting.exists())
    })?;
    withdrawn(&f, "slow persistence")?;
    f.wait_log(&t, "config_reloaded", 2, Duration::from_secs(30))?;
    std::fs::remove_file(&writes)?;
    wait_members(&t, Family::V4, &["ppp0", "wana", "wanb"], Duration::from_secs(30))?;
    f.stop()?;
    Ok(())
}

/// FR-API-1, FR-API-2, IMPL-6: the status and control sockets exist with
/// their modes (status 0666, control 0660 with its group), the lock is a
/// 0600 file; `status` reports the paths and active sets, `events` the
/// history with sequence numbers, and a carrier loss appears in both; the
/// status socket refuses the control endpoints (404) and other methods
/// (405), the control socket serves the status too; the sockets are removed
/// at shutdown.
#[test]
#[ignore = "needs root and network namespaces"]
fn api_status_and_events_through_the_sockets() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let t = build();
    let mut f = t.start_polywan(&polywan::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let mode = |p: &std::path::Path| std::fs::metadata(p).map(|m| (m.mode() & 0o7777, m.uid(), m.gid()));
    assert_eq!(mode(&f.status_socket())?, (0o666, 0, 0));
    assert_eq!(mode(&f.control_socket())?, (0o660, 0, 0));
    assert_eq!(mode(&f.lock)?.0, 0o600);
    let s = f.status()?;
    assert_eq!(s["status"], "ok", "{s}");
    assert_eq!(s["active"]["ipv4"], serde_json::json!(["a", "b"]), "{s}");
    assert_eq!(s["generation"]["desired"], s["generation"]["applied"], "{s}");
    let paths = s["paths"].as_array().cloned().unwrap_or_default();
    assert!(
        paths
            .iter()
            .all(|p| p["state"] == "up" && p["ready"] == true && p["source"].is_string()),
        "{s}"
    );
    let events = f.events()?;
    assert_eq!(
        events.first().map(|e| e.1.as_str()),
        Some("daemon_started"),
        "{events:?}"
    );
    assert!(
        events.windows(2).all(|w| w[1].0 == w[0].0 + 1),
        "consecutive sequence numbers: {events:?}"
    );
    let before = f.latest_event()?;
    t.carrier_down(Uplink::B)?;
    f.wait_event(
        before,
        "path_state_changed",
        // The reason is the first readiness loss observed (carrier,
        // address), which depends on the kernel.
        "uplink b ipv4: up -> down (",
        1,
        Duration::from_secs(5),
    )?;
    f.wait_event(
        before,
        "active_set_changed",
        "ipv4 active set: [a, b] -> [a]",
        1,
        Duration::from_secs(5),
    )?;
    // A probe lost under load can report the path down before the
    // carrier loss is observed: wait for the readiness loss too.
    f.wait_path_where(&t, "b", Family::V4, "down and not ready", Duration::from_secs(5), |p| {
        p["state"] == "down" && p["ready"] == false
    })?;
    t.carrier_up(Uplink::B)?;
    // Allowlists (IMPL-11).
    let code = |socket: &std::path::Path, method: &str, path: &str| t.http(socket, method, path).map(|r| r.0);
    assert_eq!(code(&f.status_socket(), "POST", "/v1/reload")?, 404);
    assert_eq!(code(&f.status_socket(), "POST", "/v1/uplinks/a/drain")?, 404);
    assert_eq!(code(&f.status_socket(), "DELETE", "/v1/status")?, 405);
    assert_eq!(code(&f.status_socket(), "GET", "/v1/nothing")?, 404);
    assert_eq!(code(&f.status_socket(), "GET", "/v1/events?verbose=1")?, 400);
    assert_eq!(code(&f.control_socket(), "GET", "/v1/status")?, 200);
    assert_eq!(code(&f.control_socket(), "GET", "/v1/reload")?, 405);
    f.stop()?;
    assert!(
        !f.status_socket().exists() && !f.control_socket().exists(),
        "sockets removed at shutdown"
    );
    Ok(())
}

/// FR-API-1: a foreign object at a socket path refuses startup and is left
/// alone; after a crash the record of published sockets identifies the
/// stale sockets, which a restart replaces; a reload changes the status
/// socket's access (group, mode 0660), disables it (removed), and is
/// refused when it would swap the roles of the existing paths.
#[test]
#[ignore = "needs root and network namespaces"]
fn api_socket_lifecycle() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    let (status, control) = (f.status_socket(), f.control_socket());
    std::fs::write(&status, "not a socket")?;
    f.start(&t)?;
    f.wait_exit(&t, Duration::from_secs(10))?;
    assert!(f.log().contains("PolyWAN cannot identify as its own"), "{}", f.log());
    assert_eq!(std::fs::read_to_string(&status)?, "not a socket", "left alone");
    std::fs::remove_file(&status)?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    // A crash leaves the sockets; the record identifies them.
    f.kill()?;
    assert!(status.exists() && control.exists());
    f.start(&t)?;
    f.wait_installed(&t)?;
    assert_eq!(f.status()?["status"], "ok");
    let api = |extra: &str| {
        let mut c = polywan::ipv4(&ab());
        c += &format!("\n[api]\nsocket = \"{}\"\ngroup = \"root\"\n{extra}", control.display());
        c
    };
    // Restricted access: group and mode change, the socket stays.
    let ino = std::fs::metadata(&status)?.ino();
    f.write_config(&api(&format!(
        "status_socket = \"{}\"\nstatus_group = \"daemon\"\n",
        status.display()
    )))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(10))?;
    let daemon_gid = t
        .router()
        .sh("getent group daemon | cut -d: -f3")?
        .trim()
        .parse::<u32>()?;
    let m = std::fs::metadata(&status)?;
    assert_eq!((m.mode() & 0o7777, m.gid(), m.ino()), (0o660, daemon_gid, ino));
    // Swapping the roles of the existing paths is refused.
    let mut swapped = polywan::ipv4(&ab());
    swapped += &format!(
        "\n[api]\nsocket = \"{}\"\nstatus_socket = \"{}\"\ngroup = \"root\"\n",
        status.display(),
        control.display()
    );
    f.write_config(&swapped)?;
    f.reload()?;
    f.wait_log(&t, "reload_failed", 1, Duration::from_secs(10))?;
    assert!(f.log().contains("cannot change from the"), "{}", f.log());
    // Disabled: removed.
    f.write_config(&api("status_socket = \"\"\n"))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 2, Duration::from_secs(10))?;
    t.wait_for("the status socket removed", Duration::from_secs(5), || {
        Ok(!status.exists())
    })?;
    assert!(control.exists());
    // A symbolic link at a socket path is refused at startup.
    f.stop()?;
    std::os::unix::fs::symlink("/dev/null", &status)?;
    f.write_config(&polywan::ipv4(&ab()))?;
    f.start(&t)?;
    f.wait_exit(&t, Duration::from_secs(10))?;
    assert!(f.log().contains("PolyWAN cannot identify as its own"), "{}", f.log());
    std::fs::remove_file(&status)?;
    Ok(())
}

per_family!(as16_drain_and_undrain);

/// AS-16 with the drain variants of AS-29 and AS-42: draining A takes it
/// out of new connections, balance-policy ones included, while its existing
/// flows continue, connections bound to its address still use it, and its
/// probes still leave through A (lost in its provider, they take its path
/// down, then back up while it stays drained); the last candidate needs
/// `force`, after which new connections are rejected; the drain survives a
/// restart (INV-2, INV-5, INV-6, FR-SEL-3, FR-SEL-4).
fn as16_drain_and_undrain(fam: Family) -> Result<()> {
    let t = build();
    let rules = policies(&[(
        "https-on-a",
        fam,
        "a",
        "balance",
        &format!("protocol = \"tcp\"\ndestination_port = {TCP_PORT_HTTPS}\n"),
    )]);
    let mut f = t.start_polywan(&polywan::config(&ab(), &[fam], &HealthSpec::fast(), "", &rules))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    let flows = start_flows(&t, fam, 30, 20)?;
    std::thread::sleep(Duration::from_millis(500));
    succeeded(f.drain("a", true, false)?)?;
    assert_eq!(
        balancing_members(&t, fam)?,
        ["wanb"],
        "applied when the command returns"
    );
    f.wait_event(0, "uplink_drained", "uplink a drained", 1, Duration::from_secs(5))?;
    for port in [TCP_PORT, TCP_PORT_HTTPS] {
        let r = t.connect_to(
            Node::Client,
            &servers(fam, 1, 20, port),
            20,
            false,
            Duration::from_secs(2),
        )?;
        assert_eq!(tally(&r).get(&Some(Uplink::B)), Some(&20), "{port}: {:?}", tally(&r));
    }
    // AS-42: bound to A's address, a router connection still uses A.
    let a = t.uplink_address(Uplink::A, fam)?.context("A's address")?;
    let binding = testbed::agent::Binding {
        source: Some(a),
        device: None,
    };
    let r = t.connect_bound(
        Node::Router,
        &servers(fam, 1, 5, TCP_PORT),
        5,
        false,
        Duration::from_secs(2),
        &binding,
    )?;
    assert_eq!(tally(&r).get(&Some(Uplink::A)), Some(&5), "{:?}", tally(&r));
    // AS-09: an inbound connection on A (port forwarding to the LAN host)
    // is answered through A (INV-5).
    let _server = serve_in(&t, Node::Client)?;
    t.router().nft(&format!(
        "table {ipk} admin {{\n  chain pre {{\n    type nat hook prerouting priority -100; policy accept;\n    iifname \"wana\" {ipk} daddr {a} tcp dport {TCP_PORT} dnat to {}\n  }}\n}}\n",
        lan_client(fam),
        ipk = ip(fam),
    ))?;
    let r = t.connect_to(
        Node::Inet,
        &[endpoint(&a.to_string(), TCP_PORT)],
        3,
        false,
        Duration::from_secs(2),
    )?;
    assert!(
        r.iter().all(|c| c.outcome == Outcome::Ok),
        "inbound on drained A: {r:?}"
    );
    flows_on_continuous(flows, &[Uplink::A, Uplink::B])?;
    // AS-29: A's probes keep running through A while it is drained: lost in
    // A's provider, they take its path down, and back up once they pass.
    t.drop_probe_echoes(Uplink::A, 1)?;
    f.wait_path_where(&t, "a", fam, "down", Duration::from_secs(10), |p| p["state"] == "down")?;
    t.clear_provider_rules(Uplink::A)?;
    wait_a_eligible(&t, &f, fam)?;
    let s = f.status()?;
    assert_eq!(s["uplinks"][0]["drained"], true, "{s}");
    assert_eq!(balancing_members(&t, fam)?, ["wanb"], "still drained");
    // FR-SEL-4: the last candidate.
    let out = f.drain("b", true, false)?;
    assert!(
        !out.status.success() && polywan::output_text(&out).contains("last"),
        "{}",
        polywan::output_text(&out)
    );
    assert_eq!(balancing_members(&t, fam)?, ["wanb"]);
    succeeded(f.drain("b", true, true)?)?;
    assert!(balancing_members(&t, fam)?.is_empty());
    assert_rejected(&t.connect_to(
        Node::Client,
        &servers(fam, 1, 5, TCP_PORT),
        5,
        false,
        Duration::from_secs(2),
    )?);
    succeeded(f.drain("b", false, false)?)?;
    assert_eq!(balancing_members(&t, fam)?, ["wanb"]);
    // The drain survives a restart.
    f.stop()?;
    f.start(&t)?;
    wait_a_eligible(&t, &f, fam)?;
    assert_eq!(balancing_members(&t, fam)?, ["wanb"], "still drained after the restart");
    assert_eq!(f.status()?["uplinks"][0]["drained"], true);
    succeeded(f.drain("a", false, false)?)?;
    assert_eq!(balancing_members(&t, fam)?, ["wana", "wanb"]);
    f.stop()?;
    Ok(())
}

/// Waits until the desired state is applied with A's path of `fam` up and
/// ready: A is then out of the balancing members only if it is drained.
fn wait_a_eligible(t: &Topology, f: &polywan::Polywan, fam: Family) -> Result<()> {
    f.wait_path_where(t, "a", fam, "up and ready", Duration::from_secs(20), |p| {
        p["state"] == "up" && p["ready"] == true
    })?;
    f.wait_settled(t)
}

/// AS-46: a crash between the persistence of a drain and its routes, and
/// between the routes and the answer: after the restart the persisted
/// intent is in force. A crash before the persistence leaves A undrained,
/// and the command was never acknowledged.
#[test]
#[ignore = "needs root and network namespaces"]
fn as46_drain_survives_a_crash_at_each_step() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    let faults = f.dir.join("faults");
    f.set_env("POLYWAN_TEST_FAULTS", &faults.display().to_string());
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    for (crash, drained) in [
        ("persist drain", false),
        ("replace ipv4 route of table 1000", true),
        ("respond drain", true),
    ] {
        std::fs::write(&faults, format!("crash:{crash}"))?;
        let out = f.drain("a", true, false)?;
        assert!(!out.status.success(), "{crash}: never acknowledged");
        f.wait_exit(&t, Duration::from_secs(10))?;
        std::fs::remove_file(&faults)?;
        f.start(&t)?;
        wait_a_eligible(&t, &f, Family::V4)?;
        let expected: &[&str] = if drained { &["wanb"] } else { &["wana", "wanb"] };
        wait_members(&t, Family::V4, expected, Duration::from_secs(10))?;
        assert_eq!(f.status()?["uplinks"][0]["drained"], drained, "{crash}");
        if drained {
            succeeded(f.drain("a", false, false)?)?;
            wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
        }
    }
    f.stop()?;
    Ok(())
}

/// FR-API-3: a reload through the control socket answers once the
/// generation that includes it is applied, also when the first pass after
/// the commit cannot plan yet: a reload that adds IPv6 waits for the new
/// family's global settings, which the persistence lane writes slowly here.
#[test]
#[ignore = "needs root and network namespaces"]
fn api_reload_answers_once_its_generation_is_applied() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    let writes = f.dir.join("slow-writes");
    f.set_env("POLYWAN_TEST_SLOW_WRITES", &writes.display().to_string());
    f.start(&t)?;
    f.wait_settled(&t)?;
    let before = f.status()?["generation"]["applied"].as_u64().unwrap_or(0);
    std::fs::write(&writes, "1000")?;
    f.reload_with(&polywan::dual(&ab()))?;
    let applied = f.status()?["generation"]["applied"].as_u64().unwrap_or(0);
    let forwarding = t.router().output("sysctl", ["-n", "net.ipv6.conf.all.forwarding"])?;
    std::fs::remove_file(&writes)?;
    assert!(
        applied > before,
        "answered before its generation: {before} -> {applied}"
    );
    assert_eq!(String::from_utf8_lossy(&forwarding.stdout).trim(), "1");
    f.stop()?;
    Ok(())
}

/// FR-SEL-3: a SIGHUP reload while a drain's intent is being written does
/// not undo the drain once both complete: the reload waits for the write
/// (the persistence lane writes slowly here).
#[test]
#[ignore = "needs root and network namespaces"]
fn a_reload_signal_keeps_a_drain_being_written() -> Result<()> {
    let t = build();
    let mut f = t.prepare_polywan(&polywan::ipv4(&ab()))?;
    let writes = f.dir.join("slow-writes");
    let waiting = f.dir.join("slow-writes.waiting");
    f.set_env("POLYWAN_TEST_SLOW_WRITES", &writes.display().to_string());
    f.start(&t)?;
    f.wait_settled(&t)?;
    let _ = std::fs::remove_file(&waiting);
    std::fs::write(&writes, "1500")?;
    let drained = std::thread::scope(|s| -> Result<std::process::Output> {
        let drain = s.spawn(|| f.drain("a", true, false));
        t.wait_for("the drain's write", Duration::from_secs(10), || Ok(waiting.exists()))?;
        f.reload()?;
        drain.join().expect("the drain")
    })?;
    succeeded(drained)?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(15))?;
    std::fs::remove_file(&writes)?;
    f.wait_settled(&t)?;
    let status = f.status()?;
    let a = status["uplinks"]
        .as_array()
        .and_then(|u| u.iter().find(|u| u["name"] == "a"))
        .context("uplink a")?;
    assert_eq!(a["drained"], true, "{status}");
    wait_members(&t, Family::V4, &["wanb"], Duration::from_secs(5))?;
    f.stop()?;
    Ok(())
}

/// FR-API-3, FR-MARK-4, FR-CFG-3: `reload` through the control socket
/// reports success with the applied generation, or the validation errors
/// (only to the client and the log: the public `reload_failed` event has a
/// fixed message); `forget-uplink` through the control socket is refused
/// while the uplink is configured, then releases its id for another name.
#[test]
#[ignore = "needs root and network namespaces"]
fn api_reload_and_forget() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&polywan::ipv4(&ab()))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let before = f.status()?["generation"]["applied"].as_u64().unwrap_or(0);
    let out = f.reload_with(&polywan::ipv4(&[
        polywan::UplinkSpec::new(Uplink::A, 1).weight(3),
        polywan::UplinkSpec::new(Uplink::B, 2),
    ]))?;
    let text = polywan::output_text(&out);
    assert!(text.contains("configuration reloaded"), "{text}");
    assert!(f.status()?["generation"]["applied"].as_u64().unwrap_or(0) > before);
    // Validation errors go to the client, not to the public event.
    f.write_config(&format!("bogus_key = 1\n{}", polywan::ipv4(&ab())))?;
    let out = f.reload_cli()?;
    let text = polywan::output_text(&out);
    assert!(!out.status.success() && text.contains("bogus_key"), "{text}");
    f.wait_event(0, "reload_failed", "was not reloaded", 1, Duration::from_secs(5))?;
    assert!(
        !f.events()?.iter().any(|(_, _, l)| l.contains("bogus_key")),
        "no configuration excerpt in events"
    );
    // forget-uplink: refused while configured, then through the socket.
    let socket = f.control_socket().display().to_string();
    let out = f.cli_config(&["forget-uplink", "a", "--socket", &socket])?;
    assert!(
        !out.status.success() && polywan::output_text(&out).contains("still in the configuration"),
        "{}",
        polywan::output_text(&out)
    );
    f.reload_with(&polywan::ipv4(&ab()[1..]))?;
    let reuse = polywan::ipv4(&ab()).replace("name = \"a\"", "name = \"fiber\"");
    f.write_config(&reuse)?;
    let out = f.reload_cli()?;
    assert!(
        !out.status.success() && polywan::output_text(&out).contains("forget-uplink a"),
        "{}",
        polywan::output_text(&out)
    );
    succeeded(f.cli_config(&["forget-uplink", "a", "--socket", &socket])?)?;
    succeeded(f.reload_cli()?)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(15))?;
    Ok(())
}

/// AS-25, hooks (FR-HOOK-1 to FR-HOOK-4): a recording hook gets the event
/// as JSON on standard input and in the `POLYWAN_*` variables, runs as
/// `nobody` without supplementary groups or capabilities, with only
/// descriptors 0–2, as the leader of its own process group; a hook that
/// sleeps 60 s with a background child is killed with its child at its 2 s
/// timeout; routing is unaffected meanwhile (INV-8).
#[test]
#[ignore = "needs root and network namespaces"]
fn as25_hooks_run_bounded_and_detached() -> Result<()> {
    let t = build();
    let out = t.exec_dir()?.join("hook-out");
    std::fs::create_dir_all(&out)?;
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o777))?;
    let o = out.display();
    let record = format!(
        "ls /proc/$$/fd; f={o}/$$; echo \"event=$POLYWAN_EVENT uplink=$POLYWAN_UPLINK family=$POLYWAN_FAMILY old=$POLYWAN_OLD new=$POLYWAN_NEW reason=$POLYWAN_REASON\" > $f.env; id -u > $f.id; id -G >> $f.id; grep -E '^Cap(Eff|Prm):' /proc/self/status > $f.caps; cut -d' ' -f5 /proc/$$/stat > $f.pgid; echo $$ > $f.pid; env > $f.vars; cat > $f.stdin; mv $f.env $f.done"
    );
    let sleeper = format!("sleep 60 & echo $! > {o}/child; sleep 60");
    let hooks = format!(
        "[[notify.hook]]\ncommand = [\"/bin/sh\", \"-c\", {record:?}]\nevents = [\"path_state_changed\"]\n[[notify.hook]]\ncommand = [\"/bin/sh\", \"-c\", {sleeper:?}]\nevents = [\"path_state_changed\"]\ntimeout = \"2s\"\n"
    );
    let f = t.start_polywan(&with(&hooks))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let lost = Instant::now();
    t.carrier_down(Uplink::B)?;
    wait_members(&t, Family::V4, &["wana"], Duration::from_secs(3))?;
    assert!(
        lost.elapsed() < Duration::from_secs(2),
        "routing unaffected by the hooks"
    );
    let done = t.wait_for("the recording hook", Duration::from_secs(10), || {
        Ok(std::fs::read_dir(&out)?
            .flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(".done")))
    });
    done?;
    let base = std::fs::read_dir(&out)?
        .flatten()
        .find_map(|e| e.file_name().to_str()?.strip_suffix(".done").map(str::to_owned))
        .context("no hook record")?;
    let read = |ext: &str| std::fs::read_to_string(out.join(format!("{base}.{ext}"))).unwrap_or_default();
    assert!(
        read("done").contains("event=path_state_changed uplink=b family=ipv4 old=up new=down reason="),
        "{}",
        read("done")
    );
    assert_eq!(read("id").split_whitespace().collect::<Vec<_>>(), ["65534", "65534"]);
    assert!(
        read("caps").lines().all(|l| l.ends_with("0000000000000000")),
        "{}",
        read("caps")
    );
    // Listed first, without a redirection (the shell saves descriptors
    // around redirections), to the captured standard output, logged once
    // the hook has exited (after its record).
    f.wait_log(&t, "hook finished", 1, Duration::from_secs(5))?;
    assert!(f.log().contains("stdout=0\\n1\\n2\\n stderr="), "only 0–2: {}", f.log());
    assert_eq!(read("pgid").trim(), read("pid").trim(), "its own process group");
    let vars: Vec<String> = read("vars")
        .lines()
        .map(|l| l.split('=').next().unwrap_or("").to_owned())
        .collect();
    assert!(
        vars.iter()
            .all(|v| v.starts_with("POLYWAN_") || ["PATH", "PWD", "SHLVL", "_"].contains(&v.as_str())),
        "{vars:?}"
    );
    let stdin: serde_json::Value = serde_json::from_str(&read("stdin"))?;
    assert_eq!(
        (stdin["type"].as_str(), stdin["uplink"].as_str()),
        (Some("path_state_changed"), Some("b"))
    );
    // The sleeping hook and its child are gone after the timeout.
    let child: u32 = t
        .wait_for("the sleeping hook's child", Duration::from_secs(5), || {
            Ok(out.join("child").exists())
        })
        .and_then(|_| Ok(std::fs::read_to_string(out.join("child"))?.trim().parse()?))?;
    t.wait_for("the child killed with its group", Duration::from_secs(6), || {
        Ok(exited(child))
    })?;
    f.wait_log(&t, "hook failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains("end=timed out"), "{}", f.log());
    t.carrier_up(Uplink::B)?;
    Ok(())
}

/// The event types that email selects by default (FR-MAIL-2).
const MAILED: [&str; 10] = [
    "daemon_started",
    "daemon_stopping",
    "config_reloaded",
    "reload_failed",
    "path_state_changed",
    "active_set_changed",
    "uplink_drained",
    "uplink_undrained",
    "status_degraded",
    "status_recovered",
];

/// Waits until every event after sequence number `after` of the types
/// `kinds` is in a message that the stub accepted: none waits in a batch
/// or for a retry.
fn wait_mailed(t: &Topology, f: &polywan::Polywan, stub: &Stub, after: u64, kinds: &[&str]) -> Result<()> {
    t.wait_for("the emails of the events", Duration::from_secs(20), || {
        let bodies: String = stub
            .calls()?
            .into_iter()
            .filter(|c| c.mode == "accept")
            .filter_map(|c| Some(c.message?.body))
            .collect();
        Ok(f.events()?
            .iter()
            .filter(|(seq, kind, _)| *seq > after && kinds.contains(&kind.as_str()))
            .all(|(_, kind, l)| bodies.contains(&format!("{} {kind}", l.split(' ').next().unwrap_or("")))))
    })
    .map(|_| ())
}

/// AS-25, sendmail (FR-MAIL-1, FR-MAIL-3), with the minute of the retries
/// shortened to 500 ms and the deadline to 2 s: sendmail runs as
/// `-i -f FROM RECIPIENT...` in its own process group; a failing one is
/// retried after 1, 5 and 15 (short) minutes with the same Message-ID,
/// then the message is dropped; one that floods standard error or dies by
/// a signal fails without blocking, and the retry is accepted; one that
/// hangs with a child, and one that never reads its input, are killed with
/// their group at the deadline, while routing meets its deadlines (INV-8),
/// and the retry is accepted.
#[test]
#[ignore = "needs root and network namespaces"]
fn as25_sendmail_failures_are_bounded_and_retried() -> Result<()> {
    let t = build();
    let stub = Stub::new(&t, "sendmail")?;
    let to = ["admin@example.com", "noc@example.org"];
    let mut f = t.prepare_polywan(&with(&notify_email(&stub.path, "coalesce = \"1s\"\n", &to, "")))?;
    f.set_env("POLYWAN_TEST_MAIL_TIMES", "500,2000");
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    // The startup batch.
    let calls = stub.wait_calls(&t, 1, Duration::from_secs(10))?;
    let first = &calls[0];
    assert_eq!(
        first.args,
        ["-i", "-f", "router@example.com", "admin@example.com", "noc@example.org"]
    );
    assert_eq!(first.pgid, first.pid, "its own process group");
    let m = first.message.as_ref().context("the startup message")?;
    assert!(m.body.contains(" daemon_started: polywan "), "{}", m.body);
    assert!(
        first
            .header("Subject")
            .is_some_and(|s| s.starts_with("PolyWAN notification")),
        "{}",
        m.raw
    );
    let mut toggle = {
        let mut drained = false;
        move |f: &polywan::Polywan| -> Result<()> {
            drained = !drained;
            succeeded(f.drain("a", drained, false)?).map(|_| ())
        }
    };
    // Exit status 75: three retries, 0.5, 2.5 and 7.5 s after each failure.
    stub.script(&[Mode::Exit(75); 4])?;
    let before = stub.calls()?.len();
    toggle(&f)?;
    let calls = stub.wait_calls(&t, before + 4, Duration::from_secs(20))?;
    let tries = &calls[before..before + 4];
    let id = tries[0].header("Message-ID").context("Message-ID")?;
    assert!(tries.iter().all(|c| c.header("Message-ID") == Some(id)), "{tries:?}");
    for (pair, minutes) in tries.windows(2).zip([1u64, 5, 15]) {
        let gap = pair[1].at.duration_since(pair[0].at)?;
        let expected = Duration::from_millis(500 * minutes);
        assert!(
            gap >= expected && gap < expected + Duration::from_millis(1500),
            "{gap:?}"
        );
    }
    f.wait_log(&t, "email dropped after its last retry", 1, Duration::from_secs(5))?;
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(stub.calls()?.len(), before + 4, "no retry after the third");
    // A flood of standard error, then a signal: each fails without
    // blocking, and the retry with the same Message-ID is accepted.
    for (mode, needle, n) in [
        (Mode::Flood, "exit status 1, stderr: xxxx", 1),
        (Mode::Signal, "killed by signal 9", 1),
    ] {
        stub.script(&[mode])?;
        let before = stub.calls()?.len();
        let submitted = f.log().matches("email submitted").count();
        toggle(&f)?;
        let calls = stub.wait_calls(&t, before + 2, Duration::from_secs(20))?;
        assert_eq!(
            calls[before].header("Message-ID"),
            calls[before + 1].header("Message-ID")
        );
        f.wait_log(&t, "email submitted", submitted + 1, Duration::from_secs(5))?;
        assert_eq!(f.log().matches(needle).count(), n, "{}", f.log());
    }
    assert!(f.log().contains("xxxx [truncated]"), "bounded standard error");
    // Hanging with a child (A undrained by the toggle), then never reading:
    // killed at the deadline, and routing meets its deadlines meanwhile.
    // Each phase ends with every email out, so that the next phase's mode
    // goes to its own message.
    for mode in [Mode::Hang, Mode::NoRead] {
        stub.script(&[mode])?;
        let before = stub.calls()?.len();
        let since = f.latest_event()?;
        let timeouts = f.log().matches("timed out").count();
        toggle(&f)?;
        let calls = stub.wait_calls(&t, before + 1, Duration::from_secs(10))?;
        let call = calls[before].clone();
        assert_eq!(call.mode, mode.word());
        let pid = call.pid;
        if mode == Mode::Hang {
            t.wait_for("the stub's child", Duration::from_secs(5), || {
                Ok(stub.child().is_some())
            })?;
            let lost = Instant::now();
            t.carrier_down(Uplink::B)?;
            wait_members(&t, Family::V4, &["wana"], Duration::from_secs(3))?;
            assert!(
                lost.elapsed() < Duration::from_secs(2),
                "routing unaffected by sendmail"
            );
            // The next toggle drains A, which needs B (FR-SEL-4).
            t.carrier_up(Uplink::B)?;
            wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
        }
        t.wait_for("the timeout", Duration::from_secs(5), || {
            Ok(f.log().matches("timed out").count() > timeouts)
        })
        .with_context(|| format!("{mode:?}: {}", f.log()))?;
        t.wait_for("the group killed", Duration::from_secs(5), || {
            Ok(exited(pid) && stub.child().is_none_or(exited))
        })?;
        // The retry is accepted (after the batch of B's carrier loss, due
        // first), with the same Message-ID when the first attempt read it.
        let id = call.header("Message-ID");
        t.wait_for("the accepted retry", Duration::from_secs(10), || {
            Ok(stub.calls()?[before + 1..]
                .iter()
                .any(|c| c.mode == "accept" && c.message.is_some() && (id.is_none() || c.header("Message-ID") == id)))
        })?;
        wait_mailed(&t, &f, &stub, since, &MAILED)?;
    }
    Ok(())
}

/// AS-25, reloads (FR-MAIL-1): a submission running when a reload changes
/// the sendmail path and the recipients finishes with the configuration it
/// started with; its retry uses the new path and recipients with the same
/// Message-ID; a reload that removes `[notify.email]` discards the pending
/// retry, logging the number.
#[test]
#[ignore = "needs root and network namespaces"]
fn as25_sendmail_retries_follow_reloads() -> Result<()> {
    let t = build();
    let old = Stub::new(&t, "sendmail")?;
    let new = Stub::new(&t, "sendmail2")?;
    let email = |stub: &Stub, to: &[&str]| with(&notify_email(&stub.path, "coalesce = \"1s\"\n", to, ""));
    let mut f = t.prepare_polywan(&email(&old, &["admin@example.com", "noc@example.org"]))?;
    // Retries 2 s after a failure; the deadline 2 s.
    f.set_env("POLYWAN_TEST_MAIL_TIMES", "2000,2000");
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    old.wait_calls(&t, 1, Duration::from_secs(10))?;
    old.script(&[Mode::Hang])?;
    succeeded(f.drain("a", true, false)?)?;
    // Its message read (it hangs after reading).
    let calls = old.wait_calls(&t, 2, Duration::from_secs(10))?;
    let pid = calls[1].pid;
    let id = calls[1].header("Message-ID").context("Message-ID")?;
    // While it runs, the path and the recipients change.
    f.reload_with(&email(&new, &["ops@example.net"]))?;
    // It ends at its deadline, with the old path; the retry takes the new
    // path and recipients, with the same Message-ID.
    t.wait_for("the old submission's deadline", Duration::from_secs(5), || {
        Ok(exited(pid))
    })?;
    t.wait_for("the retry through the new path", Duration::from_secs(10), || {
        Ok(!new.attempts(id)?.is_empty())
    })?;
    let retry = new.attempts(id)?.remove(0);
    assert_eq!(retry.args, ["-i", "-f", "router@example.com", "ops@example.net"]);
    let m = retry.message.as_ref().context("message")?;
    assert_eq!(m.header("To"), Some("ops@example.net"));
    assert!(m.body.contains(" uplink_drained a: "), "{}", m.body);
    assert_eq!(old.calls()?.len(), 2, "nothing more through the old path");
    // A failing submission, then email removed: the retry is discarded.
    new.script(&[Mode::Exit(75)])?;
    let before = new.calls()?.len();
    succeeded(f.drain("a", false, false)?)?;
    new.wait_calls(&t, before + 1, Duration::from_secs(10))?;
    f.reload_with(&polywan::ipv4(&ab()))?;
    f.wait_log(&t, "pending email discarded", 1, Duration::from_secs(5))?;
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(new.calls()?.len(), before + 1, "no retry once email is removed");
    Ok(())
}

/// AS-25, notification tests (FR-MAIL-4, FR-API-3, FR-API-4): `notify-test`
/// tries email and every hook once, bypassing their filters; a hook that
/// takes 11 s makes the test outlast the ordinary 10 s deadline, and a
/// second test meanwhile is refused (429). Hooks get the synthetic
/// `notify_test` event, which never enters the event history. A failing
/// sendmail is reported with its exit status and not retried. Offline,
/// the test is refused while the daemon holds the lock, and runs once it
/// has stopped, warning that the sandbox was not exercised.
#[test]
#[ignore = "needs root and network namespaces"]
fn as25_notification_tests() -> Result<()> {
    let t = build();
    let stub = Stub::new(&t, "sendmail")?;
    let out = t.exec_dir()?.join("test-hook");
    std::fs::create_dir_all(&out)?;
    // Hooks run as nobody (FR-HOOK-3: never with UID 0).
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o777))?;
    let delay = out.join("delay");
    std::fs::write(&delay, "11")?;
    let record = format!("cat > {}/stdin", out.display());
    let sleeper = format!("sleep $(cat {})", delay.display());
    // Filters that the tests bypass.
    let hooks = format!(
        "[[notify.hook]]\ncommand = [\"/bin/sh\", \"-c\", {record:?}]\nevents = [\"daemon_stopping\"]\n[[notify.hook]]\ncommand = [\"/bin/sh\", \"-c\", {sleeper:?}]\nevents = [\"daemon_stopping\"]\ntimeout = \"15s\"\n"
    );
    let notify = "coalesce = \"1s\"\n";
    let config = with(&notify_email(&stub.path, notify, &["admin@example.com"], &hooks));
    let mut f = t.prepare_polywan(&config)?;
    f.set_env("POLYWAN_TEST_MAIL_TIMES", "500,5000");
    f.start(&t)?;
    f.wait_installed(&t)?;
    stub.wait_calls(&t, 1, Duration::from_secs(10))?;
    // A test outlasting the ordinary deadline, and a second one meanwhile:
    // once the first runs its hooks.
    let started = Instant::now();
    let (long, second) = std::thread::scope(|s| {
        let h = s.spawn(|| f.notify_test());
        let second = t
            .wait_for("the first test's recording hook", Duration::from_secs(10), || {
                Ok(out.join("stdin").exists())
            })
            .and_then(|_| f.notify_test());
        (h.join().expect("the long test"), second)
    });
    let (long, second) = (succeeded(long?)?, second?);
    let elapsed = started.elapsed();
    let text = polywan::output_text(&long);
    assert!(
        elapsed > Duration::from_secs(10) && elapsed < Duration::from_secs(20),
        "{elapsed:?}"
    );
    assert_eq!(
        text.lines().filter(|l| l.ends_with(": succeeded")).count(),
        3,
        "email and both hooks: {text}"
    );
    let refused = polywan::output_text(&second);
    assert!(!second.status.success() && refused.contains("429"), "{refused}");
    // The synthetic event, outside the history.
    let event: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(out.join("stdin"))?)?;
    assert_eq!(
        (event["type"].as_str(), event["test"].as_bool()),
        (Some("notify_test"), Some(true))
    );
    assert!(!f.events()?.iter().any(|(_, k, _)| k == "notify_test"));
    let calls = stub.calls()?;
    assert_eq!(calls.iter().filter(|c| kind(c) == "test").count(), 1);
    // A failing sendmail: reported, not retried.
    std::fs::write(&delay, "0")?;
    stub.script(&[Mode::Exit(75)])?;
    let before = stub.calls()?.len();
    let failed = f.notify_test()?;
    let text = polywan::output_text(&failed);
    assert!(!failed.status.success(), "{text}");
    assert!(text.contains("email: failed, exit status 75"), "{text}");
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(stub.calls()?.len(), before + 1, "tests are not retried");
    // Offline: refused while the daemon holds the lock, then run.
    let refused = f.cli_config(&["notify-test", "--offline"])?;
    let text = polywan::output_text(&refused);
    assert!(
        !refused.status.success() && text.contains("without --offline"),
        "{text}"
    );
    f.stop()?;
    let before = stub.calls()?.len();
    let offline = succeeded(f.cli_config(&["notify-test", "--offline"])?)?;
    let text = polywan::output_text(&offline);
    assert!(text.contains("sandbox was not exercised"), "{text}");
    let calls = stub.wait_calls(&t, before + 1, Duration::from_secs(5))?;
    assert_eq!(kind(&calls[before]), "test");
    Ok(())
}

/// AS-07 (FR-HEALTH-2, FR-HEALTH-3, FR-MAIL-2), with the hour of the rate
/// limit shortened to 12 s: while B's carrier flaps every 2 s for 60 s, B
/// goes down once (with `rise = 5`, 2 s of carrier never bring it back) and
/// up once after the flapping; the emails carry these events within the
/// coalescing window, with their headers. Then, with `max_per_hour = 3`
/// and events every second, every 12 s window holds at most three
/// notifications and one suppression notice, and a notification after the
/// window reports the suppressed ones. Notification tests, one while a
/// batch is open and two during the suppression, are sent at once, keep a
/// Unicode line and a lone-dot line, and neither flush the batch nor reset
/// the hourly allowance; two tests between admissions take none of it
/// (FR-MAIL-4).
#[test]
#[ignore = "needs root and network namespaces"]
fn as07_flapping_coalescing_and_the_hourly_limit() -> Result<()> {
    let t = build();
    let stub = Stub::new(&t, "sendmail")?;
    let health = HealthSpec::fast().with("rise = 5\n");
    let config = |max: u32| {
        let more = format!("max_per_hour = {max}\n");
        let email = notify_email(&stub.path, "coalesce = \"2s\"\n", &["admin@example.com"], &more);
        polywan::config(&ab(), &[Family::V4], &health, "", &email)
    };
    let mut f = t.prepare_polywan(&config(1000))?;
    f.set_env("POLYWAN_TEST_MAIL_TIMES", "200,5000");
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    stub.wait_calls(&t, 1, Duration::from_secs(10))?;
    let start = f.latest_event()?;
    for i in 0..15 {
        t.carrier_down(Uplink::B)?;
        if i == 0 {
            // B's loss opened a batch: the test goes out at once.
            succeeded(f.notify_test()?)?;
        }
        std::thread::sleep(Duration::from_secs(2));
        t.carrier_up(Uplink::B)?;
        std::thread::sleep(Duration::from_secs(2));
    }
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let changes: Vec<String> = f
        .events()?
        .into_iter()
        .filter(|(seq, kind, _)| *seq > start && kind == "path_state_changed")
        .map(|(_, _, l)| l)
        .collect();
    assert_eq!(changes.len(), 2, "{changes:#?}");
    // Every selected event reaches an email, within the coalescing window.
    wait_mailed(&t, &f, &stub, start, &["path_state_changed", "active_set_changed"])?;
    let calls = stub.calls()?;
    let tests: Vec<&Call> = calls.iter().filter(|c| kind(c) == "test").collect();
    assert_eq!(tests.len(), 1);
    let m = tests[0].message.as_ref().context("message")?;
    assert!(
        m.body.contains("\nPolyWAN — prova ✓\n.\nEnd of the test.\n"),
        "{}",
        m.body
    );
    assert_eq!(tests[0].args, ["-i", "-f", "router@example.com", "admin@example.com"]);
    for c in calls.iter().filter(|c| kind(c) != "test") {
        let m = c.message.as_ref().context("message")?;
        for h in [
            "Date",
            "Message-ID",
            "From",
            "To",
            "Subject",
            "MIME-Version",
            "Content-Type",
        ] {
            assert!(m.header(h).is_some(), "{h}: {}", m.raw);
        }
        assert_eq!(m.header("Content-Type"), Some("text/plain; charset=UTF-8"));
        // The first change of the batch, then the call: the coalescing window.
        let first = m
            .body
            .lines()
            .nth(2)
            .and_then(|l| l.split(' ').next())
            .unwrap_or_default();
        let at = timestamp(first)?;
        let delay = c.at.duration_since(at).unwrap_or_default();
        assert!(
            delay >= Duration::from_millis(1900) && delay < Duration::from_secs(4),
            "{delay:?}: {}",
            m.body
        );
    }
    // The rate limit: the earlier admissions leave the 12 s window first.
    std::thread::sleep(Duration::from_secs(13));
    f.reload_with(&config(3))?;
    // Tests take none of the allowance: with three per window, one
    // notification, two tests and two more notifications are admitted, and
    // the next batch is suppressed with its notice; all within 10 s of the
    // first admission.
    let count = |k: &str| -> Result<usize> { Ok(stub.calls()?.iter().filter(|c| kind(c) == k).count()) };
    let (notified, tested) = (count("notification")?, count("test")?);
    for n in 1..=4 {
        succeeded(f.drain("a", n % 2 == 1, false)?)?;
        if n == 4 {
            t.wait_for("the suppression notice", Duration::from_secs(5), || {
                Ok(count("notice")? == 1)
            })?;
        } else {
            t.wait_for(&format!("notification {n}"), Duration::from_secs(5), || {
                Ok(count("notification")? == notified + n)
            })?;
        }
        if n == 1 {
            succeeded(f.notify_test()?)?;
            succeeded(f.notify_test()?)?;
            assert_eq!(count("test")?, tested + 2);
        }
    }
    assert_eq!(count("notification")?, notified + 3, "{:#?}", stub.calls()?);
    // The flood, once these admissions and the notice left the window.
    std::thread::sleep(Duration::from_secs(13));
    let from = std::time::SystemTime::now();
    let mut drained = false;
    for i in 0..30 {
        drained = !drained;
        f.drain("a", drained, false)?;
        if i == 12 || i == 22 {
            // During the suppression.
            succeeded(f.notify_test()?)?;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    std::thread::sleep(Duration::from_secs(4));
    let calls: Vec<Call> = stub
        .calls()?
        .into_iter()
        .filter(|c| c.at >= from - Duration::from_secs(1))
        .collect();
    let notices: Vec<&Call> = calls.iter().filter(|c| kind(c) == "notice").collect();
    let notes: Vec<&Call> = calls.iter().filter(|c| kind(c) == "notification").collect();
    assert_eq!(calls.iter().filter(|c| kind(c) == "test").count(), 2);
    let window = Duration::from_millis(12_000 - 300);
    for c in &notes {
        let within = notes
            .iter()
            .filter(|o| o.at <= c.at && c.at.duration_since(o.at).unwrap_or_default() < window)
            .count();
        assert!(within <= 3, "{} notifications within the window", within);
    }
    assert!(!notices.is_empty(), "a suppression notice");
    for pair in notices.windows(2) {
        assert!(pair[1].at.duration_since(pair[0].at)? >= window, "one notice per hour");
    }
    assert!(
        notes.iter().any(|c| c
            .message
            .as_ref()
            .is_some_and(|m| m.body.contains("suppressed by notify.email.max_per_hour"))),
        "a notification after the window reports the suppressed ones"
    );
    Ok(())
}

/// What a recorded message is, by its Subject.
fn kind(c: &Call) -> &'static str {
    let s = c.header("Subject").unwrap_or_default();
    if s.starts_with("PolyWAN notification test") {
        "test"
    } else if s.starts_with("PolyWAN notifications suppressed") {
        "notice"
    } else {
        "notification"
    }
}

/// An RFC 3339 UTC timestamp with milliseconds (event times).
fn timestamp(s: &str) -> Result<std::time::SystemTime> {
    let n = |r: std::ops::Range<usize>| -> Result<u64> { Ok(s.get(r).context("timestamp")?.parse()?) };
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    // Days since 1970-01-01 (Howard Hinnant's algorithm).
    let (y, m) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?;
    Ok(std::time::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(n(20..23)?))
}

/// FR-MET-1 and FR-MET-2: `metrics.listen` serves `GET /metrics` only, with
/// the families of FR-MET-2 following the paths (B's carrier loss: down,
/// not ready, not active, a transition counted, probe samples counted); a
/// reload that moves the listener closes the old address, one whose
/// address cannot be bound is rejected and keeps the running listener, and
/// one without `metrics.listen` disables it.
#[test]
#[ignore = "needs root and network namespaces"]
fn metrics_follow_the_paths_and_reloads() -> Result<()> {
    let t = build();
    let config = |listen: &str| {
        if listen.is_empty() {
            polywan::ipv4(&ab())
        } else {
            with(&format!("[metrics]\nlisten = \"{listen}\"\n"))
        }
    };
    let get = |addr: &str, method: &str, path: &str| t.http(std::path::Path::new(&format!("tcp:{addr}")), method, path);
    let f = t.start_polywan(&config("127.0.0.1:9750"))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let metric = |text: &str, line: &str| text.lines().any(|l| l == line);
    let (code, text) = get("127.0.0.1:9750", "GET", "/metrics")?;
    assert_eq!(code, 200, "{text}");
    for line in [
        "polywan_status_degraded 0",
        "polywan_path_up{uplink=\"b\",family=\"ipv4\"} 1",
        "polywan_path_active{uplink=\"b\",family=\"ipv4\"} 1",
        "polywan_uplink_drained{uplink=\"a\"} 0",
        "polywan_notifications_failed_total{channel=\"email\"} 0",
    ] {
        assert!(metric(&text, line), "{line}\n{text}");
    }
    // Paths start up before their first probe round: the first sample can
    // come after the members are installed.
    t.wait_for("a probe sample of A in the metrics", Duration::from_secs(10), || {
        let (_, text) = get("127.0.0.1:9750", "GET", "/metrics")?;
        Ok(text.lines().any(|l| {
            l.starts_with("polywan_probe_samples_total{uplink=\"a\",family=\"ipv4\",target=")
                && l.contains("result=\"ok\"}")
        }))
    })?;
    assert_eq!(get("127.0.0.1:9750", "POST", "/metrics")?.0, 405);
    assert_eq!(get("127.0.0.1:9750", "GET", "/v1/status")?.0, 404);
    // B's transitions to down so far, read in a scrape that shows B up: a
    // probe lost under load may have added one before, and a later one is
    // the only down transition left to the carrier loss.
    let downs = |text: &str| -> u64 {
        let name = "polywan_path_transitions_total{uplink=\"b\",family=\"ipv4\",to=\"down\"} ";
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.parse().ok())
            .unwrap_or(0)
    };
    let mut before = 0;
    t.wait_for("B up in the metrics", Duration::from_secs(10), || {
        let (_, text) = get("127.0.0.1:9750", "GET", "/metrics")?;
        before = downs(&text);
        Ok(metric(&text, "polywan_path_up{uplink=\"b\",family=\"ipv4\"} 1"))
    })?;
    t.carrier_down(Uplink::B)?;
    wait_members(&t, Family::V4, &["wana"], Duration::from_secs(3))?;
    t.wait_for("B down in the metrics", Duration::from_secs(5), || {
        let (_, text) = get("127.0.0.1:9750", "GET", "/metrics")?;
        Ok([
            "polywan_path_up{uplink=\"b\",family=\"ipv4\"} 0",
            "polywan_path_ready{uplink=\"b\",family=\"ipv4\"} 0",
            "polywan_path_active{uplink=\"b\",family=\"ipv4\"} 0",
        ]
        .iter()
        .all(|l| metric(&text, l))
            && downs(&text) > before)
    })?;
    t.carrier_up(Uplink::B)?;
    // Moved: the old address closes.
    f.reload_with(&config("127.0.0.1:9751"))?;
    assert_eq!(get("127.0.0.1:9751", "GET", "/metrics")?.0, 200);
    assert!(
        get("127.0.0.1:9750", "GET", "/metrics").is_err(),
        "the old address is closed"
    );
    // An address the router does not have: rejected, the listener stays.
    f.write_config(&config("192.0.2.99:9752"))?;
    let out = f.reload_cli()?;
    let text = polywan::output_text(&out);
    assert!(
        !out.status.success() && text.contains("metrics.listen 192.0.2.99:9752"),
        "{text}"
    );
    assert_eq!(get("127.0.0.1:9751", "GET", "/metrics")?.0, 200);
    // Disabled.
    f.reload_with(&config(""))?;
    assert!(get("127.0.0.1:9751", "GET", "/metrics").is_err(), "metrics disabled");
    Ok(())
}

/// AS-51, access (FR-API-1, IMPL-6, IMPL-11): the default status socket
/// (0666) serves an unprivileged user (`nobody` without groups), its write
/// paths are 404; the control socket refuses a non-member of `api.group`
/// and serves a member; `api.status_group` restricts the status socket to
/// its members, an empty `api.status_socket` removes it, and both changes
/// close the socket's existing connections; the instance lock
/// is root's, mode 0600, unreadable by users; a dry run opens no socket.
#[test]
#[ignore = "needs root and network namespaces"]
fn as51_socket_access() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let t = build();
    let dir = t.polywan_dir();
    let (control, status) = (dir.join("api.sock"), dir.join("status.sock"));
    let config = |status_lines: &str| {
        with(&format!(
            "[api]\nsocket = \"{}\"\ngroup = \"adm\"\n{status_lines}",
            control.display()
        ))
    };
    let open = format!("status_socket = \"{}\"\n", status.display());
    let mut f = t.start_polywan(&config(&open))?;
    f.wait_installed(&t)?;
    let get = |groups: &[&str], socket: &std::path::Path, method: &str, path: &str| {
        t.http_as_nobody(groups, socket, method, path)
    };
    assert_eq!(get(&[], &status, "GET", "/v1/status")?, Some(200));
    assert_eq!(get(&[], &status, "GET", "/v1/events")?, Some(200));
    assert_eq!(get(&[], &status, "POST", "/v1/reload")?, Some(404));
    assert_eq!(get(&[], &status, "POST", "/v1/uplinks/a/drain")?, Some(404));
    assert_eq!(get(&[], &control, "GET", "/v1/status")?, None, "not a member");
    assert_eq!(get(&["adm"], &control, "GET", "/v1/status")?, Some(200));
    // A change of the status socket's access closes its connections, also
    // one whose request is still arriving: it gets no answer.
    let status_path = status.display().to_string();
    let pending = || {
        t.agent_child(&[
            "hold",
            &status_path,
            "--count",
            "2",
            "--head",
            "GET /v1/status HTTP/1.1\\r\\n",
            "--seconds",
            "15",
        ])
    };
    let closed = |child| -> Result<()> {
        let list: Vec<Held> = t.agent_lines(child)?;
        assert!(
            list.iter()
                .all(|h| h.connected && h.received == 0 && h.closed_after.is_some_and(|s| s < 5.0)),
            "closed by the reload, before the 10 s deadline: {list:?}"
        );
        Ok(())
    };
    // Restricted to a group.
    let held = pending()?;
    f.reload_with(&config(&format!("{open}status_group = \"sys\"\n")))?;
    closed(held)?;
    let m = std::fs::metadata(&status)?;
    assert_eq!((m.mode() & 0o777, m.uid()), (0o660, 0));
    assert_eq!(get(&[], &status, "GET", "/v1/status")?, None);
    assert_eq!(get(&["sys"], &status, "GET", "/v1/status")?, Some(200));
    // Disabled.
    let held = pending()?;
    f.reload_with(&config("status_socket = \"\"\n"))?;
    closed(held)?;
    assert!(!status.exists(), "no status socket");
    assert_eq!(get(&["adm"], &control, "GET", "/v1/status")?, Some(200));
    // The lock.
    let m = std::fs::metadata(&f.lock)?;
    assert_eq!((m.mode() & 0o777, m.uid()), (0o600, 0));
    let lock = f.lock.display().to_string();
    let out = t.as_nobody(&[], "cat", &[&lock])?;
    assert!(!out.status.success(), "the lock is not readable by users");
    // A dry run serves nothing.
    f.stop()?;
    f.write_config(&config(&open))?;
    let out = succeeded(f.cli_config(&["run", "--dry-run"])?)?;
    let text = polywan::output_text(&out);
    assert!(
        !text.contains("listening") && !control.exists() && !status.exists(),
        "{text}"
    );
    Ok(())
}

/// Held connections: how many were refused at once, how many closed by the
/// 10 s deadline.
fn held(list: &[Held]) -> (usize, usize) {
    let refused = list
        .iter()
        .filter(|h| !h.connected || h.closed_after.is_some_and(|s| s < 1.0))
        .count();
    let deadline = list
        .iter()
        .filter(|h| h.closed_after.is_some_and(|s| (9.0..13.0).contains(&s)))
        .count();
    (refused, deadline)
}

/// AS-51, overload (FR-API-4, FR-MET-1, INV-8): 20 idle clients on the
/// status socket, 20 that send their head a byte a second on the metrics
/// listener and 8 that send a body a byte a second on the control socket:
/// each listener admits 16 and refuses the rest at once, the admitted ones
/// close at the 10 s deadline, and meanwhile control commands complete and
/// B's carrier loss is withdrawn within the FR-HEALTH-5 bound. Then a flood
/// of requests on the status socket and the metrics, and 16 long polls
/// that fill the status socket until an event ends them, leave routing and
/// the control socket unaffected.
#[test]
#[ignore = "needs root and network namespaces"]
fn as51_floods_and_slow_clients() -> Result<()> {
    let t = build();
    let f = t.start_polywan(&with("[metrics]\nlisten = \"127.0.0.1:9750\"\n"))?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    let status = f.status_socket().display().to_string();
    let control = f.control_socket().display().to_string();
    let metrics = "tcp:127.0.0.1:9750";
    let hold = |socket: &str, count: &str, head: &str, drip: &str| {
        t.agent_child(&[
            "hold",
            socket,
            "--count",
            count,
            "--head",
            head,
            "--drip",
            drip,
            "--seconds",
            "15",
        ])
    };
    let idle = hold(&status, "20", "", "")?;
    let slow_head = hold(metrics, "20", "GET /metrics HTTP/1.1\\r\\n", "XXXXXXXXXXXXXXXXXXXX")?;
    let slow_body = hold(
        &control,
        "8",
        "POST /v1/reload HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 100\\r\\n\\r\\n",
        "XXXXXXXXXXXXXXXXXXXX",
    )?;
    // The listeners accept in connection order: the held ones first.
    assert!(
        t.http(&f.status_socket(), "GET", "/v1/status").is_err(),
        "a 17th client is refused"
    );
    for drain in [true, false] {
        succeeded(f.drain("a", drain, false)?)?;
    }
    let lost = Instant::now();
    t.carrier_down(Uplink::B)?;
    wait_members(&t, Family::V4, &["wana"], Duration::from_secs(3))?;
    assert!(lost.elapsed() < Duration::from_secs(2), "routing unaffected");
    t.carrier_up(Uplink::B)?;
    for (child, admitted) in [(idle, 16), (slow_head, 16), (slow_body, 8)] {
        let list: Vec<Held> = t.agent_lines(child)?;
        assert_eq!(held(&list), (list.len() - admitted, admitted), "{list:?}");
    }
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    // Floods.
    let flood_status = t.agent_child(&["flood", &status, "/v1/status", "--count", "3000", "--parallel", "8"])?;
    let flood_metrics = t.agent_child(&["flood", metrics, "/metrics", "--count", "1000", "--parallel", "8"])?;
    let lost = Instant::now();
    t.carrier_down(Uplink::B)?;
    wait_members(&t, Family::V4, &["wana"], Duration::from_secs(3))?;
    assert!(
        lost.elapsed() < Duration::from_secs(2),
        "routing unaffected by the floods"
    );
    succeeded(f.drain("a", true, true)?)?;
    for child in [flood_status, flood_metrics] {
        let codes: Vec<BTreeMap<u16, usize>> = t.agent_lines(child)?;
        assert_eq!(codes[0].keys().collect::<Vec<_>>(), [&200], "{codes:?}");
    }
    succeeded(f.drain("a", false, false)?)?;
    t.carrier_up(Uplink::B)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    // Long polls fill the status socket until an event.
    let s = f.status()?;
    let instance = s["instance"].as_str().context("instance")?.to_owned();
    let latest = f.latest_event()?;
    let head = format!("GET /v1/events?instance={instance}&after={latest}&wait=30 HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n");
    let polls = t.agent_child(&["hold", &status, "--count", "16", "--head", &head, "--seconds", "40"])?;
    // Pending for a while before an event answers them.
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        t.http(&f.status_socket(), "GET", "/v1/status").is_err(),
        "the status socket is full"
    );
    assert_eq!(t.http(&f.control_socket(), "GET", "/v1/status")?.0, 200);
    succeeded(f.drain("a", true, false)?)?;
    // Answered by the drain's events, long before their 30 s wait.
    let list: Vec<Held> = t.agent_lines(polls)?;
    assert!(
        list.len() == 16
            && list
                .iter()
                .all(|h| h.closed_after.is_some_and(|s| (1.5..10.0).contains(&s))),
        "{list:?}"
    );
    Ok(())
}
