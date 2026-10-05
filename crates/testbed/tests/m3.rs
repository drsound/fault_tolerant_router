//! M3 acceptance scenarios (SPEC.md §14.3, §17): operations (API and CLI,
//! drain, policies, events, email, hooks, metrics, quality gates), with the
//! daemon under test (`POLYWAN_DAEMON_BIN`) in the router namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use testbed::Outcome;
use testbed::plan::{Family, Node, TCP_PORT, TCP_PORT_HTTPS, Uplink};
use testbed::polywan::{self, HealthSpec};
use testbed::sendmail::{Call, Mode, Stub};
use testbed::traffic::tally;

#[macro_use]
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
    HealthSpec {
        text: format!("{}[health.quality]\n{gates}", HealthSpec::fast().text),
    }
}

per_family!(as06_deterministic_loss_violates_the_loss_gate);

/// AS-06: every third probe echo on A is lost, with `max_loss = 0.2`: A goes
/// down with reason `degraded` although its rounds pass reachability, and
/// comes back once the pattern stops, within `rise` rounds plus the
/// clearing of the window (FR-PROBE-5).
fn as06_deterministic_loss_violates_the_loss_gate(fam: Family) -> Result<()> {
    let t = build();
    // The gate is enabled once the topology forwards steadily (as AS-39).
    let f = t.start_polywan(&polywan::config(&ab(), &[fam], &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    std::thread::sleep(Duration::from_secs(2));
    let health = with_gates("max_loss = 0.2\n");
    f.write_config(&polywan::config(&ab(), &[fam], &health, "", ""))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    t.drop_probe_echoes(Uplink::A, 3)?;
    f.wait_log(
        &t,
        &format!("uplink=1 family={fam} from=Up to=Down reason=degraded"),
        1,
        Duration::from_secs(20),
    )?;
    wait_members(&t, fam, &["wanb"], Duration::from_secs(2))?;
    let log = f.log();
    assert!(log.contains(&format!("uplink=1 family={fam} violations=loss")), "{log}");
    assert!(!log.contains("reason=probe_failed"), "reachability kept passing: {log}");
    t.clear_provider_rules(Uplink::A)?;
    let cleared = Instant::now();
    f.wait_log(
        &t,
        &format!("uplink=1 family={fam} from=Down to=Up reason=probes_recovered"),
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
    let mut f = t.start_polywan(&polywan::config(&ab(), &[fam], &HealthSpec::fast(), "", ""))?;
    f.wait_installed(&t)?;
    wait_members(&t, fam, &["wana", "wanb"], Duration::from_secs(10))?;
    std::thread::sleep(Duration::from_secs(2));
    f.write_config(&config("100ms"))?;
    f.reload()?;
    f.wait_log(&t, "config_reloaded", 1, Duration::from_secs(5))?;
    // More than quality_min_samples samples and five RTTs and differences.
    std::thread::sleep(Duration::from_secs(10));
    let log = f.log();
    let gated = log.split("config_reloaded").nth(1).unwrap_or_default();
    assert!(
        !gated.contains("quality gate violated") && !gated.contains("reason=degraded"),
        "{log}"
    );
    f.write_config(&config("5ms"))?;
    f.reload()?;
    f.wait_log(
        &t,
        &format!("uplink=1 family={fam} from=Up to=Down reason=degraded"),
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
    f.wait_log(
        &t,
        &format!("uplink=1 family={fam} from=Down to=Up reason=probes_recovered"),
        1,
        Duration::from_secs(8),
    )?;
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
    let nft = t.router().sh("command -v nft")?.trim().to_owned();
    let slow = f.dir.join("nft-slow");
    let wrapper = t.exec_dir()?.join("nft");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nif [ -e {slow} ] && [ \"$1\" = -f ]; then sleep 5; fi\nexec {nft} \"$@\"\n",
            slow = slow.display()
        ),
    )?;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))?;
    let writes = f.dir.join("slow-writes");
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
    std::thread::sleep(Duration::from_millis(500));
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
    std::thread::sleep(Duration::from_millis(500));
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
    t.carrier_down(Uplink::B)?;
    f.wait_event(
        &t,
        "path_state_changed",
        // The reason is the first readiness loss observed (carrier,
        // address), which depends on the kernel.
        "uplink b ipv4: up -> down (",
        1,
        Duration::from_secs(5),
    )?;
    f.wait_event(
        &t,
        "active_set_changed",
        "ipv4 active set: [a, b] -> [a]",
        1,
        Duration::from_secs(5),
    )?;
    let s = f.status()?;
    let b = s["paths"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["uplink"] == "b"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        (b["state"].as_str(), b["ready"].as_bool()),
        (Some("down"), Some(false)),
        "{s}"
    );
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
/// flows continue, its probes keep it up and connections bound to its
/// address still use it; the last candidate needs `force`, after which new
/// connections are rejected; the drain survives a restart (INV-2, INV-5,
/// INV-6, FR-SEL-3, FR-SEL-4).
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
    let out = f.drain("a", true, false)?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    assert_eq!(
        balancing_members(&t, fam)?,
        ["wanb"],
        "applied when the command returns"
    );
    f.wait_event(&t, "uplink_drained", "uplink a drained", 1, Duration::from_secs(5))?;
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
    // AS-29: A's probes keep running; it stays up while drained.
    std::thread::sleep(Duration::from_secs(4));
    let s = f.status()?;
    let path_a = |s: &serde_json::Value| {
        s["paths"]
            .as_array()
            .and_then(|p| p.iter().find(|p| p["uplink"] == "a"))
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(path_a(&s)["state"], "up", "{s}");
    assert_eq!(s["uplinks"][0]["drained"], true, "{s}");
    flows_on_continuous(flows, &[Uplink::A, Uplink::B])?;
    // FR-SEL-4: the last candidate.
    let out = f.drain("b", true, false)?;
    assert!(
        !out.status.success() && polywan::output_text(&out).contains("last"),
        "{}",
        polywan::output_text(&out)
    );
    assert_eq!(balancing_members(&t, fam)?, ["wanb"]);
    let out = f.drain("b", true, true)?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    assert!(balancing_members(&t, fam)?.is_empty());
    assert_rejected(&t.connect_to(
        Node::Client,
        &servers(fam, 1, 5, TCP_PORT),
        5,
        false,
        Duration::from_secs(2),
    )?);
    let out = f.drain("b", false, false)?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    assert_eq!(balancing_members(&t, fam)?, ["wanb"]);
    // The drain survives a restart.
    f.stop()?;
    f.start(&t)?;
    f.wait_installed(&t)?;
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(balancing_members(&t, fam)?, ["wanb"], "still drained after the restart");
    assert_eq!(f.status()?["uplinks"][0]["drained"], true);
    let out = f.drain("a", false, false)?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    assert_eq!(balancing_members(&t, fam)?, ["wana", "wanb"]);
    f.stop()?;
    Ok(())
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
        f.wait_installed(&t)?;
        std::thread::sleep(Duration::from_secs(2));
        let expected: &[&str] = if drained { &["wanb"] } else { &["wana", "wanb"] };
        wait_members(&t, Family::V4, expected, Duration::from_secs(10))?;
        assert_eq!(f.status()?["uplinks"][0]["drained"], drained, "{crash}");
        if drained {
            let out = f.drain("a", false, false)?;
            assert!(out.status.success(), "{}", polywan::output_text(&out));
            wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
        }
    }
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
    f.write_config(&polywan::ipv4(&[
        polywan::UplinkSpec::new(Uplink::A, 1).weight(3),
        polywan::UplinkSpec::new(Uplink::B, 2),
    ]))?;
    let out = f.reload_cli()?;
    let text = polywan::output_text(&out);
    assert!(
        out.status.success() && text.contains("configuration reloaded"),
        "{text}"
    );
    assert!(f.status()?["generation"]["applied"].as_u64().unwrap_or(0) > before);
    // Validation errors go to the client, not to the public event.
    f.write_config(&polywan::ipv4(&ab()).replace("version = 2\n", "version = 2\nbogus_key = 1\n"))?;
    let out = f.reload_cli()?;
    let text = polywan::output_text(&out);
    assert!(!out.status.success() && text.contains("bogus_key"), "{text}");
    f.wait_event(&t, "reload_failed", "was not reloaded", 1, Duration::from_secs(5))?;
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
    f.write_config(&polywan::ipv4(&ab()[1..]))?;
    assert!(f.reload_cli()?.status.success());
    let reuse = polywan::ipv4(&ab()).replace("name = \"a\"", "name = \"fiber\"");
    f.write_config(&reuse)?;
    let out = f.reload_cli()?;
    assert!(
        !out.status.success() && polywan::output_text(&out).contains("forget-uplink a"),
        "{}",
        polywan::output_text(&out)
    );
    let out = f.cli_config(&["forget-uplink", "a", "--socket", &socket])?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    let out = f.reload_cli()?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
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
        Ok(gone(child))
    })?;
    f.wait_log(&t, "hook failed", 1, Duration::from_secs(5))?;
    assert!(f.log().contains("end=timed out"), "{}", f.log());
    t.carrier_up(Uplink::B)?;
    Ok(())
}

/// An IPv4 configuration over A and B with email through `sendmail`,
/// coalescing over `coalesce`, and `more` keys of `[notify.email]`.
fn with_email(sendmail: &std::path::Path, coalesce: &str, more: &str) -> String {
    with(&format!(
        "[notify]\ncoalesce = \"{coalesce}\"\n[notify.email]\nfrom = \"router@example.com\"\nto = [\"admin@example.com\", \"noc@example.org\"]\nsendmail = \"{}\"\n{more}",
        sendmail.display()
    ))
}

fn message_id(c: &Call) -> Option<String> {
    c.message.as_ref()?.header("Message-ID").map(str::to_owned)
}

fn subject(c: &Call) -> String {
    c.message
        .as_ref()
        .and_then(|m| m.header("Subject"))
        .unwrap_or_default()
        .to_owned()
}

/// Whether a process has ended: gone, or a zombie (an orphan whose init
/// does not reap, as in a virtme-ng guest).
fn gone(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| s.rsplit_once(") ").map(|(_, rest)| rest.starts_with('Z')))
        .is_none_or(|zombie| zombie)
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
    let mut f = t.prepare_polywan(&with_email(&stub.path, "1s", ""))?;
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
    assert!(subject(first).starts_with("PolyWAN notification"), "{}", m.raw);
    let mut toggle = {
        let mut drained = false;
        move |f: &polywan::Polywan| -> Result<()> {
            drained = !drained;
            let out = f.drain("a", drained, false)?;
            anyhow::ensure!(out.status.success(), "{}", polywan::output_text(&out));
            Ok(())
        }
    };
    // Exit status 75: three retries, 0.5, 2.5 and 7.5 s after each failure.
    stub.set(Mode::Exit(75))?;
    let before = stub.calls()?.len();
    toggle(&f)?;
    let calls = stub.wait_calls(&t, before + 4, Duration::from_secs(20))?;
    let tries = &calls[before..before + 4];
    let id = message_id(&tries[0]).context("Message-ID")?;
    assert!(tries.iter().all(|c| message_id(c).as_ref() == Some(&id)), "{tries:?}");
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
        stub.set(mode)?;
        let before = stub.calls()?.len();
        let submitted = f.log().matches("email submitted").count();
        toggle(&f)?;
        stub.wait_calls(&t, before + 1, Duration::from_secs(10))?;
        stub.set(Mode::Accept)?;
        let calls = stub.wait_calls(&t, before + 2, Duration::from_secs(10))?;
        assert_eq!(message_id(&calls[before]), message_id(&calls[before + 1]));
        f.wait_log(&t, "email submitted", submitted + 1, Duration::from_secs(5))?;
        assert_eq!(f.log().matches(needle).count(), n, "{}", f.log());
    }
    assert!(f.log().contains("xxxx [truncated]"), "bounded standard error");
    // Hanging with a child (A undrained by the toggle), then never reading:
    // killed at the deadline, and routing meets its deadlines meanwhile.
    for mode in [Mode::Hang, Mode::NoRead] {
        stub.set(mode)?;
        let before = stub.calls()?.len();
        let timeouts = f.log().matches("timed out").count();
        toggle(&f)?;
        let calls = stub.wait_calls(&t, before + 1, Duration::from_secs(10))?;
        let pid = calls[before].pid;
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
        stub.set(Mode::Accept)?;
        t.wait_for("the timeout", Duration::from_secs(5), || {
            Ok(f.log().matches("timed out").count() > timeouts)
        })?;
        t.wait_for("the group killed", Duration::from_secs(5), || {
            Ok(gone(pid) && stub.child().is_none_or(gone))
        })?;
        // The retry (after the batch of B's carrier loss, due first), with
        // the same Message-ID when the first attempt read it.
        let calls = stub.wait_calls(&t, before + 2, Duration::from_secs(10))?;
        if let Some(id) = message_id(&calls[before]) {
            t.wait_for("the retry", Duration::from_secs(10), || {
                Ok(stub.calls()?[before + 1..]
                    .iter()
                    .any(|c| message_id(c).as_ref() == Some(&id)))
            })?;
        } else {
            assert!(calls[before + 1].message.is_some(), "the retry was accepted");
        }
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
    let mut f = t.prepare_polywan(&with_email(&old.path, "1s", ""))?;
    // Retries 2 s after a failure; the deadline 2 s.
    f.set_env("POLYWAN_TEST_MAIL_TIMES", "2000,2000");
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    old.wait_calls(&t, 1, Duration::from_secs(10))?;
    old.set(Mode::Hang)?;
    let out = f.drain("a", true, false)?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    let calls = old.wait_calls(&t, 2, Duration::from_secs(10))?;
    let pid = calls[1].pid;
    let id = t
        .wait_for("the running submission's message", Duration::from_secs(5), || {
            Ok(old.calls()?.get(1).and_then(message_id).is_some())
        })
        .and_then(|_| old.calls()?.get(1).and_then(message_id).context("Message-ID"))?;
    // While it runs, the path and the recipients change.
    let changed = with(&format!(
        "[notify]\ncoalesce = \"1s\"\n[notify.email]\nfrom = \"router@example.com\"\nto = [\"ops@example.net\"]\nsendmail = \"{}\"\n",
        new.path.display()
    ));
    f.write_config(&changed)?;
    let out = f.reload_cli()?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    // It ends at its deadline, with the old path; the retry takes the new
    // path and recipients, with the same Message-ID.
    t.wait_for("the old submission's deadline", Duration::from_secs(5), || {
        Ok(gone(pid))
    })?;
    let is_retry = |c: &Call| message_id(c).as_ref() == Some(&id);
    t.wait_for("the retry through the new path", Duration::from_secs(10), || {
        Ok(new.calls()?.iter().any(is_retry))
    })?;
    let retry = new.calls()?.into_iter().find(is_retry).context("the retry")?;
    assert_eq!(retry.args, ["-i", "-f", "router@example.com", "ops@example.net"]);
    let m = retry.message.as_ref().context("message")?;
    assert_eq!(m.header("To"), Some("ops@example.net"));
    assert!(m.body.contains(" uplink_drained a: "), "{}", m.body);
    assert_eq!(old.calls()?.len(), 2, "nothing more through the old path");
    // A failing submission, then email removed: the retry is discarded.
    new.set(Mode::Exit(75))?;
    let before = new.calls()?.len();
    let out = f.drain("a", false, false)?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    new.wait_calls(&t, before + 1, Duration::from_secs(10))?;
    f.write_config(&polywan::ipv4(&ab()))?;
    let out = f.reload_cli()?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
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
    let delay = out.join("delay");
    std::fs::write(&delay, "11")?;
    let record = format!("cat > {}/stdin", out.display());
    let sleeper = format!("sleep $(cat {})", delay.display());
    // Filters that the tests bypass; hooks as root, to write the record.
    let config = with(&format!(
        "[notify]\ncoalesce = \"1s\"\nhook_user = \"root\"\n[notify.email]\nfrom = \"router@example.com\"\nto = [\"admin@example.com\"]\nsendmail = \"{}\"\n[[notify.hook]]\ncommand = [\"/bin/sh\", \"-c\", {record:?}]\nevents = [\"daemon_stopping\"]\n[[notify.hook]]\ncommand = [\"/bin/sh\", \"-c\", {sleeper:?}]\nevents = [\"daemon_stopping\"]\ntimeout = \"15s\"\n",
        stub.path.display()
    ));
    let mut f = t.prepare_polywan(&config)?;
    f.set_env("POLYWAN_TEST_MAIL_TIMES", "500,5000");
    f.start(&t)?;
    f.wait_installed(&t)?;
    stub.wait_calls(&t, 1, Duration::from_secs(10))?;
    // A test outlasting the ordinary deadline, and a second one meanwhile.
    let socket = f.control_socket().display().to_string();
    let bin = polywan::daemon_bin()?;
    let started = Instant::now();
    let (long, second) = std::thread::scope(|s| {
        let h = s.spawn(|| {
            std::process::Command::new(&bin)
                .args(["notify-test", "--socket", &socket])
                .output()
        });
        std::thread::sleep(Duration::from_secs(2));
        let second = std::process::Command::new(&bin)
            .args(["notify-test", "--socket", &socket])
            .output();
        (h.join().expect("the long test"), second)
    });
    let (long, second) = (long?, second?);
    let elapsed = started.elapsed();
    let text = polywan::output_text(&long);
    assert!(long.status.success(), "{text}");
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
    stub.set(Mode::Exit(75))?;
    let before = stub.calls()?.len();
    let failed = f.notify_test()?;
    let text = polywan::output_text(&failed);
    assert!(!failed.status.success(), "{text}");
    assert!(text.contains("email: failed, exit status 75"), "{text}");
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(stub.calls()?.len(), before + 1, "tests are not retried");
    // Offline: refused while the daemon holds the lock, then run.
    stub.set(Mode::Accept)?;
    let refused = f.cli_config(&["notify-test", "--offline"])?;
    let text = polywan::output_text(&refused);
    assert!(
        !refused.status.success() && text.contains("without --offline"),
        "{text}"
    );
    f.stop()?;
    let before = stub.calls()?.len();
    let offline = f.cli_config(&["notify-test", "--offline"])?;
    let text = polywan::output_text(&offline);
    assert!(offline.status.success(), "{text}");
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
/// Unicode line and a lone-dot line, and neither flush the batch nor take
/// or reset the hourly allowance (FR-MAIL-4).
#[test]
#[ignore = "needs root and network namespaces"]
fn as07_flapping_coalescing_and_the_hourly_limit() -> Result<()> {
    let t = build();
    let stub = Stub::new(&t, "sendmail")?;
    let health = HealthSpec {
        text: HealthSpec::fast().text + "rise = 5\n",
    };
    let config = |max: u32| {
        polywan::config(
            &ab(),
            &[Family::V4],
            &health,
            "",
            &format!(
                "[notify]\ncoalesce = \"2s\"\n[notify.email]\nfrom = \"router@example.com\"\nto = [\"admin@example.com\"]\nsendmail = \"{}\"\nmax_per_hour = {max}\n",
                stub.path.display()
            ),
        )
    };
    let mut f = t.prepare_polywan(&config(1000))?;
    f.set_env("POLYWAN_TEST_MAIL_TIMES", "200,5000");
    f.start(&t)?;
    f.wait_installed(&t)?;
    wait_members(&t, Family::V4, &["wana", "wanb"], Duration::from_secs(10))?;
    stub.wait_calls(&t, 1, Duration::from_secs(10))?;
    let start = f.events()?.last().map_or(0, |e| e.0);
    for i in 0..15 {
        t.carrier_down(Uplink::B)?;
        if i == 0 {
            // B's loss opened a batch: the test goes out at once.
            let out = f.notify_test()?;
            assert!(out.status.success(), "{}", polywan::output_text(&out));
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
    let selected = ["path_state_changed", "active_set_changed"];
    t.wait_for("the emails of the flapping", Duration::from_secs(10), || {
        let bodies: String = stub
            .calls()?
            .iter()
            .filter_map(|c| Some(c.message.as_ref()?.body.clone()))
            .collect();
        Ok(f.events()?
            .iter()
            .filter(|(seq, kind, _)| *seq > start && selected.contains(&kind.as_str()))
            .all(|(_, kind, l)| bodies.contains(&format!("{} {kind}", l.split(' ').next().unwrap_or("")))))
    })?;
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
    f.write_config(&config(3))?;
    let out = f.reload_cli()?;
    assert!(out.status.success(), "{}", polywan::output_text(&out));
    let from = std::time::SystemTime::now();
    let mut drained = false;
    for i in 0..30 {
        drained = !drained;
        f.drain("a", drained, false)?;
        if i == 12 || i == 22 {
            // During the suppression.
            let out = f.notify_test()?;
            assert!(out.status.success(), "{}", polywan::output_text(&out));
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
    let s = subject(c);
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
