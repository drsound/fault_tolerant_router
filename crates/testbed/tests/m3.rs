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
        Ok(t.router()
            .sh("nft list table inet polywan")?
            .contains("meta l4proto udp"))
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
        "uplink b ipv4: up -> down (carrier_lost)",
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
        (b["state"].as_str(), b["reason"].as_str()),
        (Some("down"), Some("carrier_lost")),
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
