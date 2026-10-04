//! M3 acceptance scenarios (SPEC.md §14.3, §17): operations (API and CLI,
//! drain, policies, events, email, hooks, metrics, quality gates), with the
//! daemon under test (`POLYWAN_DAEMON_BIN`) in the router namespace.
//!
//! They need root and the harness tools: `tests/vm/run-suite.sh`.

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use anyhow::Result;
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
