use std::time::Duration;

use super::*;

/// The example of SPEC.md §11.3, with every feature enabled.
const SPEC_EXAMPLE: &str = r#"version = 2

[routing]
all_down_policy = "ready"

[[downlink]]
interface = "lan0"

[[downlink]]
interface = "dmz0"

[[uplink]]
id = 1
name = "fiber"
description = "Fiber 1 Gbps (provider A)"
interface = "wan0"
priority = 1
weight = 10

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"

[[uplink]]
id = 2
name = "fwa5g"
description = "5G FWA (provider B, CGNAT)"
interface = "wan1"
priority = 1
weight = 3

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"

[[uplink]]
id = 3
name = "metered"
description = "Metered LTE, last resort"
interface = "ppp0"
priority = 2

[uplink.ipv4]
nat = "masquerade"

[health]
interval = "5s"
timeout = "1s"
attempts = 2
required_reachable = 2

[health.ipv4]
targets = ["icmp:1.1.1.1", "icmp:8.8.8.8", "icmp:9.9.9.9", "icmp:208.67.222.222"]

[health.ipv6]
targets = ["icmp:2606:4700:4700::1111", "icmp:2001:4860:4860::8888", "icmp:2620:fe::fe"]

[[policy]]
name = "smtp-via-fiber"
family = "ipv4"
source = "192.168.1.25/32"
protocol = "tcp"
destination_port = 25
uplink = "fiber"
fallback = "block"

[notify.email]
from = "router@example.com"
to = ["admin@example.com"]
# The mail system (for example msmtp) is configured separately; test it
# through the running daemon with `polywan notify-test`.
sendmail = "/usr/sbin/sendmail"

[[notify.hook]]
command = ["/usr/local/bin/polywan-to-ntfy"]
events = ["path_state_changed", "active_set_changed"]

[api]
# Status and event history are readable by every local user by default.
# status_group = "monitoring"   # restrict them to an existing group
# status_socket = ""            # or disable the status socket

[metrics]
listen = "127.0.0.1:9750"
"#;

const MINIMAL: &str = r#"version = 2
[[downlink]]
interface = "lan"
[[uplink]]
id = 1
name = "a"
interface = "wana"
priority = 1
[uplink.ipv4]
"#;

fn errors(text: &str) -> Vec<Diagnostic> {
    parse(text).expect_err("configuration should be rejected")
}

fn has(diags: &[Diagnostic], key: &str, needle: &str) -> bool {
    diags.iter().any(|d| d.key == key && d.message.contains(needle))
}

#[test]
fn spec_example_is_valid() {
    let c = parse(SPEC_EXAMPLE).unwrap();
    assert_eq!(c.downlinks, ["lan0", "dmz0"]);
    assert_eq!(c.uplinks.len(), 3);
    let fiber = &c.uplinks[0];
    assert_eq!((fiber.id.get(), fiber.weight, fiber.priority), (1, 10, Some(1)));
    assert_eq!(fiber.ipv6.as_ref().unwrap().nat, Nat::Masquerade);
    assert_eq!(c.uplinks[2].weight, 1);
    assert!(c.uplinks[2].ipv6.is_none());
    assert_eq!(c.policies[0].destination_port, Some((25, 25)));
    assert_eq!(c.policies[0].source.unwrap().to_string(), "192.168.1.25/32");
    let email = c.notify.email.as_ref().unwrap();
    assert_eq!(email.max_per_hour, 20);
    assert_eq!(email.sendmail, PathBuf::from("/usr/sbin/sendmail"));
    assert_eq!(c.metrics_listen.unwrap().port(), 9750);
    assert!(c.manages(Family::V6));
    assert_eq!(c.unsupported_features().len(), 3, "email, hooks, metrics");
}

#[test]
fn digest_is_the_sha256_of_the_text() {
    assert_eq!(
        digest(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(parse(MINIMAL).unwrap().digest, digest(MINIMAL));
}

#[test]
fn generated_example_is_valid_and_supported() {
    let c = parse(EXAMPLE).unwrap();
    assert_eq!(c.uplinks.len(), 3);
    assert!(c.manages(Family::V6));
    assert!(c.unsupported_features().is_empty());
}

#[test]
fn defaults_follow_the_schema() {
    let c = parse(MINIMAL).unwrap();
    let r = &c.routing;
    assert_eq!(
        (r.table_base, r.rule_priority_base, r.route_protocol),
        (1000, 1000, 249)
    );
    assert_eq!(r.fwmark_mask, FwMask::DEFAULT);
    assert_eq!(r.all_down_policy, AllDownPolicy::Ready);
    assert_eq!(r.discovery_tables, [254]);
    assert!(r.manage_sysctls);
    assert_eq!(r.reconcile_interval, Duration::from_secs(60));
    assert_eq!(r.on_shutdown, OnShutdown::Keep);
    assert_eq!(c.firewall.mode, FirewallMode::Managed);
    assert_eq!(c.firewall.nat_priority, 100);
    assert_eq!(c.firewall.nft_path, PathBuf::from("/usr/sbin/nft"));
    let u = &c.uplinks[0];
    assert_eq!(u.description, "a");
    let p = u.ipv4.as_ref().unwrap();
    assert_eq!(
        (p.source, p.gateway, p.gateway_onlink, p.nat),
        (AutoOr::Auto, AutoOr::Auto, false, Nat::Masquerade)
    );
    let h = &u.health;
    assert_eq!(
        (h.interval, h.timeout),
        (Duration::from_secs(5), Duration::from_secs(1))
    );
    assert_eq!((h.attempts, h.required_reachable, h.fall, h.rise), (2, 2, 2, 3));
    assert_eq!(h.targets_v4.len(), 4);
    assert_eq!(h.targets_v6.len(), 3);
    assert_eq!((h.quality_window, h.quality_min_samples), (6, 10));
    assert_eq!(c.state_dir, PathBuf::from("/var/lib/polywan"));
    assert_eq!(c.api.socket, PathBuf::from("/run/polywan/api.sock"));
    assert_eq!(c.api.group, "polywan");
    assert_eq!(c.api.status_socket, Some(PathBuf::from("/run/polywan/status.sock")));
    assert_eq!(c.api.status_group, None);
    assert_eq!(c.notify.hook_user, "nobody");
}

#[test]
fn version_must_come_first_and_be_two() {
    let d = errors("[[downlink]]\ninterface = \"lan\"\nversion = 2\n");
    assert_eq!((d[0].line, d[0].key.as_str()), (Some(1), "version"));
    let d = errors("# comment\n\nversion = 1\n");
    assert_eq!(d[0].line, Some(3));
    assert!(d[0].message.contains("unsupported configuration version 1"));
    assert!(parse("version = 2 # comment\n[[downlink]]\ninterface=\"l\"\n").is_err_and(|d| d[0].key != "version"));
}

#[test]
fn unknown_keys_are_reported_with_their_line() {
    let text = MINIMAL.replace("priority = 1", "priority = 1\nwieght = 3");
    let d = errors(&text);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].line, Some(9));
    assert!(d[0].message.contains("wieght"), "{}", d[0].message);
}

#[test]
fn errors_are_formatted_with_file_line_and_key() {
    let e = ConfigError {
        file: "/etc/x.toml".into(),
        diagnostics: vec![Diagnostic {
            line: Some(4),
            key: "uplink[0].weight".into(),
            message: "bad".into(),
        }],
    };
    assert_eq!(e.to_string(), "/etc/x.toml:4: uplink[0].weight: bad");
}

#[test]
fn structural_ranges_are_checked() {
    let with = |s: &str| errors(&format!("version = 2\n[routing]\n{s}\n{}", &MINIMAL[12..]));
    assert!(has(
        &with("table_base = 100"),
        "routing.table_base",
        "reserved tables 253–255"
    ));
    assert!(has(&with("table_base = 0"), "routing.table_base", "out of range"));
    assert!(has(
        &with("rule_priority_base = 32067"),
        "routing.rule_priority_base",
        "out of range"
    ));
    assert!(has(
        &with("route_protocol = 4"),
        "routing.route_protocol",
        "out of range"
    ));
    assert!(has(
        &with("fwmark_mask = 0x0f0f"),
        "routing.fwmark_mask",
        "8 contiguous"
    ));
    assert!(has(&with("fwmark_mask = 0x1ff"), "routing.fwmark_mask", "8 contiguous"));
    assert!(has(
        &with("discovery_tables = [\"main\", 1010]"),
        "routing.discovery_tables",
        "PolyWAN's own range"
    ));
    assert!(has(
        &with("reconcile_interval = \"5s\""),
        "routing.reconcile_interval",
        "out of range"
    ));
    assert!(has(&with("all_down_policy = \"never\""), "", "unknown variant"));
    let c = parse(&format!(
        "version = 2\n[routing]\nfwmark_mask = 0xff000000\ntable_base = 256\nrule_priority_base = 31066\n{}",
        &MINIMAL[12..]
    ))
    .unwrap();
    assert_eq!(c.routing.fwmark_mask.shift(), 24);
}

#[test]
fn uplink_identity_is_checked() {
    let two = format!(
        "{MINIMAL}[[uplink]]\nid = 1\nname = \"a\"\ninterface = \"lan\"\n[uplink.ipv4]\n[[uplink]]\nid = 64\nname = \"Bad\"\ninterface = \"wanc\"\n"
    );
    let d = errors(&two);
    assert!(has(&d, "uplink[1].id", "used by another uplink"));
    assert!(has(&d, "uplink[1].name", "used by another uplink"));
    assert!(has(&d, "uplink[1].interface", "already used"));
    assert!(has(&d, "uplink[2].id", "out of range"));
    assert!(has(&d, "uplink[2].name", "must match"));
    assert!(has(&d, "uplink[2]", "at least one of"));
}

#[test]
fn path_settings_are_checked() {
    let path = |body: &str| errors(&MINIMAL.replace("[uplink.ipv4]\n", &format!("[uplink.ipv4]\n{body}\n")));
    assert!(has(
        &path("source = \"2001:db8::1\""),
        "uplink[0].ipv4.source",
        "not an ipv4 address"
    ));
    assert!(has(&path("gateway = \"bogus\""), "uplink[0].ipv4.gateway", "neither"));
    assert!(has(
        &path("gateway_onlink = true"),
        "uplink[0].ipv4.gateway_onlink",
        "static gateway"
    ));
    assert!(has(&path("nat = \"snat\""), "uplink[0].ipv4.source", "static source"));
    let v6 = errors(&MINIMAL.replace("[uplink.ipv4]\n", "[uplink.ipv6]\n"));
    assert!(has(&v6, "uplink[0].ipv6.nat", "explicitly"));
    // Private and shared addresses are normal uplink sources.
    let ok = MINIMAL.replace(
        "[uplink.ipv4]\n",
        "[uplink.ipv4]\nsource = \"100.64.0.5\"\nnat = \"snat\"\n",
    );
    assert!(parse(&ok).is_ok());
}

#[test]
fn health_constraints_are_checked() {
    let health = |body: &str| errors(&format!("{MINIMAL}[health]\n{body}\n"));
    assert!(has(
        &health("timeout = \"3s\""),
        "health.timeout",
        "shorter than interval"
    ));
    assert!(has(&health("interval = \"500ms\""), "health.interval", "out of range"));
    assert!(has(
        &health("required_reachable = 5"),
        "health.required_reachable",
        "exceeds the 4 distinct"
    ));
    assert!(has(
        &health(
            "[health.ipv4]\ntargets = [\"icmp:10.0.0.1\", \"tcp:1.1.1.1:0\", \"icmp:1.1.1.1\", \"icmp:1.1.1.1\", \"icmp:::1\", \"ping:1.1.1.1\"]"
        ),
        "health.ipv4.targets",
        "not global unicast"
    ));
    let d = health(
        "[health.ipv4]\ntargets = [\"tcp:1.1.1.1:0\", \"icmp:1.1.1.1\", \"icmp:1.1.1.1\", \"icmp:2620:fe::fe\", \"ping:1.1.1.1\"]",
    );
    assert!(has(&d, "health.ipv4.targets", "port 0"));
    assert!(has(&d, "health.ipv4.targets", "more than once"));
    assert!(has(&d, "health.ipv4.targets", "not an ipv4 target"));
    assert!(has(&d, "health.ipv4.targets", "is not a target"));
    // TCP and ICMP targets on the same address count once for
    // required_reachable.
    assert!(has(
        &health("[health.ipv4]\ntargets = [\"icmp:1.1.1.1\", \"tcp:1.1.1.1:443\"]"),
        "health.required_reachable",
        "exceeds the 1 distinct"
    ));
}

#[test]
fn per_uplink_health_overrides_the_global_settings() {
    let text = format!(
        "{}[uplink.health]\ninterval = \"10s\"\n[uplink.health.ipv4]\ntargets = [\"tcp:[2620:fe::fe]:53\"]\n[health]\ninterval = \"7s\"\nfall = 4\n",
        MINIMAL
    );
    assert!(has(
        &errors(&text),
        "uplink[0].health.ipv4.targets",
        "not an ipv4 target"
    ));
    let text = text.replace("tcp:[2620:fe::fe]:53", "tcp:9.9.9.9:53\", \"icmp:1.1.1.1");
    let c = parse(&text).unwrap();
    let h = &c.uplinks[0].health;
    assert_eq!((h.interval, h.fall), (Duration::from_secs(10), 4));
    assert_eq!(
        h.targets_v4.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["tcp:9.9.9.9:53", "icmp:1.1.1.1"]
    );
}

#[test]
fn quality_window_capacity_is_checked() {
    let text =
        format!("{MINIMAL}[health]\nquality_window = 2\nquality_min_samples = 9\n[health.quality]\nmax_loss = 0.2\n");
    assert!(has(
        &errors(&text),
        "health.quality_min_samples",
        "targets × quality_window (8)"
    ));
    let text = text.replace("max_loss = 0.2", "max_loss = 1.5");
    assert!(has(&errors(&text), "health.quality.max_loss", "out of range"));
}

#[test]
fn policies_are_checked() {
    let pol = |body: &str| errors(&format!("{MINIMAL}[[policy]]\nname = \"p\"\n{body}\n"));
    assert!(has(
        &pol("family = \"ipv6\"\nuplink = \"a\""),
        "policy[0].uplink",
        "does not enable ipv6"
    ));
    assert!(has(
        &pol("family = \"ipv4\"\nuplink = \"zz\""),
        "policy[0].uplink",
        "no uplink"
    ));
    assert!(has(
        &pol("family = \"ipv4\"\nuplink = \"a\"\ninput_interface = \"wana\""),
        "policy[0].input_interface",
        "not a downlink"
    ));
    assert!(has(
        &pol("family = \"ipv4\"\nuplink = \"a\"\nprotocol = \"icmpv6\""),
        "policy[0].protocol",
        "IPv6 only"
    ));
    assert!(has(
        &pol("family = \"ipv4\"\nuplink = \"a\"\ndestination_port = 25"),
        "policy[0].destination_port",
        "require protocol"
    ));
    assert!(has(
        &pol("family = \"ipv4\"\nuplink = \"a\"\nprotocol = \"udp\"\ndestination_port = \"9-3\""),
        "policy[0].destination_port",
        "A ≤ B"
    ));
    assert!(has(
        &pol("family = \"ipv4\"\nuplink = \"a\"\ndestination = \"2001:db8::/32\""),
        "policy[0].destination",
        "not an ipv4 prefix"
    ));
    let ok = format!(
        "{MINIMAL}[[policy]]\nname = \"p\"\nfamily = \"ipv4\"\nuplink = \"a\"\nprotocol = \"udp\"\ndestination_port = \"5000-5100\"\ndestination = \"192.0.2.77/24\"\n"
    );
    let c = parse(&ok).unwrap();
    assert_eq!(c.policies[0].destination_port, Some((5000, 5100)));
    assert_eq!(c.policies[0].destination.unwrap().to_string(), "192.0.2.0/24");
    assert_eq!(c.policies[0].fallback, Fallback::Balance);
}

#[test]
fn interfaces_and_downlinks_are_checked() {
    let d = errors("version = 2\n[[uplink]]\nid = 1\nname = \"a\"\ninterface = \"wan a\"\n[uplink.ipv4]\n");
    assert!(has(&d, "downlink", "at least one"));
    assert!(has(&d, "uplink[0].interface", "not a valid interface name"));
    let d = errors(&MINIMAL.replace("interface = \"lan\"", "interface = \"a-very-long-interface\""));
    assert!(has(&d, "downlink[0].interface", "not a valid interface name"));
}

#[test]
fn hooks_are_checked() {
    let d = errors(&format!(
        "{MINIMAL}[[notify.hook]]\ncommand = [\"ntfy\"]\nevents = [\"path_up\"]\n"
    ));
    assert!(has(&d, "notify.hook[0].command", "absolute"));
    assert!(has(&d, "notify.hook[0].events", "unknown event type"));
    let d = errors(&format!(
        "{MINIMAL}[[notify.hook]]\ncommand = [\"/bin/true\"]\nevents = []\n"
    ));
    assert!(has(&d, "notify.hook[0].events", "must not be empty"));
}

#[test]
fn hook_settings_are_checked() {
    let d = errors(&format!(
        "{MINIMAL}[notify]\nhook_user = \"-x\"\n[[notify.hook]]\ncommand = [\"/bin/true\"]\ntimeout = \"0s\"\n"
    ));
    assert!(has(&d, "notify.hook[0].timeout", "greater than zero"));
    assert!(has(&d, "notify.hook_user", "not a valid user"));
}

const EMAIL: &str = "[notify.email]\nfrom = \"router@example.com\"\nto = [\"admin@example.com\"]\n";

#[test]
fn email_settings_follow_the_sendmail_interface() {
    let c = parse(&format!("{MINIMAL}{EMAIL}")).unwrap();
    let e = c.notify.email.unwrap();
    assert_eq!((e.from.as_str(), e.to.len()), ("router@example.com", 1));
    assert_eq!(e.sendmail, PathBuf::from("/usr/sbin/sendmail"));
    assert_eq!(e.events.len(), 10);
    assert!(!e.events.iter().any(|e| e == "path_address_changed"));
    let c = parse(&format!(
        "{MINIMAL}{EMAIL}events = [\"path_state_changed\", \"apply_failed\", \"path_state_changed\"]\n"
    ))
    .unwrap();
    assert_eq!(c.notify.email.unwrap().events, ["path_state_changed", "apply_failed"]);
    let d = errors(&format!("{MINIMAL}{EMAIL}events = []\n"));
    assert!(has(&d, "notify.email.events", "must not be empty"));
    let d = errors(&format!("{MINIMAL}{EMAIL}events = [\"notify_test\"]\n"));
    assert!(has(&d, "notify.email.events", "unknown event type"));
    // The SMTP keys of earlier drafts are unknown keys (AS-20).
    for key in [
        "host = \"smtp.example.com\"",
        "port = 587",
        "security = \"starttls\"",
        "username = \"u\"",
        "password_file = \"/etc/p\"",
    ] {
        let d = errors(&format!("{MINIMAL}{EMAIL}{key}\n"));
        assert!(d[0].message.contains("unknown field"), "{key}: {d:?}");
    }
    let d = errors(&format!("{MINIMAL}{EMAIL}sendmail = \"sendmail -t\"\n"));
    assert!(has(&d, "notify.email.sendmail", "absolute path"));
    let d = errors(&format!(
        "{MINIMAL}[notify.email]\nfrom = \"Router <r@example.com>\"\nto = []\n"
    ));
    assert!(has(&d, "notify.email.from", "not a single address"));
    assert!(has(&d, "notify.email.to", "at least one"));
}

#[test]
fn mailboxes_are_single_ascii_addresses() {
    for ok in [
        "admin@example.com",
        "root@localhost",
        "first.last+tag@mail.example.org",
        "x_y-z@a-b.example",
        "o'brien@example.ie",
    ] {
        assert!(validate::check_mailbox(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "admin",
        "Admin <admin@example.com>",
        "\"quoted\"@example.com",
        "a@example.com, b@example.com",
        "a@example.com\r\nBcc: x@example.com",
        "a@example.com\n",
        "a b@example.com",
        "-oQ/tmp@example.com",
        "/var/mail/x@example.com",
        "|/bin/sh@example.com",
        "a..b@example.com",
        ".a@example.com",
        "a.@example.com",
        "a@-example.com",
        "a@example-.com",
        "a@example..com",
        "a@example.com.",
        "a@[192.0.2.1]",
        "a(comment)@example.com",
        "ü@example.com",
        "a@exämple.com",
        "a@b@example.com",
    ] {
        assert!(validate::check_mailbox(bad).is_err(), "{bad:?}");
    }
    let long = format!("{}@example.com", "a".repeat(65));
    assert!(validate::check_mailbox(&long).is_err());
}

#[test]
fn api_sockets_are_checked() {
    let api = |body: &str| parse(&format!("{MINIMAL}[api]\n{body}\n"));
    let c = api("status_socket = \"\"\nstatus_group = \"monitoring\"").unwrap();
    assert_eq!(c.api.status_socket, None);
    let c = api("socket = \"/run/x/c.sock\"\nstatus_socket = \"/run/x/s.sock\"\ngroup = \"adm\"").unwrap();
    assert_eq!(
        (
            c.api.socket.to_str(),
            c.api.status_socket.unwrap().to_str(),
            c.api.group.as_str()
        ),
        (Some("/run/x/c.sock"), Some("/run/x/s.sock"), "adm")
    );
    let d = api("socket = \"/run/x/a.sock\"\nstatus_socket = \"/run//x/a.sock\"").unwrap_err();
    assert!(has(&d, "api.status_socket", "distinct"));
    let d = api("socket = \"run/a.sock\"\nstatus_socket = \"/run/x/../s.sock\"").unwrap_err();
    assert!(has(&d, "api.socket", "absolute"));
    assert!(has(&d, "api.status_socket", "components"));
    let d = api("socket = \"/run/x/\"").unwrap_err();
    assert!(has(&d, "api.socket", "must name a file"));
    let long = format!("/run/{}/a.sock", "d".repeat(80));
    let d = api(&format!("socket = \"{long}\"")).unwrap_err();
    assert!(has(&d, "api.socket", "too long"));
    let d = api("group = \"a:b\"\nstatus_group = \"\"").unwrap_err();
    assert!(has(&d, "api.group", "not a valid"));
    assert!(has(&d, "api.status_group", "not a valid"));
    let d = api("sockets = \"/run/a\"").unwrap_err();
    assert!(d[0].message.contains("unknown field"));
}
