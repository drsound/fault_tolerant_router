//! nftables ruleset generator (SPEC.md §4.7, §6, §7). The ruleset depends on
//! the configuration only (FR-FW-5); the managed mode applies exactly the
//! text that `export-nft` prints (FR-FW-3).

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::config::{AutoOr, Config, Nat};
use crate::model::{Family, FieldValue, FwMask, UplinkId};

/// Name of the managed table (`inet`, FR-FW-1).
pub const TABLE: &str = "fault_tolerant_router";

/// Priority of the marking chains (§4.7).
pub const MARK_PRIORITY: i32 = -150;

fn nfproto(family: Family) -> &'static str {
    match family {
        Family::V4 => "ipv4",
        Family::V6 => "ipv6",
    }
}

/// Quotes a configuration-derived string. Interface names are validated
/// (`config::validate::check_interface_name`) and contain no quote or
/// backslash; quoting keeps names such as `dnat` from being parsed as
/// keywords (IMPL-3).
fn quote(s: &str) -> String {
    debug_assert!(!s.contains(['"', '\\']));
    format!("\"{s}\"")
}

struct Gen {
    mask: FwMask,
    out: String,
}

impl Gen {
    fn line(&mut self, indent: usize, text: &str) {
        let _ = writeln!(self.out, "{:indent$}{text}", "", indent = indent * 2);
    }

    fn hex(v: u32) -> String {
        format!("{v:#010x}")
    }

    fn mask(&self) -> String {
        Self::hex(self.mask.mask())
    }

    fn not_mask(&self) -> String {
        Self::hex(!self.mask.mask())
    }

    fn enc(&self, v: FieldValue) -> String {
        Self::hex(self.mask.encode(v))
    }

    /// Constant-only write of the FTR field (FR-MARK-3).
    fn set(&self, what: &str, v: FieldValue) -> String {
        format!("{what} set {what} & {} | {}", self.not_mask(), self.enc(v))
    }

    fn probe_skip(&self) -> String {
        format!(
            "meta mark & {} == {} return",
            Self::hex(self.mask.class_mask()),
            self.enc(FieldValue::PROBE_CLASS)
        )
    }

    fn restore_all(&mut self) {
        for id in UplinkId::all() {
            let v = FieldValue::path(id);
            let rule = format!(
                "ct mark & {} == {} {} return",
                self.mask(),
                self.enc(v),
                self.set("meta mark", v)
            );
            self.line(2, &rule);
        }
    }
}

/// The table definition (without the replacement commands).
pub fn ruleset(config: &Config) -> String {
    let mut g = Gen {
        mask: config.routing.fwmark_mask,
        out: String::new(),
    };
    let families: Vec<Family> = Family::ALL.into_iter().filter(|f| config.manages(*f)).collect();
    // With a single managed family, the other family is left alone (§4.3).
    let other_family_skip = match families.as_slice() {
        [only] => Some(format!("meta nfproto != {} return", nfproto(*only))),
        _ => None,
    };
    let paths: Vec<(&crate::config::Uplink, Family)> = config
        .uplinks
        .iter()
        .flat_map(|u| u.families().map(move |f| (u, f)))
        .collect();

    g.line(0, &format!("table inet {TABLE} {{"));

    g.line(
        1,
        "# §4.7 step 1: restore the path of known connections, assign new inbound ones.",
    );
    g.line(1, "chain prerouting {");
    g.line(
        2,
        &format!("type filter hook prerouting priority {MARK_PRIORITY}; policy accept;"),
    );
    if let Some(s) = &other_family_skip {
        g.line(2, s);
    }
    g.line(2, "# Only tracked unicast traffic is marked (§4.8).");
    g.line(2, "ct state untracked return");
    g.line(2, "meta pkttype != host return");
    g.line(
        2,
        "# Restore the path value of the connection, for every path id (FR-MARK-3).",
    );
    g.restore_all();
    g.line(
        2,
        "# New inbound connection on an uplink: assign that uplink's path (INV-5).",
    );
    for (u, f) in &paths {
        let v = FieldValue::path(u.id);
        let rule = format!(
            "meta nfproto {} iifname {} ct direction original {} {} return",
            nfproto(*f),
            quote(&u.interface),
            g.set("ct mark", v),
            g.set("meta mark", v)
        );
        g.line(2, &format!("# uplink {:?}, {f}", u.name));
        g.line(2, &rule);
    }
    g.line(1, "}");

    g.line(
        1,
        "# §4.7 step 2: route chain, so that a restored mark triggers a new routing decision.",
    );
    g.line(1, "chain output {");
    g.line(
        2,
        &format!("type route hook output priority {MARK_PRIORITY}; policy accept;"),
    );
    if let Some(s) = &other_family_skip {
        g.line(2, s);
    }
    g.line(2, "# Probe traffic keeps its probe value (INV-6).");
    g.line(2, &g.probe_skip());
    g.line(2, "ct state untracked return");
    g.line(
        2,
        "# Restore the path value of the connection, for every path id (FR-MARK-3).",
    );
    g.restore_all();
    g.line(1, "}");

    g.line(
        1,
        "# §4.7 step 3: outgoing connections get the path they actually left through.",
    );
    g.line(1, "chain postrouting {");
    g.line(
        2,
        &format!("type filter hook postrouting priority {MARK_PRIORITY}; policy accept;"),
    );
    if let Some(s) = &other_family_skip {
        g.line(2, s);
    }
    g.line(2, &g.probe_skip());
    g.line(2, "ct state untracked return");
    g.line(2, "# Only unicast traffic is marked (§4.8).");
    g.line(2, "ip daddr { 224.0.0.0/4, 255.255.255.255 } return");
    g.line(2, "ip6 daddr ff00::/8 return");
    g.line(2, "# Connections that already have a path keep it (INV-2).");
    g.line(2, &format!("ct mark & {} != 0 return", g.mask()));
    for (u, f) in &paths {
        let v = FieldValue::path(u.id);
        let rule = format!(
            "meta nfproto {} oifname {} ct direction original {} {} return",
            nfproto(*f),
            quote(&u.interface),
            g.set("ct mark", v),
            g.set("meta mark", v)
        );
        g.line(2, &format!("# uplink {:?}, {f}", u.name));
        g.line(2, &rule);
    }
    g.line(1, "}");

    g.line(1, "# §6: source NAT of traffic from the downlinks.");
    g.line(1, "chain nat {");
    g.line(
        2,
        &format!(
            "type nat hook postrouting priority {}; policy accept;",
            config.firewall.nat_priority
        ),
    );
    let downlinks = config.downlinks.iter().map(|d| quote(d)).collect::<Vec<_>>().join(", ");
    for (u, f) in &paths {
        let p = u.path(*f).expect("paths lists enabled families");
        let action = match (p.nat, p.source) {
            (Nat::None, _) => continue,
            (Nat::Masquerade, _) => "masquerade".to_owned(),
            (Nat::Snat, AutoOr::Static(IpAddr::V4(a))) => format!("snat ip to {a}"),
            (Nat::Snat, AutoOr::Static(IpAddr::V6(a))) => format!("snat ip6 to {a}"),
            // Rejected by validation (snat needs a static source).
            (Nat::Snat, AutoOr::Auto) => continue,
        };
        g.line(2, &format!("# uplink {:?}, {f}: {action}", u.name));
        g.line(
            2,
            &format!(
                "meta nfproto {} iifname {{ {downlinks} }} oifname {} {action}",
                nfproto(*f),
                quote(&u.interface)
            ),
        );
    }
    g.line(1, "}");
    g.line(0, "}");
    g.out
}

/// The atomic replacement transaction (FR-FW-1): `add table` (so that the
/// delete succeeds when the table is missing), `delete table`, full table.
pub fn transaction(config: &Config) -> String {
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n{}", ruleset(config))
}

/// Transaction removing the table (FR-REC-4); succeeds when it is missing.
pub fn removal() -> String {
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    const CONFIG: &str = include_str!("../tests/golden/ipv4.toml");

    #[test]
    fn golden_ipv4_ruleset() {
        let cfg = config::parse(CONFIG).unwrap();
        let text = ruleset(&cfg);
        let expected = include_str!("../tests/golden/ipv4.nft");
        if text != expected {
            // Print the generated text to make updating the golden file easy.
            eprintln!("{text}");
        }
        assert_eq!(text, expected);
    }

    #[test]
    fn mark_operations_use_the_configured_mask() {
        let text = CONFIG.replace("[firewall]", "[routing]\nfwmark_mask = 0xff\n[firewall]");
        let cfg = config::parse(&text).unwrap();
        let text = ruleset(&cfg);
        assert!(
            text.contains(
                "ct mark & 0x000000ff == 0x0000003f meta mark set meta mark & 0xffffff00 | 0x0000003f return"
            )
        );
        assert!(text.contains("meta mark & 0x000000c0 == 0x00000040 return"));
    }

    #[test]
    fn no_verdicts_other_than_return() {
        let cfg = config::parse(CONFIG).unwrap();
        let text = ruleset(&cfg);
        for word in ["accept", "drop", "reject", "jump", "goto", "queue"] {
            let uses = text
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .filter(|l| l.split_whitespace().any(|w| w.trim_end_matches(';') == word))
                .filter(|l| !l.contains("policy accept;"))
                .count();
            assert_eq!(uses, 0, "{word}");
        }
    }

    #[test]
    fn restoration_covers_all_63_path_values() {
        let cfg = config::parse(CONFIG).unwrap();
        let text = ruleset(&cfg);
        let restores = text
            .lines()
            .filter(|l| l.trim_start().starts_with("ct mark & 0x00ff0000 =="))
            .count();
        assert_eq!(restores, 2 * 63);
    }

    #[test]
    fn transaction_replaces_the_table() {
        let cfg = config::parse(CONFIG).unwrap();
        let t = transaction(&cfg);
        assert!(t.starts_with(
            "add table inet fault_tolerant_router\ndelete table inet fault_tolerant_router\ntable inet fault_tolerant_router {\n"
        ));
    }
}
