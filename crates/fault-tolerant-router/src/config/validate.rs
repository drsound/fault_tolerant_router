//! Validation of the raw configuration (SPEC.md §11.2). Every problem is
//! collected, with the line of the innermost table that holds the key.

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::ops::{Range, RangeInclusive};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use toml::Spanned;

use super::raw;
use super::*;
use crate::duration;

/// Event types of FR-EV-1, accepted in hook filters.
pub const EVENT_TYPES: &[&str] = &[
    "daemon_started",
    "daemon_stopping",
    "config_reloaded",
    "reload_failed",
    "path_state_changed",
    "path_address_changed",
    "path_gateway_changed",
    "active_set_changed",
    "uplink_drained",
    "uplink_undrained",
    "artifact_repaired",
    "apply_failed",
    "status_degraded",
    "status_recovered",
];

/// Built-in probe targets: anycast resolvers of different operators
/// (FR-PROBE-6).
pub const DEFAULT_TARGETS_V4: &[&str] = &["icmp:1.1.1.1", "icmp:8.8.8.8", "icmp:9.9.9.9", "icmp:208.67.222.222"];
pub const DEFAULT_TARGETS_V6: &[&str] = &[
    "icmp:2606:4700:4700::1111",
    "icmp:2001:4860:4860::8888",
    "icmp:2620:fe::fe",
];

struct Ctx<'a> {
    text: &'a str,
    diags: Vec<Diagnostic>,
}

impl Ctx<'_> {
    fn err(&mut self, span: Option<&Range<usize>>, key: impl Into<String>, message: impl Into<String>) {
        let line = span.map(|s| line_of(self.text, s.start));
        self.diags.push(Diagnostic {
            line,
            key: key.into(),
            message: message.into(),
        });
    }

    /// An integer in `range`, `default` when absent.
    fn int<T: TryFrom<i64> + Copy>(
        &mut self,
        value: Option<i64>,
        default: T,
        range: RangeInclusive<i64>,
        span: Option<&Range<usize>>,
        key: &str,
    ) -> T {
        let Some(v) = value else { return default };
        if !range.contains(&v) {
            self.err(
                span,
                key,
                format!("{v} is out of range {}–{}", range.start(), range.end()),
            );
            return default;
        }
        T::try_from(v).unwrap_or(default)
    }

    fn duration(&mut self, value: Option<&str>, default: Duration, span: Option<&Range<usize>>, key: &str) -> Duration {
        let Some(text) = value else { return default };
        match duration::parse(text) {
            Ok(d) => d,
            Err(e) => {
                self.err(span, key, e);
                default
            }
        }
    }

    fn duration_in(
        &mut self,
        value: Option<&str>,
        default: Duration,
        range: RangeInclusive<Duration>,
        span: Option<&Range<usize>>,
        key: &str,
    ) -> Duration {
        let d = self.duration(value, default, span, key);
        if !range.contains(&d) {
            self.err(
                span,
                key,
                format!(
                    "{} is out of range {}–{}",
                    duration::format(d),
                    duration::format(*range.start()),
                    duration::format(*range.end())
                ),
            );
            return default;
        }
        d
    }
}

fn span_of<T>(s: &Option<Spanned<T>>) -> Option<Range<usize>> {
    s.as_ref().map(Spanned::span)
}

pub fn validate(text: &str, raw: raw::Config) -> Result<Config, Vec<Diagnostic>> {
    let mut cx = Ctx {
        text,
        diags: Vec::new(),
    };
    let routing = routing(&mut cx, raw.routing);
    let firewall = firewall(&mut cx, raw.firewall);

    let mut interfaces: HashSet<String> = HashSet::new();
    let mut downlinks = Vec::new();
    if raw.downlink.is_empty() {
        cx.err(None, "downlink", "at least one [[downlink]] is required");
    }
    for (i, d) in raw.downlink.iter().enumerate() {
        let key = format!("downlink[{i}].interface");
        let span = d.span();
        let name = &d.get_ref().interface;
        if let Err(e) = check_interface_name(name) {
            cx.err(Some(&span), &key, e);
        } else if !interfaces.insert(name.clone()) {
            cx.err(
                Some(&span),
                &key,
                format!("interface {name:?} is listed more than once"),
            );
        }
        downlinks.push(name.clone());
    }

    let global_health = raw.health.as_ref().map(|h| (h.get_ref().clone(), h.span()));
    let mut uplinks: Vec<Uplink> = Vec::new();
    if raw.uplink.is_empty() {
        cx.err(None, "uplink", "at least one [[uplink]] is required");
    }
    let mut static_sources: Vec<(IpAddr, String)> = Vec::new();
    for (i, u) in raw.uplink.into_iter().enumerate() {
        let span = u.span();
        let u = u.into_inner();
        let key = format!("uplink[{i}]");
        let id = match u8::try_from(u.id).ok().and_then(UplinkId::new) {
            Some(id) => id,
            None => {
                cx.err(
                    Some(&span),
                    format!("{key}.id"),
                    format!("{} is out of range 1–63", u.id),
                );
                UplinkId::new(1).expect("1 is a valid id")
            }
        };
        if uplinks.iter().any(|o| o.id == id) && (1..=63).contains(&u.id) {
            cx.err(
                Some(&span),
                format!("{key}.id"),
                format!("id {id} is used by another uplink"),
            );
        }
        if !valid_uplink_name(&u.name) {
            cx.err(
                Some(&span),
                format!("{key}.name"),
                format!("{:?} must match [a-z0-9_-]{{1,32}}", u.name),
            );
        } else if uplinks.iter().any(|o| o.name == u.name) {
            cx.err(
                Some(&span),
                format!("{key}.name"),
                format!("name {:?} is used by another uplink", u.name),
            );
        }
        if let Err(e) = check_interface_name(&u.interface) {
            cx.err(Some(&span), format!("{key}.interface"), e);
        } else if !interfaces.insert(u.interface.clone()) {
            cx.err(
                Some(&span),
                format!("{key}.interface"),
                format!(
                    "interface {:?} is already used by another uplink or downlink",
                    u.interface
                ),
            );
        }
        let priority = u
            .priority
            .map(|p| cx.int::<u16>(Some(p), 1, 1..=1000, Some(&span), &format!("{key}.priority")));
        let weight = cx.int::<u16>(u.weight, 1, 1..=256, Some(&span), &format!("{key}.weight"));
        if u.ipv4.is_none() && u.ipv6.is_none() {
            cx.err(
                Some(&span),
                &key,
                "at least one of [uplink.ipv4] and [uplink.ipv6] is required",
            );
        }
        let ipv4 = u.ipv4.map(|p| path(&mut cx, p, Family::V4, &format!("{key}.ipv4")));
        let ipv6 = u.ipv6.map(|p| path(&mut cx, p, Family::V6, &format!("{key}.ipv6")));
        for p in [&ipv4, &ipv6].into_iter().flatten() {
            if let AutoOr::Static(a) = p.source {
                if let Some((_, other)) = static_sources.iter().find(|(s, _)| *s == a) {
                    cx.err(
                        Some(&span),
                        format!("{key}.source"),
                        format!("static source {a} is also used by uplink {other:?} (FR-DISC-2)"),
                    );
                }
                static_sources.push((a, u.name.clone()));
            }
        }
        let (health_key, health_span, merged) = match &u.health {
            Some(h) => (
                format!("{key}.health"),
                Some(h.span()),
                merge_health(global_health.as_ref().map(|g| &g.0), Some(h.get_ref())),
            ),
            None => (
                "health".to_owned(),
                global_health.as_ref().map(|g| g.1.clone()),
                merge_health(global_health.as_ref().map(|g| &g.0), None),
            ),
        };
        let families: Vec<Family> = [(Family::V4, ipv4.is_some()), (Family::V6, ipv6.is_some())]
            .into_iter()
            .filter(|f| f.1)
            .map(|f| f.0)
            .collect();
        let health = health(&mut cx, &merged, &families, health_span.as_ref(), &health_key);
        uplinks.push(Uplink {
            id,
            description: u.description.unwrap_or_else(|| u.name.clone()),
            name: u.name,
            interface: u.interface,
            priority,
            weight,
            ipv4,
            ipv6,
            health,
        });
    }
    // Problems found while merging the global health settings repeat for
    // every uplink without an override.
    cx.diags.sort();
    cx.diags.dedup();

    let policies = raw
        .policy
        .into_iter()
        .enumerate()
        .filter_map(|(i, p)| policy(&mut cx, p, i, &uplinks, &downlinks))
        .collect::<Vec<_>>();
    let mut names = HashSet::new();
    for (i, p) in policies.iter().enumerate() {
        if !names.insert(p.name.clone()) {
            cx.err(
                None,
                format!("policy[{i}].name"),
                format!("policy name {:?} is used more than once", p.name),
            );
        }
    }

    let notify = notify(&mut cx, raw.notify);
    let api = match raw.api {
        Some(a) => {
            let span = a.span();
            let a = a.into_inner();
            let socket = a
                .socket
                .unwrap_or_else(|| PathBuf::from("/run/fault-tolerant-router/api.sock"));
            if !socket.is_absolute() {
                cx.err(Some(&span), "api.socket", "must be an absolute path");
            }
            Api {
                socket,
                group: a.group.unwrap_or_else(|| "fault-tolerant-router".into()),
            }
        }
        None => Api {
            socket: PathBuf::from("/run/fault-tolerant-router/api.sock"),
            group: "fault-tolerant-router".into(),
        },
    };
    let metrics_listen = raw.metrics.and_then(|m| {
        let span = m.span();
        m.into_inner().listen.and_then(|l| match l.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(_) => {
                cx.err(
                    Some(&span),
                    "metrics.listen",
                    format!("{l:?} is not a socket address such as 127.0.0.1:9750"),
                );
                None
            }
        })
    });
    let state_dir = match raw.state_dir {
        Some(s) => {
            let span = s.span();
            let p = s.into_inner();
            if !p.is_absolute() {
                cx.err(Some(&span), "state_dir", "must be an absolute path");
            }
            p
        }
        None => PathBuf::from("/var/lib/fault-tolerant-router"),
    };

    if cx.diags.is_empty() {
        Ok(Config {
            routing,
            firewall,
            downlinks,
            uplinks,
            policies,
            notify,
            api,
            metrics_listen,
            state_dir,
            digest: String::new(),
        })
    } else {
        cx.diags.sort_by_key(|d| (d.line, d.key.clone()));
        cx.diags.dedup();
        Err(cx.diags)
    }
}

fn routing(cx: &mut Ctx, raw: Option<Spanned<raw::Routing>>) -> Routing {
    let span = span_of(&raw);
    let span = span.as_ref();
    let r = raw.map(Spanned::into_inner).unwrap_or(raw::Routing {
        table_base: None,
        rule_priority_base: None,
        route_protocol: None,
        fwmark_mask: None,
        all_down_policy: None,
        discovery_tables: None,
        manage_sysctls: None,
        reconcile_interval: None,
        on_shutdown: None,
    });
    let table_base = cx.int::<u32>(r.table_base, 1000, 1..=4_294_967_294 - 191, span, "routing.table_base");
    if (table_base..=table_base + 191).contains(&253) || (table_base..=table_base + 191).contains(&255) {
        cx.err(
            span,
            "routing.table_base",
            format!(
                "tables {table_base}–{} include the reserved tables 253–255",
                table_base + 191
            ),
        );
    }
    let rule_priority_base = cx.int::<u32>(
        r.rule_priority_base,
        1000,
        1..=32765 - 699,
        span,
        "routing.rule_priority_base",
    );
    let route_protocol = cx.int::<u8>(r.route_protocol, 249, 5..=255, span, "routing.route_protocol");
    let fwmark_mask = match r.fwmark_mask {
        None => FwMask::DEFAULT,
        Some(v) => match u32::try_from(v).ok().and_then(FwMask::new) {
            Some(m) => m,
            None => {
                cx.err(
                    span,
                    "routing.fwmark_mask",
                    format!("{v:#x} is not exactly 8 contiguous bits"),
                );
                FwMask::DEFAULT
            }
        },
    };
    let mut discovery_tables = Vec::new();
    for t in r
        .discovery_tables
        .unwrap_or_else(|| vec![raw::TableRef::Name("main".into())])
    {
        let id = match t {
            raw::TableRef::Name(n) => match n.as_str() {
                "main" => Some(254),
                "default" => Some(253),
                _ => {
                    cx.err(
                        span,
                        "routing.discovery_tables",
                        format!("unknown table name {n:?} (use \"main\", \"default\" or a number)"),
                    );
                    None
                }
            },
            raw::TableRef::Id(n) => match u32::try_from(n) {
                Ok(n) if n >= 1 && n != 255 => Some(n),
                _ => {
                    cx.err(
                        span,
                        "routing.discovery_tables",
                        format!("{n} is not a usable table id"),
                    );
                    None
                }
            },
        };
        if let Some(id) = id {
            if (table_base..=table_base + 191).contains(&id) {
                cx.err(
                    span,
                    "routing.discovery_tables",
                    format!("table {id} is in FTR's own range"),
                );
            } else if !discovery_tables.contains(&id) {
                discovery_tables.push(id);
            }
        }
    }
    let reconcile_interval = cx.duration_in(
        r.reconcile_interval.as_deref(),
        Duration::from_secs(60),
        Duration::from_secs(10)..=Duration::from_secs(3600),
        span,
        "routing.reconcile_interval",
    );
    Routing {
        table_base,
        rule_priority_base,
        route_protocol,
        fwmark_mask,
        all_down_policy: r.all_down_policy.unwrap_or(AllDownPolicy::Ready),
        discovery_tables,
        manage_sysctls: r.manage_sysctls.unwrap_or(true),
        reconcile_interval,
        on_shutdown: r.on_shutdown.unwrap_or(OnShutdown::Keep),
    }
}

fn firewall(cx: &mut Ctx, raw: Option<Spanned<raw::Firewall>>) -> Firewall {
    let span = span_of(&raw);
    let span = span.as_ref();
    let f = raw.map(Spanned::into_inner).unwrap_or(raw::Firewall {
        mode: None,
        nat_priority: None,
        nft_path: None,
    });
    let nat_priority = cx.int::<i32>(f.nat_priority, 100, -149..=400, span, "firewall.nat_priority");
    let nft_path = f.nft_path.unwrap_or_else(|| PathBuf::from("/usr/sbin/nft"));
    if !nft_path.is_absolute() {
        cx.err(span, "firewall.nft_path", "must be an absolute path");
    }
    Firewall {
        mode: f.mode.unwrap_or(FirewallMode::Managed),
        nat_priority,
        nft_path,
    }
}

fn path(cx: &mut Ctx, raw: Spanned<raw::Path>, family: Family, key: &str) -> PathSettings {
    let span = raw.span();
    let p = raw.into_inner();
    let addr = |cx: &mut Ctx, value: Option<String>, what: &str| -> AutoOr<IpAddr> {
        match value.as_deref() {
            None | Some("auto") => AutoOr::Auto,
            Some(text) => match text.parse::<IpAddr>() {
                Ok(a) if Family::of(a) == family => AutoOr::Static(a),
                Ok(_) => {
                    cx.err(
                        Some(&span),
                        format!("{key}.{what}"),
                        format!("{text} is not an {family} address"),
                    );
                    AutoOr::Auto
                }
                Err(_) => {
                    cx.err(
                        Some(&span),
                        format!("{key}.{what}"),
                        format!("{text:?} is neither \"auto\" nor an address"),
                    );
                    AutoOr::Auto
                }
            },
        }
    };
    let source = addr(cx, p.source, "source");
    let gateway = addr(cx, p.gateway, "gateway");
    if let AutoOr::Static(a) = source
        && !is_usable_source(a)
    {
        cx.err(
            Some(&span),
            format!("{key}.source"),
            format!("{a} cannot be a source address"),
        );
    }
    let gateway_onlink = p.gateway_onlink.unwrap_or(false);
    if gateway_onlink && gateway == AutoOr::Auto {
        cx.err(
            Some(&span),
            format!("{key}.gateway_onlink"),
            "requires a static gateway (FR-DISC-4)",
        );
    }
    let nat = match (p.nat, family) {
        (Some(n), _) => n,
        (None, Family::V4) => Nat::Masquerade,
        (None, Family::V6) => {
            cx.err(
                Some(&span),
                format!("{key}.nat"),
                "must be set explicitly for IPv6 (\"masquerade\", \"snat\" or \"none\", FR-NAT-1)",
            );
            Nat::None
        }
    };
    if nat == Nat::Snat && source == AutoOr::Auto {
        cx.err(
            Some(&span),
            format!("{key}.source"),
            "nat = \"snat\" requires a static source address",
        );
    }
    PathSettings {
        source,
        gateway,
        gateway_onlink,
        nat,
    }
}

fn merge_health(global: Option<&raw::Health>, local: Option<&raw::Health>) -> raw::Health {
    let g = global.cloned().unwrap_or_default();
    let Some(l) = local else { return g };
    let l = l.clone();
    let gq = g.quality.unwrap_or_default();
    let quality = l.quality.map(|lq| raw::Quality {
        max_rtt: lq.max_rtt.or(gq.max_rtt.clone()),
        max_jitter: lq.max_jitter.or(gq.max_jitter.clone()),
        max_loss: lq.max_loss.or(gq.max_loss),
    });
    raw::Health {
        interval: l.interval.or(g.interval),
        timeout: l.timeout.or(g.timeout),
        attempts: l.attempts.or(g.attempts),
        required_reachable: l.required_reachable.or(g.required_reachable),
        fall: l.fall.or(g.fall),
        rise: l.rise.or(g.rise),
        ipv4: l.ipv4.or(g.ipv4),
        ipv6: l.ipv6.or(g.ipv6),
        quality: quality.or(Some(gq)),
        quality_window: l.quality_window.or(g.quality_window),
        quality_min_samples: l.quality_min_samples.or(g.quality_min_samples),
    }
}

fn health(cx: &mut Ctx, h: &raw::Health, families: &[Family], span: Option<&Range<usize>>, key: &str) -> Health {
    let k = |s: &str| format!("{key}.{s}");
    let interval = cx.duration_in(
        h.interval.as_deref(),
        Duration::from_secs(5),
        Duration::from_secs(1)..=Duration::from_secs(300),
        span,
        &k("interval"),
    );
    let timeout = cx.duration(h.timeout.as_deref(), Duration::from_secs(1), span, &k("timeout"));
    if timeout.is_zero() {
        cx.err(span, k("timeout"), "must be greater than zero");
    }
    let attempts = cx.int::<u8>(h.attempts, 2, 1..=5, span, &k("attempts"));
    if timeout * u32::from(attempts) >= interval {
        cx.err(
            span,
            k("timeout"),
            format!(
                "timeout × attempts ({} × {attempts}) must be shorter than interval ({}) (FR-PROBE-4)",
                duration::format(timeout),
                duration::format(interval)
            ),
        );
    }
    let fall = cx.int::<u8>(h.fall, 2, 1..=20, span, &k("fall"));
    let rise = cx.int::<u8>(h.rise, 3, 1..=20, span, &k("rise"));
    let targets = |cx: &mut Ctx, family: Family| -> Vec<Target> {
        let list: Vec<String> = match family {
            Family::V4 => h.ipv4.as_ref().map(|t| t.targets.clone()),
            Family::V6 => h.ipv6.as_ref().map(|t| t.targets.clone()),
        }
        .unwrap_or_else(|| {
            let d = if family == Family::V4 {
                DEFAULT_TARGETS_V4
            } else {
                DEFAULT_TARGETS_V6
            };
            d.iter().map(|s| (*s).to_owned()).collect()
        });
        let key = format!("{key}.{family}.targets");
        let mut out: Vec<Target> = Vec::new();
        for text in &list {
            match parse_target(text) {
                Ok(t) if Family::of(t.addr()) != family => {
                    cx.err(span, &key, format!("{text:?} is not an {family} target"))
                }
                Ok(t) if !is_global_unicast(t.addr()) => cx.err(
                    span,
                    &key,
                    format!("{text:?}: the address is not global unicast (FR-PROBE-2)"),
                ),
                Ok(t) if out.contains(&t) => cx.err(span, &key, format!("{text:?} is listed more than once")),
                Ok(t) => out.push(t),
                Err(e) => cx.err(span, &key, e),
            }
        }
        if out.is_empty() && families.contains(&family) {
            cx.err(span, &key, "at least one target is required");
        }
        out
    };
    let targets_v4 = targets(cx, Family::V4);
    let targets_v6 = targets(cx, Family::V6);
    let max_targets = families
        .iter()
        .map(|f| distinct_addresses(if *f == Family::V4 { &targets_v4 } else { &targets_v6 }))
        .min();
    let required_reachable = cx.int::<u8>(h.required_reachable, 2, 1..=255, span, &k("required_reachable"));
    for f in families {
        let n = distinct_addresses(if *f == Family::V4 { &targets_v4 } else { &targets_v6 });
        if n > 0 && usize::from(required_reachable) > n {
            cx.err(
                span,
                k("required_reachable"),
                format!("{required_reachable} exceeds the {n} distinct {f} targets (FR-PROBE-4)"),
            );
        }
    }
    let q = h.quality.clone().unwrap_or_default();
    let quality = Quality {
        max_rtt: q
            .max_rtt
            .as_deref()
            .map(|t| cx.duration(Some(t), Duration::ZERO, span, &k("quality.max_rtt"))),
        max_jitter: q
            .max_jitter
            .as_deref()
            .map(|t| cx.duration(Some(t), Duration::ZERO, span, &k("quality.max_jitter"))),
        max_loss: q.max_loss,
    };
    if let Some(l) = quality.max_loss
        && !(0.0..=1.0).contains(&l)
    {
        cx.err(span, k("quality.max_loss"), format!("{l} is out of range 0–1"));
    }
    let quality_window = cx.int::<u8>(h.quality_window, 6, 2..=100, span, &k("quality_window"));
    let quality_min_samples = cx.int::<u16>(h.quality_min_samples, 10, 1..=10_000, span, &k("quality_min_samples"));
    if quality.enabled() {
        // Sample capacity of the window uses the smallest target list.
        if let Some(n) = max_targets {
            let capacity = n * usize::from(quality_window);
            if usize::from(quality_min_samples) > capacity {
                cx.err(
                    span,
                    k("quality_min_samples"),
                    format!("{quality_min_samples} exceeds targets × quality_window ({capacity}) (FR-PROBE-5)"),
                );
            }
        }
    }
    Health {
        interval,
        timeout,
        attempts,
        required_reachable,
        fall,
        rise,
        targets_v4,
        targets_v6,
        quality,
        quality_window,
        quality_min_samples,
    }
}

fn distinct_addresses(targets: &[Target]) -> usize {
    targets.iter().map(Target::addr).collect::<BTreeSet<_>>().len()
}

/// `icmp:ADDRESS`, `tcp:IPV4:PORT` or `tcp:[IPV6]:PORT` (FR-PROBE-2).
pub fn parse_target(text: &str) -> Result<Target, String> {
    let bad = || format!("{text:?} is not a target (icmp:ADDRESS, tcp:IPV4:PORT or tcp:[IPV6]:PORT)");
    if let Some(a) = text.strip_prefix("icmp:") {
        return a.parse::<IpAddr>().map(Target::Icmp).map_err(|_| bad());
    }
    if let Some(s) = text.strip_prefix("tcp:") {
        let sa = s.parse::<SocketAddr>().map_err(|_| bad())?;
        if sa.port() == 0 {
            return Err(format!("{text:?}: port 0 is not valid"));
        }
        return Ok(Target::Tcp(sa));
    }
    Err(bad())
}

fn policy(
    cx: &mut Ctx,
    raw: Spanned<raw::Policy>,
    i: usize,
    uplinks: &[Uplink],
    downlinks: &[String],
) -> Option<Policy> {
    let span = raw.span();
    let p = raw.into_inner();
    let key = format!("policy[{i}]");
    let before = cx.diags.len();
    let family = match p.family {
        raw::PolicyFamily::Ipv4 => Family::V4,
        raw::PolicyFamily::Ipv6 => Family::V6,
    };
    let uplink = match uplinks.iter().find(|u| u.name == p.uplink) {
        Some(u) => {
            if u.path(family).is_none() {
                cx.err(
                    Some(&span),
                    format!("{key}.uplink"),
                    format!("uplink {:?} does not enable {family}", u.name),
                );
            }
            Some(u.id)
        }
        None => {
            cx.err(
                Some(&span),
                format!("{key}.uplink"),
                format!("no uplink is named {:?}", p.uplink),
            );
            None
        }
    };
    if let Some(i) = &p.input_interface
        && !downlinks.contains(i)
    {
        cx.err(
            Some(&span),
            format!("{key}.input_interface"),
            format!("{i:?} is not a downlink"),
        );
    }
    let prefix = |cx: &mut Ctx, v: &Option<String>, what: &str| -> Option<IpNet> {
        let text = v.as_deref()?;
        let net = text
            .parse::<IpNet>()
            .or_else(|_| text.parse::<IpAddr>().map(IpNet::from));
        match net {
            Ok(n) if Family::of(n.addr()) == family => Some(n.trunc()),
            Ok(_) => {
                cx.err(
                    Some(&span),
                    format!("{key}.{what}"),
                    format!("{text} is not an {family} prefix"),
                );
                None
            }
            Err(_) => {
                cx.err(
                    Some(&span),
                    format!("{key}.{what}"),
                    format!("{text:?} is not a prefix"),
                );
                None
            }
        }
    };
    let source = prefix(cx, &p.source, "source");
    let destination = prefix(cx, &p.destination, "destination");
    match (p.protocol, family) {
        (Some(Protocol::Icmp), Family::V6) => cx.err(
            Some(&span),
            format!("{key}.protocol"),
            "\"icmp\" is IPv4 only, use \"icmpv6\"",
        ),
        (Some(Protocol::Icmpv6), Family::V4) => cx.err(
            Some(&span),
            format!("{key}.protocol"),
            "\"icmpv6\" is IPv6 only, use \"icmp\"",
        ),
        _ => {}
    }
    let destination_port = p.destination_port.as_ref().and_then(|spec| {
        if !matches!(p.protocol, Some(Protocol::Tcp | Protocol::Udp | Protocol::Sctp)) {
            cx.err(
                Some(&span),
                format!("{key}.destination_port"),
                "ports require protocol \"tcp\", \"udp\" or \"sctp\"",
            );
            return None;
        }
        let range = match spec {
            raw::PortSpec::Port(n) => Some((*n, *n)),
            raw::PortSpec::Range(s) => s
                .split_once('-')
                .and_then(|(a, b)| Some((a.trim().parse::<i64>().ok()?, b.trim().parse::<i64>().ok()?))),
        };
        match range {
            Some((a, b)) if (1..=65535).contains(&a) && (1..=65535).contains(&b) && a <= b => {
                Some((a as u16, b as u16))
            }
            _ => {
                cx.err(
                    Some(&span),
                    format!("{key}.destination_port"),
                    "must be a port 1–65535 or a range \"A-B\" with A ≤ B",
                );
                None
            }
        }
    });
    if cx.diags.len() != before {
        return None;
    }
    Some(Policy {
        name: p.name,
        family,
        input_interface: p.input_interface,
        source,
        destination,
        protocol: p.protocol,
        destination_port,
        uplink: uplink?,
        fallback: p.fallback.unwrap_or(Fallback::Balance),
    })
}

fn notify(cx: &mut Ctx, raw: Option<Spanned<raw::Notify>>) -> Notify {
    let Some(raw) = raw else {
        return Notify {
            coalesce: Duration::from_secs(30),
            email: None,
            hooks: Vec::new(),
            hook_user: "nobody".into(),
        };
    };
    let span = raw.span();
    let n = raw.into_inner();
    let coalesce = cx.duration(
        n.coalesce.as_deref(),
        Duration::from_secs(30),
        Some(&span),
        "notify.coalesce",
    );
    let email = n.email.map(|e| {
        let span = e.span();
        let e = e.into_inner();
        let default_port = match e.security {
            Security::Tls => 465,
            Security::Starttls => 587,
            Security::Plain => 25,
        };
        let port = cx.int::<u16>(e.port, default_port, 1..=65535, Some(&span), "notify.email.port");
        let max_per_hour = cx.int::<u32>(e.max_per_hour, 20, 1..=10_000, Some(&span), "notify.email.max_per_hour");
        if e.to.is_empty() {
            cx.err(Some(&span), "notify.email.to", "at least one recipient is required");
        }
        if let Some(p) = &e.password_file
            && !p.is_absolute()
        {
            cx.err(Some(&span), "notify.email.password_file", "must be an absolute path");
        }
        Email {
            from: e.from,
            to: e.to,
            host: e.host,
            port,
            security: e.security,
            username: e.username,
            password_file: e.password_file,
            max_per_hour,
        }
    });
    let hooks = n
        .hook
        .into_iter()
        .enumerate()
        .map(|(i, h)| {
            let span = h.span();
            let h = h.into_inner();
            let key = format!("notify.hook[{i}]");
            match h.command.first() {
                Some(exe) if Path::new(exe).is_absolute() => {}
                _ => cx.err(
                    Some(&span),
                    format!("{key}.command"),
                    "the first element must be an absolute executable path",
                ),
            }
            for ev in h.events.iter().flatten() {
                if !EVENT_TYPES.contains(&ev.as_str()) {
                    cx.err(
                        Some(&span),
                        format!("{key}.events"),
                        format!("unknown event type {ev:?}"),
                    );
                }
            }
            let timeout = cx.duration(
                h.timeout.as_deref(),
                Duration::from_secs(10),
                Some(&span),
                &format!("{key}.timeout"),
            );
            Hook {
                command: h.command,
                events: h.events,
                timeout,
            }
        })
        .collect();
    Notify {
        coalesce,
        email,
        hooks,
        hook_user: n.hook_user.unwrap_or_else(|| "nobody".into()),
    }
}

fn valid_uplink_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Interface names end up quoted in the nftables ruleset (IMPL-3); only the
/// characters that Linux interface names use in practice are accepted.
pub fn check_interface_name(name: &str) -> Result<(), String> {
    let ok_char = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'+');
    if name.is_empty() || name.len() > 15 || name == "." || name == ".." || !name.bytes().all(ok_char) {
        return Err(format!(
            "{name:?} is not a valid interface name (1–15 characters among A–Z a–z 0–9 _ - . : +)"
        ));
    }
    Ok(())
}

/// Global unicast in the sense of FR-PROBE-2: excludes unspecified,
/// loopback, multicast, broadcast, link-local, private and unique-local
/// addresses. Documentation and benchmarking prefixes are accepted, since
/// test topologies use them (§14.2).
pub fn is_global_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_link_local()
                || a.is_private()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
                || a.to_ipv4_mapped().is_some())
        }
    }
}

/// A source address has global scope in the kernel's sense: private and
/// shared (CGNAT) IPv4 addresses are common on uplinks and are accepted.
pub fn is_usable_source(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_broadcast() || a.is_link_local())
        }
        IpAddr::V6(a) => {
            !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || (a.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}
