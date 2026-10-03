#![forbid(unsafe_code)]
//! Spike S3: exercise `rtnetlink` / `netlink-packet-route` for the operations
//! FTR needs (SPEC.md §15). Run inside a network namespace prepared by
//! `run.sh`. Every check prints `PASS`, `FAIL` or `INFO` lines.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::process::CommandExt,
    time::Duration,
};

use futures::{StreamExt, channel::mpsc::UnboundedReceiver};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_FILTERED, NLM_F_DUMP_INTR, NLM_F_EXCL, NLM_F_MULTIPART,
    NLM_F_REPLACE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlags, LinkMessage},
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage, RouteNextHop, RouteNextHopFlags,
        RouteProtocol, RouteScope, RouteType,
    },
    rule::{RuleAction, RuleAttribute, RuleMessage},
};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{Handle, MulticastGroup, RouteMessageBuilder, RouteNextHopBuilder};

const PROTO: u8 = 249;
const MASK: u32 = 0x00ff_0000;
const B: u32 = 1000; // rule_priority_base
const T: u32 = 1000; // table_base

fn enc(v: u32) -> u32 {
    v << MASK.trailing_zeros()
}

// ---------------------------------------------------------------------------
// Low-level request helper: raw flags, errno and extended ack.

#[derive(Debug)]
struct NlError {
    errno: i32,
    extack: Option<String>,
}

impl std::fmt::Display for NlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let e = std::io::Error::from_raw_os_error(self.errno);
        match &self.extack {
            Some(m) => write!(f, "errno {} ({e}), extack \"{m}\"", self.errno),
            None => write!(f, "errno {} ({e}), no extack", self.errno),
        }
    }
}

/// Parse the extended acknowledgement TLVs that follow the echoed request in
/// an NLMSG_ERROR payload. `capped` tells whether NETLINK_CAP_ACK is set on
/// the socket (then only the 16-byte request header is echoed).
fn parse_extack(payload: &[u8], capped: bool) -> Option<String> {
    if payload.len() < 16 {
        return None;
    }
    let orig_len = u32::from_ne_bytes(payload[0..4].try_into().ok()?) as usize;
    let mut off = if capped { 16 } else { (orig_len + 3) & !3 };
    while off + 4 <= payload.len() {
        let len = u16::from_ne_bytes(payload[off..off + 2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(payload[off + 2..off + 4].try_into().ok()?) & 0x3fff;
        if len < 4 || off + len > payload.len() {
            return None;
        }
        if kind == 1 {
            // NLMSGERR_ATTR_MSG: NUL-terminated string
            let s = &payload[off + 4..off + len];
            let s = s.split(|b| *b == 0).next().unwrap_or(&[]);
            return Some(String::from_utf8_lossy(s).into_owned());
        }
        off += (len + 3) & !3;
    }
    None
}

struct Nl {
    handle: Handle,
    capped: bool,
}

impl Nl {
    /// Send one request with explicit flags; collect all replies until done.
    async fn req(
        &mut self,
        msg: RouteNetlinkMessage,
        flags: u16,
    ) -> Result<Vec<NetlinkMessage<RouteNetlinkMessage>>, NlError> {
        let mut req = NetlinkMessage::from(msg);
        req.header.flags = flags;
        let mut resp = self.handle.request(req).map_err(|_| NlError {
            errno: 0,
            extack: Some("request failed".into()),
        })?;
        let mut out = Vec::new();
        while let Some(m) = resp.next().await {
            if let NetlinkPayload::Error(e) = &m.payload {
                if let Some(code) = e.code {
                    return Err(NlError {
                        errno: -code.get(),
                        extack: parse_extack(&e.header, self.capped),
                    });
                }
                continue; // ACK
            }
            out.push(m);
        }
        Ok(out)
    }

    async fn mutate(&mut self, msg: RouteNetlinkMessage, flags: u16) -> Result<(), NlError> {
        self.req(msg, NLM_F_REQUEST | NLM_F_ACK | flags).await.map(|_| ())
    }

    async fn dump_rules(&mut self, family: AddressFamily) -> Vec<RuleMessage> {
        let mut m = RuleMessage::default();
        m.header.family = family;
        let r = self
            .req(RouteNetlinkMessage::GetRule(m), NLM_F_REQUEST | NLM_F_DUMP)
            .await;
        match r {
            Ok(v) => v
                .into_iter()
                .filter_map(|m| match m.payload {
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(r)) => Some(r),
                    _ => None,
                })
                .collect(),
            Err(e) => {
                println!("FAIL rule dump: {e}");
                vec![]
            }
        }
    }

    /// Route dump; with strict checking the kernel filters by the header
    /// table/protocol/type and by RTA_TABLE.
    async fn dump_routes(
        &mut self,
        family: AddressFamily,
        table: Option<u32>,
        protocol: RouteProtocol,
    ) -> Result<(Vec<RouteMessage>, u16), NlError> {
        let mut m = RouteMessage::default();
        m.header.address_family = family;
        m.header.protocol = protocol;
        m.header.kind = RouteType::Unspec;
        m.header.scope = RouteScope::Universe;
        if let Some(t) = table {
            m.attributes.push(RouteAttribute::Table(t));
        }
        let v = self
            .req(RouteNetlinkMessage::GetRoute(m), NLM_F_REQUEST | NLM_F_DUMP)
            .await?;
        let mut flags = 0;
        let routes = v
            .into_iter()
            .filter_map(|m| {
                flags |= m.header.flags;
                match m.payload {
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(r)) => Some(r),
                    _ => None,
                }
            })
            .collect();
        Ok((routes, flags))
    }
}

async fn connect(ext_ack: bool, cap_ack: bool, strict: bool) -> Nl {
    let (mut conn, handle, _unsolicited) = rtnetlink::new_connection().expect("netlink socket");
    {
        let s = conn.socket_mut().socket_mut();
        s.set_ext_ack(ext_ack).expect("NETLINK_EXT_ACK");
        s.set_cap_ack(cap_ack).expect("NETLINK_CAP_ACK");
        s.set_netlink_get_strict_chk(strict).expect("NETLINK_GET_STRICT_CHK");
    }
    tokio::spawn(conn);
    Nl {
        handle,
        capped: cap_ack,
    }
}

fn check(ok: bool, what: &str) {
    println!("{} {what}", if ok { "PASS" } else { "FAIL" });
}

// ---------------------------------------------------------------------------
// Rule construction and description.

#[derive(Clone, Debug)]
struct Rule {
    family: AddressFamily,
    priority: u32,
    fwmark: Option<(u32, u32)>,
    from: Option<(IpAddr, u8)>,
    action: RuleAction,
    table: u32,
    suppress_prefixlen: Option<u32>,
}

impl Rule {
    fn msg(&self) -> RuleMessage {
        let mut m = RuleMessage::default();
        m.header.family = self.family;
        m.header.action = self.action;
        // Table 0 in the header; the real id goes into FRA_TABLE (u32).
        m.header.table = 0;
        m.attributes.push(RuleAttribute::Priority(self.priority));
        m.attributes.push(RuleAttribute::Protocol(RouteProtocol::Other(PROTO)));
        if self.action == RuleAction::ToTable {
            m.attributes.push(RuleAttribute::Table(self.table));
        }
        if let Some((mark, mask)) = self.fwmark {
            m.attributes.push(RuleAttribute::FwMark(mark));
            m.attributes.push(RuleAttribute::FwMask(mask));
        }
        if let Some((addr, len)) = self.from {
            m.header.src_len = len;
            m.attributes.push(RuleAttribute::Source(addr));
        }
        if let Some(p) = self.suppress_prefixlen {
            m.attributes.push(RuleAttribute::SuppressPrefixLen(p));
        }
        m
    }
}

fn describe_rule(r: &RuleMessage) -> String {
    let mut prio = 0;
    let mut table = r.header.table as u32;
    let (mut mark, mut mask, mut src, mut proto, mut spl) = (None, None, None, None, None);
    for a in &r.attributes {
        match a {
            RuleAttribute::Priority(p) => prio = *p,
            RuleAttribute::Table(t) => table = *t,
            RuleAttribute::FwMark(m) => mark = Some(*m),
            RuleAttribute::FwMask(m) => mask = Some(*m),
            RuleAttribute::Source(a) => src = Some(*a),
            RuleAttribute::Protocol(p) => proto = Some(u8::from(*p)),
            RuleAttribute::SuppressPrefixLen(p) => spl = Some(*p),
            _ => {}
        }
    }
    let mut s = format!("{prio}:");
    if let Some(a) = src {
        s += &format!(" from {a}/{}", r.header.src_len);
    }
    if mark.is_some() || mask.is_some() {
        s += &format!(" fwmark {:#x}/{:#x}", mark.unwrap_or(0), mask.unwrap_or(0));
    }
    match r.header.action {
        RuleAction::ToTable => s += &format!(" lookup {table}"),
        a => s += &format!(" {a:?} (hdr table {})", r.header.table),
    }
    if let Some(p) = spl {
        s += &format!(" suppress_prefixlength {p}");
    }
    if let Some(p) = proto {
        s += &format!(" proto {p}");
    }
    s
}

/// The full FR-ROUTE-3 layout for uplinks `ids`, with one local address each.
fn layout(family: AddressFamily, ids: &[u32], addrs: &[IpAddr]) -> Vec<Rule> {
    let base = Rule {
        family,
        priority: 0,
        fwmark: None,
        from: None,
        action: RuleAction::ToTable,
        table: 0,
        suppress_prefixlen: None,
    };
    let host = if family == AddressFamily::Inet { 32 } else { 128 };
    let mut v = Vec::new();
    for &id in ids {
        v.push(Rule {
            priority: B + id,
            fwmark: Some((enc(0x40 + id), MASK)),
            table: T + id,
            ..base.clone()
        });
    }
    v.push(Rule {
        priority: B + 64,
        fwmark: Some((enc(0x40), enc(0xc0))),
        action: RuleAction::Unreachable,
        ..base.clone()
    });
    v.push(Rule {
        priority: B + 100,
        table: 254,
        suppress_prefixlen: Some(0),
        ..base.clone()
    });
    for &id in ids {
        v.push(Rule {
            priority: B + 200 + id,
            fwmark: Some((enc(id), MASK)),
            table: T + id,
            ..base.clone()
        });
    }
    for k in 0..6 {
        v.push(Rule {
            priority: B + 264,
            fwmark: Some((enc(1 << k), enc(0xc0 + (1 << k)))),
            action: RuleAction::Unreachable,
            ..base.clone()
        });
    }
    for &id in ids {
        v.push(Rule {
            priority: B + 300 + id,
            fwmark: Some((enc(0x80 + id), MASK)),
            table: T + 64 + id,
            ..base.clone()
        });
        v.push(Rule {
            priority: B + 400 + id,
            fwmark: Some((enc(0xc0 + id), MASK)),
            table: T + 128 + id,
            ..base.clone()
        });
    }
    v.push(Rule {
        priority: B + 464,
        fwmark: Some((enc(0xc0), enc(0xc0))),
        action: RuleAction::Unreachable,
        ..base.clone()
    });
    for (&id, &a) in ids.iter().zip(addrs) {
        v.push(Rule {
            priority: B + 500 + id,
            from: Some((a, host)),
            fwmark: Some((0, MASK)),
            table: T + id,
            ..base.clone()
        });
        v.push(Rule {
            priority: B + 564,
            from: Some((a, host)),
            fwmark: Some((0, MASK)),
            action: RuleAction::Unreachable,
            ..base.clone()
        });
    }
    v.push(Rule {
        priority: B + 600,
        table: T,
        ..base.clone()
    });
    v.push(Rule {
        priority: B + 699,
        action: RuleAction::Unreachable,
        ..base
    });
    v
}

fn ours(r: &RuleMessage) -> bool {
    r.attributes
        .iter()
        .any(|a| matches!(a, RuleAttribute::Protocol(p) if u8::from(*p) == PROTO))
}

async fn test_rules(nl: &mut Nl) {
    println!("== rules");
    for (family, addrs) in [
        (
            AddressFamily::Inet,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            ],
        ),
        (
            AddressFamily::Inet6,
            vec![
                IpAddr::V6("2001:db8:1::2".parse().unwrap()),
                IpAddr::V6("2001:db8:2::2".parse().unwrap()),
            ],
        ),
    ] {
        let rules = layout(family, &[1, 2], &addrs);
        let mut ok = true;
        for r in &rules {
            if let Err(e) = nl
                .mutate(RouteNetlinkMessage::NewRule(r.msg()), NLM_F_CREATE | NLM_F_EXCL)
                .await
            {
                println!("FAIL add rule {:?}: {e}", r);
                ok = false;
            }
        }
        check(
            ok,
            &format!(
                "{family:?}: add {} FR-ROUTE-3 rules with NLM_F_CREATE|NLM_F_EXCL",
                rules.len()
            ),
        );

        let dumped: Vec<_> = nl.dump_rules(family).await.into_iter().filter(ours).collect();
        check(
            dumped.len() == rules.len(),
            &format!(
                "{family:?}: dump returns {} rules tagged proto {PROTO} (expected {})",
                dumped.len(),
                rules.len()
            ),
        );
        for r in dumped
            .iter()
            .take(3)
            .chain(dumped.iter().filter(|r| describe_rule(r).contains("from")).take(2))
        {
            println!("INFO   {}", describe_rule(r));
        }
        // fwmark 0/mask: does the dump carry FRA_FWMARK=0 or only FRA_FWMASK?
        if let Some(r) = dumped
            .iter()
            .find(|r| r.attributes.iter().any(|a| matches!(a, RuleAttribute::Source(_))))
        {
            let has_mark = r.attributes.iter().any(|a| matches!(a, RuleAttribute::FwMark(_)));
            let has_mask = r.attributes.iter().any(|a| matches!(a, RuleAttribute::FwMask(_)));
            println!("INFO {family:?}: zero-field selector dumped with FRA_FWMARK={has_mark} FRA_FWMASK={has_mask}");
        }
        // Unreachable action: what table does the dump report?
        if let Some(r) = dumped.iter().find(|r| r.header.action == RuleAction::Unreachable) {
            let t = r.attributes.iter().find_map(|a| {
                if let RuleAttribute::Table(t) = a {
                    Some(*t)
                } else {
                    None
                }
            });
            println!(
                "INFO {family:?}: unreachable rule dumped with header table {} FRA_TABLE {:?}",
                r.header.table, t
            );
        }

        // Duplicate add with EXCL -> EEXIST.
        let dup = rules[0].msg();
        let e = nl
            .mutate(RouteNetlinkMessage::NewRule(dup.clone()), NLM_F_CREATE | NLM_F_EXCL)
            .await;
        check(
            matches!(&e, Err(e) if e.errno == libc_eexist()),
            &format!(
                "{family:?}: duplicate rule with EXCL rejected: {:?}",
                e.as_ref().err().map(|e| e.to_string())
            ),
        );
        // Same rule with a different protocol and EXCL: is protocol part of the identity?
        let mut other = dup.clone();
        for a in other.attributes.iter_mut() {
            if let RuleAttribute::Protocol(p) = a {
                *p = RouteProtocol::Static;
            }
        }
        let e = nl
            .mutate(RouteNetlinkMessage::NewRule(other.clone()), NLM_F_CREATE | NLM_F_EXCL)
            .await;
        println!(
            "INFO {family:?}: same rule, proto static, EXCL -> {:?}",
            e.as_ref().err().map(|e| e.to_string())
        );
        if e.is_ok() {
            let _ = nl.mutate(RouteNetlinkMessage::DelRule(other), 0).await;
        }
        // NLM_F_REPLACE (what rtnetlink's RuleAddRequest::replace() sends): replace or duplicate?
        let before = nl.dump_rules(family).await.into_iter().filter(ours).count();
        let e = nl
            .mutate(RouteNetlinkMessage::NewRule(dup.clone()), NLM_F_CREATE | NLM_F_REPLACE)
            .await;
        let after = nl.dump_rules(family).await.into_iter().filter(ours).count();
        println!(
            "INFO {family:?}: NLM_F_CREATE|NLM_F_REPLACE on an existing rule -> {:?}, rules {before} -> {after}",
            e.err().map(|e| e.to_string())
        );
        if after > before {
            let _ = nl.mutate(RouteNetlinkMessage::DelRule(dup.clone()), 0).await;
        }

        // Delete by exact key (constructed message, not the dumped one).
        let target = rules.iter().find(|r| r.from.is_some()).unwrap().clone();
        let e = nl.mutate(RouteNetlinkMessage::DelRule(target.msg()), 0).await;
        check(
            e.is_ok(),
            &format!(
                "{family:?}: delete `from` rule by constructed key: {:?}",
                e.err().map(|e| e.to_string())
            ),
        );
        let e = nl.mutate(RouteNetlinkMessage::DelRule(target.msg()), 0).await;
        println!("INFO {family:?}: delete again -> {:?}", e.err().map(|e| e.to_string()));
        // Deleting a rule identified only by priority would match the first rule with that priority:
        // check that the six path-guard rules at the same priority are distinguished by mark/mask.
        let guard = rules
            .iter()
            .find(|r| r.priority == B + 264 && r.fwmark == Some((enc(4), enc(0xc4))))
            .unwrap();
        let e = nl.mutate(RouteNetlinkMessage::DelRule(guard.msg()), 0).await;
        let left: Vec<_> = nl
            .dump_rules(family)
            .await
            .into_iter()
            .filter(ours)
            .filter(|r| describe_rule(r).starts_with(&format!("{}:", B + 264)))
            .map(|r| describe_rule(&r))
            .collect();
        check(
            e.is_ok() && left.len() == 5 && !left.iter().any(|s| s.contains("0x40000/0xc40000")),
            &format!(
                "{family:?}: delete one of six same-priority guards by mark/mask, {} left",
                left.len()
            ),
        );

        // Delete everything we own, using the dumped messages.
        let mut n = 0;
        for r in nl.dump_rules(family).await.into_iter().filter(ours) {
            if nl.mutate(RouteNetlinkMessage::DelRule(r), 0).await.is_ok() {
                n += 1;
            }
        }
        let rest = nl.dump_rules(family).await.into_iter().filter(ours).count();
        check(
            rest == 0,
            &format!("{family:?}: deleted {n} rules from their dumps, {rest} left"),
        );
    }
}

fn libc_eexist() -> i32 {
    17
}

// ---------------------------------------------------------------------------
// Routes.

async fn ifindex(nl: &mut Nl, name: &str) -> u32 {
    let mut s = nl.handle.link().get().match_name(name.to_string()).execute();
    s.next().await.expect("link").expect("link").header.index
}

fn nh_v4(gw: Option<Ipv4Addr>, oif: u32, weight: u16, onlink: bool) -> RouteNextHop {
    let mut b = RouteNextHopBuilder::new_ipv4()
        .interface(oif)
        .weight((weight - 1) as u8);
    if let Some(g) = gw {
        b = b.via(IpAddr::V4(g)).unwrap();
    }
    if onlink {
        b = b.onlink();
    }
    b.build()
}

fn nh_v6(gw: Ipv6Addr, oif: u32, weight: u16) -> RouteNextHop {
    RouteNextHopBuilder::new_ipv6()
        .interface(oif)
        .weight((weight - 1) as u8)
        .via(IpAddr::V6(gw))
        .unwrap()
        .build()
}

fn default_route(family: AddressFamily, table: u32) -> RouteMessage {
    let mut m = RouteMessage::default();
    m.header.address_family = family;
    m.header.table = RouteHeader::RT_TABLE_UNSPEC;
    m.header.protocol = RouteProtocol::Other(PROTO);
    m.header.scope = RouteScope::Universe;
    m.header.kind = RouteType::Unicast;
    m.attributes.push(RouteAttribute::Table(table));
    m.attributes.push(RouteAttribute::Priority(100));
    m
}

fn describe_route(r: &RouteMessage) -> String {
    let mut s = String::new();
    let mut table = r.header.table as u32;
    let mut parts = Vec::new();
    for a in &r.attributes {
        match a {
            RouteAttribute::Table(t) => table = *t,
            RouteAttribute::Priority(p) => parts.push(format!("metric {p}")),
            RouteAttribute::Gateway(g) => parts.push(format!("via {}", addr(g))),
            RouteAttribute::Oif(i) => parts.push(format!("oif {i}")),
            RouteAttribute::PrefSource(a) => parts.push(format!("src {}", addr(a))),
            RouteAttribute::Preference(p) => parts.push(format!("pref {p:?}")),
            RouteAttribute::NhId(i) => parts.push(format!("nhid {i}")),
            RouteAttribute::MultiPath(hops) => {
                for h in hops {
                    let gw = h.attributes.iter().find_map(|a| {
                        if let RouteAttribute::Gateway(g) = a {
                            Some(addr(g))
                        } else {
                            None
                        }
                    });
                    parts.push(format!(
                        "[nexthop via {} oif {} weight {} flags {:?}]",
                        gw.unwrap_or_else(|| "-".into()),
                        h.interface_index,
                        h.hops as u16 + 1,
                        h.flags
                    ));
                }
            }
            _ => {}
        }
    }
    s += &format!(
        "table {table} proto {} type {:?} flags {:?} ",
        u8::from(r.header.protocol),
        r.header.kind,
        r.header.flags
    );
    s += &parts.join(" ");
    s
}

fn addr(a: &RouteAddress) -> String {
    match a {
        RouteAddress::Inet(a) => a.to_string(),
        RouteAddress::Inet6(a) => a.to_string(),
        o => format!("{o:?}"),
    }
}

fn hops(r: &RouteMessage) -> usize {
    r.attributes
        .iter()
        .find_map(|a| {
            if let RouteAttribute::MultiPath(h) = a {
                Some(h.len())
            } else {
                None
            }
        })
        .unwrap_or(1)
}

async fn table_routes(nl: &mut Nl, family: AddressFamily, table: u32) -> Vec<RouteMessage> {
    match nl.dump_routes(family, Some(table), RouteProtocol::Other(PROTO)).await {
        Ok((v, _)) => v,
        Err(e) => {
            println!("FAIL dump table {table}: {e}");
            vec![]
        }
    }
}

async fn test_routes(nl: &mut Nl) {
    println!("== routes");
    let d1 = ifindex(nl, "d1").await;
    let d2 = ifindex(nl, "d2").await;
    let p0 = ifindex(nl, "p0").await;
    let g6 = ifindex(nl, "g6").await;
    let gw1 = Ipv4Addr::new(192, 0, 2, 1);
    let gw2 = Ipv4Addr::new(198, 51, 100, 1);
    let v4 = AddressFamily::Inet;
    let v6 = AddressFamily::Inet6;

    // IPv4 inline multipath: two gateways and a device-only point-to-point member.
    let mut m = default_route(v4, T);
    m.attributes.push(RouteAttribute::MultiPath(vec![
        nh_v4(Some(gw1), d1, 10, false),
        nh_v4(Some(gw2), d2, 3, false),
        nh_v4(None, p0, 1, false),
    ]));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    check(
        e.is_ok(),
        &format!(
            "v4 multipath (2 gateways + device-only ptp member) in table {T} with CREATE|REPLACE: {:?}",
            e.err().map(|e| e.to_string())
        ),
    );
    let r = table_routes(nl, v4, T).await;
    check(
        r.len() == 1 && hops(&r[0]) == 3,
        &format!(
            "v4 dump of table {T}: {} route(s), {} hops",
            r.len(),
            r.first().map(hops).unwrap_or(0)
        ),
    );
    for x in &r {
        println!("INFO   {}", describe_route(x));
    }
    // Replace with a single nexthop expressed as RTA_GATEWAY + RTA_OIF (one-member active set).
    let mut m = default_route(v4, T);
    m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(gw2)));
    m.attributes.push(RouteAttribute::Oif(d2));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let r = table_routes(nl, v4, T).await;
    check(
        e.is_ok() && r.len() == 1 && hops(&r[0]) == 1,
        &format!(
            "v4 replace multipath -> single nexthop: {} route(s) {:?}",
            r.len(),
            r.first().map(describe_route)
        ),
    );
    // And back to multipath with new weights.
    let mut m = default_route(v4, T);
    m.attributes.push(RouteAttribute::MultiPath(vec![
        nh_v4(Some(gw1), d1, 1, false),
        nh_v4(Some(gw2), d2, 256, false),
    ]));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let r = table_routes(nl, v4, T).await;
    check(
        e.is_ok() && r.len() == 1 && hops(&r[0]) == 2,
        &format!(
            "v4 replace single -> multipath weights 1/256: {:?}",
            r.first().map(describe_route)
        ),
    );

    // Path table with src; ptp path; onlink gateway outside the connected prefix.
    let mut m = default_route(v4, T + 1);
    m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(gw1)));
    m.attributes.push(RouteAttribute::Oif(d1));
    m.attributes
        .push(RouteAttribute::PrefSource(RouteAddress::Inet(Ipv4Addr::new(
            192, 0, 2, 2,
        ))));
    let e1 = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let mut m = default_route(v4, T + 3);
    m.attributes.push(RouteAttribute::Oif(p0));
    m.attributes
        .push(RouteAttribute::PrefSource(RouteAddress::Inet(Ipv4Addr::new(
            203, 0, 113, 2,
        ))));
    let e2 = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    check(
        e1.is_ok() && e2.is_ok(),
        &format!(
            "v4 path routes `via gw dev d1 src` and `dev p0 src`: {:?} {:?}",
            e1.err().map(|e| e.to_string()),
            e2.err().map(|e| e.to_string())
        ),
    );
    let mut m = default_route(v4, T + 2);
    m.attributes
        .push(RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(10, 99, 0, 1))));
    m.attributes.push(RouteAttribute::Oif(d1));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m.clone()), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    println!(
        "INFO v4 off-subnet gateway without onlink -> {:?}",
        e.err().map(|e| e.to_string())
    );
    m.header.flags.insert(RouteFlags::Onlink);
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let r = table_routes(nl, v4, T + 2).await;
    check(
        e.is_ok()
            && r.first()
                .map(|r| r.header.flags.contains(RouteFlags::Onlink))
                .unwrap_or(false),
        &format!("v4 off-subnet gateway with onlink: {:?}", r.first().map(describe_route)),
    );
    // onlink inside a multipath member
    let mut m = default_route(v4, T + 66);
    m.attributes.push(RouteAttribute::MultiPath(vec![
        nh_v4(Some(Ipv4Addr::new(10, 99, 0, 1)), d1, 1, true),
        nh_v4(Some(gw2), d2, 1, false),
    ]));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let r = table_routes(nl, v4, T + 66).await;
    check(
        e.is_ok() && hops(&r[0]) == 2,
        &format!(
            "v4 multipath with an onlink member: {:?}",
            r.first().map(describe_route)
        ),
    );

    // Strict-checked dump filtered by table and protocol: only our route comes back.
    match nl.dump_routes(v4, Some(T), RouteProtocol::Other(PROTO)).await {
        Ok((v, flags)) => check(
            v.len() == 1 && flags & NLM_F_DUMP_FILTERED != 0,
            &format!(
                "v4 strict dump filtered by RTA_TABLE+protocol: {} route(s), NLM_F_DUMP_FILTERED={}",
                v.len(),
                flags & NLM_F_DUMP_FILTERED != 0
            ),
        ),
        Err(e) => println!("FAIL filtered dump: {e}"),
    }
    // Whole-family dump filtered by protocol only: all our routes across tables.
    if let Ok((v, _)) = nl.dump_routes(v4, None, RouteProtocol::Other(PROTO)).await {
        println!(
            "INFO v4 strict dump filtered by protocol {PROTO} only: {} route(s)",
            v.len()
        );
    }
    // Pitfall: a dump request built with RouteMessageBuilder defaults (protocol static, type unicast).
    let req = RouteMessageBuilder::<Ipv4Addr>::new().table_id(T).build();
    let n = nl.handle.route().get(req).execute().collect::<Vec<_>>().await.len();
    println!(
        "INFO v4 rtnetlink route().get(RouteMessageBuilder::new().table_id({T})) on a strict socket returns {n} route(s) (builder sets protocol=static)"
    );

    // Delete by exact key: table, family, default, metric 100.
    let e = nl.mutate(RouteNetlinkMessage::DelRoute(default_route(v4, T)), 0).await;
    let r = table_routes(nl, v4, T).await;
    check(
        e.is_ok() && r.is_empty(),
        &format!(
            "v4 delete multipath by exact key (no nexthops given): {:?}",
            e.err().map(|e| e.to_string())
        ),
    );
    let mut k = default_route(v4, T + 1);
    k.header.protocol = RouteProtocol::Static;
    let e = nl.mutate(RouteNetlinkMessage::DelRoute(k), 0).await;
    println!(
        "INFO v4 delete with protocol=static (rtnetlink builder default) on a proto {PROTO} route -> {:?}",
        e.err().map(|e| e.to_string())
    );
    let mut k = default_route(v4, T + 1);
    k.attributes.retain(|a| !matches!(a, RouteAttribute::Priority(_)));
    k.attributes.push(RouteAttribute::Priority(200));
    let e = nl.mutate(RouteNetlinkMessage::DelRoute(k), 0).await;
    println!(
        "INFO v4 delete with a different metric -> {:?}",
        e.err().map(|e| e.to_string())
    );
    let e = nl
        .mutate(RouteNetlinkMessage::DelRoute(default_route(v4, T + 1)), 0)
        .await;
    check(
        e.is_ok(),
        &format!(
            "v4 delete path route by exact key: {:?}",
            e.err().map(|e| e.to_string())
        ),
    );

    // IPv6: identical link-local gateway on two interfaces, weights; ptp member with link-local gateway.
    let ll: Ipv6Addr = "fe80::1".parse().unwrap();
    let mut m = default_route(v6, T);
    m.attributes
        .push(RouteAttribute::MultiPath(vec![nh_v6(ll, d1, 10), nh_v6(ll, d2, 3)]));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let r = table_routes(nl, v6, T).await;
    check(
        e.is_ok() && r.len() == 1 && hops(&r[0]) == 2,
        &format!(
            "v6 multipath fe80::1 dev d1 + fe80::1 dev d2: {} message(s) {:?}",
            r.len(),
            r.iter().map(describe_route).collect::<Vec<_>>()
        ),
    );
    let mut m = default_route(v6, T);
    m.attributes.push(RouteAttribute::MultiPath(vec![
        nh_v6(ll, d1, 1),
        nh_v6(ll, d2, 1),
        nh_v6(ll, g6, 1),
    ]));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let r = table_routes(nl, v6, T).await;
    check(
        e.is_ok() && r.len() == 1 && hops(&r[0]) == 3,
        &format!(
            "v6 replace with 3 members incl. ptp g6 via fe80::1: {:?}",
            r.iter().map(describe_route).collect::<Vec<_>>()
        ),
    );
    let mut m = default_route(v6, T);
    m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet6(ll)));
    m.attributes.push(RouteAttribute::Oif(g6));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let r = table_routes(nl, v6, T).await;
    check(
        e.is_ok() && r.len() == 1 && hops(&r[0]) == 1,
        &format!(
            "v6 replace 3 members -> single ptp member: {:?}",
            r.iter().map(describe_route).collect::<Vec<_>>()
        ),
    );
    // A single-member RTA_MULTIPATH with NLM_F_REPLACE over a single route.
    let mut m = default_route(v6, T);
    m.attributes.push(RouteAttribute::MultiPath(vec![nh_v6(ll, d1, 1)]));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let r = table_routes(nl, v6, T).await;
    println!(
        "INFO v6 replace single -> single-member RTA_MULTIPATH: {:?} -> {:?}",
        e.err().map(|e| e.to_string()),
        r.iter().map(describe_route).collect::<Vec<_>>()
    );
    // Device-only member in IPv6 multipath: expected rejection (Q12), shows extack.
    let mut m = default_route(v6, T + 5);
    let mut dev_only = RouteNextHopBuilder::new_ipv6().interface(g6).build();
    dev_only.flags = RouteNextHopFlags::empty();
    m.attributes
        .push(RouteAttribute::MultiPath(vec![nh_v6(ll, d1, 1), dev_only]));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    println!(
        "INFO v6 multipath with a device-only member -> {:?}",
        e.err().map(|e| e.to_string())
    );
    // Path route with src.
    let mut m = default_route(v6, T + 1);
    m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet6(ll)));
    m.attributes.push(RouteAttribute::Oif(d1));
    m.attributes.push(RouteAttribute::PrefSource(RouteAddress::Inet6(
        "2001:db8:1::2".parse().unwrap(),
    )));
    let e = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    check(
        e.is_ok(),
        &format!(
            "v6 path route via fe80::1 dev d1 src 2001:db8:1::2: {:?}",
            e.err().map(|e| e.to_string())
        ),
    );
    // Delete IPv6 multipath by exact key (no nexthops): removes all siblings?
    let mut m = default_route(v6, T);
    m.attributes
        .push(RouteAttribute::MultiPath(vec![nh_v6(ll, d1, 1), nh_v6(ll, d2, 1)]));
    let _ = nl
        .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await;
    let e = nl.mutate(RouteNetlinkMessage::DelRoute(default_route(v6, T)), 0).await;
    let r = table_routes(nl, v6, T).await;
    check(
        e.is_ok() && r.is_empty(),
        &format!(
            "v6 delete 2-member multipath by exact key: {:?}, {} left {:?}",
            e.err().map(|e| e.to_string()),
            r.len(),
            r.iter().map(describe_route).collect::<Vec<_>>()
        ),
    );
    let e = nl.mutate(RouteNetlinkMessage::DelRoute(default_route(v6, T)), 0).await;
    println!(
        "INFO v6 delete of a missing route -> {:?}",
        e.err().map(|e| e.to_string())
    );

    // Clean all our routes using the dumped messages.
    for fam in [v4, v6] {
        if let Ok((v, _)) = nl.dump_routes(fam, None, RouteProtocol::Other(PROTO)).await {
            for r in v {
                let _ = nl.mutate(RouteNetlinkMessage::DelRoute(r), 0).await;
            }
        }
        let left = nl
            .dump_routes(fam, None, RouteProtocol::Other(PROTO))
            .await
            .map(|v| v.0.len())
            .unwrap_or(99);
        check(
            left == 0,
            &format!("{fam:?}: delete all proto {PROTO} routes from their dumps, {left} left"),
        );
    }
}

// ---------------------------------------------------------------------------
// Extended acknowledgement.

async fn test_extack() {
    println!("== extack");
    for (ext, cap) in [(false, false), (true, false), (true, true)] {
        let mut nl = connect(ext, cap, true).await;
        let d1 = ifindex(&mut nl, "d1").await;
        let mut m = default_route(AddressFamily::Inet, T + 7);
        m.attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(10, 99, 0, 1))));
        m.attributes.push(RouteAttribute::Oif(d1));
        let e1 = nl
            .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_EXCL)
            .await
            .err();
        let mut r = Rule {
            family: AddressFamily::Inet,
            priority: B + 699,
            fwmark: None,
            from: None,
            action: RuleAction::Unreachable,
            table: 0,
            suppress_prefixlen: None,
        }
        .msg();
        r.attributes.push(RuleAttribute::Iifname("x".repeat(20)));
        let e2 = nl
            .mutate(RouteNetlinkMessage::NewRule(r), NLM_F_CREATE | NLM_F_EXCL)
            .await
            .err();
        let e3 = nl
            .mutate(
                RouteNetlinkMessage::DelRoute(default_route(AddressFamily::Inet6, T + 7)),
                0,
            )
            .await
            .err();
        println!("INFO EXT_ACK={ext} CAP_ACK={cap}:");
        for (what, e) in [
            ("off-subnet gateway", e1),
            ("iifname too long", e2),
            ("delete missing v6 route", e3),
        ] {
            println!(
                "INFO   {what}: {}",
                e.map(|e| e.to_string()).unwrap_or_else(|| "no error".into())
            );
        }
    }
    // The high-level rtnetlink API: what does the caller get?
    let (conn, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(conn);
    let req = RouteMessageBuilder::<Ipv4Addr>::new()
        .table_id(T + 7)
        .gateway(Ipv4Addr::new(10, 99, 0, 1))
        .output_interface(1)
        .build();
    match handle.route().add(req).execute().await {
        Err(rtnetlink::Error::NetlinkError(e)) => println!(
            "INFO rtnetlink high-level error: code {:?}, Display \"{e}\", payload {} bytes (extack only if the caller enabled NETLINK_EXT_ACK and parses the payload)",
            e.code,
            e.header.len()
        ),
        other => println!("INFO rtnetlink high-level result: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Notifications.

type Unsolicited = UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

fn describe_notification(m: &NetlinkMessage<RouteNetlinkMessage>) -> String {
    let h = &m.header;
    let body = match &m.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(l)) => format!("NewLink {}", link_desc(l)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(l)) => format!("DelLink {}", link_desc(l)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(a)) => format!("NewAddress {}", addr_desc(a)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(a)) => format!("DelAddress {}", addr_desc(a)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(r)) => format!("NewRoute {}", describe_route(r)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(r)) => format!("DelRoute {}", describe_route(r)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(r)) => format!("NewRule {}", describe_rule(r)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRule(r)) => format!("DelRule {}", describe_rule(r)),
        NetlinkPayload::Overrun(_) => "OVERRUN (ENOBUFS)".into(),
        p => format!("{p:?}").chars().take(80).collect(),
    };
    format!(
        "seq {} portid {} flags {:#x}: {body}",
        h.sequence_number, h.port_number, h.flags
    )
}

fn link_desc(l: &LinkMessage) -> String {
    let name = l
        .attributes
        .iter()
        .find_map(|a| {
            if let LinkAttribute::IfName(n) = a {
                Some(n.clone())
            } else {
                None
            }
        })
        .unwrap_or_default();
    let carrier = l.attributes.iter().find_map(|a| {
        if let LinkAttribute::Carrier(c) = a {
            Some(*c)
        } else {
            None
        }
    });
    format!(
        "{name} idx {} up={} lower_up={} ptp={} carrier={carrier:?}",
        l.header.index,
        l.header.flags.contains(LinkFlags::Up),
        l.header.flags.contains(LinkFlags::LowerUp),
        l.header.flags.contains(LinkFlags::Pointopoint)
    )
}

fn addr_desc(a: &AddressMessage) -> String {
    let ip = a.attributes.iter().find_map(|x| match x {
        AddressAttribute::Local(ip) => Some(*ip),
        _ => None,
    });
    let ip = ip.or_else(|| {
        a.attributes.iter().find_map(|x| {
            if let AddressAttribute::Address(ip) = x {
                Some(*ip)
            } else {
                None
            }
        })
    });
    let flags = a.attributes.iter().find_map(|x| {
        if let AddressAttribute::Flags(f) = x {
            Some(*f)
        } else {
            None
        }
    });
    format!(
        "{:?}/{} idx {} scope {:?} flags {:?}",
        ip, a.header.prefix_len, a.header.index, a.header.scope, flags
    )
}

async fn drain(rx: &mut Unsolicited, ms: u64) -> Vec<NetlinkMessage<RouteNetlinkMessage>> {
    let mut v = Vec::new();
    while let Ok(Some((m, _))) = tokio::time::timeout(Duration::from_millis(ms), rx.next()).await {
        v.push(m);
    }
    v
}

const GROUPS: &[MulticastGroup] = &[
    MulticastGroup::Link,
    MulticastGroup::Ipv4Ifaddr,
    MulticastGroup::Ipv6Ifaddr,
    MulticastGroup::Ipv4Route,
    MulticastGroup::Ipv6Route,
    MulticastGroup::Ipv4Rule,
    MulticastGroup::Ipv6Rule,
];

async fn test_notify(nl: &mut Nl) {
    println!("== notify");
    // Observer socket: subscribe first, then dump on a separate socket, buffering notifications.
    let (conn, _obs_handle, mut rx) = rtnetlink::new_multicast_connection(GROUPS).unwrap();
    tokio::spawn(conn);
    let links = nl.handle.link().get().execute().collect::<Vec<_>>().await.len();
    let addrs = nl.handle.address().get().execute().collect::<Vec<_>>().await.len();
    println!("INFO dump after subscribe: {links} links, {addrs} addresses");
    let d1 = ifindex(nl, "d1").await;
    let gw1 = Ipv4Addr::new(192, 0, 2, 1);
    let ll: Ipv6Addr = "fe80::1".parse().unwrap();
    let d2 = ifindex(nl, "d2").await;

    // Changes made on another socket.
    let mut m = default_route(AddressFamily::Inet, T + 9);
    m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(gw1)));
    m.attributes.push(RouteAttribute::Oif(d1));
    nl.mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_EXCL)
        .await
        .unwrap();
    let r = Rule {
        family: AddressFamily::Inet6,
        priority: B + 699,
        fwmark: None,
        from: None,
        action: RuleAction::Unreachable,
        table: 0,
        suppress_prefixlen: None,
    };
    nl.mutate(RouteNetlinkMessage::NewRule(r.msg()), NLM_F_CREATE | NLM_F_EXCL)
        .await
        .unwrap();
    let mut m = default_route(AddressFamily::Inet6, T + 9);
    m.attributes
        .push(RouteAttribute::MultiPath(vec![nh_v6(ll, d1, 1), nh_v6(ll, d2, 1)]));
    nl.mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_EXCL)
        .await
        .unwrap();
    let mut m = default_route(AddressFamily::Inet6, T + 9);
    m.attributes
        .push(RouteAttribute::MultiPath(vec![nh_v6(ll, d2, 1), nh_v6(ll, d1, 2)]));
    nl.mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await
        .unwrap();
    let got = drain(&mut rx, 300).await;
    println!("INFO notifications for changes made on another socket ({}):", got.len());
    for m in &got {
        println!("INFO   {}", describe_notification(m));
    }
    check(
        got.iter()
            .any(|m| matches!(m.payload, NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(_))))
            && got.iter().any(|m| {
                matches!(
                    m.payload,
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(_))
                )
            }),
        "rule and route notifications received for changes made on another socket",
    );

    // External changes (ip link/addr, run.sh hook): link down/up, address add/del, a deprecated address.
    run(
        "ip link set d2 down; ip link set d2 up; ip addr add 192.0.2.77/24 dev d1; ip addr add 2001:db8:1::77/64 dev d1 preferred_lft 0 nodad; ip addr del 192.0.2.77/24 dev d1",
    );
    let got = drain(&mut rx, 300).await;
    println!("INFO notifications for ip link/addr changes ({}):", got.len());
    for m in &got {
        println!("INFO   {}", describe_notification(m));
    }
    check(
        got.iter()
            .any(|m| matches!(m.payload, NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(_))))
            && got.iter().any(|m| {
                matches!(
                    m.payload,
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(_))
                )
            }),
        "link and address notifications received",
    );
    run("ip addr del 2001:db8:1::77/64 dev d1");

    // Pitfall: the notification of a change made on the subscribed socket itself carries that
    // request's sequence number and is consumed as a reply to the pending request.
    let (conn, mut h2, mut rx2) = rtnetlink::new_multicast_connection(GROUPS).unwrap();
    tokio::spawn(conn);
    let mut m = default_route(AddressFamily::Inet, T + 10);
    m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(gw1)));
    m.attributes.push(RouteAttribute::Oif(d1));
    let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(m));
    req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    let replies: Vec<_> = h2.request(req).unwrap().collect().await;
    let got = drain(&mut rx2, 300).await;
    println!(
        "INFO change made on the subscribed socket itself: {} message(s) in the request's reply stream ({:?}), {} on the notification stream",
        replies.len(),
        replies.iter().map(describe_notification).collect::<Vec<_>>(),
        got.len()
    );

    // Cross-socket misrouting: the observer socket dumps a large table with its first request
    // (seq 1) while another socket's first request (also seq 1) adds a route. The notification
    // carries seq 1, and netlink-proto matches replies by sequence number and source port (the
    // kernel, 0) only, without checking the destination port id.
    run(
        "for j in $(seq 1 20000); do echo \"route add 10.66.$((j/250)).$((j%250))/32 via 192.0.2.1 dev d1 table 3002\"; done | ip -batch -",
    );
    let (conn, mut h3, mut rx3) = rtnetlink::new_multicast_connection(GROUPS).unwrap();
    tokio::spawn(conn);
    let mut dm = RouteMessage::default();
    dm.header.address_family = AddressFamily::Inet;
    let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(dm));
    req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    // Writer thread: 300 fresh sockets, each adding one route with its first request (seq 1).
    let writer = std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for j in 0..300u32 {
                let mut w = connect(true, true, true).await;
                let mut m = RouteMessage::default();
                m.header.address_family = AddressFamily::Inet;
                m.header.destination_prefix_length = 32;
                m.header.protocol = RouteProtocol::Other(PROTO);
                m.header.kind = RouteType::Unicast;
                m.attributes.push(RouteAttribute::Table(3003));
                m.attributes
                    .push(RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(
                        10,
                        55,
                        (j / 250) as u8,
                        (j % 250) as u8,
                    ))));
                m.attributes
                    .push(RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(192, 0, 2, 1))));
                w.mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_EXCL)
                    .await
                    .unwrap();
            }
        });
    });
    let mut dump = h3.request(req).unwrap();
    let first = dump.next().await;
    let mut in_dump = 0;
    let mut foreign_in_dump = 0;
    let mut next = first;
    loop {
        let Some(msg) = next.take() else {
            match tokio::time::timeout(Duration::from_millis(500), dump.next()).await {
                Ok(Some(m)) => {
                    next = Some(m);
                    continue;
                }
                _ => break,
            }
        };
        in_dump += 1;
        if msg.header.flags & NLM_F_MULTIPART == 0 {
            foreign_in_dump += 1;
            println!("INFO   in dump stream: {}", describe_notification(&msg));
        }
    }
    writer.join().unwrap();
    let on_stream = drain(&mut rx3, 500).await;
    let leaked = on_stream
        .iter()
        .filter(|m| m.header.flags & NLM_F_MULTIPART != 0)
        .count();
    let total = nl
        .dump_routes(AddressFamily::Inet, None, RouteProtocol::Unspec)
        .await
        .map(|v| v.0.len())
        .unwrap_or(0);
    println!(
        "INFO cross-socket seq collision: dump stream ended after {in_dump} message(s) of ~{total} ({foreign_in_dump} notification(s) inside it); notification stream got {} message(s), {leaked} of them dump replies",
        on_stream.len()
    );
    check(
        foreign_in_dump == 0 && leaked == 0,
        "observer dump not corrupted by a notification with a colliding sequence number",
    );
    run("ip route flush table 3002; ip route flush table 3003");

    for t in [9, 10, 11, 12] {
        let _ = nl
            .mutate(
                RouteNetlinkMessage::DelRoute(default_route(AddressFamily::Inet, T + t)),
                0,
            )
            .await;
    }
    let _ = nl
        .mutate(
            RouteNetlinkMessage::DelRoute(default_route(AddressFamily::Inet6, T + 9)),
            0,
        )
        .await;
    let _ = nl.mutate(RouteNetlinkMessage::DelRule(r.msg()), 0).await;
}

fn run(cmd: &str) {
    let st = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .expect("sh");
    assert!(st.success(), "{cmd}");
}

// ---------------------------------------------------------------------------
// NLM_F_DUMP_INTR and ENOBUFS.

async fn test_dump_intr() {
    println!("== dump_intr");
    // Populate many addresses and routes, then dump while another process churns them.
    run(
        "for i in $(seq 0 15); do for j in $(seq 1 250); do echo \"address add 10.200.$i.$j/32 dev d1\"; done; done | ip -batch -",
    );
    run(
        "for i in $(seq 0 79); do for j in $(seq 0 249); do echo \"route add 10.$((100+i/40)).$((i%40)).$j/32 via 192.0.2.1 dev d1 table 3000\"; done; done | ip -batch -",
    );
    let mut churn = std::process::Command::new("sh")
        .arg("-c")
        .arg("while true; do ip link add c0 type dummy; ip link del c0; ip addr add 10.201.0.1/32 dev d1; ip addr del 10.201.0.1/32 dev d1; ip route add 10.250.0.1/32 via 192.0.2.1 dev d1 table 3000; ip route del 10.250.0.1/32 table 3000; ip -6 route add 2001:db8:ff::1/128 via fe80::1 dev d1 table 3000; ip -6 route del 2001:db8:ff::1/128 table 3000; done")
        .spawn()
        .unwrap();
    let mut nl = connect(true, true, false).await;
    let (mut addr_intr, mut route_intr, mut route6_intr, mut rule_intr, mut link_intr) = (0, 0, 0, 0, 0);
    let rounds = 40;
    for _ in 0..rounds {
        for (kind, counter) in [
            (0, &mut addr_intr),
            (1, &mut route_intr),
            (2, &mut route6_intr),
            (3, &mut rule_intr),
            (4, &mut link_intr),
        ] {
            let msg = match kind {
                0 => RouteNetlinkMessage::GetAddress(AddressMessage::default()),
                1 => {
                    let mut m = RouteMessage::default();
                    m.header.address_family = AddressFamily::Inet;
                    RouteNetlinkMessage::GetRoute(m)
                }
                2 => {
                    let mut m = RouteMessage::default();
                    m.header.address_family = AddressFamily::Inet6;
                    RouteNetlinkMessage::GetRoute(m)
                }
                3 => RouteNetlinkMessage::GetRule(RuleMessage::default()),
                _ => RouteNetlinkMessage::GetLink(LinkMessage::default()),
            };
            match nl.req(msg, NLM_F_REQUEST | NLM_F_DUMP).await {
                Ok(v) => {
                    if v.iter().any(|m| m.header.flags & NLM_F_DUMP_INTR != 0) {
                        *counter += 1;
                    }
                }
                Err(e) => println!("FAIL dump: {e}"),
            }
        }
    }
    let _ = churn.kill();
    let _ = churn.wait();
    println!(
        "INFO dumps with NLM_F_DUMP_INTR on a data message over {rounds} rounds while churning: addresses {addr_intr}, v4 routes {route_intr}, v6 routes {route6_intr}, rules {rule_intr}, links {link_intr}"
    );
    println!(
        "INFO note: netlink-proto drops NLMSG_DONE unless Connection::set_forward_done(true); the flag can also be on DONE"
    );
    // Repeat with DONE forwarded to see whether the flag only appears there.
    let (mut conn, mut handle, _) = rtnetlink::new_connection().unwrap();
    conn.set_forward_done(true);
    tokio::spawn(conn);
    let mut churn = std::process::Command::new("sh")
        .arg("-c")
        .arg("while true; do ip addr add 10.201.0.1/32 dev d1; ip addr del 10.201.0.1/32 dev d1; done")
        .spawn()
        .unwrap();
    let (mut on_data, mut on_done) = (0, 0);
    for _ in 0..rounds {
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetAddress(AddressMessage::default()));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        let v: Vec<_> = handle.request(req).unwrap().collect().await;
        if v.iter()
            .any(|m| m.header.flags & NLM_F_DUMP_INTR != 0 && !matches!(m.payload, NetlinkPayload::Done(_)))
        {
            on_data += 1;
        }
        if v.iter()
            .any(|m| m.header.flags & NLM_F_DUMP_INTR != 0 && matches!(m.payload, NetlinkPayload::Done(_)))
        {
            on_done += 1;
        }
    }
    let _ = churn.kill();
    let _ = churn.wait();
    println!(
        "INFO address dumps with forward_done: DUMP_INTR on a data message in {on_data}/{rounds}, on NLMSG_DONE in {on_done}/{rounds}"
    );
    let _ = std::process::Command::new("sh").arg("-c").arg("ip route flush table 3000; ip -6 route flush table 3000 2>/dev/null; ip addr flush dev d1 to 10.200.0.0/16").status();
}

async fn test_enobufs() {
    println!("== enobufs");
    // Observer with a small receive buffer whose connection task starts only after a burst.
    let (mut conn, _h, mut rx) = rtnetlink::new_multicast_connection(&[MulticastGroup::Ipv4Route]).unwrap();
    conn.socket_mut().socket_mut().set_rx_buf_sz(4096usize).unwrap();
    run(
        "for j in $(seq 1 2000); do echo \"route add 10.77.$((j/250)).$((j%250))/32 via 192.0.2.1 dev d1 table 3001\"; done | ip -batch -",
    );
    tokio::spawn(conn);
    let got = drain(&mut rx, 500).await;
    let overruns = got
        .iter()
        .filter(|m| matches!(m.payload, NetlinkPayload::Overrun(_)))
        .count();
    println!(
        "INFO after a 2000-route burst into a 4 KiB receive buffer: {} message(s) delivered, {overruns} overrun marker(s)",
        got.len()
    );
    check(
        overruns >= 1,
        "ENOBUFS surfaces as NetlinkPayload::Overrun on the notification stream",
    );
    // The stream keeps working after the overrun.
    run("ip route add 10.78.0.1/32 via 192.0.2.1 dev d1 table 3001");
    let after = drain(&mut rx, 300).await;
    check(
        after.iter().any(|m| {
            matches!(
                m.payload,
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(_))
            )
        }),
        "notifications continue after the overrun",
    );
    run("ip route flush table 3001");
}

// ---------------------------------------------------------------------------
// Interrupted dumps: silent skips and duplicates (dumpskip).
//
// Dumps run on a blocking `netlink_sys::Socket` so that every datagram (one kernel batch) is visible, the read size
// (which sets the kernel's batch size) is controlled, and a change can be injected between two batches. An entry of
// the reference dump, taken before any churn, exists unchanged during every later dump, so it must appear exactly
// once in each of them.

const MSG_TRUNC: i32 = 0x20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_GETNEXTHOP: u16 = 106;
/// Read size of 4 KiB: the kernel then builds batches of about 4 KiB, like the first batch of any socket.
const SMALL_READ: usize = 4096;
/// Read size of 64 KiB (what `netlink-proto` uses): batches of up to 32 KiB after the first one.
const LARGE_READ: usize = 64 * 1024;
const MAX_BATCHES: usize = 5000;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Rule4,
    Rule6,
    Route4,
    Route6,
    Addr4,
    Addr6,
    Link,
    Nexthop,
}

impl Kind {
    fn ip(self) -> &'static str {
        match self {
            Kind::Rule6 | Kind::Route6 | Kind::Addr6 => "ip -6",
            _ => "ip",
        }
    }

    fn family(self) -> AddressFamily {
        match self {
            Kind::Rule6 | Kind::Route6 | Kind::Addr6 => AddressFamily::Inet6,
            Kind::Rule4 | Kind::Route4 | Kind::Addr4 => AddressFamily::Inet,
            _ => AddressFamily::Unspec,
        }
    }
}

fn dump_request(kind: Kind, seq: u32) -> Vec<u8> {
    if kind == Kind::Nexthop {
        // netlink-packet-route 0.33 has no nexthop messages: nlmsghdr + struct nhmsg (AF_UNSPEC).
        let mut b = Vec::with_capacity(24);
        b.extend_from_slice(&24u32.to_ne_bytes());
        b.extend_from_slice(&RTM_GETNEXTHOP.to_ne_bytes());
        b.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        b.extend_from_slice(&seq.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&[0u8; 8]);
        return b;
    }
    let payload = match kind {
        Kind::Rule4 | Kind::Rule6 => {
            let mut m = RuleMessage::default();
            m.header.family = kind.family();
            RouteNetlinkMessage::GetRule(m)
        }
        Kind::Route4 | Kind::Route6 => {
            let mut m = RouteMessage::default();
            m.header.address_family = kind.family();
            RouteNetlinkMessage::GetRoute(m)
        }
        Kind::Addr4 | Kind::Addr6 => {
            let mut m = AddressMessage::default();
            m.header.family = kind.family();
            RouteNetlinkMessage::GetAddress(m)
        }
        _ => RouteNetlinkMessage::GetLink(LinkMessage::default()),
    };
    let mut msg = NetlinkMessage::from(payload);
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = seq;
    msg.finalize();
    let mut buf = vec![0u8; msg.buffer_len()];
    msg.serialize(&mut buf);
    buf
}

/// Identity of a dumped entry (what FTR would use to compare dumps with the desired state).
fn entry_key(kind: Kind, msg: &[u8]) -> Option<String> {
    if kind == Kind::Nexthop {
        let mut off = 24;
        while off + 4 <= msg.len() {
            let len = u16::from_ne_bytes([msg[off], msg[off + 1]]) as usize;
            let ty = u16::from_ne_bytes([msg[off + 2], msg[off + 3]]) & 0x3fff;
            if len < 4 || off + len > msg.len() {
                return None;
            }
            if ty == 1 && len >= 8 {
                return Some(format!(
                    "nhid {}",
                    u32::from_ne_bytes(msg[off + 4..off + 8].try_into().ok()?)
                ));
            }
            off += (len + 3) & !3;
        }
        return None;
    }
    let m = NetlinkMessage::<RouteNetlinkMessage>::deserialize(msg).ok()?;
    match m.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(r)) => Some(describe_rule(&r)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(r)) => {
            let mut table = r.header.table as u32;
            let (mut dst, mut metric, mut oif) = ("default".to_string(), 0, 0);
            for a in &r.attributes {
                match a {
                    RouteAttribute::Table(t) => table = *t,
                    RouteAttribute::Destination(d) => dst = addr(d),
                    RouteAttribute::Priority(p) => metric = *p,
                    RouteAttribute::Oif(o) => oif = *o,
                    _ => {}
                }
            }
            let len = r.header.destination_prefix_length;
            Some(format!(
                "table {table} {:?} {dst}/{len} metric {metric} oif {oif}",
                r.header.kind
            ))
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(a)) => {
            let ip = a.attributes.iter().find_map(|x| {
                if let AddressAttribute::Address(ip) = x {
                    Some(*ip)
                } else {
                    None
                }
            });
            Some(format!("ifindex {} {ip:?}/{}", a.header.index, a.header.prefix_len))
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(l)) => {
            let name = l.attributes.iter().find_map(|x| {
                if let LinkAttribute::IfName(n) = x {
                    Some(n.clone())
                } else {
                    None
                }
            });
            Some(format!("ifindex {} {}", l.header.index, name.unwrap_or_default()))
        }
        _ => None,
    }
}

struct Dump {
    keys: Vec<String>,
    batches: usize,
    bytes: usize,
    intr: bool,
    complete: bool,
    unparsed: usize,
    /// Size of the first batch and of the largest one.
    first: usize,
    largest: usize,
}

fn raw_socket() -> netlink_sys::Socket {
    let mut s = netlink_sys::Socket::new(netlink_sys::protocols::NETLINK_ROUTE).expect("netlink socket");
    s.bind_auto().expect("bind");
    s
}

/// Run one dump, reading each batch with a buffer of `read` bytes; `between(n)` runs after batch `n` is read (the
/// kernel builds batch n + 1 inside that read, so a change made there takes effect from batch n + 2 on).
fn raw_dump(s: &netlink_sys::Socket, kind: Kind, seq: u32, read: usize, mut between: impl FnMut(usize)) -> Dump {
    s.send_to(&dump_request(kind, seq), &SocketAddr::new(0, 0), 0)
        .expect("send dump request");
    let mut d = Dump {
        keys: Vec::new(),
        batches: 0,
        bytes: 0,
        intr: false,
        complete: false,
        unparsed: 0,
        first: 0,
        largest: 0,
    };
    let mut buf: Vec<u8> = Vec::with_capacity(read);
    while d.batches < MAX_BATCHES {
        buf.clear();
        let n = s.recv(&mut buf, MSG_TRUNC).expect("recv");
        assert!(
            n <= buf.len(),
            "datagram of {n} bytes truncated by a {}-byte read",
            buf.capacity()
        );
        d.batches += 1;
        d.bytes += n;
        if d.batches == 1 {
            d.first = n;
        }
        d.largest = d.largest.max(n);
        let mut off = 0;
        while off + 16 <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            let flags = u16::from_ne_bytes(buf[off + 6..off + 8].try_into().unwrap());
            if len < 16 || off + len > n {
                break;
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                d.intr = true;
            }
            match ty {
                NLMSG_DONE | NLMSG_ERROR => d.complete = true,
                _ => match entry_key(kind, &buf[off..off + len]) {
                    Some(k) => d.keys.push(k),
                    None => d.unparsed += 1,
                },
            }
            off += (len + 3) & !3;
        }
        if d.complete {
            break;
        }
        between(d.batches);
    }
    d
}

/// Reference entries missing from a dump, and entries returned more than once (reference entries first).
fn anomalies(reference: &HashSet<String>, keys: &[String]) -> (Vec<String>, Vec<String>, usize) {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for k in keys {
        *seen.entry(k.as_str()).or_default() += 1;
    }
    let mut missing: Vec<String> = reference
        .iter()
        .filter(|k| !seen.contains_key(k.as_str()))
        .cloned()
        .collect();
    missing.sort();
    let mut dups: Vec<String> = seen
        .iter()
        .filter(|(k, n)| **n > 1 && reference.contains(**k))
        .map(|(k, _)| k.to_string())
        .collect();
    dups.sort();
    let all_dups = seen.values().filter(|n| **n > 1).count();
    (missing, dups, all_dups)
}

fn sample(v: &[String]) -> String {
    let mut s = v.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
    if v.len() > 3 {
        s += "; ...";
    }
    s
}

/// Apply `ip -force -batch` lines; returns whether every line succeeded.
fn ip_batch(kind: Kind, tag: &str, lines: &[String]) -> bool {
    if lines.is_empty() {
        return true;
    }
    let path = std::env::temp_dir().join(format!("s3-dumpskip-{tag}.txt"));
    std::fs::write(&path, lines.join("\n") + "\n").expect("write batch file");
    let cmd = format!("{} -force -batch {} >/dev/null 2>&1", kind.ip(), path.display());
    std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

struct Case {
    name: &'static str,
    kind: Kind,
    /// Stable entries, created before the reference dump and never touched afterwards.
    setup: Vec<String>,
    /// Churn entries that sort before the stable ones, created before each injected change.
    victims: Vec<String>,
    /// Changes injected after the first batch: (description, shell command).
    ops: Vec<(&'static str, String)>,
    /// Lines looped by the background churn process (another socket).
    churn: Vec<String>,
    /// Lines removing victims and churn entries.
    unchurn: Vec<String>,
    /// Lines removing the stable entries.
    cleanup: Vec<String>,
    rounds: usize,
}

#[derive(Default)]
struct Tally {
    dumps: usize,
    batches: usize,
    missing: usize,
    missing_flagged: usize,
    dup: usize,
    dup_flagged: usize,
    /// Dumps where only churn entries were returned twice.
    churn_dup: usize,
    /// Dumps with a missing or duplicated stable entry and no NLM_F_DUMP_INTR.
    silent: usize,
    flagged: usize,
    incomplete: usize,
    missing_max: usize,
    missing_example: Option<String>,
    dup_example: Option<String>,
    /// How often each reference entry was missing.
    missing_keys: HashMap<String, usize>,
}

fn churn_round(case: &Case, reference: &HashSet<String>, read: usize) -> Tally {
    let mut t = Tally::default();
    let mut s = raw_socket();
    for i in 0..case.rounds {
        let d = raw_dump(&s, case.kind, i as u32 + 1, read, |_| {});
        t.dumps += 1;
        t.batches += d.batches;
        if !d.complete {
            t.incomplete += 1;
            s = raw_socket();
            continue;
        }
        let (missing, dups, all_dups) = anomalies(reference, &d.keys);
        if d.intr {
            t.flagged += 1;
        }
        if !missing.is_empty() {
            t.missing += 1;
            t.missing_flagged += d.intr as usize;
            t.missing_max = t.missing_max.max(missing.len());
            for k in &missing {
                *t.missing_keys.entry(k.clone()).or_default() += 1;
            }
            if t.missing_example.is_none() {
                t.missing_example = Some(format!("missing {}: {}", missing.len(), sample(&missing)));
            }
        }
        if !dups.is_empty() {
            t.dup += 1;
            t.dup_flagged += d.intr as usize;
            if t.dup_example.is_none() {
                t.dup_example = Some(format!("duplicated {}: {}", dups.len(), sample(&dups)));
            }
        } else if all_dups > 0 {
            t.churn_dup += 1;
        }
        if (!missing.is_empty() || !dups.is_empty()) && !d.intr {
            t.silent += 1;
        }
    }
    t
}

/// The reference entries missing most often across the dumps of a churn round.
fn most_missing(m: &HashMap<String, usize>) -> String {
    if m.is_empty() {
        return String::new();
    }
    let mut v: Vec<(&String, &usize)> = m.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let top: Vec<String> = v.iter().take(3).map(|(k, n)| format!("{k} ({n})")).collect();
    format!("; {} distinct entries missing, most often: {}", m.len(), top.join("; "))
}

fn run_case(case: &Case) {
    let kind = case.kind;
    if !ip_batch(kind, case.name, &case.setup) {
        println!("FAIL dumpskip {}: setup", case.name);
    }
    // Reference dump and sizes: a fresh socket (first batch about 4 KiB), the same socket again with 64 KiB reads,
    // and 4 KiB reads.
    let s = raw_socket();
    let fresh = raw_dump(&s, kind, 1, LARGE_READ, |_| {});
    let reused = raw_dump(&s, kind, 2, LARGE_READ, |_| {});
    let small = raw_dump(&raw_socket(), kind, 1, SMALL_READ, |_| {});
    let reference: HashSet<String> = reused.keys.iter().cloned().collect();
    let (_, _, ref_dups) = anomalies(&reference, &reused.keys);
    println!(
        "INFO dumpskip size {}: {} entries, {} bytes; batches: {} on a fresh socket (first {} bytes), {} on a reused socket with 64 KiB reads (largest {} bytes), {} with 4 KiB reads{}",
        case.name,
        reused.keys.len(),
        reused.bytes,
        fresh.batches,
        fresh.first,
        reused.batches,
        reused.largest,
        small.batches,
        if ref_dups > 0 || reused.unparsed > 0 {
            format!(" (reference has {ref_dups} duplicates, {} unparsed)", reused.unparsed)
        } else {
            String::new()
        }
    );
    // Deterministic interleaving: a change after the first batch, before the resume point of the third.
    for (what, op) in &case.ops {
        ip_batch(kind, case.name, &case.victims);
        let d = raw_dump(&raw_socket(), kind, 1, SMALL_READ, |n| {
            if n == 1 {
                run(op);
            }
        });
        let (missing, dups, _) = anomalies(&reference, &d.keys);
        println!(
            "INFO dumpskip change {} / {what}: {} batches, {} stable missing{}, {} stable duplicated{}, NLM_F_DUMP_INTR {}{}",
            case.name,
            d.batches,
            missing.len(),
            if missing.is_empty() {
                String::new()
            } else {
                format!(" ({})", sample(&missing))
            },
            dups.len(),
            if dups.is_empty() {
                String::new()
            } else {
                format!(" ({})", sample(&dups))
            },
            if d.intr { "set" } else { "not set" },
            if d.complete { "" } else { ", dump did not complete" },
        );
        ip_batch(kind, case.name, &case.unchurn);
    }
    // Concurrent churn by another process (separate sockets), many dumps, both read sizes.
    if !case.churn.is_empty() {
        let path = std::env::temp_dir().join(format!("s3-dumpskip-{}-churn.txt", case.name));
        std::fs::write(&path, case.churn.join("\n") + "\n").expect("write churn file");
        let mut churn = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "while :; do {} -force -batch {} >/dev/null 2>&1; done",
                kind.ip(),
                path.display()
            ))
            .process_group(0)
            .spawn()
            .expect("churn");
        std::thread::sleep(Duration::from_millis(100));
        for (label, read) in [("4 KiB reads", SMALL_READ), ("64 KiB reads", LARGE_READ)] {
            let t = churn_round(case, &reference, read);
            println!(
                "INFO dumpskip churn {} ({label}): {} dumps, {:.1} batches each; stable entries missing in {} dumps ({} of them flagged, at most {} per dump), stable entries duplicated in {} dumps ({} flagged), only churn entries duplicated in {}, NLM_F_DUMP_INTR in {} dumps, anomalies without NLM_F_DUMP_INTR in {} dumps, incomplete {}{}",
                case.name,
                t.dumps,
                t.batches as f64 / t.dumps.max(1) as f64,
                t.missing,
                t.missing_flagged,
                t.missing_max,
                t.dup,
                t.dup_flagged,
                t.churn_dup,
                t.flagged,
                t.silent,
                t.incomplete,
                [t.missing_example, t.dup_example]
                    .into_iter()
                    .flatten()
                    .map(|e| format!("; e.g. {e}"))
                    .collect::<String>()
                    + &most_missing(&t.missing_keys),
            );
        }
        let _ = std::process::Command::new("kill")
            .args(["-TERM", "--", &format!("-{}", churn.id())])
            .status();
        let _ = churn.wait();
        std::thread::sleep(Duration::from_millis(50));
        ip_batch(kind, case.name, &case.unchurn);
    }
    ip_batch(kind, case.name, &case.cleanup);
}

fn rule_line(r: &Rule) -> String {
    let mut s = format!("rule add prio {}", r.priority);
    if let Some((a, l)) = r.from {
        s += &format!(" from {a}/{l}");
    }
    if let Some((m, k)) = r.fwmark {
        s += &format!(" fwmark {m:#x}/{k:#x}");
    }
    match r.action {
        RuleAction::Unreachable => s += " unreachable",
        _ => s += &format!(" lookup {}", r.table),
    }
    if let Some(p) = r.suppress_prefixlen {
        s += &format!(" suppress_prefixlength {p}");
    }
    s + &format!(" protocol {PROTO}")
}

fn lines(range: std::ops::Range<u32>, f: impl Fn(u32) -> String) -> Vec<String> {
    range.map(f).collect()
}

fn dumpskip_cases() -> Vec<Case> {
    let mut v = Vec::new();
    // Rules: 1000 stable rules after 10 churn rules (index-based resume in the rule list).
    for (name, kind) in [("rules4-large", Kind::Rule4), ("rules6-large", Kind::Rule6)] {
        let ip = kind.ip();
        v.push(Case {
            name,
            kind,
            setup: lines(20000..21000, |p| format!("rule add prio {p} fwmark {p} lookup 3100")),
            victims: lines(10000..10010, |p| format!("rule add prio {p} fwmark 7 lookup 3100")),
            ops: vec![
                (
                    "delete a rule before the resume point",
                    format!("{ip} rule del prio 10000"),
                ),
                (
                    "add a rule before the resume point",
                    format!("{ip} rule add prio 10050 fwmark 7 lookup 3100"),
                ),
            ],
            churn: (10000..10020)
                .flat_map(|p| {
                    [
                        format!("rule add prio {p} fwmark 7 lookup 3100"),
                        format!("rule del prio {p}"),
                    ]
                })
                .collect(),
            unchurn: lines(10000..10060, |p| format!("rule del prio {p}")),
            cleanup: lines(20000..21000, |p| format!("rule del prio {p}")),
            rounds: 300,
        });
    }
    // Rules at FTR's size: the FR-ROUTE-3 layout for 3 uplinks, 5 foreign rules, the kernel's default rules; a
    // foreign rule appears and disappears before all of them.
    for (name, kind) in [("rules4-ftr", Kind::Rule4), ("rules6-ftr", Kind::Rule6)] {
        let (addrs, net, host): (Vec<IpAddr>, &str, &str) = if kind == Kind::Rule4 {
            (
                ["192.0.2.2", "198.51.100.2", "203.0.113.2"]
                    .iter()
                    .map(|a| a.parse().unwrap())
                    .collect(),
                "10.9.0.0/16",
                "10.8.0.0/16",
            )
        } else {
            (
                ["2001:db8:1::2", "2001:db8:2::2", "2001:db8:3::2"]
                    .iter()
                    .map(|a| a.parse().unwrap())
                    .collect(),
                "2001:db8:9::/48",
                "2001:db8:8::/48",
            )
        };
        let ftr = layout(kind.family(), &[1, 2, 3], &addrs);
        let mut setup: Vec<String> = ftr.iter().map(rule_line).collect();
        setup.extend([
            format!("rule add prio 100 from {net} lookup 200"),
            "rule add prio 220 lookup 220".to_string(),
            "rule add prio 5000 fwmark 0xca6c lookup 51820".to_string(),
            "rule add prio 5001 lookup main suppress_prefixlength 0".to_string(),
            format!("rule add prio 32000 from {net} lookup 201"),
        ]);
        let mut cleanup: Vec<String> = ftr
            .iter()
            .map(|r| rule_line(r).replacen("rule add", "rule del", 1))
            .collect();
        cleanup.extend([100, 220, 5000, 5001, 32000].map(|p| format!("rule del prio {p}")));
        v.push(Case {
            name,
            kind,
            setup,
            victims: vec![],
            ops: vec![],
            churn: vec![
                format!("rule add prio 50 from {host} lookup 300"),
                "rule del prio 50".to_string(),
            ],
            unchurn: vec!["rule del prio 50".to_string()],
            cleanup,
            rounds: 1000,
        });
    }
    // IPv4 routes, large table: resume by key, churn on lower keys.
    v.push(Case {
        name: "routes4-large",
        kind: Kind::Route4,
        setup: lines(0..10000, |i| {
            format!(
                "route add 10.100.{}.{}/32 via 192.0.2.1 dev d1 table 3000",
                i / 250,
                i % 250
            )
        }),
        victims: lines(0..10, |i| {
            format!("route add 10.0.0.{i}/32 via 192.0.2.1 dev d1 table 3000")
        }),
        ops: vec![
            (
                "delete a route with a lower key",
                "ip route del 10.0.0.0/32 table 3000".to_string(),
            ),
            (
                "add a route with a lower key",
                "ip route add 10.0.0.50/32 via 192.0.2.1 dev d1 table 3000".to_string(),
            ),
        ],
        churn: (0..20)
            .flat_map(|i| {
                [
                    format!("route add 10.0.0.{i}/32 via 192.0.2.1 dev d1 table 3000"),
                    format!("route del 10.0.0.{i}/32 table 3000"),
                ]
            })
            .collect(),
        unchurn: lines(0..60, |i| format!("route del 10.0.0.{i}/32 table 3000")),
        cleanup: vec!["route flush table 3000".to_string()],
        rounds: 300,
    });
    // IPv4 routes, many aliases in one leaf: 1500 default routes with different metrics (resume by alias index).
    v.push(Case {
        name: "routes4-leaf",
        kind: Kind::Route4,
        setup: lines(1000..2500, |m| {
            format!("route add default via 192.0.2.1 dev d1 table 3100 metric {m}")
        }),
        victims: lines(1..11, |m| {
            format!("route add default via 192.0.2.1 dev d1 table 3100 metric {m}")
        }),
        ops: vec![
            (
                "delete a default route with a lower metric",
                "ip route del default table 3100 metric 1".to_string(),
            ),
            (
                "add a default route with a lower metric",
                "ip route add default via 192.0.2.1 dev d1 table 3100 metric 50".to_string(),
            ),
        ],
        churn: (1..21)
            .flat_map(|m| {
                [
                    format!("route add default via 192.0.2.1 dev d1 table 3100 metric {m}"),
                    format!("route del default table 3100 metric {m}"),
                ]
            })
            .collect(),
        unchurn: lines(1..61, |m| format!("route del default table 3100 metric {m}")),
        cleanup: vec!["route flush table 3100".to_string()],
        rounds: 300,
    });
    // IPv4 at FTR's size: 200 tables with one default route each, main with 3 default routes; another default route
    // with a lower metric appears and disappears in main (same leaf as the 3, before them).
    v.push(Case {
        name: "routes4-ftr",
        kind: Kind::Route4,
        setup: lines(1001..1201, |t| {
            format!("route add default via 192.0.2.1 dev d1 table {t} metric 100 proto 249")
        })
        .into_iter()
        .chain([
            "route add default via 198.51.100.1 dev d2 metric 200 proto dhcp".to_string(),
            "route add default dev p0 metric 300 proto static".to_string(),
        ])
        .collect(),
        victims: vec![],
        ops: vec![],
        churn: vec![
            "route add default via 198.51.100.1 dev d2 metric 50".to_string(),
            "route del default via 198.51.100.1 dev d2 metric 50".to_string(),
        ],
        unchurn: vec!["route del default via 198.51.100.1 dev d2 metric 50".to_string()],
        cleanup: lines(1001..1201, |t| format!("route flush table {t}"))
            .into_iter()
            .chain([
                "route del default via 198.51.100.1 dev d2 metric 200".to_string(),
                "route del default dev p0 metric 300".to_string(),
            ])
            .collect(),
        rounds: 1000,
    });
    // IPv6 routes, large table: the walker restarts from the root and skips `count` nodes when the tree changed.
    v.push(Case {
        name: "routes6-large",
        kind: Kind::Route6,
        setup: lines(0..10000, |i| format!("route add 2001:db8:100::{i:x}/128 via fe80::1 dev d1 table 3000")),
        victims: lines(0..10, |i| format!("route add 2001:db8:1::{i:x}/128 via fe80::1 dev d1 table 3000")),
        ops: vec![
            ("delete a route before the resume point", "ip -6 route del 2001:db8:1::/128 table 3000".to_string()),
            ("add a route before the resume point", "ip -6 route add 2001:db8:1::50/128 via fe80::1 dev d1 table 3000".to_string()),
            (
                "delete a route before the resume point, then add one after it",
                "ip -6 route del 2001:db8:1::/128 table 3000; ip -6 route add 2001:db8:ffff::1/128 via fe80::1 dev d1 table 3000".to_string(),
            ),
        ],
        churn: (0..20)
            .flat_map(|i| [format!("route add 2001:db8:1::{i:x}/128 via fe80::1 dev d1 table 3000"), format!("route del 2001:db8:1::{i:x}/128 table 3000")])
            .collect(),
        unchurn: lines(0..0x60, |i| format!("route del 2001:db8:1::{i:x}/128 table 3000"))
            .into_iter()
            .chain(["route del 2001:db8:ffff::1/128 table 3000".to_string()])
            .collect(),
        cleanup: vec!["route flush table 3000".to_string()],
        rounds: 300,
    });
    // IPv6 routes, many routes in one node: 600 default routes with different metrics.
    v.push(Case {
        name: "routes6-node",
        kind: Kind::Route6,
        setup: lines(1000..1600, |m| {
            format!("route add default via fe80::1 dev d1 table 3100 metric {m}")
        }),
        victims: lines(1..11, |m| {
            format!("route add default via fe80::1 dev d1 table 3100 metric {m}")
        }),
        ops: vec![
            (
                "delete a default route with a lower metric",
                "ip -6 route del default table 3100 metric 1".to_string(),
            ),
            (
                "add a default route with a lower metric",
                "ip -6 route add default via fe80::1 dev d1 table 3100 metric 50".to_string(),
            ),
        ],
        churn: (1..21)
            .flat_map(|m| {
                [
                    format!("route add default via fe80::1 dev d1 table 3100 metric {m}"),
                    format!("route del default table 3100 metric {m}"),
                ]
            })
            .collect(),
        unchurn: lines(1..61, |m| format!("route del default table 3100 metric {m}")),
        cleanup: vec!["route flush table 3100".to_string()],
        rounds: 50,
    });
    // IPv6 at FTR's size: 200 tables with one default route each, main with 3 default routes; in main a prefix route
    // is removed and a default route added and removed (like Router Advertisements).
    v.push(Case {
        name: "routes6-ftr",
        kind: Kind::Route6,
        setup: lines(1001..1201, |t| {
            format!("route add default via fe80::1 dev d1 table {t} metric 100 proto 249")
        })
        .into_iter()
        .chain([
            "route add default via fe80::1 dev d2 metric 1025 proto ra".to_string(),
            "route add default via fe80::2 dev d1 metric 1026 proto ra".to_string(),
        ])
        .collect(),
        victims: vec![],
        ops: vec![],
        churn: vec![
            "route add 2001:db8:99::/64 dev d2".to_string(),
            "route del 2001:db8:99::/64 dev d2".to_string(),
            "route add default via fe80::1 dev d2 metric 50".to_string(),
            "route del default via fe80::1 dev d2 metric 50".to_string(),
        ],
        unchurn: vec![
            "route del 2001:db8:99::/64 dev d2".to_string(),
            "route del default via fe80::1 dev d2 metric 50".to_string(),
        ],
        cleanup: lines(1001..1201, |t| format!("route flush table {t}"))
            .into_iter()
            .chain([
                "route del default via fe80::1 dev d2 metric 1025".to_string(),
                "route del default via fe80::2 dev d1 metric 1026".to_string(),
            ])
            .collect(),
        rounds: 1000,
    });
    // IPv4 addresses: 2000 stable addresses on d1; host-scope churn addresses go to the head of d1's list.
    v.push(Case {
        name: "addr4",
        kind: Kind::Addr4,
        setup: lines(0..2000, |i| {
            format!("address add 10.200.{}.{}/32 dev d1", i / 250, i % 250 + 1)
        }),
        victims: lines(0..10, |i| {
            format!("address add 10.201.0.{}/32 dev d1 scope host", i + 1)
        }),
        ops: vec![
            (
                "delete an address before the resume point",
                "ip address del 10.201.0.1/32 dev d1".to_string(),
            ),
            (
                "add an address before the resume point",
                "ip address add 10.201.0.50/32 dev d1 scope host".to_string(),
            ),
        ],
        churn: (1..21)
            .flat_map(|i| {
                [
                    format!("address add 10.201.0.{i}/32 dev d1 scope host"),
                    format!("address del 10.201.0.{i}/32 dev d1"),
                ]
            })
            .collect(),
        unchurn: lines(1..61, |i| format!("address del 10.201.0.{i}/32 dev d1")),
        cleanup: lines(0..2000, |i| {
            format!("address del 10.200.{}.{}/32 dev d1", i / 250, i % 250 + 1)
        }),
        rounds: 1000,
    });
    // IPv6 addresses: 1000 stable global addresses on d1; a new global address goes to the head of the global ones.
    v.push(Case {
        name: "addr6",
        kind: Kind::Addr6,
        setup: lines(0..1000, |i| {
            format!("address add 2001:db8:100::{:x}/128 dev d1 nodad", i + 1)
        }),
        victims: lines(1..11, |i| format!("address add 2001:db8:1::{i:x}/128 dev d1 nodad")),
        ops: vec![
            (
                "delete an address before the resume point",
                "ip -6 address del 2001:db8:1::1/128 dev d1".to_string(),
            ),
            (
                "add an address before the resume point",
                "ip -6 address add 2001:db8:1::50/128 dev d1 nodad".to_string(),
            ),
        ],
        churn: (1..21)
            .flat_map(|i| {
                [
                    format!("address add 2001:db8:1::{i:x}/128 dev d1 nodad"),
                    format!("address del 2001:db8:1::{i:x}/128 dev d1"),
                ]
            })
            .collect(),
        unchurn: lines(1..0x60, |i| format!("address del 2001:db8:1::{i:x}/128 dev d1")),
        cleanup: lines(0..1000, |i| format!("address del 2001:db8:100::{:x}/128 dev d1", i + 1)),
        rounds: 1000,
    });
    // Links: 200 stable dummy links; a dummy link is created and deleted (new ifindex every time).
    v.push(Case {
        name: "links",
        kind: Kind::Link,
        setup: lines(0..200, |i| format!("link add s3s{i} type dummy")),
        victims: vec![],
        ops: vec![],
        churn: (0..10)
            .flat_map(|i| [format!("link add s3c{i} type dummy"), format!("link del s3c{i}")])
            .collect(),
        unchurn: lines(0..10, |i| format!("link del s3c{i}")),
        cleanup: lines(0..200, |i| format!("link del s3s{i}")),
        rounds: 100,
    });
    // Nexthop objects: 2000 stable blackhole nexthops; churn ids are lower (resume by id).
    v.push(Case {
        name: "nexthops",
        kind: Kind::Nexthop,
        setup: lines(10000..12000, |i| format!("nexthop add id {i} blackhole")),
        victims: lines(100..110, |i| format!("nexthop add id {i} blackhole")),
        ops: vec![
            ("delete a nexthop with a lower id", "ip nexthop del id 100".to_string()),
            (
                "add a nexthop with a lower id",
                "ip nexthop add id 150 blackhole".to_string(),
            ),
        ],
        churn: (100..120)
            .flat_map(|i| [format!("nexthop add id {i} blackhole"), format!("nexthop del id {i}")])
            .collect(),
        unchurn: lines(100..160, |i| format!("nexthop del id {i}")),
        cleanup: lines(10000..12000, |i| format!("nexthop del id {i}")),
        rounds: 300,
    });
    v
}

/// Size of a rule dump with the FR-ROUTE-3 layout for `n` uplinks plus 5 foreign rules: does it fit in one batch?
fn ftr_rule_sizes() {
    for kind in [Kind::Rule4, Kind::Rule6] {
        for n in [2u32, 3, 4, 5, 6, 8, 16, 32] {
            let ids: Vec<u32> = (1..=n).collect();
            let addrs: Vec<IpAddr> = ids
                .iter()
                .map(|i| {
                    if kind == Kind::Rule4 {
                        format!("10.0.{i}.2")
                    } else {
                        format!("2001:db8:{i:x}::2")
                    }
                })
                .map(|a| a.parse().unwrap())
                .collect();
            let rules = layout(kind.family(), &ids, &addrs);
            let foreign: Vec<String> = [100, 220, 5000, 5001, 32000]
                .iter()
                .map(|p| format!("rule add prio {p} lookup 200"))
                .collect();
            let mut add: Vec<String> = rules.iter().map(rule_line).collect();
            add.extend(foreign.iter().cloned());
            ip_batch(kind, "sizes", &add);
            let s = raw_socket();
            let fresh = raw_dump(&s, kind, 1, LARGE_READ, |_| {});
            let reused = raw_dump(&s, kind, 2, LARGE_READ, |_| {});
            println!(
                "INFO dumpskip size {kind:?} FR-ROUTE-3 layout, {n} uplinks: {} rules, {} bytes; {} batch(es) on a fresh socket, {} on a reused socket",
                reused.keys.len(),
                reused.bytes,
                fresh.batches,
                reused.batches
            );
            let mut del: Vec<String> = add.iter().map(|l| l.replacen("rule add", "rule del", 1)).collect();
            del.reverse();
            ip_batch(kind, "sizes", &del);
        }
    }
}

fn test_dump_skip() {
    println!("== dump_skip");
    ftr_rule_sizes();
    let only = std::env::var("S3_DUMPSKIP_CASES").ok();
    for case in dumpskip_cases() {
        if only.as_deref().is_some_and(|o| !o.split(',').any(|c| c == case.name)) {
            continue;
        }
        run_case(&case);
    }
}

// ---------------------------------------------------------------------------
// Discovery inputs (FR-DISC-2/3): link flags, address flags, default routes.

async fn test_inspect(nl: &mut Nl) {
    println!("== inspect");
    let links: Vec<_> = nl
        .handle
        .link()
        .get()
        .execute()
        .filter_map(|r| async { r.ok() })
        .collect()
        .await;
    for l in &links {
        println!("INFO   link {}", link_desc(l));
    }
    let addrs: Vec<_> = nl
        .handle
        .address()
        .get()
        .execute()
        .filter_map(|r| async { r.ok() })
        .collect()
        .await;
    for a in addrs
        .iter()
        .filter(|a| a.header.scope == netlink_packet_route::address::AddressScope::Universe)
    {
        println!("INFO   addr {}", addr_desc(a));
    }
    for fam in [AddressFamily::Inet, AddressFamily::Inet6] {
        for table in [254, 3005] {
            if let Ok((v, _)) = nl.dump_routes(fam, Some(table), RouteProtocol::Unspec).await {
                for r in v.iter().filter(|r| r.header.destination_prefix_length == 0) {
                    println!("INFO   default in table {table} {fam:?}: {}", describe_route(r));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel-initiated changes to FTR routes: which are notified?

async fn ftr_tables(nl: &mut Nl) -> Vec<String> {
    let mut v = Vec::new();
    for fam in [AddressFamily::Inet, AddressFamily::Inet6] {
        if let Ok((rs, _)) = nl.dump_routes(fam, None, RouteProtocol::Other(PROTO)).await {
            v.extend(rs.iter().map(|r| format!("{fam:?} {}", describe_route(r))));
        }
    }
    v
}

async fn test_implicit(nl: &mut Nl) {
    println!("== implicit");
    let d1 = ifindex(nl, "d1").await;
    let v1 = ifindex(nl, "v1").await;
    let ll: Ipv6Addr = "fe80::1".parse().unwrap();
    let gwv = Ipv4Addr::new(100, 64, 0, 1);
    let install = async |nl: &mut Nl| {
        let mut m = default_route(AddressFamily::Inet, T + 1);
        m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(gwv)));
        m.attributes.push(RouteAttribute::Oif(v1));
        m.attributes
            .push(RouteAttribute::PrefSource(RouteAddress::Inet(Ipv4Addr::new(
                100, 64, 0, 2,
            ))));
        let a = nl
            .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
            .await;
        let mut m = default_route(AddressFamily::Inet, T);
        m.attributes.push(RouteAttribute::MultiPath(vec![
            nh_v4(Some(Ipv4Addr::new(192, 0, 2, 1)), d1, 1, false),
            nh_v4(Some(gwv), v1, 1, false),
        ]));
        let b = nl
            .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
            .await;
        let mut m = default_route(AddressFamily::Inet6, T + 1);
        m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet6(ll)));
        m.attributes.push(RouteAttribute::Oif(v1));
        let c = nl
            .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
            .await;
        let mut m = default_route(AddressFamily::Inet6, T);
        m.attributes
            .push(RouteAttribute::MultiPath(vec![nh_v6(ll, d1, 1), nh_v6(ll, v1, 1)]));
        let d = nl
            .mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
            .await;
        for e in [a, b, c, d] {
            if let Err(e) = e {
                println!("FAIL install: {e}");
            }
        }
    };
    install(nl).await;
    let (conn, _h, mut rx) =
        rtnetlink::new_multicast_connection(&[MulticastGroup::Ipv4Route, MulticastGroup::Ipv6Route]).unwrap();
    tokio::spawn(conn);
    for (what, cmd, reinstall) in [
        ("carrier loss on v1 (peer down)", "ip link set v1p down", false),
        ("carrier back", "ip link set v1p up; sleep 0.2", false),
        ("admin down v1", "ip link set v1 down", false),
        ("admin up v1", "ip link set v1 up; sleep 0.3", true),
        (
            "IPv4 address 100.64.0.2/24 removed from v1",
            "ip addr del 100.64.0.2/24 dev v1",
            false,
        ),
        ("IPv4 address restored", "ip addr add 100.64.0.2/24 dev v1", true),
        (
            "IPv6 link-local removed from v1",
            "ip -6 addr flush dev v1 scope link",
            false,
        ),
    ] {
        run(cmd);
        let got = drain(&mut rx, 300).await;
        let ours: Vec<_> = got
            .iter()
            .map(describe_notification)
            .filter(|s| s.contains("proto 249"))
            .collect();
        println!(
            "INFO {what}: {} notification(s) for proto {PROTO} routes {:?}",
            ours.len(),
            ours
        );
        println!("INFO   FTR routes now: {:?}", ftr_tables(nl).await);
        if reinstall {
            install(nl).await;
            let _ = drain(&mut rx, 200).await;
        }
    }
    if let Ok((v, _)) = nl
        .dump_routes(AddressFamily::Inet, None, RouteProtocol::Other(PROTO))
        .await
    {
        for r in v {
            let _ = nl.mutate(RouteNetlinkMessage::DelRoute(r), 0).await;
        }
    }
    if let Ok((v, _)) = nl
        .dump_routes(AddressFamily::Inet6, None, RouteProtocol::Other(PROTO))
        .await
    {
        for r in v {
            let _ = nl.mutate(RouteNetlinkMessage::DelRoute(r), 0).await;
        }
    }
}

/// Install the layout and sample routes and leave them in place, so that `run.sh install`
/// can show them with `ip rule` / `ip route` for comparison with the FR-ROUTE-3 table.
async fn install(nl: &mut Nl) {
    let v4a = vec![
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
    ];
    let v6a = vec![
        IpAddr::V6("2001:db8:1::2".parse().unwrap()),
        IpAddr::V6("2001:db8:2::2".parse().unwrap()),
    ];
    for (fam, a) in [(AddressFamily::Inet, v4a), (AddressFamily::Inet6, v6a)] {
        for r in layout(fam, &[1, 2], &a) {
            nl.mutate(RouteNetlinkMessage::NewRule(r.msg()), NLM_F_CREATE | NLM_F_EXCL)
                .await
                .unwrap();
        }
    }
    let d1 = ifindex(nl, "d1").await;
    let d2 = ifindex(nl, "d2").await;
    let p0 = ifindex(nl, "p0").await;
    let g6 = ifindex(nl, "g6").await;
    let ll: Ipv6Addr = "fe80::1".parse().unwrap();
    let mut m = default_route(AddressFamily::Inet, T);
    m.attributes.push(RouteAttribute::MultiPath(vec![
        nh_v4(Some(Ipv4Addr::new(192, 0, 2, 1)), d1, 10, false),
        nh_v4(Some(Ipv4Addr::new(198, 51, 100, 1)), d2, 3, false),
        nh_v4(None, p0, 1, false),
    ]));
    nl.mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await
        .unwrap();
    let mut m = default_route(AddressFamily::Inet, T + 3);
    m.attributes.push(RouteAttribute::Oif(p0));
    m.attributes
        .push(RouteAttribute::PrefSource(RouteAddress::Inet(Ipv4Addr::new(
            203, 0, 113, 2,
        ))));
    nl.mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await
        .unwrap();
    let mut m = default_route(AddressFamily::Inet6, T);
    m.attributes.push(RouteAttribute::MultiPath(vec![
        nh_v6(ll, d1, 10),
        nh_v6(ll, d2, 3),
        nh_v6(ll, g6, 1),
    ]));
    nl.mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await
        .unwrap();
    let mut m = default_route(AddressFamily::Inet6, T + 1);
    m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet6(ll)));
    m.attributes.push(RouteAttribute::Oif(d1));
    m.attributes.push(RouteAttribute::PrefSource(RouteAddress::Inet6(
        "2001:db8:1::2".parse().unwrap(),
    )));
    nl.mutate(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_REPLACE)
        .await
        .unwrap();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let what = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    let mut nl = connect(true, true, true).await;
    if what == "install" {
        install(&mut nl).await;
        return;
    }
    let all = what == "all";
    if all || what == "rules" {
        test_rules(&mut nl).await;
    }
    if all || what == "routes" {
        test_routes(&mut nl).await;
    }
    if all || what == "extack" {
        test_extack().await;
    }
    if all || what == "notify" {
        test_notify(&mut nl).await;
    }
    if all || what == "inspect" {
        test_inspect(&mut nl).await;
    }
    if all || what == "implicit" {
        test_implicit(&mut nl).await;
    }
    if all || what == "dumpintr" {
        test_dump_intr().await;
    }
    if all || what == "enobufs" {
        test_enobufs().await;
    }
    if all || what == "dumpskip" {
        test_dump_skip();
    }
}
