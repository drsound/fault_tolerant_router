//! Address plan of the reference topology (SPEC.md §14.2).
//!
//! Only documentation and benchmarking prefixes are used, plus the real
//! addresses of the default probe targets, which live on the internet node.
//!
//! | Segment | IPv4 | IPv6 |
//! |---|---|---|
//! | internet – provider A | 198.18.0.0/30 | 2001:db8:fff0:a::/64 |
//! | internet – provider B | 198.18.0.4/30 | 2001:db8:fff0:b::/64 |
//! | internet – provider C | 198.18.0.8/30 | 2001:db8:fff0:c::/64 |
//! | test servers (any address) | 198.18.100.0/24 | 2001:db8:ff00::/64 |
//! | provider A customer link (DHCPv4, DHCPv6 + SLAAC) | 192.0.2.0/24 | 2001:db8:a:ffff::/64 (routed /48) |
//! | provider B customer link (DHCPv4, CGNAT, SLAAC) | 100.64.0.0/24, public 198.18.0.6 | 2001:db8:b:ffff::/64 (routed /48) |
//! | provider C (PPPoE) | 203.0.113.1 → 203.0.113.10–19 | link-local `fe80::1` → `fe80::2`, SLAAC in 2001:db8:c:ffff::/64 (routed /48) |
//! | LAN | 198.51.100.0/24 | 2001:db8:1::/64 |

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::V4, Family::V6];

    /// The `ip` command family flag.
    pub fn flag(self) -> &'static str {
        match self {
            Family::V4 => "-4",
            Family::V6 => "-6",
        }
    }

    pub fn of(addr: IpAddr) -> Family {
        match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        })
    }
}

/// A node of the topology; each one is a network namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Node {
    Inet,
    IspA,
    IspB,
    IspC,
    Router,
    Client,
}

impl Node {
    pub const ALL: [Node; 6] = [
        Node::Inet,
        Node::IspA,
        Node::IspB,
        Node::IspC,
        Node::Router,
        Node::Client,
    ];

    /// Suffix of the namespace name.
    pub fn short(self) -> &'static str {
        match self {
            Node::Inet => "inet",
            Node::IspA => "ispa",
            Node::IspB => "ispb",
            Node::IspC => "ispc",
            Node::Router => "router",
            Node::Client => "client",
        }
    }
}

impl FromStr for Node {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Node> {
        Node::ALL
            .into_iter()
            .find(|n| n.short() == s)
            .ok_or_else(|| anyhow::anyhow!("unknown node {s:?} (expected inet, ispa, ispb, ispc, router or client)"))
    }
}

/// An uplink of the router, named after its provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Uplink {
    /// Plain routing with DHCPv4, DHCPv6 and SLAAC.
    A,
    /// CGNAT for IPv4, SLAAC for IPv6.
    B,
    /// PPPoE for both families, MTU 1492; IPv6 by Router Advertisements
    /// over the PPP link from the server's link-local address.
    C,
}

impl Uplink {
    pub const ALL: [Uplink; 3] = [Uplink::A, Uplink::B, Uplink::C];

    pub fn provider(self) -> Node {
        match self {
            Uplink::A => Node::IspA,
            Uplink::B => Node::IspB,
            Uplink::C => Node::IspC,
        }
    }

    /// The router interface that carries the link (Ethernet side).
    pub fn carrier_iface(self) -> &'static str {
        match self {
            Uplink::A => "wana",
            Uplink::B => "wanb",
            Uplink::C => "wanc",
        }
    }

    /// The router interface that carries IP traffic.
    pub fn l3_iface(self) -> &'static str {
        match self {
            Uplink::A => "wana",
            Uplink::B => "wanb",
            Uplink::C => "ppp0",
        }
    }

    /// Metric of the operating-system default route on this uplink.
    pub fn os_metric(self) -> u32 {
        match self {
            Uplink::A => 100,
            Uplink::B => 200,
            Uplink::C => 300,
        }
    }

    /// Source prefixes under which traffic leaving through this uplink is
    /// seen by the internet node.
    pub fn public_prefixes(self) -> Vec<Prefix> {
        match self {
            Uplink::A => vec![p("192.0.2.0/24"), p("2001:db8:a::/48")],
            Uplink::B => vec![p("198.18.0.6/32"), p("2001:db8:b::/48")],
            Uplink::C => vec![p("203.0.113.0/24"), p("2001:db8:c::/48")],
        }
    }
}

impl fmt::Display for Uplink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Uplink::A => "A",
            Uplink::B => "B",
            Uplink::C => "C",
        })
    }
}

impl FromStr for Uplink {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Uplink> {
        match s.to_ascii_lowercase().as_str() {
            "a" => Ok(Uplink::A),
            "b" => Ok(Uplink::B),
            "c" => Ok(Uplink::C),
            _ => anyhow::bail!("unknown uplink {s:?} (expected a, b or c)"),
        }
    }
}

/// The uplink whose public prefixes contain `src`, as seen by the internet node.
pub fn attribute(src: IpAddr) -> Option<Uplink> {
    let src = canonical(src);
    Uplink::ALL
        .into_iter()
        .find(|u| u.public_prefixes().iter().any(|p| p.contains(src)))
}

/// Unwraps IPv4-mapped IPv6 addresses.
pub fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(addr),
        v4 => v4,
    }
}

/// An IP prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.len)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Prefix {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Prefix> {
        let (a, l) = s
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("prefix {s:?} without length"))?;
        Ok(Prefix {
            addr: a.parse()?,
            len: l.parse()?,
        })
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

fn p(s: &str) -> Prefix {
    s.parse().expect("valid built-in prefix")
}

/// Default probe targets (SPEC.md FR-PROBE-6), hosted on the internet node.
pub const PROBE_TARGETS_V4: [Ipv4Addr; 4] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(208, 67, 222, 222),
];
pub const PROBE_TARGETS_V6: [Ipv6Addr; 3] = [
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
];

pub fn probe_targets(family: Family) -> Vec<IpAddr> {
    match family {
        Family::V4 => PROBE_TARGETS_V4.iter().map(|a| IpAddr::V4(*a)).collect(),
        Family::V6 => PROBE_TARGETS_V6.iter().map(|a| IpAddr::V6(*a)).collect(),
    }
}

/// Every address of these prefixes is local to the internet node (AnyIP)
/// and answered by the test servers.
pub const SERVERS_V4: &str = "198.18.100.0/24";
pub const SERVERS_V6: &str = "2001:db8:ff00::/64";

/// The `n`-th test server address (1-based, up to 254).
pub fn server(family: Family, n: u8) -> IpAddr {
    match family {
        Family::V4 => IpAddr::V4(Ipv4Addr::new(198, 18, 100, n)),
        Family::V6 => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xff00, 0, 0, 0, 0, u16::from(n))),
    }
}

/// `count` distinct test server addresses.
pub fn servers(family: Family, count: u8) -> Vec<IpAddr> {
    (1..=count).map(|n| server(family, n)).collect()
}

/// TCP port of the test servers: reports the peer address, then echoes.
pub const TCP_PORT: u16 = 7000;
/// Additional TCP port served like [`TCP_PORT`] (for TCP probes).
pub const TCP_PORT_HTTPS: u16 = 443;
/// UDP port of the test servers: answers every datagram with the peer address.
pub const UDP_PORT: u16 = 7001;
/// UDP sink: datagrams are logged, never answered (one-way flows).
pub const UDP_SINK_PORT: u16 = 7002;

pub const LAN_ROUTER_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
pub const LAN_CLIENT_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
pub const LAN_ROUTER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
pub const LAN_CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x10);

/// Realm attached to every operating-system default route of the router, so
/// that packets routed by them can be counted (IPv4 leak detection).
pub const OS_ROUTE_REALM: u32 = 99;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribution() {
        assert_eq!(attribute("192.0.2.150".parse().unwrap()), Some(Uplink::A));
        assert_eq!(attribute("::ffff:198.18.0.6".parse().unwrap()), Some(Uplink::B));
        assert_eq!(attribute("203.0.113.12".parse().unwrap()), Some(Uplink::C));
        assert_eq!(attribute("2001:db8:a:ffff::1234".parse().unwrap()), Some(Uplink::A));
        assert_eq!(attribute("2001:db8:b:ffff:1::1".parse().unwrap()), Some(Uplink::B));
        assert_eq!(attribute("2001:db8:c:ffff::2".parse().unwrap()), Some(Uplink::C));
        assert_eq!(attribute("198.51.100.10".parse().unwrap()), None);
        assert_eq!(attribute("198.18.0.7".parse().unwrap()), None);
    }

    #[test]
    fn prefix_edges() {
        let all: Prefix = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("203.0.113.1".parse().unwrap()));
        assert!(!all.contains("::1".parse().unwrap()));
        let host: Prefix = "2001:db8::1/128".parse().unwrap();
        assert!(host.contains("2001:db8::1".parse().unwrap()));
        assert!(!host.contains("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn names_round_trip() {
        for n in Node::ALL {
            assert_eq!(n.short().parse::<Node>().unwrap(), n);
        }
        assert_eq!("b".parse::<Uplink>().unwrap(), Uplink::B);
        assert_eq!(servers(Family::V6, 50).len(), 50);
    }
}
