//! Nexthop object messages (`RTM_*NEXTHOP`, `struct nhmsg`), which
//! `netlink-packet-route` does not provide (0.33.0): a bounded local
//! implementation of what FTR reads (FR-DISC-3, IMPL-2). FTR owns no nexthop
//! objects, so it only parses notifications and dump replies, and emits the
//! dump request.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{DecodeError, NetlinkDeserializable, NetlinkHeader, NetlinkPayload, NetlinkSerializable};
use netlink_packet_route::RouteNetlinkMessage;

pub const RTM_NEWNEXTHOP: u16 = 104;
pub const RTM_DELNEXTHOP: u16 = 105;
pub const RTM_GETNEXTHOP: u16 = 106;

const NHA_ID: u16 = 1;
const NHA_GROUP: u16 = 2;
const NHA_BLACKHOLE: u16 = 4;
const NHA_OIF: u16 = 5;
const NHA_GATEWAY: u16 = 6;
const NHA_FDB: u16 = 11;

const RTNH_F_DEAD: u32 = 1;
const RTNH_F_ONLINK: u32 = 4;
const RTNH_F_LINKDOWN: u32 = 16;

/// A nexthop object as the kernel reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NexthopMessage {
    pub id: u32,
    /// The ids of the members of a group (`NHA_GROUP`); empty for a single
    /// object.
    pub group: Vec<u32>,
    pub blackhole: bool,
    /// A nexthop of the bridge forwarding database, never of a route.
    pub fdb: bool,
    pub ifindex: Option<u32>,
    pub gateway: Option<IpAddr>,
    pub onlink: bool,
    pub dead: bool,
    pub linkdown: bool,
}

impl NexthopMessage {
    /// Parses `struct nhmsg` (family, scope, protocol, reserved, flags) and
    /// its attributes.
    pub fn parse(payload: &[u8]) -> Result<NexthopMessage, DecodeError> {
        if payload.len() < 8 {
            return Err(format!("nexthop message of {} bytes", payload.len()).into());
        }
        let flags = u32::from_ne_bytes(payload[4..8].try_into().expect("four bytes"));
        let mut m = NexthopMessage {
            onlink: flags & RTNH_F_ONLINK != 0,
            dead: flags & RTNH_F_DEAD != 0,
            linkdown: flags & RTNH_F_LINKDOWN != 0,
            ..NexthopMessage::default()
        };
        let mut off = 8;
        while off + 4 <= payload.len() {
            let len = usize::from(u16::from_ne_bytes([payload[off], payload[off + 1]]));
            let kind = u16::from_ne_bytes([payload[off + 2], payload[off + 3]]) & 0x3fff;
            if len < 4 || off + len > payload.len() {
                return Err(format!("nexthop attribute {kind} of length {len} at {off}").into());
            }
            let value = &payload[off + 4..off + len];
            match (kind, value.len()) {
                (NHA_ID, 4) => m.id = u32::from_ne_bytes(value.try_into().expect("four bytes")),
                (NHA_OIF, 4) => m.ifindex = Some(u32::from_ne_bytes(value.try_into().expect("four bytes"))),
                (NHA_GATEWAY, 4) => {
                    m.gateway = Some(IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(value).expect("four bytes"),
                    )))
                }
                (NHA_GATEWAY, 16) => {
                    m.gateway = Some(IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(value).expect("sixteen bytes"),
                    )))
                }
                // `struct nexthop_grp`: id, weight, two reserved fields.
                (NHA_GROUP, n) if n % 8 == 0 => {
                    m.group = value
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
                        .collect();
                }
                (NHA_BLACKHOLE, _) => m.blackhole = true,
                (NHA_FDB, _) => m.fdb = true,
                _ => {}
            }
            off += (len + 3) & !3;
        }
        Ok(m)
    }
}

/// A route netlink message, or a nexthop message that `netlink-packet-route`
/// does not parse. Both travel on the same sockets, so that nexthop and
/// route notifications keep their order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Route(RouteNetlinkMessage),
    NewNexthop(NexthopMessage),
    DelNexthop(NexthopMessage),
    /// Dump request for every nexthop object.
    GetNexthops,
}

impl From<RouteNetlinkMessage> for Message {
    fn from(m: RouteNetlinkMessage) -> Message {
        Message::Route(m)
    }
}

impl From<Message> for NetlinkPayload<Message> {
    fn from(m: Message) -> NetlinkPayload<Message> {
        NetlinkPayload::InnerMessage(m)
    }
}

impl NetlinkSerializable for Message {
    fn message_type(&self) -> u16 {
        match self {
            Message::Route(m) => NetlinkSerializable::message_type(m),
            Message::NewNexthop(_) => RTM_NEWNEXTHOP,
            Message::DelNexthop(_) => RTM_DELNEXTHOP,
            Message::GetNexthops => RTM_GETNEXTHOP,
        }
    }

    fn buffer_len(&self) -> usize {
        match self {
            Message::Route(m) => NetlinkSerializable::buffer_len(m),
            // FTR sends only the dump request: an `nhmsg` of family
            // `AF_UNSPEC`, which strict checking accepts.
            _ => 8,
        }
    }

    fn serialize(&self, buffer: &mut [u8]) {
        match self {
            Message::Route(m) => NetlinkSerializable::serialize(m, buffer),
            _ => buffer[..8].fill(0),
        }
    }
}

impl NetlinkDeserializable for Message {
    type Error = DecodeError;

    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Message, DecodeError> {
        match header.message_type {
            RTM_NEWNEXTHOP => NexthopMessage::parse(payload).map(Message::NewNexthop),
            RTM_DELNEXTHOP => NexthopMessage::parse(payload).map(Message::DelNexthop),
            _ => RouteNetlinkMessage::deserialize(header, payload).map(Message::Route),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut v = ((4 + value.len()) as u16).to_ne_bytes().to_vec();
        v.extend_from_slice(&kind.to_ne_bytes());
        v.extend_from_slice(value);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    fn nhmsg(family: u8, flags: u32) -> Vec<u8> {
        let mut v = vec![family, 0, 4, 0];
        v.extend_from_slice(&flags.to_ne_bytes());
        v
    }

    #[test]
    fn single_objects_are_parsed() {
        // As `ip nexthop add id 10 via fe80::1 dev wa onlink` is notified.
        let mut p = nhmsg(10, RTNH_F_ONLINK);
        p.extend(attr(NHA_ID, &10u32.to_ne_bytes()));
        p.extend(attr(NHA_OIF, &2u32.to_ne_bytes()));
        p.extend(attr(NHA_GATEWAY, &"fe80::1".parse::<Ipv6Addr>().unwrap().octets()));
        let m = NexthopMessage::parse(&p).unwrap();
        assert_eq!(
            m,
            NexthopMessage {
                id: 10,
                ifindex: Some(2),
                gateway: Some("fe80::1".parse().unwrap()),
                onlink: true,
                ..NexthopMessage::default()
            }
        );
        let mut p = nhmsg(2, RTNH_F_DEAD | RTNH_F_LINKDOWN);
        p.extend(attr(NHA_ID, &30u32.to_ne_bytes()));
        p.extend(attr(NHA_GATEWAY, &[192, 0, 2, 1]));
        let m = NexthopMessage::parse(&p).unwrap();
        assert_eq!(m.gateway, Some("192.0.2.1".parse().unwrap()));
        assert!(m.dead && m.linkdown && !m.onlink);
    }

    #[test]
    fn groups_blackholes_and_bad_attributes() {
        let mut p = nhmsg(0, 0);
        p.extend(attr(NHA_ID, &20u32.to_ne_bytes()));
        let mut grp = Vec::new();
        for id in [10u32, 11] {
            grp.extend_from_slice(&id.to_ne_bytes());
            grp.extend_from_slice(&[0, 0, 0, 0]);
        }
        p.extend(attr(NHA_GROUP, &grp));
        let m = NexthopMessage::parse(&p).unwrap();
        assert_eq!((m.id, m.group), (20, vec![10, 11]));
        let mut p = nhmsg(10, 0);
        p.extend(attr(NHA_ID, &5u32.to_ne_bytes()));
        p.extend(attr(NHA_BLACKHOLE, &[]));
        assert!(NexthopMessage::parse(&p).unwrap().blackhole);
        let mut bad = nhmsg(10, 0);
        bad.extend_from_slice(&[40, 0, 1, 0, 1, 0, 0, 0]);
        assert!(NexthopMessage::parse(&bad).is_err());
        assert!(NexthopMessage::parse(&[0; 4]).is_err());
    }

    #[test]
    fn route_messages_pass_through() {
        let mut header = NetlinkHeader::default();
        header.message_type = RTM_NEWNEXTHOP;
        let mut p = nhmsg(10, 0);
        p.extend(attr(NHA_ID, &7u32.to_ne_bytes()));
        assert!(matches!(Message::deserialize(&header, &p), Ok(Message::NewNexthop(m)) if m.id == 7));
        let get = Message::GetNexthops;
        assert_eq!(
            (get.message_type(), NetlinkSerializable::buffer_len(&get)),
            (RTM_GETNEXTHOP, 8)
        );
        let route = Message::Route(crate::netlink::msg::link_dump());
        assert_eq!(route.message_type(), 18, "RTM_GETLINK");
    }
}
