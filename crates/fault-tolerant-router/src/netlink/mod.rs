//! Netlink transport (SPEC.md §12.2, IMPL-2, PLAT-1, spike S3).
//!
//! FTR builds its own rule and route messages ([`msg`]) and sends them with
//! explicit flags through `netlink-proto`. Sockets have one role each:
//! a [`Client`] sends requests (dumps or mutations) and is never subscribed
//! to notifications; the observer's [`Subscription`] receives notifications
//! and never sends requests, because `netlink-proto` matches replies by
//! sequence number only (S3).

pub mod msg;

use std::fmt;
use std::io;

use futures_util::StreamExt;
use futures_channel::mpsc::UnboundedReceiver;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_proto::ConnectionHandle;
use netlink_sys::{AsyncSocket, SocketAddr, protocols::NETLINK_ROUTE};

/// A failed kernel operation: errno and the extended acknowledgement message
/// when the kernel sent one (PLAT-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelError {
    pub errno: i32,
    pub extack: Option<String>,
}

impl KernelError {
    pub fn transport(e: impl fmt::Display) -> KernelError {
        // EIO stands for a failure of the socket rather than of the request.
        KernelError {
            errno: 5,
            extack: Some(format!("netlink transport failure: {e}")),
        }
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = io::Error::from_raw_os_error(self.errno);
        match &self.extack {
            Some(m) => write!(f, "errno {} ({text}), extended acknowledgement \"{m}\"", self.errno),
            None => write!(f, "errno {} ({text}), no extended acknowledgement", self.errno),
        }
    }
}

impl std::error::Error for KernelError {}

pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EEXIST: i32 = 17;

/// Extracts `NLMSGERR_ATTR_MSG` from the payload of an error message. With
/// `NETLINK_CAP_ACK` the kernel echoes only the 16-byte header of the
/// request, followed by the TLVs. No crate parses them (S3).
pub fn parse_extack(payload: &[u8]) -> Option<String> {
    let mut off = 16;
    while off + 4 <= payload.len() {
        let len = usize::from(u16::from_ne_bytes([payload[off], payload[off + 1]]));
        let kind = u16::from_ne_bytes([payload[off + 2], payload[off + 3]]) & 0x3fff;
        if len < 4 || off + len > payload.len() {
            return None;
        }
        if kind == 1 {
            let s = &payload[off + 4..off + len];
            let s = s.split(|b| *b == 0).next().unwrap_or(&[]);
            return Some(String::from_utf8_lossy(s).into_owned());
        }
        off += (len + 3) & !3;
    }
    None
}

/// Kind of mutation, mapped to netlink flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    /// `NLM_F_CREATE | NLM_F_EXCL`: rules (never `NLM_F_REPLACE`, which adds
    /// a duplicate rule, FR-REC-6) and new objects.
    Create,
    /// `NLM_F_CREATE | NLM_F_REPLACE`: route replacement (FR-ROUTE-2).
    Replace,
    /// Deletion (the message type is `Del*`).
    Delete,
}

impl Mutation {
    fn flags(self) -> u16 {
        NLM_F_REQUEST
            | NLM_F_ACK
            | match self {
                Mutation::Create => NLM_F_CREATE | NLM_F_EXCL,
                Mutation::Replace => NLM_F_CREATE | NLM_F_REPLACE,
                Mutation::Delete => 0,
            }
    }
}

/// The messages of a dump and whether the kernel flagged it as interrupted.
#[derive(Debug)]
pub struct Dump {
    pub messages: Vec<RouteNetlinkMessage>,
    pub interrupted: bool,
}

/// A request socket: dumps and mutations, never subscribed.
pub struct Client {
    handle: ConnectionHandle<RouteNetlinkMessage>,
    port: u32,
    // Kept open: an unsubscribed socket receives nothing unsolicited, but
    // dropping the receiver would make the connection log warnings.
    _unsolicited: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>,
}

impl Client {
    /// Opens a socket with extended acknowledgements, capped acks and strict
    /// dump checking, and spawns its connection task on the current runtime.
    pub fn new() -> io::Result<Client> {
        let (mut conn, handle, unsolicited) = netlink_proto::new_connection(NETLINK_ROUTE)?;
        let socket = conn.socket_mut().socket_mut();
        let port = socket.bind_auto()?.port_number();
        socket.set_ext_ack(true)?;
        socket.set_cap_ack(true)?;
        socket.set_netlink_get_strict_chk(true)?;
        tokio::spawn(conn);
        Ok(Client {
            handle,
            port,
            _unsolicited: unsolicited,
        })
    }

    /// The socket's port id, which the kernel copies into the notifications
    /// caused by this socket's requests (FR-COEX-3).
    pub fn port(&self) -> u32 {
        self.port
    }

    async fn request(
        &self,
        msg: RouteNetlinkMessage,
        flags: u16,
    ) -> Result<Vec<NetlinkMessage<RouteNetlinkMessage>>, KernelError> {
        let mut req = NetlinkMessage::from(msg);
        req.header.flags = flags;
        let mut stream = self
            .handle
            .request(req, SocketAddr::new(0, 0))
            .map_err(KernelError::transport)?;
        let mut out = Vec::new();
        let mut error = None;
        while let Some(m) = stream.next().await {
            match &m.payload {
                NetlinkPayload::Error(e) => {
                    if let Some(code) = e.code {
                        error.get_or_insert(KernelError {
                            errno: -code.get(),
                            extack: parse_extack(&e.header),
                        });
                    }
                }
                NetlinkPayload::Overrun(_) => {
                    error.get_or_insert(KernelError::transport("receive buffer overrun"));
                }
                _ => out.push(m),
            }
        }
        match error {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    /// Applies one mutation and waits for its acknowledgement.
    pub async fn mutate(&self, msg: RouteNetlinkMessage, kind: Mutation) -> Result<(), KernelError> {
        self.request(msg, kind.flags()).await.map(|_| ())
    }

    /// Runs a dump. With strict checking, the header and attributes of
    /// `filter` select what the kernel returns (S3).
    pub async fn dump(&self, filter: RouteNetlinkMessage) -> Result<Dump, KernelError> {
        let replies = self.request(filter, NLM_F_REQUEST | NLM_F_DUMP).await?;
        let interrupted = replies.iter().any(|m| m.header.flags & NLM_F_DUMP_INTR != 0);
        let messages = replies
            .into_iter()
            .filter_map(|m| match m.payload {
                NetlinkPayload::InnerMessage(i) => Some(i),
                _ => None,
            })
            .collect();
        Ok(Dump { messages, interrupted })
    }
}

/// rtnetlink multicast groups (`RTNLGRP_*`) the observer subscribes to.
pub mod groups {
    pub const LINK: u32 = 1;
    pub const IPV4_IFADDR: u32 = 5;
    pub const IPV4_ROUTE: u32 = 7;
    pub const IPV4_RULE: u32 = 8;
    pub const IPV6_IFADDR: u32 = 9;
    pub const IPV6_ROUTE: u32 = 11;
    pub const IPV6_RULE: u32 = 19;
    pub const NEXTHOP: u32 = 32;
    pub const ALL: [u32; 8] = [
        LINK,
        IPV4_IFADDR,
        IPV4_ROUTE,
        IPV4_RULE,
        IPV6_IFADDR,
        IPV6_ROUTE,
        IPV6_RULE,
        NEXTHOP,
    ];
}

/// A notification and the port id of the request that caused it (0 for the
/// kernel itself).
#[derive(Debug)]
pub enum Notification {
    Message {
        message: RouteNetlinkMessage,
        port: u32,
    },
    /// `ENOBUFS`: notifications were lost; the observer must resynchronise.
    Overrun,
}

/// A subscribed socket that never sends requests.
pub struct Subscription {
    rx: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>,
    // Never used to send: holding it keeps the connection task alive.
    _handle: ConnectionHandle<RouteNetlinkMessage>,
}

impl Subscription {
    pub fn new(groups: &[u32], receive_buffer: usize) -> io::Result<Subscription> {
        let (mut conn, handle, rx) = netlink_proto::new_connection(NETLINK_ROUTE)?;
        let socket = conn.socket_mut().socket_mut();
        socket.bind_auto()?;
        socket.set_rx_buf_sz(receive_buffer)?;
        for g in groups {
            socket.add_membership(*g)?;
        }
        tokio::spawn(conn);
        Ok(Subscription { rx, _handle: handle })
    }

    /// The next notification; `None` when the socket is closed.
    pub async fn next(&mut self) -> Option<Notification> {
        loop {
            let (m, _) = self.rx.next().await?;
            match m.payload {
                NetlinkPayload::InnerMessage(message) => {
                    return Some(Notification::Message {
                        message,
                        port: m.header.port_number,
                    });
                }
                NetlinkPayload::Overrun(_) => return Some(Notification::Overrun),
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extack_is_parsed_after_the_capped_header() {
        let mut payload = vec![0u8; 16];
        // NLMSGERR_ATTR_MSG "Nexthop has invalid gateway" with padding.
        let msg = b"Nexthop has invalid gateway\0";
        let len = (4 + msg.len()) as u16;
        payload.extend_from_slice(&len.to_ne_bytes());
        payload.extend_from_slice(&1u16.to_ne_bytes());
        payload.extend_from_slice(msg);
        while payload.len() % 4 != 0 {
            payload.push(0);
        }
        assert_eq!(parse_extack(&payload).as_deref(), Some("Nexthop has invalid gateway"));
        assert_eq!(parse_extack(&payload[..16]), None);
    }

    #[test]
    fn errors_say_when_there_is_no_extended_ack() {
        let e = KernelError {
            errno: EEXIST,
            extack: None,
        };
        assert!(e.to_string().starts_with("errno 17 ("));
        assert!(e.to_string().ends_with("no extended acknowledgement"));
    }
}
