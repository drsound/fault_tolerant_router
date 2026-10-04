//! Router Advertisements seen on arrival (FR-DISC-5). The kernel notifies
//! neither the refresh nor the shortening of an advertised router lifetime,
//! and `RTM_NEWPREFIX` covers only advertisements with prefix information
//! (M2 inventory D6). A raw ICMPv6 socket receives a copy of every
//! advertisement that reaches the host, with the receiving interface as the
//! scope of its link-local source: each one is reported by interface index,
//! so that the daemon re-reads the tables of that interface's advertised
//! default routes.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// ICMPv6 type of a Router Advertisement.
const ROUTER_ADVERTISEMENT: u8 = 134;

/// The fixed part of a Router Advertisement (RFC 4861 §4.2).
const HEADER_LEN: usize = 16;

/// Raw sockets get their copy before the kernel processes the
/// advertisement: the report waits for that processing.
const SETTLE: Duration = Duration::from_millis(20);

/// Starts the listener; it reports the interface index of every
/// advertisement on `tx`.
pub fn spawn(tx: mpsc::UnboundedSender<u32>) -> io::Result<JoinHandle<()>> {
    let s = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    s.set_nonblocking(true)?;
    // A raw socket is a datagram socket for recv_from (see probe.rs).
    let fd = AsyncFd::new(UdpSocket::from(s))?;
    Ok(tokio::spawn(listen(fd, tx)))
}

async fn listen(fd: AsyncFd<UdpSocket>, tx: mpsc::UnboundedSender<u32>) {
    // Only the fixed part is read; the rest of the datagram is discarded.
    let mut buf = [0u8; HEADER_LEN];
    loop {
        let Ok(mut guard) = fd.readable().await else {
            return;
        };
        while let Ok(Ok((len, from))) = guard.try_io(|fd| fd.get_ref().recv_from(&mut buf)) {
            if let Some(ifindex) = advertisement(&buf[..len], from) {
                let tx = tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(SETTLE).await;
                    let _ = tx.send(ifindex);
                });
            }
        }
    }
}

/// The receiving interface of a Router Advertisement: the scope of its
/// link-local source (the kernel accepts no other source).
fn advertisement(packet: &[u8], from: SocketAddr) -> Option<u32> {
    match from {
        SocketAddr::V6(a) if packet.len() == HEADER_LEN && packet[0] == ROUTER_ADVERTISEMENT && a.scope_id() != 0 => {
            Some(a.scope_id())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddrV6};

    use super::*;

    fn from(scope: u32) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            0,
            0,
            scope,
        ))
    }

    #[test]
    fn advertisements_are_reported_by_receiving_interface() {
        let mut ra = [0u8; HEADER_LEN];
        ra[0] = ROUTER_ADVERTISEMENT;
        assert_eq!(advertisement(&ra, from(7)), Some(7));
        // Neighbour discovery, a truncated advertisement, no scope.
        let mut ns = ra;
        ns[0] = 135;
        assert_eq!(advertisement(&ns, from(7)), None);
        assert_eq!(advertisement(&ra[..8], from(7)), None);
        assert_eq!(advertisement(&ra, from(0)), None);
    }
}
