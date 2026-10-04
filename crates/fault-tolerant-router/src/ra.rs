//! Router Advertisements seen on arrival (FR-DISC-5). The kernel notifies
//! neither the refresh nor the shortening of an advertised router lifetime,
//! and `RTM_NEWPREFIX` covers only advertisements with prefix information
//! (M2 inventory D6). A raw ICMPv6 socket receives a copy of every
//! advertisement that reaches the host, with the receiving interface as the
//! scope of its link-local source. The interfaces that received
//! advertisements are reported, at most once per interface and window
//! however many arrive, so that the daemon re-reads the tables of their
//! advertised default routes.

use std::collections::BTreeSet;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};

/// ICMPv6 type of a Router Advertisement.
const ROUTER_ADVERTISEMENT: u8 = 134;

/// The fixed part of a Router Advertisement (RFC 4861 §4.2).
const HEADER_LEN: usize = 16;

/// The window from an interface's first advertisement to its report: raw
/// sockets get their copy before the kernel processes it, and the
/// advertisements of the window are reported once.
const WINDOW: Duration = Duration::from_millis(100);

/// Packets read before the other tasks run.
const BATCH: usize = 64;

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
    let mut pending = BTreeSet::new();
    let mut due: Option<Instant> = None;
    loop {
        tokio::select! {
            ready = fd.readable() => {
                let Ok(mut guard) = ready else {
                    return;
                };
                let mut read = 0;
                while read < BATCH
                    && let Ok(Ok((len, from))) = guard.try_io(|fd| fd.get_ref().recv_from(&mut buf))
                {
                    read += 1;
                    if let Some(ifindex) = advertisement(&buf[..len], from) {
                        pending.insert(ifindex);
                        due.get_or_insert_with(|| Instant::now() + WINDOW);
                    }
                }
                if read == BATCH {
                    tokio::task::yield_now().await;
                }
            }
            () = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                due = None;
                for ifindex in std::mem::take(&mut pending) {
                    let _ = tx.send(ifindex);
                }
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
