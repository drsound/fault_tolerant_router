//! Test agents, run inside namespaces as `polywan-testbed agent ...`.
//!
//! - `serve` (internet node): TCP on [`TCP_PORT`] and [`TCP_PORT_HTTPS`]
//!   writes the peer address as the first line, then echoes; UDP on
//!   [`UDP_PORT`] answers each datagram with the peer address; UDP on
//!   [`UDP_SINK_PORT`] only logs. Every accepted connection and datagram is
//!   appended to a JSON-lines log, so one-way flows can be attributed too.
//! - `connect` (client): opens many connections and prints one
//!   [`ConnResult`] per connection as a JSON array.
//! - `flow` (client): one long-lived TCP connection exchanging a counter at
//!   a fixed interval until standard input closes; prints a [`FlowReport`].
//! - `udp-send` (client): a one-way UDP flow from a fixed local port.
//! - `send-ra` (provider): Router Advertisements, with or without prefix
//!   information, one or a flood (FR-DISC-5).
//!
//! The agents use the standard library only and blocking threads, which
//! keeps them independent of the daemon's runtime.

use std::fs::File;
use std::io::{self, BufRead, BufReader, IoSlice, IoSliceMut, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::libc;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn, SockaddrIn6,
    SockaddrStorage, bind, recvmsg, sendmsg, setsockopt, socket, sockopt,
};
use serde::Serialize;

use crate::plan::{TCP_PORT, TCP_PORT_HTTPS, UDP_PORT, UDP_SINK_PORT, canonical};
use crate::traffic::{ConnResult, FlowReport, Outcome, ServerEvent};

fn canon(sa: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical(sa.ip()), sa.port())
}

struct Log(Option<Mutex<File>>);

impl Log {
    fn write<T: Serialize>(&self, ev: &T) {
        if let Some(f) = &self.0
            && let (Ok(mut f), Ok(line)) = (f.lock(), serde_json::to_string(ev))
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Runs the servers forever.
pub fn serve(log_path: Option<&str>) -> Result<()> {
    let log = Arc::new(Log(match log_path {
        Some(p) => Some(Mutex::new(File::options().create(true).append(true).open(p)?)),
        None => None,
    }));
    let any = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let mut handles = Vec::new();
    for port in [TCP_PORT, TCP_PORT_HTTPS] {
        // Dual-stack: IPv4 clients appear as IPv4-mapped addresses.
        let l = TcpListener::bind(SocketAddr::new(any, port)).with_context(|| format!("binding TCP {port}"))?;
        let log = log.clone();
        handles.push(thread::spawn(move || {
            for s in l.incoming().flatten() {
                let log = log.clone();
                thread::spawn(move || tcp_session(s, &log));
            }
        }));
    }
    for (port, reply) in [(UDP_PORT, true), (UDP_SINK_PORT, false)] {
        for v6 in [false, true] {
            let s = udp_socket(v6, port).with_context(|| format!("binding UDP {port}"))?;
            let log = log.clone();
            handles.push(thread::spawn(move || udp_loop(&s, port, reply, &log)));
        }
    }
    eprintln!("polywan-testbed agent: serving");
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// A UDP socket of one family that reports the destination address of each
/// datagram, so that answers leave from the address the client used (the
/// servers answer on every address of a prefix, see [`crate::plan::SERVERS_V4`]).
fn udp_socket(v6: bool, port: u16) -> Result<UdpSocket> {
    let fd = if v6 {
        let fd = socket(AddressFamily::Inet6, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None)?;
        setsockopt(&fd, sockopt::Ipv6V6Only, &true)?;
        setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true)?;
        bind(
            fd.as_raw_fd(),
            &SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)),
        )?;
        fd
    } else {
        let fd = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None)?;
        setsockopt(&fd, sockopt::Ipv4PacketInfo, &true)?;
        bind(
            fd.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
        )?;
        fd
    };
    Ok(UdpSocket::from(fd))
}

fn udp_loop(s: &UdpSocket, port: u16, reply: bool, log: &Log) {
    let fd = s.as_raw_fd();
    let mut buf = [0u8; 2048];
    loop {
        let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo);
        let (bytes, peer, dst) = {
            let mut iov = [IoSliceMut::new(&mut buf)];
            let Ok(msg) = recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty()) else {
                continue;
            };
            let mut dst = None;
            for c in msg.cmsgs().into_iter().flatten() {
                match c {
                    ControlMessageOwned::Ipv4PacketInfo(pi) => {
                        dst = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(pi.ipi_addr.s_addr))));
                    }
                    ControlMessageOwned::Ipv6PacketInfo(pi) => {
                        dst = Some(IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr)))
                    }
                    _ => {}
                }
            }
            let peer = msg.address.and_then(|a| {
                a.as_sockaddr_in()
                    .map(|v4| SocketAddr::V4(SocketAddrV4::from(*v4)))
                    .or_else(|| a.as_sockaddr_in6().map(|v6| SocketAddr::V6(SocketAddrV6::from(*v6))))
            });
            (msg.bytes, peer, dst)
        };
        let Some(peer) = peer else { continue };
        log.write(&ServerEvent {
            proto: "udp".into(),
            port,
            peer,
            local: dst.map(|d| SocketAddr::new(d, port)),
            bytes,
        });
        if !reply {
            continue;
        }
        let text = format!("{peer}\n");
        let iov = [IoSlice::new(text.as_bytes())];
        let _ = match (peer, dst) {
            (SocketAddr::V4(p), Some(IpAddr::V4(d))) => {
                let pi = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from(d).to_be(),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                sendmsg(
                    fd,
                    &iov,
                    &[ControlMessage::Ipv4PacketInfo(&pi)],
                    MsgFlags::empty(),
                    Some(&SockaddrIn::from(p)),
                )
            }
            (SocketAddr::V6(p), Some(IpAddr::V6(d))) => {
                let pi = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr { s6_addr: d.octets() },
                    ipi6_ifindex: 0,
                };
                sendmsg(
                    fd,
                    &iov,
                    &[ControlMessage::Ipv6PacketInfo(&pi)],
                    MsgFlags::empty(),
                    Some(&SockaddrIn6::from(p)),
                )
            }
            (SocketAddr::V4(p), _) => sendmsg(fd, &iov, &[], MsgFlags::empty(), Some(&SockaddrIn::from(p))),
            (SocketAddr::V6(p), _) => sendmsg(fd, &iov, &[], MsgFlags::empty(), Some(&SockaddrIn6::from(p))),
        };
    }
}

fn tcp_session(mut s: TcpStream, log: &Log) {
    let (Ok(peer), Ok(local)) = (s.peer_addr(), s.local_addr()) else {
        return;
    };
    log.write(&ServerEvent {
        proto: "tcp".into(),
        port: local.port(),
        peer: canon(peer),
        local: Some(canon(local)),
        bytes: 0,
    });
    if s.write_all(format!("{}\n", canon(peer)).as_bytes()).is_err() {
        return;
    }
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if s.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

fn classify(e: &io::Error) -> Outcome {
    match e.raw_os_error() {
        Some(101) | Some(113) => Outcome::Unreachable,
        Some(111) => Outcome::Refused,
        _ if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => Outcome::Timeout,
        _ => Outcome::Error,
    }
}

/// Opens one connection (TCP) or exchange (UDP) and reports what happened.
/// Optional binding of the agent's sockets: a source address
/// (`bind(2)`) and an interface (`SO_BINDTODEVICE`).
#[derive(Clone, Debug, Default)]
pub struct Binding {
    pub source: Option<IpAddr>,
    pub device: Option<String>,
}

impl Binding {
    fn is_none(&self) -> bool {
        self.source.is_none() && self.device.is_none()
    }

    fn socket(&self, dst: SocketAddr, udp: bool) -> io::Result<socket2::Socket> {
        use socket2::{Domain, Protocol, Socket, Type};
        let domain = if dst.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let (ty, proto) = if udp {
            (Type::DGRAM, Protocol::UDP)
        } else {
            (Type::STREAM, Protocol::TCP)
        };
        let s = Socket::new(domain, ty, Some(proto))?;
        if let Some(d) = &self.device {
            s.bind_device(Some(d.as_bytes()))?;
        }
        if let Some(a) = self.source {
            s.bind(&SocketAddr::new(a, 0).into())?;
        }
        Ok(s)
    }
}

fn one(dst: SocketAddr, udp: bool, timeout: Duration, binding: &Binding) -> ConnResult {
    let start = Instant::now();
    let mut r = ConnResult {
        dst,
        local: None,
        observed: None,
        outcome: Outcome::Ok,
        errno: None,
        millis: 0,
    };
    let res: io::Result<String> = (|| {
        if udp {
            let s = if binding.is_none() {
                let bind = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                UdpSocket::bind(bind)?
            } else {
                let s: UdpSocket = binding.socket(dst, true)?.into();
                s
            };
            s.connect(dst)?;
            r.local = s.local_addr().ok();
            s.set_read_timeout(Some(timeout))?;
            s.send(b"polywan-testbed")?;
            let mut buf = [0u8; 256];
            let n = s.recv(&mut buf)?;
            Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
        } else {
            let s = if binding.is_none() {
                TcpStream::connect_timeout(&dst, timeout)?
            } else {
                let sock = binding.socket(dst, false)?;
                sock.connect_timeout(&dst.into(), timeout)?;
                sock.into()
            };
            r.local = s.local_addr().ok();
            s.set_read_timeout(Some(timeout))?;
            let mut line = String::new();
            BufReader::new(&s).read_line(&mut line)?;
            Ok(line)
        }
    })();
    match res {
        Ok(line) => r.observed = line.trim().parse().ok(),
        Err(e) => {
            r.outcome = classify(&e);
            r.errno = e.raw_os_error();
        }
    }
    r.millis = start.elapsed().as_millis() as u64;
    r
}

/// Opens `count` connections, cycling over `dsts`, with up to `parallel` in flight.
pub fn connect(
    dsts: &[SocketAddr],
    count: usize,
    udp: bool,
    timeout: Duration,
    parallel: usize,
    binding: &Binding,
) -> Vec<ConnResult> {
    let next = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::with_capacity(count)));
    let dsts: Arc<Vec<SocketAddr>> = Arc::new(dsts.to_vec());
    let workers: Vec<_> = (0..parallel.clamp(1, count.max(1)))
        .map(|_| {
            let (next, results, dsts, binding) = (next.clone(), results.clone(), dsts.clone(), binding.clone());
            thread::spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= count {
                        return;
                    }
                    let r = one(dsts[i % dsts.len()], udp, timeout, &binding);
                    if let Ok(mut v) = results.lock() {
                        v.push((i, r));
                    }
                }
            })
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
    let mut v = Arc::try_unwrap(results)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_default();
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, r)| r).collect()
}

/// A long-lived TCP flow; stops when standard input closes or after `duration`.
/// Sends `bytes` bytes to a test server and reads them back (the server
/// echoes), in full-size segments both ways (path MTU discovery, AS-31).
pub fn bulk(dst: SocketAddr, bytes: usize, timeout: Duration) -> FlowReport {
    let mut rep = FlowReport::default();
    let start = Instant::now();
    let res: io::Result<()> = (|| {
        let s = TcpStream::connect_timeout(&dst, Duration::from_secs(3))?;
        rep.local = s.local_addr().ok();
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;
        let mut first = Vec::new();
        let mut b = [0u8; 1];
        while (&s).read(&mut b)? == 1 && b[0] != b'\n' {
            first.push(b[0]);
        }
        rep.observed = String::from_utf8_lossy(&first).trim().parse().ok();
        let reader = {
            let mut r = s.try_clone()?;
            thread::spawn(move || -> io::Result<u64> {
                let mut buf = vec![0u8; 65536];
                let mut got = 0u64;
                while (got as usize) < bytes {
                    let n = r.read(&mut buf)?;
                    if n == 0 {
                        return Err(io::Error::other("closed before the echo was complete"));
                    }
                    got += n as u64;
                }
                Ok(got)
            })
        };
        let chunk = vec![0x5au8; 16384];
        let mut sent = 0;
        while sent < bytes {
            let n = chunk.len().min(bytes - sent);
            (&s).write_all(&chunk[..n])?;
            sent += n;
        }
        rep.sent = sent as u64;
        rep.received = reader.join().map_err(|_| io::Error::other("reader panicked"))??;
        Ok(())
    })();
    if let Err(e) = res {
        rep.error = Some(e.to_string());
        rep.errno = e.raw_os_error();
    }
    rep.millis = start.elapsed().as_millis() as u64;
    rep
}

pub fn flow(dst: SocketAddr, interval: Duration, duration: Option<Duration>) -> FlowReport {
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = io::stdin().read_to_end(&mut sink);
            stop.store(true, Ordering::SeqCst);
        });
    }
    let mut rep = FlowReport::default();
    let start = Instant::now();
    let res: io::Result<()> = (|| {
        let mut s = TcpStream::connect_timeout(&dst, Duration::from_secs(3))?;
        rep.local = s.local_addr().ok();
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_nodelay(true)?;
        let mut first = Vec::new();
        let mut b = [0u8; 1];
        while s.read(&mut b)? == 1 && b[0] != b'\n' {
            first.push(b[0]);
        }
        rep.observed = String::from_utf8_lossy(&first).trim().parse().ok();
        let mut last_ok = Instant::now();
        let mut seq: u64 = 0;
        while !stop.load(Ordering::SeqCst) && duration.is_none_or(|d| start.elapsed() < d) {
            s.write_all(&seq.to_be_bytes())?;
            rep.sent += 1;
            let mut echo = [0u8; 8];
            s.read_exact(&mut echo)?;
            if u64::from_be_bytes(echo) != seq {
                return Err(io::Error::other("echo out of sequence"));
            }
            rep.received += 1;
            let gap = last_ok.elapsed().as_millis() as u64;
            rep.max_gap_ms = rep.max_gap_ms.max(gap);
            last_ok = Instant::now();
            seq += 1;
            thread::sleep(interval);
        }
        Ok(())
    })();
    if let Err(e) = res {
        rep.error = Some(e.to_string());
        rep.errno = e.raw_os_error();
    }
    rep.millis = start.elapsed().as_millis() as u64;
    rep
}

/// Sends `count` datagrams from `src_port` to `dst` (UDP sink), one per `interval`.
pub fn udp_send(dst: SocketAddr, src_port: u16, count: u32, interval: Duration) -> Result<u32> {
    let bind = if dst.is_ipv4() {
        format!("0.0.0.0:{src_port}")
    } else {
        format!("[::]:{src_port}")
    };
    let s = UdpSocket::bind(&bind).with_context(|| format!("binding {bind}"))?;
    let mut sent = 0;
    for i in 0..count {
        if s.send_to(format!("polywan-testbed {i}").as_bytes(), dst).is_ok() {
            sent += 1;
        }
        thread::sleep(interval);
    }
    Ok(sent)
}

/// A Router Advertisement: current hop limit 64, the given flags and
/// router lifetime, and optionally prefix information for a /64.
pub struct Advertisement {
    pub lifetime: u16,
    pub flags: u8,
    pub prefix: Option<Ipv6Addr>,
}

/// Sends `count` Router Advertisements to all nodes on `device`,
/// `interval` apart. The kernel picks the interface's link-local address
/// as the source and fills in the ICMPv6 checksum; neighbour discovery
/// needs a hop limit of 255.
pub fn send_ra(device: &str, ra: &Advertisement, count: u32, interval: Duration) -> Result<()> {
    let ifindex: u32 = std::fs::read_to_string(format!("/sys/class/net/{device}/ifindex"))
        .with_context(|| format!("interface {device}"))?
        .trim()
        .parse()?;
    let s = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV6),
    )?;
    s.bind_device(Some(device.as_bytes()))?;
    s.set_multicast_if_v6(ifindex)?;
    s.set_multicast_hops_v6(255)?;
    let mut packet = vec![134, 0, 0, 0, 64, ra.flags];
    packet.extend_from_slice(&ra.lifetime.to_be_bytes());
    packet.extend_from_slice(&[0; 8]);
    if let Some(prefix) = ra.prefix {
        // RFC 4861 §4.6.2: type 3, length 4 (32 bytes), /64, on-link and
        // autonomous, valid and preferred lifetimes, reserved, prefix.
        packet.extend_from_slice(&[3, 4, 64, 0xc0]);
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&[0; 4]);
        packet.extend_from_slice(&prefix.octets());
    }
    let all_nodes = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        0,
        0,
        ifindex,
    ));
    for n in 0..count {
        if n > 0 && !interval.is_zero() {
            thread::sleep(interval);
        }
        s.send_to(&packet, &all_nodes.into())
            .context("sending the Router Advertisement")?;
    }
    Ok(())
}

/// One HTTP/1.1 request on a Unix socket, the connection closed after it:
/// the status code and the body.
pub fn http(socket: &Path, method: &str, path: &str, body: &str) -> Result<(u16, String)> {
    use std::io::{Read, Write};

    let mut s = std::os::unix::net::UnixStream::connect(socket).with_context(|| socket.display().to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: polywan\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut text = String::new();
    s.read_to_string(&mut text)?;
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .context("no HTTP status line")?;
    let body = text.split_once("\r\n\r\n").map_or("", |(_, b)| b).to_owned();
    Ok((code, body))
}
