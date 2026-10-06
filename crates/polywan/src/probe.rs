//! Prober (SPEC.md §5.2, spike S5): one task per ready path, rounds at a
//! fixed rate, ICMP echo over a raw socket and TCP handshakes, every socket
//! bound to the path's source and interface and marked with the path's probe
//! value before its first packet (FR-PROBE-1).
//!
//! Every report carries the path generation the task was started with; the
//! State task discards reports of older generations (FR-PROBE-3). A task is
//! aborted as soon as its path stops being ready or its interface, source or
//! configuration changes, which cancels its open attempts.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use socket2::{Domain, Protocol, SockAddr, SockFilter, Socket, Type};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior, sleep_until, timeout_at};

use crate::config::Target;
use crate::model::PathKey;

const TOKEN_LEN: usize = 16;
const EINPROGRESS: i32 = 115;

/// ICMP echo reply types.
const ECHO_REPLY_V4: u8 = 0;
const ECHO_REPLY_V6: u8 = 129;

/// Packets read from a raw socket before the other tasks of the routing
/// executor run: a flood must not monopolise it.
pub(crate) const BATCH: usize = 64;

/// Classic BPF opcodes (linux/filter.h).
const LDB_ABS: u16 = 0x30; // BPF_LD | BPF_B | BPF_ABS
const LDB_IND: u16 = 0x50; // BPF_LD | BPF_B | BPF_IND
const LDX_MSH: u16 = 0xb1; // BPF_LDX | BPF_B | BPF_MSH: X = 4 * (P[k] & 0xf)
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

/// A socket filter for a raw ICMP socket that passes only messages of
/// `icmp_type` with code 0, so that the kernel drops every other message
/// before it is queued. An IPv4 raw socket sees the IP header first; an
/// IPv6 one starts at the ICMPv6 header.
pub(crate) fn icmp_filter(ipv4: bool, icmp_type: u8) -> Vec<SockFilter> {
    // Load the byte at offset k of the ICMP header into A.
    let load = |k| {
        if ipv4 {
            SockFilter::new(LDB_IND, 0, 0, k)
        } else {
            SockFilter::new(LDB_ABS, 0, 0, k)
        }
    };
    let mut v = Vec::new();
    if ipv4 {
        // X = the IP header's length.
        v.push(SockFilter::new(LDX_MSH, 0, 0, 0));
    }
    v.extend([
        load(0),
        SockFilter::new(JEQ_K, 0, 3, u32::from(icmp_type)),
        load(1),
        SockFilter::new(JEQ_K, 0, 1, 0),
        SockFilter::new(RET_K, 0, 0, u32::MAX),
        SockFilter::new(RET_K, 0, 0, 0),
    ]);
    v
}

/// What a prober task needs; any change means a new generation.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    pub path: PathKey,
    pub generation: u64,
    pub interface: String,
    /// The interface's index when the prober starts: an interface recreated
    /// under the same name is a new generation (FR-PROBE-3), since sockets
    /// bound to the old one never see the new one.
    pub ifindex: u32,
    pub source: IpAddr,
    /// Encoded probe value of the uplink (FR-MARK-2, FR-MARK-3).
    pub mark: u32,
    pub targets: Vec<Target>,
    pub interval: Duration,
    pub timeout: Duration,
    pub attempts: u8,
    pub required_reachable: u8,
    /// With quality gates every started attempt runs to its end (FR-PROBE-4).
    pub run_to_completion: bool,
}

/// One completed attempt (FR-PROBE-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub target: Target,
    pub rtt: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct RoundReport {
    pub path: PathKey,
    pub generation: u64,
    pub passed: bool,
    pub reachable: usize,
    pub samples: Vec<Sample>,
    /// Attempts stopped by the early end of the round.
    pub canceled: usize,
}

/// A prober that could not start (for example a socket error); the State
/// task logs it and retries with the next generation or reconciliation.
#[derive(Debug)]
pub struct StartError {
    pub path: PathKey,
    pub generation: u64,
    pub error: io::Error,
}

pub enum Report {
    Round(RoundReport),
    Failed(StartError),
}

/// Starts the prober task of a path.
pub fn spawn(spec: Spec, tx: mpsc::Sender<Report>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = run(&spec, &tx).await {
            let _ = tx
                .send(Report::Failed(StartError {
                    path: spec.path,
                    generation: spec.generation,
                    error,
                }))
                .await;
        }
    })
}

async fn run(spec: &Spec, tx: &mpsc::Sender<Report>) -> io::Result<()> {
    let icmp = if spec.targets.iter().any(|t| matches!(t, Target::Icmp(_))) {
        Some(Arc::new(Icmp::new(spec)?))
    } else {
        None
    };
    let _reader = icmp.as_ref().map(|i| {
        let i = Arc::clone(i);
        AbortOnDrop(tokio::spawn(async move { i.read_loop().await }))
    });
    let mut ticker = tokio::time::interval(spec.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let report = round(spec, icmp.as_deref()).await;
        if tx.send(Report::Round(report)).await.is_err() {
            return Ok(());
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One round (FR-PROBE-4): every target concurrently, attempts in sequence,
/// early end once the outcome is certain unless `run_to_completion`.
async fn round(spec: &Spec, icmp: Option<&Icmp>) -> RoundReport {
    let samples = Mutex::new(Vec::new());
    let started = Mutex::new(0usize);
    let required = usize::from(spec.required_reachable);
    let mut pending: FuturesUnordered<_> = spec
        .targets
        .iter()
        .map(|t| target_attempts(spec, icmp, *t, &samples, &started))
        .collect();
    let total = pending.len();
    let (mut reachable, mut done) = (0, 0);
    while let Some(ok) = pending.next().await {
        done += 1;
        reachable += usize::from(ok);
        let certain = reachable >= required || reachable + (total - done) < required;
        if certain && !spec.run_to_completion {
            break;
        }
    }
    drop(pending);
    let samples = samples.into_inner().unwrap_or_else(|e| e.into_inner());
    let started = started.into_inner().unwrap_or_else(|e| e.into_inner());
    RoundReport {
        path: spec.path,
        generation: spec.generation,
        passed: reachable >= required,
        reachable,
        canceled: started.saturating_sub(samples.len()),
        samples,
    }
}

/// The attempts of one target; true if any got a valid reply.
async fn target_attempts(
    spec: &Spec,
    icmp: Option<&Icmp>,
    target: Target,
    samples: &Mutex<Vec<Sample>>,
    started: &Mutex<usize>,
) -> bool {
    for _ in 0..spec.attempts {
        *started.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        let deadline = Instant::now() + spec.timeout;
        let rtt = match (target, icmp) {
            (Target::Icmp(addr), Some(i)) => i.attempt(addr, deadline).await,
            (Target::Tcp(addr), _) => tcp_attempt(spec, addr, deadline).await,
            (Target::Icmp(_), None) => None,
        };
        samples
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Sample { target, rtt });
        if rtt.is_some() {
            return true;
        }
        // The next attempt is sent only after the previous one timed out,
        // also when it failed early (local error).
        sleep_until(deadline).await;
    }
    false
}

/// FR-PROBE-1: non-blocking, `SO_MARK`, `SO_BINDTODEVICE` and bound source,
/// all before the first packet.
fn probe_socket(spec: &Spec, ty: Type, protocol: Protocol) -> io::Result<Socket> {
    let domain = if spec.source.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let s = Socket::new(domain, ty, Some(protocol))?;
    s.set_nonblocking(true)?;
    s.set_mark(spec.mark)?;
    s.bind_device(Some(spec.interface.as_bytes()))?;
    s.bind(&SockAddr::from(SocketAddr::new(spec.source, 0)))?;
    Ok(s)
}

/// TCP attempt: a SYN-ACK or a RST on the attempt's own socket is a reply;
/// anything else, including local errors, is a loss (FR-PROBE-2, 3).
async fn tcp_attempt(spec: &Spec, target: SocketAddr, deadline: Instant) -> Option<Duration> {
    let start = Instant::now();
    let s = probe_socket(spec, Type::STREAM, Protocol::TCP).ok()?;
    // Close with a RST: no TIME_WAIT on the router.
    let _ = s.set_linger(Some(Duration::ZERO));
    match s.connect(&SockAddr::from(target)) {
        Ok(()) => return Some(start.elapsed()),
        Err(e) if e.raw_os_error() == Some(EINPROGRESS) => {}
        Err(_) => return None,
    }
    let fd = AsyncFd::with_interest(s, Interest::WRITABLE).ok()?;
    let mut guard = timeout_at(deadline, fd.writable()).await.ok()?.ok()?;
    let rtt = start.elapsed();
    guard.clear_ready();
    match fd.get_ref().take_error() {
        Ok(None) if fd.get_ref().peer_addr().is_ok() => Some(rtt),
        Ok(Some(e)) if e.kind() == io::ErrorKind::ConnectionRefused => Some(rtt),
        _ => None,
    }
}

struct Waiter {
    target: IpAddr,
    token: [u8; TOKEN_LEN],
    sent: Instant,
    reply: oneshot::Sender<Duration>,
}

/// The raw ICMP socket of a path and the attempts waiting for a reply,
/// keyed by sequence number.
struct Icmp {
    fd: AsyncFd<UdpSocket>,
    v6: bool,
    id: u16,
    state: Mutex<(u16, HashMap<u16, Waiter>)>,
}

impl Icmp {
    fn new(spec: &Spec) -> io::Result<Icmp> {
        let v6 = spec.source.is_ipv6();
        let protocol = if v6 { Protocol::ICMPV6 } else { Protocol::ICMPV4 };
        let s = probe_socket(spec, Type::RAW, protocol)?;
        s.attach_filter(&icmp_filter(!v6, if v6 { ECHO_REPLY_V6 } else { ECHO_REPLY_V4 }))?;
        // A raw socket is a datagram socket for send_to/recv_from; std's
        // UdpSocket offers them on initialised buffers.
        let fd = AsyncFd::new(UdpSocket::from(s))?;
        let [a, b, c, d] = random::<4>();
        Ok(Icmp {
            fd,
            v6,
            id: u16::from_be_bytes([a, b]),
            state: Mutex::new((u16::from_be_bytes([c, d]), HashMap::new())),
        })
    }

    async fn attempt(&self, target: IpAddr, deadline: Instant) -> Option<Duration> {
        let token = random::<TOKEN_LEN>();
        let (tx, rx) = oneshot::channel();
        let seq = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.0 = st.0.wrapping_add(1);
            let seq = st.0;
            st.1.insert(
                seq,
                Waiter {
                    target,
                    token,
                    sent: Instant::now(),
                    reply: tx,
                },
            );
            seq
        };
        let _cleanup = Unregister(self, seq);
        let packet = echo_request(self.v6, self.id, seq, &token);
        if self.fd.get_ref().send_to(&packet, SocketAddr::new(target, 0)).is_err() {
            return None;
        }
        timeout_at(deadline, rx).await.ok()?.ok()
    }

    async fn read_loop(&self) {
        let mut buf = [0u8; 2048];
        loop {
            let Ok(mut guard) = self.fd.readable().await else {
                return;
            };
            let mut read = 0;
            while read < BATCH
                && let Ok(Ok((len, from))) = guard.try_io(|fd| fd.get_ref().recv_from(&mut buf))
            {
                read += 1;
                self.deliver(&buf[..len], from.ip());
            }
            if read == BATCH {
                tokio::task::yield_now().await;
            }
        }
    }

    /// FR-PROBE-3: source equal to the target, identifier, sequence of an
    /// open attempt, token, and (IPv4) a valid checksum.
    fn deliver(&self, packet: &[u8], from: IpAddr) {
        let Some(reply) = parse_echo_reply(self.v6, packet, from) else {
            return;
        };
        if reply.id != self.id {
            return;
        }
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let matches =
            st.1.get(&reply.seq)
                .is_some_and(|w| w.target == reply.source && w.token == reply.token);
        if matches && let Some(w) = st.1.remove(&reply.seq) {
            let _ = w.reply.send(w.sent.elapsed());
        }
    }
}

/// Removes an attempt's waiter when the attempt ends (reply, timeout or
/// cancellation), so that late replies match nothing.
struct Unregister<'a>(&'a Icmp, u16);

impl Drop for Unregister<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner()).1.remove(&self.1);
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // getrandom fails only without any entropy source; zeros still work
    // as identifiers, only less unpredictable.
    let _ = getrandom::fill(&mut b);
    b
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Echo request with identifier, sequence and token. The kernel computes the
/// checksum of ICMPv6 raw sockets itself.
pub fn echo_request(v6: bool, id: u16, seq: u16, token: &[u8; TOKEN_LEN]) -> Vec<u8> {
    let mut p = vec![if v6 { 128 } else { 8 }, 0, 0, 0];
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(token);
    if !v6 {
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
    }
    p
}

#[derive(Debug, PartialEq, Eq)]
pub struct EchoReply {
    pub source: IpAddr,
    pub id: u16,
    pub seq: u16,
    pub token: [u8; TOKEN_LEN],
}

/// Parses what a raw ICMP socket received. IPv4 raw sockets deliver the IP
/// header and receive messages before the kernel validates the checksum;
/// IPv6 raw sockets deliver only the ICMPv6 message, already validated.
pub fn parse_echo_reply(v6: bool, packet: &[u8], from: IpAddr) -> Option<EchoReply> {
    let (source, icmp) = if v6 {
        (from, packet)
    } else {
        let ihl = usize::from(*packet.first()? & 0x0f) * 4;
        if packet.len() < ihl.max(20) {
            return None;
        }
        (
            IpAddr::from([packet[12], packet[13], packet[14], packet[15]]),
            &packet[ihl..],
        )
    };
    if icmp.len() < 8 + TOKEN_LEN || icmp[0] != if v6 { 129 } else { 0 } || icmp[1] != 0 {
        return None;
    }
    if !v6 && checksum(icmp) != 0 {
        return None;
    }
    Some(EchoReply {
        source,
        id: u16::from_be_bytes([icmp[4], icmp[5]]),
        seq: u16::from_be_bytes([icmp[6], icmp[7]]),
        token: icmp[8..8 + TOKEN_LEN].try_into().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_reply(src: [u8; 4], request: &[u8]) -> Vec<u8> {
        let mut icmp = request.to_vec();
        icmp[0] = 0;
        icmp[2] = 0;
        icmp[3] = 0;
        let c = checksum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&[192, 0, 2, 2]);
        ip.extend_from_slice(&icmp);
        ip
    }

    /// The socket filter on real raw sockets over loopback: a message of
    /// another type, or of the type with another code, never reaches the
    /// socket; the type with code 0 does. Needs CAP_NET_RAW (skipped
    /// without it).
    #[test]
    fn icmp_filter_passes_only_the_type_with_code_0() {
        for (v6, ty) in [(false, ECHO_REPLY_V4), (true, ECHO_REPLY_V6), (true, 134)] {
            let (domain, protocol, to) = if v6 {
                (
                    Domain::IPV6,
                    Protocol::ICMPV6,
                    SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
                )
            } else {
                (
                    Domain::IPV4,
                    Protocol::ICMPV4,
                    SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
                )
            };
            let receiver = match Socket::new(domain, Type::RAW, Some(protocol)) {
                Ok(s) => s,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return,
                Err(e) => panic!("raw socket: {e}"),
            };
            receiver.attach_filter(&icmp_filter(!v6, ty)).unwrap();
            receiver.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let receiver = UdpSocket::from(receiver);
            let sender = UdpSocket::from(Socket::new(domain, Type::RAW, Some(protocol)).unwrap());
            let marker = random::<TOKEN_LEN>();
            // Types the kernel itself ignores, so that nothing answers them.
            let message = |ty: u8, code: u8, tag: u8| {
                let mut p = vec![ty, code, 0, 0, 0, 0, 0, tag];
                p.extend_from_slice(&marker);
                if !v6 {
                    let c = checksum(&p);
                    p[2..4].copy_from_slice(&c.to_be_bytes());
                }
                p
            };
            for (t, code, tag) in [(ty, 1, 1), (42, 0, 2), (ty, 0, 3)] {
                sender.send_to(&message(t, code, tag), to).unwrap();
            }
            let mut buf = [0u8; 2048];
            let tag = loop {
                let (len, _) = receiver
                    .recv_from(&mut buf)
                    .expect("the message of the type with code 0");
                let icmp = if v6 {
                    &buf[..len]
                } else {
                    &buf[usize::from(buf[0] & 0xf) * 4..len]
                };
                if icmp.len() == 8 + TOKEN_LEN && icmp[8..] == marker {
                    break icmp[7];
                }
            };
            assert_eq!(tag, 3, "v6 {v6}, type {ty}");
        }
    }

    #[test]
    fn echo_request_checksum_is_valid() {
        let req = echo_request(false, 0x1234, 7, &[0xab; TOKEN_LEN]);
        assert_eq!(checksum(&req), 0);
        assert_eq!(req.len(), 8 + TOKEN_LEN);
        assert_eq!(echo_request(true, 1, 2, &[0; TOKEN_LEN])[0], 128);
    }

    #[test]
    fn replies_are_parsed_and_validated() {
        let token = [0x5a; TOKEN_LEN];
        let req = echo_request(false, 0x1234, 7, &token);
        let reply = ipv4_reply([1, 1, 1, 1], &req);
        let r = parse_echo_reply(false, &reply, "9.9.9.9".parse().unwrap()).unwrap();
        // The source comes from the IP header, not from recvfrom.
        assert_eq!(
            r,
            EchoReply {
                source: "1.1.1.1".parse().unwrap(),
                id: 0x1234,
                seq: 7,
                token
            }
        );
        let mut bad = reply.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            parse_echo_reply(false, &bad, "1.1.1.1".parse().unwrap()),
            None,
            "bad checksum"
        );
        let mut request_echoed = reply;
        request_echoed[20] = 8;
        assert_eq!(
            parse_echo_reply(false, &request_echoed, "1.1.1.1".parse().unwrap()),
            None,
            "not a reply"
        );
        let mut v6 = echo_request(true, 9, 10, &token);
        v6[0] = 129;
        let r = parse_echo_reply(true, &v6, "2620:fe::fe".parse().unwrap()).unwrap();
        assert_eq!((r.id, r.seq), (9, 10));
    }
}
