#![forbid(unsafe_code)]
//! Spike S5: probe sockets for one path, ICMP echo / ICMPv6 echo over raw sockets and TCP
//! handshakes, each bound to the path source address, with SO_BINDTODEVICE and SO_MARK set
//! before the first packet (FR-PROBE-1), reply validation (FR-PROBE-3) and the round logic of
//! FR-PROBE-4. Throw-away code: output is one `key=value` line per event, for the test scripts.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, sleep_until, timeout_at};

const EINPROGRESS: i32 = 115;
const TOKEN_LEN: usize = 16;

#[derive(Clone)]
struct PathCfg {
    /// Empty: no SO_BINDTODEVICE (comparison experiments only).
    dev: String,
    src: IpAddr,
    mark: u32,
}

#[derive(Clone)]
struct RoundCfg {
    attempts: u32,
    timeout: Duration,
    required: usize,
    rounds: u32,
    interval: Duration,
    early: bool,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  s5-probes icmp --dev IF --src ADDR --mark MARK --targets A,B,.. [--attempts N] [--timeout-ms MS] [--required N] [--rounds N] [--interval-ms MS] [--no-early] [--no-device]\n  s5-probes tcp  --dev IF --src ADDR --mark MARK --targets A:PORT,[B]:PORT,.. [same options]\n  s5-probes dgram-check --src ADDR --target ADDR [--dev IF] [--id N]"
    );
    ExitCode::from(2)
}

struct Args(HashMap<String, String>);

impl Args {
    fn parse(raw: &[String]) -> Option<Args> {
        let mut map = HashMap::new();
        let mut it = raw.iter();
        while let Some(k) = it.next() {
            let key = k.strip_prefix("--")?;
            if key == "no-early" || key == "no-device" {
                map.insert(key.to_string(), "1".to_string());
            } else {
                map.insert(key.to_string(), it.next()?.clone());
            }
        }
        Some(Args(map))
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }
    fn num(&self, k: &str, default: u64) -> Option<u64> {
        match self.get(k) {
            None => Some(default),
            Some(v) => match v.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => v.parse().ok(),
            },
        }
    }
    fn path(&self) -> Option<PathCfg> {
        Some(PathCfg {
            dev: if self.get("no-device").is_some() { String::new() } else { self.get("dev")?.to_string() },
            src: self.get("src")?.parse().ok()?,
            mark: u32::try_from(self.num("mark", 0)?).ok()?,
        })
    }
    fn round(&self) -> Option<RoundCfg> {
        Some(RoundCfg {
            attempts: u32::try_from(self.num("attempts", 2)?).ok()?,
            timeout: Duration::from_millis(self.num("timeout-ms", 1000)?),
            required: usize::try_from(self.num("required", 2)?).ok()?,
            rounds: u32::try_from(self.num("rounds", 1)?).ok()?,
            interval: Duration::from_millis(self.num("interval-ms", 5000)?),
            early: self.get("no-early").is_none(),
        })
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("getrandom");
    b
}

/// FR-PROBE-1: non-blocking, SO_MARK, SO_BINDTODEVICE and bound source, all before any packet.
fn probe_socket(path: &PathCfg, ty: Type, proto: Protocol, port: u16) -> io::Result<Socket> {
    let domain = if path.src.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let s = Socket::new(domain, ty, Some(proto))?;
    s.set_nonblocking(true)?;
    s.set_mark(path.mark)?;
    if !path.dev.is_empty() {
        s.bind_device(Some(path.dev.as_bytes()))?;
    }
    s.bind(&SockAddr::from(SocketAddr::new(path.src, port)))?;
    Ok(s)
}

fn describe_socket(kind: &str, s: &Socket) {
    let dev = s
        .device()
        .ok()
        .flatten()
        .map(|d| String::from_utf8_lossy(&d).into_owned())
        .unwrap_or_default();
    let mark = s.mark().map(|m| format!("{m:#010x}")).unwrap_or_else(|e| e.to_string());
    let local = s
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .map(|a| a.to_string())
        .unwrap_or_default();
    println!("socket kind={kind} dev={dev} mark={mark} local={local}");
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo_request(v6: bool, id: u16, seq: u16, token: &[u8; TOKEN_LEN]) -> Vec<u8> {
    let mut p = vec![if v6 { 128 } else { 8 }, 0, 0, 0];
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(token);
    if !v6 {
        // The kernel computes the ICMPv6 checksum of raw IPPROTO_ICMPV6 sockets itself.
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
    }
    p
}

struct Attempt {
    target: usize,
    number: u32,
    token: [u8; TOKEN_LEN],
    sent: Instant,
    deadline: Instant,
}

#[derive(Clone, Copy, PartialEq)]
enum TargetState {
    Pending,
    Reachable,
    Unreachable,
}

struct IcmpProber {
    fd: AsyncFd<UdpSocket>,
    v6: bool,
    id: u16,
    seq: u16,
}

impl IcmpProber {
    fn new(path: &PathCfg) -> io::Result<IcmpProber> {
        let v6 = path.src.is_ipv6();
        let proto = if v6 { Protocol::ICMPV6 } else { Protocol::ICMPV4 };
        let s = probe_socket(path, Type::RAW, proto, 0)?;
        describe_socket("icmp-raw", &s);
        // A raw socket is a datagram socket for recvfrom/sendto purposes; std's UdpSocket gives
        // safe, initialised-buffer access to those calls.
        let udp = UdpSocket::from(s);
        let id = u16::from_be_bytes(random_bytes::<2>());
        let seq = u16::from_be_bytes(random_bytes::<2>());
        println!("icmp path id={id} first_seq={seq}");
        Ok(IcmpProber { fd: AsyncFd::new(udp)?, v6, id, seq })
    }

    fn send(&mut self, target: IpAddr, number: u32, idx: usize, timeout: Duration, pending: &mut HashMap<u16, Attempt>) {
        self.seq = self.seq.wrapping_add(1);
        let token = random_bytes::<TOKEN_LEN>();
        let pkt = echo_request(self.v6, self.id, self.seq, &token);
        let now = Instant::now();
        if let Err(e) = self.fd.get_ref().send_to(&pkt, SocketAddr::new(target, 0)) {
            println!("icmp target={target} attempt={number} seq={} send_error=\"{e}\"", self.seq);
        }
        pending.insert(self.seq, Attempt { target: idx, number, token, sent: now, deadline: now + timeout });
    }

    async fn round(&mut self, n: u32, targets: &[IpAddr], rc: &RoundCfg) -> bool {
        let start = Instant::now();
        let mut state = vec![TargetState::Pending; targets.len()];
        let mut pending: HashMap<u16, Attempt> = HashMap::new();
        let mut expired: HashMap<u16, usize> = HashMap::new();
        for (i, t) in targets.iter().enumerate() {
            self.send(*t, 1, i, rc.timeout, &mut pending);
        }
        let mut buf = [0u8; 2048];
        loop {
            let reachable = state.iter().filter(|s| **s == TargetState::Reachable).count();
            let open = state.iter().filter(|s| **s == TargetState::Pending).count();
            let certain = reachable >= rc.required || reachable + open < rc.required;
            if open == 0 || (rc.early && certain) {
                break;
            }
            let next = pending.values().map(|a| a.deadline).min().unwrap_or_else(Instant::now);
            tokio::select! {
                _ = sleep_until(next) => {
                    let now = Instant::now();
                    let due: Vec<u16> = pending.iter().filter(|(_, a)| a.deadline <= now).map(|(s, _)| *s).collect();
                    for seq in due {
                        let Some(a) = pending.remove(&seq) else { continue };
                        let target = targets[a.target];
                        println!("icmp target={target} attempt={} seq={seq} result=lost", a.number);
                        expired.insert(seq, a.target);
                        if a.number < rc.attempts {
                            self.send(target, a.number + 1, a.target, rc.timeout, &mut pending);
                        } else {
                            state[a.target] = TargetState::Unreachable;
                        }
                    }
                }
                guard = self.fd.readable() => {
                    let Ok(mut guard) = guard else { break };
                    loop {
                        match guard.try_io(|fd| fd.get_ref().recv_from(&mut buf)) {
                            Ok(Ok((len, from))) => {
                                self.validate(&buf[..len], from.ip(), targets, &mut state, &mut pending, &expired);
                            }
                            Ok(Err(e)) => { println!("icmp recv_error=\"{e}\""); break; }
                            Err(_would_block) => break,
                        }
                    }
                }
            }
        }
        for (seq, a) in &pending {
            println!("icmp target={} attempt={} seq={seq} result=canceled", targets[a.target], a.number);
        }
        report_round(n, &state, rc, start)
    }

    fn validate(
        &self,
        pkt: &[u8],
        from: IpAddr,
        targets: &[IpAddr],
        state: &mut [TargetState],
        pending: &mut HashMap<u16, Attempt>,
        expired: &HashMap<u16, usize>,
    ) {
        let now = Instant::now();
        // IPv4 raw sockets deliver the IP header; IPv6 raw sockets do not.
        let (src, icmp) = if self.v6 {
            (from, pkt)
        } else {
            if pkt.len() < 20 {
                return;
            }
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            let src = IpAddr::from([pkt[12], pkt[13], pkt[14], pkt[15]]);
            if pkt.len() < ihl {
                return;
            }
            (src, &pkt[ihl..])
        };
        let ignore = |reason: &str, seq: Option<u16>| {
            let seq = seq.map(|s| s.to_string()).unwrap_or_default();
            println!("icmp ignored reason={reason} from={src} seq={seq}");
        };
        if icmp.len() < 8 {
            return ignore("short", None);
        }
        let reply_type = if self.v6 { 129 } else { 0 };
        if icmp[0] != reply_type {
            return ignore(&format!("type_{}", icmp[0]), None);
        }
        // The kernel validates ICMPv6 checksums for raw sockets but delivers IPv4 raw ICMP
        // before icmp_rcv() checks it.
        if !self.v6 && checksum(icmp) != 0 {
            return ignore("bad_checksum", None);
        }
        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
        if id != self.id {
            return ignore("foreign_id", Some(seq));
        }
        let Some(a) = pending.get(&seq) else {
            return ignore(if expired.contains_key(&seq) { "late" } else { "unknown_seq" }, Some(seq));
        };
        let target = targets[a.target];
        if src != target {
            return ignore("wrong_source", Some(seq));
        }
        if icmp.len() < 8 + TOKEN_LEN || icmp[8..8 + TOKEN_LEN] != a.token {
            return ignore("wrong_token", Some(seq));
        }
        if now > a.deadline {
            return ignore("late", Some(seq));
        }
        let rtt = now - a.sent;
        println!("icmp target={target} attempt={} seq={seq} result=reply rtt_us={}", a.number, rtt.as_micros());
        state[a.target] = TargetState::Reachable;
        // Other outstanding attempts of the same target cannot exist (attempts are sequential).
        pending.remove(&seq);
    }
}

fn report_round(n: u32, state: &[TargetState], rc: &RoundCfg, start: Instant) -> bool {
    let reachable = state.iter().filter(|s| **s == TargetState::Reachable).count();
    let pass = reachable >= rc.required;
    println!(
        "round={n} reachable={reachable}/{} required={} result={} duration_ms={}",
        state.len(),
        rc.required,
        if pass { "pass" } else { "fail" },
        start.elapsed().as_millis()
    );
    pass
}

enum TcpOutcome {
    SynAck,
    Rst,
    Lost,
    Error(io::Error),
}

async fn tcp_attempt(path: &PathCfg, target: SocketAddr, timeout: Duration) -> (TcpOutcome, Duration) {
    let start = Instant::now();
    let s = match probe_socket(path, Type::STREAM, Protocol::TCP, 0) {
        Ok(s) => s,
        Err(e) => return (TcpOutcome::Error(e), start.elapsed()),
    };
    // Abort with RST on close: no FIN exchange, no TIME_WAIT on the router.
    let _ = s.set_linger(Some(Duration::ZERO));
    match s.connect(&SockAddr::from(target)) {
        Ok(()) => return (TcpOutcome::SynAck, start.elapsed()),
        Err(e) if e.raw_os_error() == Some(EINPROGRESS) => {}
        Err(e) => return (TcpOutcome::Error(e), start.elapsed()),
    }
    let fd = match AsyncFd::with_interest(s, Interest::WRITABLE) {
        Ok(fd) => fd,
        Err(e) => return (TcpOutcome::Error(e), start.elapsed()),
    };
    match timeout_at(start + timeout, fd.writable()).await {
        Err(_) => (TcpOutcome::Lost, start.elapsed()),
        Ok(Err(e)) => (TcpOutcome::Error(e), start.elapsed()),
        Ok(Ok(_)) => {
            let rtt = start.elapsed();
            match fd.get_ref().take_error() {
                Ok(None) if fd.get_ref().peer_addr().is_ok() => (TcpOutcome::SynAck, rtt),
                Ok(None) => (TcpOutcome::Lost, rtt),
                Ok(Some(e)) if e.kind() == io::ErrorKind::ConnectionRefused => (TcpOutcome::Rst, rtt),
                Ok(Some(e)) | Err(e) => (TcpOutcome::Error(e), rtt),
            }
        }
    }
}

async fn tcp_round(n: u32, path: &PathCfg, targets: &[SocketAddr], rc: &RoundCfg) -> bool {
    let start = Instant::now();
    let mut set = JoinSet::new();
    for (i, t) in targets.iter().enumerate() {
        let (path, t, rc) = (path.clone(), *t, rc.clone());
        set.spawn(async move {
            for number in 1..=rc.attempts {
                let (outcome, rtt) = tcp_attempt(&path, t, rc.timeout).await;
                let rtt_us = rtt.as_micros();
                match outcome {
                    TcpOutcome::SynAck | TcpOutcome::Rst => {
                        let kind = if matches!(outcome, TcpOutcome::SynAck) { "syn-ack" } else { "rst" };
                        println!("tcp target={t} attempt={number} result=reply kind={kind} rtt_us={rtt_us}");
                        return (i, true);
                    }
                    TcpOutcome::Lost => println!("tcp target={t} attempt={number} result=lost"),
                    TcpOutcome::Error(e) => {
                        println!("tcp target={t} attempt={number} result=lost error=\"{e}\" after_us={rtt_us}");
                        // Wait out the attempt deadline before the next attempt (FR-PROBE-4).
                        tokio::time::sleep(rc.timeout.saturating_sub(rtt)).await;
                    }
                }
            }
            (i, false)
        });
    }
    let mut state = vec![TargetState::Unreachable; targets.len()];
    while let Some(r) = set.join_next().await {
        if let Ok((i, true)) = r {
            state[i] = TargetState::Reachable;
        }
    }
    report_round(n, &state, rc, start)
}

/// Evaluation of unprivileged ICMP "ping" sockets (SOCK_DGRAM, IPPROTO_ICMP[V6]).
async fn dgram_check(args: &Args) -> io::Result<()> {
    let src: IpAddr = args.get("src").and_then(|s| s.parse().ok()).ok_or(io::ErrorKind::InvalidInput)?;
    let target: IpAddr = args.get("target").and_then(|s| s.parse().ok()).ok_or(io::ErrorKind::InvalidInput)?;
    let port = u16::try_from(args.num("id", 0x1234).unwrap_or(0x1234)).unwrap_or(0x1234);
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range").unwrap_or_default();
    println!("dgram ping_group_range=\"{}\"", range.trim().replace('\t', " "));
    let v6 = src.is_ipv6();
    let (domain, proto) = if v6 { (Domain::IPV6, Protocol::ICMPV6) } else { (Domain::IPV4, Protocol::ICMPV4) };
    let s = match Socket::new(domain, Type::DGRAM, Some(proto)) {
        Ok(s) => s,
        Err(e) => {
            println!("dgram socket_error=\"{e}\"");
            return Ok(());
        }
    };
    if let Some(dev) = args.get("dev") {
        s.bind_device(Some(dev.as_bytes()))?;
    }
    // For ping sockets the "port" is the ICMP identifier.
    s.bind(&SockAddr::from(SocketAddr::new(src, port)))?;
    s.set_nonblocking(true)?;
    let udp = UdpSocket::from(s);
    let token = random_bytes::<TOKEN_LEN>();
    // Ask for identifier 0xbeef: the kernel replaces it with the bound port.
    let pkt = echo_request(v6, 0xbeef, 7, &token);
    udp.send_to(&pkt, SocketAddr::new(target, 0))?;
    println!("dgram sent requested_id=0xbeef bound_port={port:#06x}");
    let fd = AsyncFd::new(udp)?;
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let Ok(guard) = timeout_at(deadline, fd.readable()).await else {
            println!("dgram result=timeout");
            return Ok(());
        };
        let mut guard = guard?;
        if let Ok(r) = guard.try_io(|fd| fd.get_ref().recv_from(&mut buf)) {
            let (len, from) = r?;
            let icmp = &buf[..len];
            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            println!(
                "dgram reply from={} type={} id={id:#06x} seq={seq} token_ok={}",
                from.ip(),
                icmp[0],
                icmp.len() >= 8 + TOKEN_LEN && icmp[8..8 + TOKEN_LEN] == token
            );
            return Ok(());
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some((mode, rest)) = argv.split_first() else { return usage() };
    let Some(args) = Args::parse(rest) else { return usage() };
    if mode == "dgram-check" {
        return match dgram_check(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                println!("dgram error=\"{e}\"");
                ExitCode::FAILURE
            }
        };
    }
    let (Some(path), Some(rc), Some(targets)) = (args.path(), args.round(), args.get("targets")) else {
        return usage();
    };
    let mut ticker = tokio::time::interval(rc.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut passed = 0;
    match mode.as_str() {
        "icmp" => {
            let Ok(targets) = targets.split(',').map(str::parse).collect::<Result<Vec<IpAddr>, _>>() else {
                return usage();
            };
            let mut prober = match IcmpProber::new(&path) {
                Ok(p) => p,
                Err(e) => {
                    println!("icmp socket_error=\"{e}\"");
                    return ExitCode::FAILURE;
                }
            };
            for n in 1..=rc.rounds {
                ticker.tick().await;
                passed += u32::from(prober.round(n, &targets, &rc).await);
            }
        }
        "tcp" => {
            let Ok(targets) = targets.split(',').map(str::parse).collect::<Result<Vec<SocketAddr>, _>>() else {
                return usage();
            };
            for n in 1..=rc.rounds {
                ticker.tick().await;
                passed += u32::from(tcp_round(n, &path, &targets, &rc).await);
            }
        }
        _ => return usage(),
    }
    println!("summary rounds={} passed={passed}", rc.rounds);
    if passed == rc.rounds { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
