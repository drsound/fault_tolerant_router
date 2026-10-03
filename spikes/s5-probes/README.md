# S5 — Probes

Status: **done** on both environments. 180 checks per environment, 0 failures; behaviour identical on both kernels.

Question (SPEC.md §15): can probes with `SO_BINDTODEVICE` + `SO_MARK` + a bound source be implemented from safe Rust, for ICMP and TCP and both families, with the reply validation of FR-PROBE-3, and do they satisfy INV-6 with the rule layout of FR-ROUTE-3?

## Environment

| Environment | Distribution | Kernel | nftables | iproute2 |
|---|---|---|---|---|
| minimum | Debian 12 | 6.1.0-53 | 1.0.6 | 6.1.0 |
| latest | Debian 13 with trixie-backports | 7.1.13 | 1.1.3 | 6.15.0 |

Rust 1.99.0, edition 2024, `socket2` 0.6.5, `tokio` 1.53.2, `getrandom` 0.4.3. The prober is built once as a static musl binary (`x86_64-unknown-linux-musl`, 509 KiB stripped) and the same binary runs on both kernels.

## Files

- `src/main.rs`: the prober (`#![forbid(unsafe_code)]`). `icmp` and `tcp` modes run FR-PROBE-4 rounds for one path; `dgram-check` evaluates `SOCK_DGRAM` ICMP sockets for comparison. Output is one `key=value` line per event.
- `topo.sh`: namespace topology (`s5-r` router, `s5-isp` upstream with the targets, `s5-dcy` decoy next hop) with the FR-ROUTE-3 artifacts relevant to probes.
- `run.sh`: the checks below. `PROBE_LOG=FILE ./run.sh PATH_TO_BINARY`, as root.
- `forge.py`: injects forged echo replies from the upstream through an `AF_PACKET` socket.
- `results/run-{minimum,latest}.log`: check output; `results/probe-output-{minimum,latest}.log`: full prober output of every invocation.

## Prober design

- Socket setup (FR-PROBE-1), all through safe `socket2` calls and before the first packet: `set_nonblocking(true)`, `set_mark(encode(0x40 + id))`, `bind_device(iface)`, `bind(source)`. The prober prints the values read back with `mark()`, `device()` and `local_addr()`, for example `socket kind=icmp-raw dev=up1 mark=0x00410000 local=192.0.2.2:1`.
- ICMP uses one raw socket per path (`SOCK_RAW`, `IPPROTO_ICMP` / `IPPROTO_ICMPV6`) wrapped in `tokio::io::unix::AsyncFd`. The `socket2::Socket` is converted into `std::net::UdpSocket` (a safe `From` provided by `socket2`) to get `recv_from`/`send_to` on initialised buffers; a raw socket behaves like any datagram socket for these calls.
- Echo request: identifier random per path, sequence number random at start and incremented per attempt (wrapping), payload = 16 random bytes per attempt. IPv4 checksum computed in user space; the kernel computes the ICMPv6 checksum of raw `IPPROTO_ICMPV6` sockets.
- A round is a single-task event loop: all targets get attempt 1 at once; on an attempt deadline the next attempt of that target is sent; replies are matched by (identifier, sequence) to the open attempt, then the source must equal the target and the token must match. Closed attempts of the round are remembered so that replies arriving after the deadline are classified `late`. With early end (default), the round stops as soon as its outcome is certain and the open attempts are reported `canceled` (not samples, FR-PROBE-5); with `--no-early` every attempt runs to reply or deadline.
- TCP uses one socket per attempt: non-blocking `connect`, `EINPROGRESS`, then `AsyncFd` writability with the attempt deadline. Connected (`take_error() == None` and `peer_addr()` succeeds) is a SYN-ACK; `ECONNREFUSED` is a RST; both count as replies. Any other error (for example an ICMP unreachable from the network, or `ENETUNREACH` from a guard rule) is a loss, and the next attempt waits for the deadline. `SO_LINGER` 0 makes the close send a RST, so the router keeps no `TIME_WAIT` or half-open state.

## Topology

```
s5-r (router)                                   s5-isp (upstream)
up1 192.0.2.2/24 2001:db8:1::2/64 fe80::2 ----- u1 192.0.2.1/24 2001:db8:1::1/64 fe80::1
                                              \- d1 macvlan in s5-dcy: 192.0.2.3 2001:db8:1::3 fe80::3 (decoy next hop, own MAC)
up2 198.51.100.2/24 2001:db8:2::2/64 fe80::2 -- u2 198.51.100.1/24 2001:db8:2::1/64 fe80::1
                                                tg (dummy): 1.1.1.1 8.8.8.8 9.9.9.9 2606:4700:4700::1111 2001:4860:4860::8888 2620:fe::fe
```

- Router main table, standing in for operating-system routes: `default via <uplink 2 gateway> dev up2`; `8.8.8.8/32` and `2001:4860:4860::8888/128` via the decoy on up1 (same interface, other next hop); `9.9.9.9/32` and `2620:fe::fe/128` via up2 (other interface).
- FTR artifacts, B = 1000, table base 1000, mask `0x00ff0000`, protocol 249, uplink ids 1 and 2, both families: path tables 1001/1002 (`default via <gateway> dev upN src <address> metric 100`, the IPv6 gateway is `fe80::1` on both uplinks); probe rules B+1/B+2 `fwmark 0x00410000/0x00ff0000` and `0x00420000/0x00ff0000`; probe guard B+64 `fwmark 0x00400000/0x00c00000 unreachable`; main bypass B+100; source rules B+501/B+502 and source guard B+564 with `fwmark 0/0x00ff0000`; balancing rule B+600 (table 1000, empty unless a test fills it); final guard B+699.
- Uplinks: `rp_filter = 2`, `src_valid_mark = 1`; `net.ipv4.conf.all.rp_filter = 0` (FR-SYS-2). The upstream runs with `arp_ignore = 1`, like a provider router that does not answer ARP for remote addresses; T7 also runs with `arp_ignore = 0` to emulate proxy ARP.
- Evidence: nftables named counters at the upstream (echo requests and SYNs per arrival interface and family, packets with a wrong source address), counters at the decoy, `tcpdump -e` on the router uplink (destination MAC = next hop), `nstat` counters in the router namespace.

## Results

| Test | What | Result (both kernels) |
|---|---|---|
| T1 | ICMP probes of path 1, empty balancing table, competing main default via uplink 2, main routes covering two targets, a foreign `ping` on the same path | 12 echo requests at the upstream on u1 (6 probes + 6 pings), 0 on u2, 0 at the decoy, 0 with a wrong source; every frame addressed to the uplink 1 gateway MAC; both rounds pass; the pings' replies, delivered to the raw socket too, ignored as `foreign_id` |
| T2 | Balancing table containing only path 2; probes of path 1 and of path 2 | path 1 only on u1, path 2 only on u2, although both IPv6 gateways are `fe80::1` |
| T3 | TCP: open port, closed port, blackholed target | `kind=syn-ack`, `kind=rst`, two `lost` attempts; round passes with 2/3; all SYNs on u1 |
| T4 | Forged replies for attempt 1 (kernel replies dropped upstream) | `wrong_token`, `wrong_source`, `bad_checksum` (IPv4), attempt 1 `lost`, a correct reply after the deadline `late`, attempt 2 `reply` |
| T5 | Early end of a round | the open attempt of the silent target `canceled`; with `--no-early` both its attempts are `lost` samples |
| T6 | IPv4 replies under `rp_filter = 2` without source rules, empty balancing table | replies from a target with no covering route dropped (`TcpExtIPReversePathFilter` +3: 2 echo replies + 1 SYN-ACK); targets covered by main routes pass; a non-empty balancing table also satisfies loose mode; with source rules every reply passes; IPv6 unaffected |
| T7 | Path table emptied (not ready) and an unconfigured probe value (id 5), with and without `SO_BINDTODEVICE` | IPv4 with `SO_BINDTODEVICE`: **the guard rules do not stop the probe**, see finding 3; IPv6, and IPv4 without `SO_BINDTODEVICE`: `ENETUNREACH` at `send`; nothing ever on u2 |
| T8 | `SOCK_DGRAM` ICMP ("ping") sockets | refused with `EACCES` under the default `ping_group_range` of a new namespace, also for root; with the range opened, identifier 0xbeef in the request replaced by the bound port 0x1234 on the wire |

Excerpt (latest, T4, IPv4):

```
icmp ignored reason=wrong_token from=1.1.1.1 seq=54342
icmp ignored reason=wrong_source from=1.0.0.1 seq=54342
icmp ignored reason=bad_checksum from=1.1.1.1 seq=
icmp target=1.1.1.1 attempt=1 seq=54342 result=lost
icmp ignored reason=late from=1.1.1.1 seq=54342
icmp target=1.1.1.1 attempt=2 seq=54343 result=reply rtt_us=800851
round=1 reachable=1/1 required=1 result=pass duration_ms=1802
```

Excerpt (minimum, T7, IPv4, path table empty, upstream answering ARP for the target; tcpdump lines simplified):

```
192.0.2.2 > ff:ff:ff:ff:ff:ff ARP Request who-has 1.1.1.1 tell 192.0.2.2
upstream > router           ARP Reply 1.1.1.1 is-at <upstream MAC>
192.0.2.2 > 1.1.1.1: ICMP echo request   (sent on up1, no route, no rule allowed it)
1.1.1.1 > 192.0.2.2: ICMP echo reply     (then dropped by reverse-path filtering)
```

## Findings

1. **FR-PROBE-1 is implementable with safe APIs.** `socket2` 0.6 provides `set_mark`, `bind_device`, `set_nonblocking`, `set_linger`, `take_error` and `attach_filter`; `tokio`'s `AsyncFd` drives raw and TCP sockets; no `unsafe` and no `libc` dependency are needed. The options are applied before the first packet and read back correctly.

2. **ICMP: raw sockets, not ping sockets.** Ping sockets (`SOCK_DGRAM`) are gated by `net.ipv4.ping_group_range` (also for IPv6), which is per network namespace, defaults to "1 0" (nobody) and is not bypassed by capabilities: root got `EACCES` in T8. Debian's systemd opens the range in the initial namespace, but FTR may neither rely on a distribution default nor change the sysctl (INV-7, §4.6). Ping sockets would otherwise be attractive: the kernel replaces the identifier with the bound port and delivers to the socket only the replies with that identifier. Raw sockets need `CAP_NET_RAW`, already in the unit's bounding set (IMPL-10), and cost some user-space filtering:
   - a raw socket bound to the path source and device receives every ICMP message for that address on that device: echo replies of other processes (T1), errors, and for IPv6 also neighbour discovery (a unicast neighbour solicitation, type 135, was seen in T4); the prober filters by type, identifier, sequence, source and token;
   - IPv4 raw sockets get ICMP before `icmp_rcv()` validates the checksum, so a corrupted reply reached the socket (T4) and the prober must verify the checksum; for ICMPv6 the kernel verifies it (`Icmp6InCsumErrors` +1, nothing delivered) and computes it on transmission;
   - an optional classic BPF filter (`Socket::attach_filter`, safe in `socket2`) could drop non-matching messages in the kernel; not needed at probe rates.

3. **IPv4 device-bound lookups bypass the guard rules (major).** When a route lookup with an output-interface constraint fails, IPv4 does not return the error: `ip_route_output_key_hash_rcu()` assumes the destination is on-link on that interface ("Apparently, routing tables are wrong. Assume, that the destination is on link.") unless the interface is an L3 master (VRF). A guard rule's `unreachable` action is such a failure. Observed on both kernels with `SO_BINDTODEVICE`:
   - path table empty: no error; ARP for the target (`who-has 1.1.1.1 tell 192.0.2.2`) on up1; with an upstream that answers ARP for the target, the echo request left on up1 addressed directly to it;
   - unconfigured probe value (id 5): the probe rule does not match, the probe guard should reject, yet with a proxy-ARP upstream the probe **succeeded** (`result=reply`), its reply accepted through the source rule of the path address;
   - IPv6 never does this (`ENETUNREACH` in every case), nor IPv4 without `SO_BINDTODEVICE`.

   The traffic can only leave through the bound interface, so INV-6's "leaves through that path's interface" and the absence of leaks to other uplinks hold; what does not hold for IPv4 is FR-ROUTE-1's statement that termination is enforced by guard rules, for any lookup constrained to a device. This also concerns router-originated traffic of other applications bound to an uplink with `SO_BINDTODEVICE`, `IP_UNICAST_IF` or an `IP_PKTINFO` interface index (INV-3). No route type helps (unreachable, prohibit and blackhole routes are lookup failures as well). For the prober the consequences are: it must stop probing a path as soon as the path stops being ready instead of relying on the guards; while the path table is empty its in-flight replies are dropped by reverse-path filtering (the source rule leads to the empty table, then to the source guard), so they appear as losses, which FR-PROBE-3 already turns into canceled attempts when the generation changes. Keeping `SO_BINDTODEVICE` is still right: it is what keeps probes on the path's interface when the probe rules are missing (repair phase, ownership conflict), because a device-constrained lookup never selects a next hop on another interface, whereas a mark-only probe would then fall through to the main bypass or the balancing table and measure another uplink.

4. **INV-6 holds for ready paths.** Competing main default, main routes covering targets through the same interface with another next hop and through the other interface, path absent from the balancing table, empty balancing table: every probe left through the path's interface, with the path source and to the path gateway's MAC. Identical link-local gateways on two uplinks are independent (T2), as FR-DISC-3 requires.

5. **FR-SYS-2 dependency confirmed, but only visible with an empty active set.** Probe replies are unmarked; under `rp_filter = 2` the IPv4 reverse lookup with mark 0 goes through the rule sequence. Without source rules, replies of targets without a covering route are dropped while the balancing table is empty, and pass as soon as it has any route (loose mode accepts any unicast route) or a main route covers the target. AS-30 must therefore run with an empty active set and targets not covered by main routes, as written. TCP SYN-ACKs of probes behave the same.

6. **TCP probes.** SYN-ACK and RST are reported as expected; `SO_LINGER` 0 avoids `TIME_WAIT`. The initial SYN retransmission timeout (1 s) equals the default `timeout`: an attempt can carry one kernel retransmission of its SYN (seen once on 6.1 in a preliminary run, 5 SYNs for 4 attempts). It is the same socket, hence the same attempt and at most one sample, but it means that TCP attempts can send more packets than `attempts`.

7. **Socket lifetime.** `SO_BINDTODEVICE` stores the interface index and `bind` the address, so a probe socket is tied to one (ifindex, source) pair: sockets must be recreated when either changes, which coincides with the path generations of FR-PROBE-3 (kernel semantics, not separately tested).

## Proposed SPEC amendments

- **FR-ROUTE-1, INV-3**: state the IPv4 exception: "For IPv4 the kernel treats a failed route lookup constrained to an output interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, `IP_PKTINFO` with an interface index) as on-link on that interface, so guard rules do not terminate such traffic; it can only leave through the bound interface." INV-3 then excludes router-originated IPv4 traffic bound to an interface; S1 should confirm with non-probe sockets and `IP_UNICAST_IF`.
- **FR-PROBE-1**: add: ICMP probes use raw sockets (not `SOCK_DGRAM` ping sockets, which depend on `net.ipv4.ping_group_range`); probe sockets are recreated whenever the path's interface index or source changes; the prober stops sending on a path as soon as it stops being ready, without relying on guard rules (IPv4 device-bound lookups are not terminated by them).
- **FR-PROBE-3**: add for IPv4 ICMP the verification of the ICMP checksum in user space; state that ICMP errors and local errors (`ENETUNREACH`) count as losses, not replies, for both probe types; a reply is matched only to an open attempt, otherwise it is discarded.
- **FR-PROBE-4**: note that a TCP attempt is one socket, possibly with kernel SYN retransmissions when `timeout` reaches the initial retransmission timeout (1 s), and still yields at most one sample.
- **FR-SYS-2 / AS-30**: note that the dependency of IPv4 probe replies on the source rules is observable only with an empty active set and targets not covered by main routes (loose mode accepts any route).
- **IMPL-2**: confirmed: `socket2` 0.6 (safe `set_mark`, `bind_device`, `set_linger`, optional `attach_filter`), `tokio` `AsyncFd`, `getrandom` for identifiers and tokens.

## Documentation cross-check (Context7)

The `socket2` documentation indexed by Context7 confirms that raw sockets and the Linux socket options used here (`set_mark`, `bind_device`) require the crate feature `all`, which the spike enables; nothing in it contradicts the findings above.

## Open issues

- Generation tagging and cancellation of results (FR-PROBE-3) belong to the daemon's Prober/State interaction and were not implemented here.
- S1: device-bound IPv4 router traffic other than probes, and `IP_UNICAST_IF`, against the guard layout (finding 3).
- Quality-gate sampling (FR-PROBE-5) was not exercised beyond the early-end/no-early distinction.
