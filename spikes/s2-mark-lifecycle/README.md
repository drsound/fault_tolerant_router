# S2 — Mark lifecycle

Spike S2 of SPEC.md §15: the chains of §4.7 with constant-only mark operations, preservation of foreign bits, retransmitted SYNs, one-way UDP and RELATED ICMP, output route chain rerouting, policies at kernel level, and the reverse-path filtering behaviour required by AS-30 (`rp_filter = 2` with `src_valid_mark = 1`).

## Environment

Both environments of `spikes/README.md`: Debian 12 with Linux 6.1.0-53 and nftables 1.0.6; Debian 13 with Linux 7.1.13 and nftables 1.1.3. Every test ran on both; full logs are in `results/linux-6.1.txt` and `results/linux-7.1.txt`.

## How to run

As root on a disposable Linux host with iproute2, nftables, conntrack, tcpdump, nstat and python3: `./run.sh`, or one test with `bash tN-name.sh`. The tests create namespaces named `s2-*` and remove them on exit. They reuse the topology of `../lib/netns.sh` (described in `../s1-routing-core/README.md`) and the FTR rules and routes of FR-ROUTE-3. `s2lib.sh` holds the refined ruleset generator (`s2_nft_text`), an observation table that counts the packets of one connection after each FTR chain, split by conntrack direction, by the FTR field of the packet mark and of the conntrack mark, and by egress interface (`chk_up`/`chk`), and the administrator's port forwarding used by several tests. `s2tool.py` adds traffic modes to `../lib/peer.py`: unanswered SYNs, one-way UDP streams, bulk transfers, raw-socket ICMP probes and datagrams with a given TTL.

## The ruleset

`s2_nft_text` implements §4.7 with these refinements over the draft used in S1: untracked packets are skipped in every chain and non-unicast packets in prerouting (`meta pkttype != host`) and postrouting (multicast and broadcast destinations), as §4.7 and §4.8 restrict marking to tracked unicast traffic; policies are prerouting rules that write the policy value into the packet mark only and end with `return`. Per family and configuration it has 151 rules for three uplinks: 63 restoration rules in prerouting and 63 in output (every path value, FR-MARK-3), one inbound assignment rule per uplink, the policies, the probe-class skips, one outbound assignment rule per uplink in postrouting, and the NAT chain. Chain types and priorities: filter/prerouting −150, route/output −150, filter/postrouting −150, nat/postrouting 100.

## Results

| Test | What it checks | 6.1 | 7.1 |
|---|---|---|---|
| `t1-ruleset.sh` | syntax, bytecode, verdicts, traffic over every uplink, JSON normalisation for FR-REC-6, atomic replacement with live flows | 13/13 | 13/13 |
| `t2-lifecycle.sh` | per-packet marks after each chain: outbound, policy-marked, inbound, ICMP and TCP probes | 46/46 | 46/46 |
| `t3-foreign.sh` | foreign packet and conntrack bits written before and after FTR, masks at offsets 0, 16 and 24 | 54/54 | 54/54 |
| `t4-flows.sh` | AS-22, RELATED ICMP from a LAN host and from the router, path MTU discovery | 11/11 | 11/11 |
| `t5-output.sh` | a reply that only the output route chain sends through the right uplink | 4/4 | 4/4 |
| `t6-policies.sh` | AS-15 core: balance and block policies, pinning across policy table changes | 22/22 | 22/22 |
| `t7-as30.sh` | AS-30 with an empty active set and no default route, negative control, `src_valid_mark = 0` | 21/21 | 21/21 |

Both kernels and both nftables versions behaved identically, except for the number of SYN retransmissions noted in F4.

## Findings

### F1. Constant-only mark operations, no verdicts (FR-MARK-3, FR-FW-4)

Both nftables versions accept the ruleset. The netlink bytecode (`nft --debug=netlink`) contains 272 bitwise operations, all of the form `reg = (reg & constant) ^ constant`; none combines two registers. `meta mark set meta mark & 0xff00ffff | 0x00010000` compiles to `[ meta load mark => reg 1 ] [ bitwise reg 1 = ( reg 1 & 0xff00ffff ) ^ 0x00010000 ] [ meta set mark with reg 1 ]`, and `ct mark set …` to the same with `ct load`/`ct set`, so FR-MARK-3 is met on nftables 1.0.6 and kernel 6.1. The rules use no verdict other than `return`; the only `accept` is the chain policy.

### F2. Lifecycle per packet (§4.7, FR-MARK-5, FR-POL-2)

Observed after each FTR chain for both families (`t2`):

- outbound forwarded connection: the first packet is unmarked in prerouting (no assignment before routing); after postrouting every packet carries the egress path in both the conntrack and the packet mark; every later packet in both directions is restored in prerouting;
- policy-marked connection: the first packet carries the policy value (`0x81`) in the packet mark only, never in the conntrack mark; after postrouting the conntrack mark holds the path value of the actual egress (1), not the policy value; with the policy table of A empty the connection is balanced through B and gets path 2 (FR-POL-2);
- inbound connection through B with active set {A}: every packet in the original direction, the first included, carries path 2 after prerouting; every reply is restored when it enters from the downlink and leaves through B (INV-5);
- ICMP and TCP probes of A with active set {B}: the probe value survives the output route chain and postrouting, so it is never replaced by a path value; probes leave through A; the conntrack entries of probes carry no path value; replies to probes enter unmarked, as §4.7 1.2 states.

### F3. Foreign bits and other mask positions (FR-MARK-1, INV-7, AS-24, AS-43)

Another table writes packet bits outside the FTR field before FTR's prerouting chain and after FTR's prerouting and postrouting chains, conntrack bits on new connections in prerouting and output, and a probe socket carries foreign bits in `SO_MARK`. With `fwmark_mask` at bit offsets 0, 16 and 24, for both families (`t3`): outbound and inbound connections and probes use the intended uplink; every packet leaves with all foreign bits and the expected FTR value; the conntrack mark ends up as foreign bits | path value (probes: foreign bits only). Routing rules with mask selectors ignore the foreign bits.

A table that writes the conntrack mark at priority −200 in prerouting or output, the same priority as connection tracking, may run before the conntrack entry exists (`ct state new` did not match on either kernel); at −190 it works. The nftables documentation lists the conntrack priority but does not define the order of hooks registered at the same priority; the documentation for administrators (FR-FW-6) should say that rules relying on conntrack must use a priority above −200.

### F4. AS-22: unanswered SYNs and one-way UDP

Ten unanswered TCP connections and ten one-way UDP flows per family ran for 8 s while the active set changed five times, including to the empty set (`t4`). All 40 flows were seen, and every packet of every flow left through a single uplink (captured on all uplinks, grouped by flow). Every SYN flow sent at least 4 SYNs on 6.1 (0, 1, 3, 7 s) and 7 on 7.1, whose default `tcp_syn_linear_timeouts` makes the first retransmissions linear. Restoration happens for every packet regardless of conntrack state, so retransmitted SYNs follow the first one.

### F5. RELATED ICMP and path MTU discovery (AS-31 core)

With active set {A} and inbound UDP through B to a closed port of a LAN host (via the administrator's port forwarding), the host's port-unreachable and the router's own time-exceeded (inbound packet arriving with TTL 1) both leave through B only, for both families (`t4`); the router-generated error is RELATED to the inbound connection, gets path 2 from the output route chain and is translated back to B's address. For path MTU discovery, a 1300-byte link inside provider A makes A answer the client's full-size segments with "fragmentation needed" / "packet too big"; a 300 kB transfer pinned to A completes after A leaves the active set, and with those ICMP errors dropped on the router a new transfer fails (control). RELATED errors are thus delivered through restoration and conntrack NAT.

### F6. The output route chain is necessary (§4.7 step 2)

Provider A routes to the router an address configured on another interface, so no source rule applies to it. With active set {B}, the router's replies to connections that arrived through A leave through A, because the output route chain restores path 1 and the mark change triggers a new routing decision. Without the output chain (control), the same replies follow the balancing route through B (`t5`, both families). The nftables documentation states that the `route` chain type exists only for the output hook and reroutes when the mark changes, which matches.

### F7. Policies at kernel level (AS-15 core)

With policies to A, fallback balance on TCP port 7 and fallback block on TCP port 8, and active set {B, C} (`t6`, both families): new policy connections use A although A is not in the active set; with A's policy tables emptied (A unhealthy or drained), flows opened before stay alive on A, new balance-policy connections are balanced over B and C, and new block-policy connections fail without any packet leaving any uplink; a flow opened during the fallback stays on its uplink after A's tables come back, while new connections return to A.

Clients do not always see an immediate error for blocked connections, for two reasons outside FTR: IPv4 errors for input-route rejections are rate-limited by the kernel per source host (`net.ipv4.route.error_cost` and `error_burst`, 1 per second after a burst of 5, counted as `IcmpOutRateLimitHost`); and a Linux client that receives the error while `connect()` still holds the socket lock ignores it (`TcpExtLockDroppedIcmps`) and reports `ENETUNREACH` only when the retransmitted SYN triggers a second error. Acceptance tests must therefore check rejection by egress counters, not by client errors within one second.

### F8. AS-30: replies with an empty active set and no default route

With every main default route removed (including the one through the unmanaged uplink) and the active set empty, all of the following are accepted, for both families (`t7`): inbound DNAT traffic, connections to a router listener, ICMP probe replies and TCP probe replies, with no IPv4 reverse-path drop. IPv4 negative control: removing the source rule of the probe source makes ICMP probe replies fail the reverse-path check, whether the source guard is still present or not (`TcpExtIPReversePathFilter` increments); TCP probe replies fail likewise. With `src_valid_mark = 0` on the uplinks, inbound DNAT traffic is dropped by the IPv4 reverse-path check (its path mark is ignored and the check runs against the post-DNAT destination, which has no source rule), while connections to router addresses and probe replies still pass through the source rules. FR-SYS-2's combination is therefore required for inbound port forwarding and sufficient for the rest; its stated dependency of probe replies on the source rules is confirmed.

### F9. JSON listing and atomic replacement (FR-REC-6, FR-FW-1)

After re-applying identical text with the replacement transaction (`add table`, `delete table`, full table), the JSON listing (`nft -j list table`) differs only in the table handle; rule and chain handles restart from the same values in the new table. After removing the `metainfo` object and every `handle` key, the listings compare equal, and a rule added by a third party is detected. FR-REC-6 should state this normalisation. This is an experimental result: the nftables documentation describes the JSON export but not the stability of handles. Twenty consecutive replacements, alternating two different versions of the table, did not disturb a running masqueraded outbound flow or an inbound DNAT flow (gaps under 0.5 s, no error), for both families.

### F10. Smaller observations

- `all` and `dnat` (S1) are nftables keywords and break the parser when used as identifiers; the generator must quote every name it emits (IMPL-3).
- Flowtables were not exercised; the nftables documentation shows the fast path bypassing the forward and postrouting hooks, which supports FR-CT-2 (documentation only).

## Proposed amendments to SPEC.md

- **§4.7**: state that untracked packets are skipped in every chain and non-unicast packets in prerouting and postrouting (F2; the generator in `s2lib.sh` shows the rules); the policy rules end with `return`.
- **FR-FW-6**: other tables that read or write conntrack marks must use priorities above −200 (F3).
- **FR-REC-6**: the comparison normalises the JSON listing by removing `metainfo` and every `handle` (F9).
- **AS-15, AS-16, AS-27 and other rejection checks**: verify rejection by the absence of egress packets, because client-visible errors are rate-limited and can be lost (F7).
- **AS-30 / FR-SYS-2**: record that `src_valid_mark = 1` is what makes inbound port forwarding pass the IPv4 reverse-path check when no source rule covers the post-DNAT destination (F8).
- **AS-31**: the RELATED path MTU check can use an MTU bottleneck inside a provider with a full-size MSS advertised by the server, as in `t4` (F5).
