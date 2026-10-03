# S1 — Routing core

Spike S1 of SPEC.md §15: the rule layout of FR-ROUTE-3 with guard rules, encoded marks and zero-field source selectors, device-bound lookups, inline multipath updates for both families (including IPv6 intermediate states, failures and point-to-point members with link-local gateways), layer-4 hashing, pinning across updates, the orders of FR-REC-1, FR-REC-3 and FR-REC-4 with traffic checked at every intermediate state, the kernel side of the startup cases of FR-REC-8, and local source address selection for unbound router traffic including the FR-DISC-6 configuration.

## Environment

Both environments of `spikes/README.md`: Debian 12 with Linux 6.1.0-53, nftables 1.0.6, iproute2 6.1.0; Debian 13 with Linux 7.1.13 (trixie-backports), nftables 1.1.3, iproute2 6.15.0. Every test was run on both; the full logs are in `results/linux-6.1.txt` and `results/linux-7.1.txt`.

## How to run

As root on a disposable Linux host with iproute2, nftables, conntrack, tcpdump and python3: `./run.sh` (all tests) or `bash tN-name.sh` (one test). The tests create namespaces named `s1-*` and remove them on exit.

The topology is built by `../lib/netns.sh` (shared with S2): a client and a router; three uplinks, `wana` (id 1) and `wanb` (id 2) on Ethernet with the same IPv6 gateway `fe80::1`, and `wanc` (id 3), a GRE tunnel standing in for a point-to-point PPP link (IPv4 device-only route, IPv6 link-local gateway); providers routing to an "internet" namespace with the default probe targets and AnyIP server ranges; and `wanx`, an uplink that FTR does not manage, carrying the operating-system default route with the best metric, whose far end counts every packet it receives. Any packet arriving there is a leak. The FTR artifacts use the defaults of §11.2 (`rule_priority_base` 1000, `table_base` 1000, protocol 249, mask `0x00ff0000`). The nftables table is a draft of §4.7 (constant-only mark operations, restoration rules for all 63 path values, masquerade per uplink); S2 examines it in depth. `../lib/peer.py` provides the server (answers with the peer address) and the traffic generators.

## Results

| Test | What it checks | 6.1 | 7.1 |
|---|---|---|---|
| `t0-smoke.sh` | full layout, balancing over three uplinks, no leak | 3/3 | 3/3 |
| `t1-rules.sh` | route lookups for every mark class, guard, bypass and source rule, both families | 63/63 | 63/63 |
| `t2-devbound.sh` | `SO_BINDTODEVICE` and `IP_UNICAST_IF` sockets with real packets | 10/10 | 10/10 |
| `t3-multipath.sh` | multipath replace sequences, failures, notifications, make-before-break, AS-35 | 36/36 | 36/36 |
| `t4-hash.sh` | layer-4 hash distribution (1000 connections, 50 destinations), carrier loss | 8/8 | 8/8 |
| `t5-pinning.sh` | pinned flows across updates, path withdrawal, inbound symmetry | 14/14 | 14/14 |
| `t6-orders.sh` | FR-REC-1, FR-REC-3 (remove and add), FR-REC-4, step by step with traffic | 38/38 | 38/38 |
| `t7-startup.sh` | partial artifacts with live marks, repair order | 14/14 | 14/14 |
| `t8-source.sh` | source selection for unbound router traffic, FR-DISC-6 | 14/14 | 14/14 |

The two kernels behaved identically in every check.

## Findings

### F1. The rule layout works as specified

Every row of FR-ROUTE-3 routes as intended for both families (`t1`): unmarked forwarded traffic reaches the balancing table; path, probe, policy-balance and policy-block values reach their tables, also with foreign bits set outside the mask; never-configured path values (5, 63) hit the path guard; unconfigured probe and policy-block values hit their class guards; an unconfigured policy-balance value falls through to balancing, as FR-ROUTE-1 intends; destinations covered by a connected or static route in main bypass every mark (INV-1); an empty policy-balance table falls through to balancing and an empty policy-block table hits its guard; an empty path table rejects its pinned traffic instead of moving it; an empty balancing table rejects new connections although main holds default routes (INV-3, INV-4). Rules with a mask selector, `suppress_prefixlength 0`, `unreachable` action, tables above 255 and protocol 249 are all accepted by both kernels and iproute2 versions.

AS-48 cannot occur for IPv4 with default settings: a forwarded packet whose source address is a local address of the router is a martian and is rejected by the kernel before the rules are consulted (`Invalid argument` from the lookup). With `accept_local=1` on the downlink, it behaves as AS-48 expects (balanced, not caught by the source rule). IPv6 behaves as AS-48 expects by default.

### F2. IPv4 lookups constrained to an output device ignore guard rules

When a router-originated IPv4 lookup carries an output interface (`SO_BINDTODEVICE`) and fails, the kernel does not return the error: it assumes that the destination is on-link on that interface (`ip_route_output_key_hash_rcu`, "Apparently, routing tables are wrong. Assume, that the destination is on link."). Every failure counts, so an `unreachable` rule is bypassed exactly like an `unreachable` route, a `prohibit` or a `blackhole` (`t1`: lookups with `oif wana` and A outside the active set, with all FTR tables empty, with an `unreachable` route added to the balancing table, and with `oif wanx`, the unmanaged uplink, all return `dev <iface> src <address>` without a gateway). With real packets (`t2`): on Ethernet the router ARPs for the remote destination and nothing else leaves; on the point-to-point uplink the datagram does leave, with all FTR tables of that uplink empty (its reply is then dropped by the reverse-path check, because the restored path mark leads to the path guard). The leak sink received ARP requests but no IP packet. Spike S5 found the same independently for probe sockets.

IPv6 never assumes on-link: a device-bound lookup that fails returns `ENETUNREACH`. However, for connected sockets and for unconnected datagrams IPv6 then selects the source address from the bound device and repeats the lookup with that source (`ip6_dst_lookup_tail`), which matches the source rule and uses the path table. IPv4 connected sockets end up in the same place: `ip_route_connect` takes the source chosen by the on-link fallback and repeats the lookup, which matches the source rule. Result (`t2`, both families): a TCP connection bound to `wana` while A is outside the active set connects through A's path; IPv6 unconnected UDP bound to `wana` goes through A's path; IPv4 unconnected UDP bound to `wana` is sent on-link (ARP for the destination); with A's path table empty, IPv6 is rejected by the source guard while IPv4 is sent on-link.

Consequences:

- The rationale of FR-ROUTE-1 and Q9 is inaccurate: a rule-level reject is skipped by device-constrained IPv4 lookups exactly like a route-level reject. Guard rules remain the right design for the other reasons (class fallthrough, policy-balance without copied routes, one place per class), but they do not close this case, and no routing construct can.
- INV-3 and INV-4 cannot hold for router-originated traffic bound to an interface. Binding to an interface is an explicit decision of the program, like binding to an address, and should be treated like FR-SEL-3 treats address binding. Probes are unaffected as long as the prober stops probing a path that is not ready (S5 reaches the same conclusion).
- `IP_UNICAST_IF` behaves the same (`t2`): an IPv4 datagram with `IP_UNICAST_IF` set to the point-to-point uplink, whose tables are all empty, is sent on-link through it; with `IPV6_UNICAST_IF` the IPv6 datagram is rejected.

### F3. Multipath updates

IPv4 `NLM_F_REPLACE` of the balancing route is a single atomic operation with one notification, in every transition tested (single → multipath, adding and removing members including the first, multipath → single, weight changes, identical replace). Invalid members (off-link gateway, missing device, member whose interface is down) reject the whole request with no change. Duplicate members are accepted.

IPv6 `NLM_F_REPLACE` emits one notification carrying the complete new route on both kernels, so the intermediate states are invisible to netlink listeners. Every validation failure tested left the previous route untouched: off-link gateway (`EHOSTUNREACH`, no extended acknowledgement message), missing device, member whose interface is down ("Nexthop device is not up"), duplicate member (`EEXIST`, also when the duplicate follows a valid member) and device-only member ("Device only routes can not be added for IPv6 using the multipath API", confirming Q12). Point-to-point members with a link-local gateway join and leave a multi-member set (single → multiple → single) without errors and carry traffic in every state (AS-35).

The kernel source of `ip6_route_multipath_add` (identical in structure in 6.1 and 7.1) explains the rest: all members are built and validated before the first insertion; the first insertion replaces the old route together with all its siblings; the other members are then appended one by one, visible to packet lookups (RCU readers) as they arrive, so every intermediate state is a non-empty subset of the target set, as FR-ROUTE-2 requires. If an insertion after the first fails, the kernel deletes the members it has already inserted and returns the error with the message "multipath route replace failed (check consistency of installed routes)": the old route is gone and the new one is not installed, so the table is empty although the target set is not. All validation happens before the first insertion, so this can only be caused by an allocation failure; it could not be injected, because Debian kernels are built without `CONFIG_FAULT_INJECTION`. This outcome contradicts FR-ROUTE-2 ("empty only if the target set is empty"); the invariants still hold, because an empty balancing table makes new connections hit the final guard (INV-4), never leak.

A make-before-break alternative works on both kernels (`t3`): add the new route with metric 101 (lookups keep using metric 100), then delete the metric-100 route by exact key (lookups switch to the new set). A failed addition leaves the previous route in force. Its own transient is the deletion of the old multipath route, which removes the siblings one by one, so for an instant lookups can see a subset of the previous set rather than of the target set.

A member whose interface goes administratively down while it is in the balancing route stays in the IPv4 route flagged `dead linkdown` and is skipped; the path route of that interface is deleted by the kernel (IPv4) and must be restored when the interface comes back (with `keep_addr_on_down=0`, the default, IPv6 addresses also disappear on admin down).

### F4. Layer-4 hashing

With `fib_multipath_hash_policy = 1`, 1000 forwarded TCP connections with distinct 5-tuples to 50 destinations split 49–52 % with weights 1:1 and 74–78 % for the heavier member with weights 3:1, for both families on both kernels, inside the ranges of AS-01 and AS-02.

### F5. Members that lose carrier keep receiving new flows until they are withdrawn

When the provider side of an uplink goes away, the kernel flags the member `linkdown` but keeps selecting it, for both families, as long as `ignore_routes_with_linkdown` is 0 (the default); connections hashed to it fail until FTR withdraws the member. With `net.ipv{4,6}.conf.<uplink>.ignore_routes_with_linkdown = 1` the member is also flagged `dead` and skipped immediately, and all new connections go to the remaining members (`t4`). Setting it on uplink interfaces would remove the failover window of FR-HEALTH-5 for carrier loss without any action of the daemon; it also makes the kernel ignore other routes through that interface while it has no carrier, which is the desired behaviour on an uplink.

### F6. Pinning

A long-lived flow keeps working, with gaps under 0.5 s, when its uplink leaves the active set and when the active set becomes empty, for both families (`t5`, AS-03). Withdrawing its path route makes its packets hit the path guard: the flow stops and nothing reaches any other uplink or the leak sink (INV-2, INV-3). Inbound connections through port forwarding on an uplink outside the active set, and with an empty active set, are answered through the arrival uplink (INV-5, AS-09). Conntrack marks are restored for router-originated replies as well.

### F7. Activation, retirement and cleanup orders

After every step, 20 new forwarded flows and 20 new router-originated flows per family were sent and their egress interface counted (`t6`, `matrix` in `../lib/netns.sh`).

- FR-REC-1: before step 8 (balancing rule) every flow used the pre-existing routing; from step 8 every flow used FTR's uplinks; at no step was any flow rejected or split between the two. The statement of FR-REC-1 holds, and the switch-over point is the balancing rule.
- FR-REC-3 removal with pinned flows on A, B and C: no new flow used C after the first step, none was lost or leaked at any step; flows on A and B were uninterrupted throughout; the flow on C kept working after its assignments were removed from the nftables table (restoration rules for every id, and the existing NAT binding survives the removal of its masquerade rule), was rejected by the path guard once C's rules were deleted (AS-37), and never left through another interface. In a preliminary run where the new UDP flows reused the same 5-tuples, those flows stayed on C after C left the active set and were rejected after the rule deletion, as INV-2 requires.
- FR-REC-3 addition: no flow used C before the last step, nothing was lost or leaked, pinned flows on A and B were uninterrupted.
- FR-REC-4 cleanup: after the nftables table and the final guard, traffic still followed FTR until the balancing rule was removed, then the pre-existing routing; no FTR rule or route remained; a foreign rule, a foreign table's routes and a foreign nftables table were untouched.

Order within "source rules each with its source guard": the tests install the source rule before its guard and remove the guard before the rule, so traffic from that address is never rejected transiently. FR-REC-1, FR-REC-2 and FR-REC-4 should state this order.

### F8. Startup with partial artifacts

`t7` damages a running installation while a flow is pinned to A and A is outside the active set (so any misrouted packet is visible):

- path rule of A missing, guards intact: the flow is blocked by the path guard, never moved; new flows are unaffected; once the rule is restored the flow resumes on A and survives;
- path rule and class guards missing: the flow falls to the balancing rule and leaves through another uplink, which breaks the connection (`ECONNRESET`). This is why FR-REC-8 installs routes and guards before lookup rules; with guards first, the repair never moves a pinned connection;
- nftables table missing: conntrack marks survive, but packets are no longer restored or assigned, so the pinned flow's packets are balanced over the active uplinks until the table is back (the repair phase of §4.1 makes no promise here); new flows keep working; after reinstallation marks are restored and new flows are correct.

The "intact artifacts with an expired checkpoint" case has no kernel side (artifacts are kernel state that outlives the daemon); the external-ruleset case uses the same ruleset text as the managed mode and was not exercised separately in S1.

### F9. Source selection for unbound router traffic

Over the multipath balancing route without `src`, unbound router-originated flows take the address of the chosen member's interface, for both families and both TCP and unconnected UDP: 300 TCP connections per family spread over the three uplinks, and in 800 flows no packet left an uplink with another uplink's address (`t8`). The kernel picks the primary IPv4 address; a secondary address is never chosen for unbound traffic, and traffic bound to it uses A's path, also with an empty active set (AS-42).

FR-DISC-6: the IPv6 path route of an uplink without a global address accepts as `src` an address configured on the LAN interface; with `snat` to that address, forwarded traffic through that uplink works; unbound router traffic hashed to that member selects the LAN address and leaves through that uplink, consistently; traffic bound to the address uses the uplink's path; LAN hosts reach the address and the replies follow the main bypass, not the source rule.

### F10. Smaller observations

- nftables chain names that are keywords (`dnat`) are syntax errors unless quoted; the generator must quote every configuration-derived identifier (IMPL-3 already requires quoting strings).
- With `NLM_F_REPLACE` an IPv6 update is rejected as a whole if any member's interface is down at that instant; a race between planning and applying therefore produces an `apply_failed` for the whole update, resolved by replanning on the link event.

## Proposed amendments to SPEC.md

- **FR-ROUTE-1, Q9**: state that IPv4 lookups constrained to an output device treat any failure, rule or route, as "destination on-link" (F2); keep guard rules for their other properties.
- **INV-3, INV-4, FR-SEL-3, §4.1**: exclude router-originated traffic bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`) from INV-3 and INV-4 and treat it like traffic bound to an uplink address; document the IPv4 on-link behaviour and the IPv6 source-rule behaviour (F2).
- **FR-PROBE-1**: probing of a path stops as soon as it is not ready, because guard rules do not stop device-bound IPv4 probes (F2, S5).
- **FR-ROUTE-2**: add the outcome of a failure after the transition boundary: the IPv6 route may be absent, new connections are rejected by the final guard until the retry succeeds, status `degraded`, reason `apply_failed` (F3). Alternatively adopt make-before-break for IPv6 (metrics 100 and 101 alternating), at the price of a second route during the update and an old-set subset transient on deletion. Recommendation: keep `NLM_F_REPLACE` and amend the text; the failure needs an allocation failure.
- **FR-SYS-2**: set `ignore_routes_with_linkdown = 1` for both families on each uplink interface, recorded and restored like the other per-interface sysctls (F5), and list it in §4.6.
- **FR-REC-1, FR-REC-2, FR-REC-4**: within each address, the source rule is installed before its source guard and the guard removed before the rule (F7).
- **AS-48**: IPv6 only, or IPv4 with `accept_local = 1` on the downlink; with default settings the IPv4 case cannot occur (F1).
- **PLAT-1**: the netlink extended acknowledgement message is reported when the kernel provides one; some errors (for example an off-link IPv6 gateway) carry only the errno (F3; S3 reaches the same conclusion).
