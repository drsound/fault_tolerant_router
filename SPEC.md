# Fault Tolerant Router 2.0 — Specification

Status: **v0.7, amended with the results of the M0 spikes S1–S5 and the fifth external review** (`spikes/`; v0.5 was agreed with the external reviewer as the contract for M0). Nothing in this document is implemented yet, except the namespace test harness (§14).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119. Every requirement has an identifier (for example `FR-ROUTE-3`) so that tests, reviews and issues can refer to it.

## 1. Context

Fault Tolerant Router (FTR) 1.x is a Ruby daemon, written in 2015–2016, that runs on a Linux router with several internet uplinks. It balances new outgoing connections across the healthy uplinks with kernel multipath routing, keeps every connection on the uplink it started on (connection marks plus policy routing), monitors the uplinks by pinging public hosts, supports priority groups and weights, and sends email on state changes. It is IPv4-only, generates iptables rules that the administrator integrates by hand, shells out to `ip` and `ping`, and requires that the main routing table has no default route.

Version 2.0 is a ground-up rewrite in Rust. It keeps the core idea of 1.x (multipath routing for new connections, connection marks for pinning) and brings it up to date with the Linux networking stack of 2026: nftables, netlink, dual-stack IPv4/IPv6, dynamic (DHCP/RA/PPP) uplinks that coexist with the operating system's own default routes, and modern observability. The routing policy database layout changes materially compared to 1.x; behaviour is defined by the invariants of §4.1, not by compatibility with 1.x.

### 1.1 Who it is for

An administrator running a general-purpose Linux distribution (Debian, Ubuntu, Fedora, Arch, Raspberry Pi OS, a virtual machine, …) as a router or firewall with two or more internet uplinks, who does not want to replace it with a router distribution such as OpenWrt (mwan3), OPNsense/pfSense or VyOS. Typical 2026 setups: fiber plus a 5G or Starlink backup; two fiber lines in an office; a metered line used only when the others fail.

### 1.2 Goals

1. Transparent use of all healthy uplinks for new outgoing connections, with weights and priority groups.
2. A connection keeps its uplink for its whole life while that uplink remains usable; inbound connections are answered through the uplink they arrived on (precise contract in §4.1).
3. Fast and reliable failure detection, including "link up but provider disconnected from the internet" and, optionally, "link degraded".
4. IPv4 and IPv6 treated as first-class and independent: an uplink can be healthy for one family and failed for the other.
5. Uplinks with static, DHCP, SLAAC/RA or PPP addressing, without per-type configuration.
6. Zero-friction installation (one static binary, a systemd unit, a managed nftables table) with an alternative for administrators who manage nftables themselves.
7. Observable and scriptable: status API and CLI, Prometheus metrics, event hooks, email.
8. Verifiable behaviour: every functional requirement is covered by automated tests that move real packets through network namespaces, in CI.

### 1.3 Non-goals for 2.0

- Configuring interfaces, addresses, DHCP/DHCPv6/PPP clients, Router Advertisements or DHCPv6 prefix delegation. These remain the job of the operating system (systemd-networkd, ifupdown, NetworkManager, pppd, …). FTR observes them.
- Filtering firewall policy. FTR only marks packets and, optionally, performs source NAT. It never drops or accepts traffic on behalf of the administrator.
- Per-packet load balancing, bandwidth measurement or dynamic weight adjustment.
- IPv6 prefix translation (stateful prefix NAT or NPTv6) and automatic use of delegated prefixes. 2.0 supports IPv6 masquerade, SNAT to a static address, and no NAT (§6).
- IPv6 multihoming without NAT (several provider prefixes advertised to the LAN, with source-address-based routing and prefix deprecation on failure).
- Policies applied to traffic originated by the router itself (§4.5).
- Owning nexthop objects (`ip nexthop`) and using nexthop groups; 2.0 installs inline multipath routes (§4.3) and only resolves single nexthop objects found in discovered routes (FR-DISC-3).
- Hardware or software flow offload (nftables flowtables) on uplink interfaces (§4.8).
- Running as a non-root user.
- High availability between two routers (VRRP and similar), a web user interface, platforms other than Linux, internationalisation (1.x issue #5), routing realms (1.x issue #4).

## 2. Terminology

- **Uplink**: an interface connected to an internet provider, identified by a stable numeric `id` and a `name` (§11).
- **Downlink**: an interface connected to an internal network (LAN, DMZ, …) whose traffic is routed through the uplinks.
- **Family**: IPv4 or IPv6. Most state in FTR is tracked per (uplink, family) pair, called a **path**. A path exists only if the uplink's configuration enables that family.
- **Ready**: a path whose interface exists and is up with carrier, has a usable source address (§5.1) and has a usable next hop (a gateway, or none for point-to-point interfaces).
- **Healthy**: a path whose health state (§5.3) is `up`. Only ready paths can be healthy.
- **Eligible**: a path whose uplink has a `priority` and is not drained (§4.4).
- **Candidate**: a path that is eligible and ready.
- **Active set**: for each family, the paths currently used for new outgoing connections (§4.4).
- **FTR field**: the 8 contiguous bits of the packet/connection mark reserved to FTR (`fwmark_mask`).
- **Artifact**: any object installed by FTR: routing rule, route, nftables table, sysctl value, state file.
- **Main bypass**: the routing of destinations covered by a non-default route in the main table (§4.1, INV-1).

## 3. Platform requirements

- **PLAT-1** Linux kernel 6.1 or later. The daemon MUST check the running kernel version at startup and refuse to start on older kernels. Every kernel error during application MUST be reported with the attempted operation, the errno and the netlink extended acknowledgement message; netlink sockets enable `NETLINK_EXT_ACK`, and when the kernel provides no message (many errors carry only the errno) the report says so. An error is described as a missing feature only after a targeted capability test has established it.
- **PLAT-2** nftables 1.0.6 or later, when the managed firewall mode is used (§7).
- **PLAT-3** Architectures: x86_64, aarch64 and armv7 (Raspberry Pi). Release binaries MUST be statically linked (musl).
- **PLAT-4** systemd is the primary supported service manager; FTR MUST NOT depend on it at runtime (it runs in the foreground and logs to stderr).
- **PLAT-5** FTR runs as root, sandboxed by its systemd unit (§12.4). Running as a non-root user is not supported in 2.0.

## 4. Routing model

### 4.1 Invariants

The design exists to guarantee the following invariants. Every acceptance scenario (§14.3) checks one or more of them. Guarantees depend on the lifecycle phase:

- **Installation** (cold installation of FR-REC-1, warm adoption of FR-REC-8): no guarantee beyond FR-REC-1's statement that traffic follows either the pre-existing routing or FTR's routing; the invariants begin at the end of installation.
- **Active operation**, including reloads, runtime changes and partially applied generations caused by failed kernel operations (FR-REC-5): the invariants hold.
- **Repair** after a third party deletes or alters FTR artifacts: the invariants cannot be guaranteed while the artifacts are missing; they hold again once restored (FR-COEX-3).
- **Cleanup** (FR-REC-4): guarantees end when cleanup starts; routing is handed back to the operating system in the documented order.

The invariants apply only to traffic of a managed family (§4.3) that reaches FTR's rules: the local table (priority 0) and any foreign rule with a priority lower than `rule_priority_base` take precedence by construction (FR-ROUTE-6).

- **INV-1 (main bypass)** Packets whose destination is covered by a non-default route in the main table (connected networks, downlinks, static routes, VPN routes, routes pushed by DHCP option 121) are routed by the main table, bypassing path selection, pinning and policies; the only FTR rules that precede the main bypass are the probe rules (INV-6). This is intentional: it keeps internal and VPN traffic working. A VPN that installs `0.0.0.0/1` + `128.0.0.0/1` therefore overrides FTR for all traffic, by design. Default routes in the main table are never used for traffic that enters FTR's rule sequence. Deployment contract: routes towards downlinks and other internal destinations MUST be in the main table (FR-DISC-8).
- **INV-2 (pinning)** Except where INV-1 applies, a tracked connection that has been assigned a path is routed through that path's table for its whole conntrack lifetime, in both directions, regardless of later changes to health, active set, drain state or policies. If the path is not ready or no longer configured, its packets are rejected with ICMP unreachable rather than moved to another uplink (moving would change the source address and break the connection anyway). Exception: IPv4 packets of router-originated connections bound to an interface may instead be sent on-link through that interface (§4.1.1); they are never moved to another uplink.
- **INV-3 (no leak)** A packet that reaches FTR's rules and is not handled by the main bypass is either routed by an FTR table or rejected by an FTR guard rule; it never reaches a non-FTR routing table, and in particular never uses a default route installed by the operating system. Router-originated traffic bound to an interface is outside this invariant (§4.1.1).
- **INV-4 (new connections)** A new forwarded connection not matched by a policy, and a new router-originated connection bound neither to an uplink address nor to an interface (§4.1.1), is routed only through a member of its family's active set, or rejected with ICMP unreachable if the active set is empty or, transiently, if the balancing route is absent after a failed IPv6 update (FR-ROUTE-2). Probes are excluded (INV-6).
- **INV-5 (inbound symmetry)** Except where INV-1 applies, packets of a connection that arrived on uplink *U* (including replies from downlink hosts after DNAT, and replies from the router itself) leave through *U*, also when *U* is not in the active set or is drained, as long as *U* is ready.
- **INV-6 (probes)** Probe traffic for a path leaves through that path's interface, using that path's next hop and source, whenever the path is ready, regardless of health, active set, drain state, policies and main-table routes.
- **INV-7 (non-interference)** FTR never modifies mark bits outside the FTR field, never deletes or modifies objects it does not own, never adds `drop`/`reject`/`accept` verdicts to nftables, and never changes sysctls other than those listed in §4.6.
- **INV-8 (decoupling)** Notifications, hooks, API clients and metrics scrapes never delay routing decisions.

Continuity is promised only for connections whose path stays ready and keeps the same source address and conntrack entry. Connections on a failed uplink generally break and are re-established by the client on another uplink.

#### 4.1.1 Traffic bound to an interface

Router-originated traffic whose socket is bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`/`IPV6_UNICAST_IF`, an `IP_PKTINFO` interface index) is an explicit egress decision of the program: it is exempt from drain like traffic bound to an uplink address (FR-SEL-3), it is excluded from INV-3 and INV-4, and for IPv4 the rejection promised by INV-2 does not apply to it. FTR guarantees only that it never leaves through another interface, and does not guarantee that it reaches its destination (an IPv4 datagram sent on-link on Ethernet is generally lost). Spike S1 established the kernel behaviour on 6.1 and 7.1, which FTR cannot change:

- IPv4: a route lookup constrained to an output interface that fails, whether because of an `unreachable` rule, an `unreachable`/`prohibit`/`blackhole` route or no route, is treated as "destination on-link on that interface" (`ip_route_output_key_hash_rcu`). Guard rules therefore do not terminate such traffic; it can only leave through the bound interface (on Ethernet the router ARPs for the destination; on a point-to-point link the packet is sent to the peer).
- IPv6: such a lookup fails with `ENETUNREACH`; for connected sockets and unconnected datagrams the kernel then selects the source address from the bound interface and repeats the lookup, which matches that address's source rule (B + 500 + id) and uses the path table, or its source guard.
- IPv4 connected sockets behave like IPv6: the source chosen by the on-link fallback is used for a second lookup that matches the source rule.

The documentation MUST describe this behaviour.

### 4.2 Marks

- **FR-MARK-1** FTR MUST use only the 8 bits selected by `fwmark_mask` (default `0x00ff0000`, MUST be exactly 8 contiguous bits) of packet and conntrack marks, and MUST preserve all other bits (INV-7).
- **FR-MARK-2** Each uplink has a stable `id` from 1 to 63, set explicitly in the configuration (§11). The **field value** stored in the FTR field encodes a class (2 high bits) and the uplink id (6 low bits); 0 means "no FTR assignment":

  | Class | Field value | Meaning | Stored in |
  |---|---|---|---|
  | path | `id` | connection assigned to the uplink's path | conntrack mark and packet mark |
  | probe | `0x40 + id` | probe traffic of the uplink | packet mark (probe sockets) |
  | policy, fallback balance | `0x80 + id` | new connection matched by a policy targeting the uplink, `fallback = "balance"` | packet mark only |
  | policy, fallback block | `0xc0 + id` | same, `fallback = "block"` | packet mark only |

  The maximum number of uplinks is therefore 63.
- **FR-MARK-3** Field values are placed in the mark by `encode(v) = v << trailing_zeros(fwmark_mask)`. Every routing rule selector and every nftables mark operation MUST use encoded values and the mask (for example, with the default mask, the probe value of uplink 1 is `0x00410000/0x00ff0000`). Writing the FTR field MUST be implemented with constant operations only (`meta mark set meta mark & ~mask | encode(value)`), one rule per value, because combining two variable registers is not available on all supported kernels. Restoration rules (§4.7) MUST exist for all 63 path values, whether configured, retired or never used, so that connections of removed uplinks keep their mark and reach the path guard; assignment rules exist only for configured uplinks.
- **FR-MARK-4** Uplink identity is the pair (`id`, `name`). The binding is persisted in the state directory (§12.3). Reusing an `id` for a different `name`, or changing the `id` of an existing `name`, MUST be rejected while the old binding is recorded. An uplink removed from the configuration keeps its id reserved until the administrator runs `fault-tolerant-router forget-uplink NAME`, whose documentation explains that connections still carrying the old id must be flushed or allowed to expire first; until then they are rejected by the path guard (FR-ROUTE-3).

### 4.3 Routing tables and rules

A family is **managed** when at least one configured uplink enables it. All of FTR's rules, guards and tables exist only for managed families; an IPv4-only installation installs nothing for IPv6. When a reload removes the last path of a family, FTR hands that family back to the operating system with a scoped procedure (FR-REC-9) and emits an event.

For each managed family, FTR owns the routing tables `table_base` to `table_base + 191` (default `table_base = 1000`) and the rule priorities `rule_priority_base` to `rule_priority_base + 699` (default 1000). All FTR rules and routes MUST be installed with the routing protocol number `route_protocol` (default 249). Every FTR table holds at most one route: a usable default route with the fixed metric 100, present only when the table says so below; otherwise the table is empty. Withdrawing a route means deleting it (exact key: table, family, destination `default`, metric 100).

| Table | Purpose | Default route present when |
|---|---|---|
| `table_base` | balancing (new connections) | the active set is non-empty: a multipath route over its members (single nexthop if one member) |
| `table_base + id` | path of uplink `id` | the path is ready, regardless of health: `via <gateway> dev <iface> src <source>` (IPv4 point-to-point: `dev <iface> src <source>`) |
| `table_base + 64 + id` | policies with fallback balance | the path is healthy and the uplink is not drained: same route as the path table |
| `table_base + 128 + id` | policies with fallback block | the path is healthy and the uplink is not drained: same route as the path table |

- **FR-ROUTE-1** Termination is enforced by **guard rules** (routing rules whose action is `unreachable`), not by routes: one guard per mark class gives class-specific fallthrough (policy-balance without copied routes) and a single final guard. Neither a guard rule nor a reject route terminates an IPv4 lookup constrained to an output interface (§4.1.1). A lookup that finds no usable route in an FTR table continues to the next rule and is caught by the guard of its class, or by the final guard (FR-ROUTE-3). The policy-balance class intentionally has no guard: its fallthrough reaches the balancing rule, which implements `fallback = "balance"` without copying routes; no rule between them can match a policy-balance mark, because the block-class rules and guard select another class and the source rules require a zero FTR field.
- **FR-ROUTE-2** The balancing route is an inline multipath route (RTA_MULTIPATH) with each member's configured weight, updated with `NLM_F_REPLACE`. For IPv4 the replacement is a single atomic operation. For IPv6 the kernel replaces the old members with the first new one and then adds the others, so the update is not atomic. The requirement is therefore defined in phases around the **transition boundary**, the first kernel mutation of the update that succeeds:
  - before the boundary (including an update rejected without any mutation), the previously applied route stays in force and new connections use the previous active set;
  - after the boundary, the route contains only members of the target active set, possibly a non-empty subset while the update is in progress or after a partial failure; it is empty only if the target set is empty, except after the IPv6 failure described below;
  - pinned connections are unaffected in every phase;
  - an update is complete when the route equals the target set; until then the status is `degraded`, the failure is reported as `apply_failed` and retried (FR-REC-5);
  - exception for IPv6: if an insertion after the first fails, the kernel deletes the members it has already inserted and reports "multipath route replace failed (check consistency of installed routes)"; the old route is gone and the new one is not installed, so the balancing table is empty although the target set is not. New connections are then rejected by the final guard (INV-4 holds) until the retry succeeds. FTR MUST re-read the table after any failed IPv6 update.

  Spike S1 established on 6.1 and 7.1 that every validation failure (off-link gateway, missing device, member interface down, duplicate member, device-only member) is detected before the first mutation and leaves the previous route in force, that IPv6 add and replace produce a single notification with the complete route, and, from the kernel source (not from an injected failure: the tested kernels lack fault injection), that the intermediate states are non-empty subsets of the target set and that the exception above requires an allocation failure. The duplicate-member and device-only rejections are IPv6 behaviour; IPv4 accepts both. A member whose interface goes down between planning and application makes the whole update fail; the failure is resolved by replanning on the link event.
- **FR-ROUTE-3** Routing rules, per family, at fixed offsets from `rule_priority_base` (B). `encode` is defined in FR-MARK-3; "/class" means the mask `encode(0xc0)`:

  | Priority | Selector | Action | Purpose |
  |---|---|---|---|
  | B + id | `fwmark encode(0x40+id)/mask` | lookup path table | probes (INV-6) |
  | B + 64 | `fwmark encode(0x40)/class` | unreachable | probe guard |
  | B + 100 | (all) | lookup `main`, `suppress_prefixlength 0` | main bypass (INV-1) |
  | B + 200 + id | `fwmark encode(id)/mask` | lookup path table | pinned connections (INV-2, INV-5) |
  | B + 264 | `fwmark encode(2^k)/encode(0xc0 + 2^k)`, k = 0…5 (six rules) | unreachable | path guard: any non-zero path-class value, including retired ids |
  | B + 300 + id | `fwmark encode(0x80+id)/mask` | lookup policy-balance table | policies with fallback balance (falls through to B + 600 when empty) |
  | B + 400 + id | `fwmark encode(0xc0+id)/mask` | lookup policy-block table | policies with fallback block |
  | B + 464 | `fwmark encode(0xc0)/class` | unreachable | policy-block guard |
  | B + 500 + id | `from <address> fwmark 0/mask`, one rule per local address of the path (FR-DISC-2) | lookup path table | router-originated traffic bound to an uplink address, including replies of router services; the zero-field selector keeps policy-marked forwarded traffic out |
  | B + 564 | `from <address> fwmark 0/mask`, one rule per address above | unreachable | source guard |
  | B + 600 | (all) | lookup balancing table | new connections (INV-4) |
  | B + 699 | (all) | unreachable | final guard (INV-3) |

  Lookup rules exist only for configured uplinks; guards exist for every managed family while FTR is installed. All rules are static for a given configuration, except the `from` rules and source guards, which follow the usable addresses. Runtime changes of health, drain and active set are applied only through route replacements and deletions (FR-REC-2).
- **FR-ROUTE-4** FTR MUST NOT delete or modify routes, rules or tables it does not own (INV-7). Default routes installed in the main table by the operating system stay there and are used for discovery (§5.1); because of the final guard they are never used for traffic that enters FTR's rule sequence while FTR is installed.
- **FR-ROUTE-5** FTR MUST set `fib_multipath_hash_policy = 1` (layer 4) for both families when `manage_sysctls = true`.
- **FR-ROUTE-6** `rule_priority_base` MUST be at least 1 and the range MUST end below 32766 (the main table rule); the table range MUST NOT include 253–255. Startup MUST fail if any rule in the priority range, or any route in the table range, exists that is not tagged with `route_protocol` (collision with another tool), and MUST fail if the local-table rule at priority 0 is missing. The kernel's VRF rule (action `l3mdev`, protocol `kernel`, priority 1000 by default) is not a collision: it matches only traffic of VRF devices; it is listed in the warning of foreign rules below. Foreign rules with priorities between 1 and `rule_priority_base` precede FTR: startup and `check-config` MUST list them in a warning, and the documentation MUST state that FTR's invariants do not cover traffic they match.

### 4.4 Active set selection

For each family independently, the active set is computed from the candidates (eligible and ready paths) with this decision table:

| Condition | Active set |
|---|---|
| At least one candidate is healthy | healthy candidates of the lowest-numbered priority group among healthy candidates |
| No healthy candidate, at least one candidate, `all_down_policy = "ready"` (default) | candidates of the lowest-numbered priority group among candidates, regardless of health |
| No healthy candidate, at least one candidate, `all_down_policy = "keep"` | previous active set (persisted, §12.3) restricted to current candidates |
| Any other case, or the result above is empty | empty: the balancing table has no route, new connections are rejected by the final guard |

- **FR-SEL-1** Selection MUST follow the table above. Rationale for `ready`: if every check fails at once, the probes themselves may be the problem (for example, the targets are unreachable); still preferring the best priority group avoids spilling onto metered uplinks.
- **FR-SEL-2** An uplink with no `priority` is never a candidate, but its path table, inbound connections, probes and policies keep working.
- **FR-SEL-3** **Drain**: the administrator MAY drain an uplink at runtime (§9). A drained uplink is not eligible: it receives no new forwarded connections, neither through balancing nor through policies (its policy tables become empty, so their fallback applies), and no new unbound router-originated connections. Existing connections, inbound connections (INV-5), probes, and router-originated traffic explicitly bound to one of the uplink's addresses continue: an explicit binding is an administrator decision that drain does not override. Traffic bound to the uplink's interface is likewise exempt from drain, with only the guarantees of §4.1.1. Drain state is persisted in the state directory and survives restarts and upgrades until undrained or until the uplink is removed from the configuration. A drain or undrain request is persisted durably (IMPL-5) before it is applied and before the API acknowledges it; on restart, the persisted intent is applied whatever the kernel state left by a crash.
- **FR-SEL-4** The API MUST refuse to drain the last candidate of a family unless the request sets `force = true`.

### 4.5 Policies

Policies force matching new forwarded connections through a specific uplink, replacing the hand-written iptables examples of 1.x (for example: always send SMTP from the address with the right PTR record; keep a VoIP device on the low-latency line).

- **FR-POL-1** A policy matches new forwarded connections by any combination of: family, input interface (MUST be a downlink), source prefix, destination prefix, L4 protocol, destination port or port range. Policies are evaluated in declaration order; the first match wins.
- **FR-POL-2** A matching connection gets, in the packet mark only, the policy value for its target uplink and fallback (FR-MARK-2). The conntrack mark is assigned the actual egress path after routing (§4.7), so a connection is pinned to whatever uplink its first packet actually used (INV-2), and later policy table changes never move it.
- **FR-POL-3** `fallback = "balance"` (default): while the target path is not healthy or the uplink is drained, matching new connections are balanced over the active set. `fallback = "block"`: they are rejected with ICMP unreachable.
- **FR-POL-4** Policies do not apply to traffic originated by the router itself in 2.0. Such traffic follows FR-ROUTE-3 (balancing or `from` rules).
- **FR-POL-5** Policies are subject to the main bypass (INV-1).

### 4.6 System settings

When `manage_sysctls = true` (default), FTR MUST set at startup, re-apply when an uplink interface is (re)created, and record the previous values in the state directory:

- **FR-SYS-1** IPv4 forwarding (`net.ipv4.ip_forward = 1`) and, if any IPv6 path is configured, IPv6 forwarding (`net.ipv6.conf.all.forwarding = 1`).
- **FR-SYS-2** On each uplink interface: `rp_filter = 2` (loose) and `src_valid_mark = 1`, so that the reverse-path check of inbound packets uses the path mark set before routing (§4.7); without `src_valid_mark`, inbound port forwarding fails the check whenever no source rule covers the post-DNAT destination. Probe replies are not marked; their IPv4 reverse-path check succeeds through the `from` rule of the probe's source address, and the documentation MUST state this dependency (it is observable only with an empty active set and targets not covered by main routes, because loose mode accepts any route). On each uplink interface, for both families: `ignore_routes_with_linkdown = 1`, so that the kernel stops selecting a multipath member as soon as its interface loses carrier, before FTR withdraws it (without it, connections hashed to that member fail until the withdrawal). FTR MUST NOT change `net.ipv4.conf.all.rp_filter`. IPv6 has no `rp_filter`; administrators using an nftables `fib`-based reverse-path filter MUST include the mark in the lookup and run it after FTR's prerouting chain (documented recipe).
- **FR-SYS-3** FTR MUST NOT change `accept_ra`. Router Advertisement processing belongs to whoever manages the interface (the kernel with `accept_ra = 2`, systemd-networkd with `IPv6AcceptRA=yes`, NetworkManager). Because IPv6 forwarding (FR-SYS-1) disables the kernel's RA processing on interfaces with `accept_ra = 1`, startup and `check-config` MUST warn for each IPv6 path with `gateway = "auto"` whose uplink has `accept_ra = 1` while forwarding is or will be enabled, explaining that `accept_ra = 2` or a user-space RA client is required (`accept_ra = 0` is normal with systemd-networkd and NetworkManager). If an IPv6 path with `gateway = "auto"` has no discovered gateway 30 s after startup or after its link came up, FTR MUST emit a warning that names the likely causes for each of these cases.
- **FR-SYS-4** The multipath hash policies of FR-ROUTE-5.

When `manage_sysctls = false`, FTR MUST check these values at startup and warn for each one that differs, without changing it. On `cleanup`, a sysctl is restored to its recorded previous value only if its current value is still the one FTR set.

### 4.7 Mark lifecycle (nftables)

This section defines what the generated ruleset (§7) does to each packet. "Restore" means copying a path value from the conntrack FTR field to the packet FTR field; "assign" means writing a path value into the conntrack FTR field and the packet FTR field.

1. **Prerouting** (filter chain, hook prerouting, priority −150: after conntrack, before DNAT):
   1. If the conntrack FTR field holds a path value: restore it into the packet, for every packet of the connection, whatever its conntrack state (covers retransmitted SYNs, one-way UDP, RELATED ICMP errors). Stop.
   2. Else, if the packet arrived on uplink `id` in the original direction of its connection: assign path `id` (new inbound connection, INV-5). Stop. Reply packets of connections without a path value, such as probe replies, are left unmarked; their reverse-path check succeeds through the source rule of the probe's local address (FR-SYS-2).
   3. Else, if the packet arrived on a downlink: evaluate policies (FR-POL-1) and, on the first match, write the policy value into the packet FTR field only. Stop.
2. **Output** (route chain, hook output, priority −150, so that a mark change triggers a new routing decision):
   1. If the packet FTR field holds a probe value: stop (INV-6).
   2. If the conntrack FTR field holds a path value: restore it (replies of the router to inbound connections, later packets of router-originated connections).
3. **Postrouting** (filter chain, hook postrouting, priority −150: before source NAT):
   1. If the packet FTR field holds a probe value: stop.
   2. If the conntrack FTR field holds no path value and the packet leaves through uplink `id` in the original direction of its connection: assign path `id`. This is the only place where outgoing connections, including policy-matched ones, get their path. Replies of connections without a path value (for example connections that arrived on an interface FTR does not manage) are not assigned.
4. **NAT** (nat chain, hook postrouting, priority `firewall.nat_priority`, default 100, always strictly greater than −150): §6.

All mark reads and writes use encoded values (FR-MARK-3). Marking applies only to tracked unicast traffic (§4.8): every chain first returns for untracked packets (`ct state untracked`), and the prerouting and postrouting chains also return for non-unicast packets. Spike S2 verified this lifecycle on 6.1/nftables 1.0.6 and 7.1/nftables 1.1.3, including that every mark write compiles to constant-only bitwise operations, except the original-direction condition of step 3.2, a design amendment of v0.6 covered by AS-50.

- **FR-MARK-5** The ruleset MUST implement exactly this lifecycle. Values outside the FTR field MUST be preserved (FR-MARK-1, FR-MARK-3).

### 4.8 Conntrack and offload requirements

- **FR-CT-1** Unicast data traffic between downlinks and uplinks, and unicast data traffic of the router through uplinks, MUST be tracked by conntrack for pinning to work. Untracked traffic is not marked. `notrack` rules for data traffic break pinning; `check-config` MUST warn if the administrator's ruleset contains `notrack` statements (best effort, by inspecting `nft -j list ruleset`).
- **FR-CT-2** Flowtables (`flow add @…`) MUST NOT include uplink interfaces, because offloaded packets bypass the hooks of §4.7. `check-config` and startup MUST detect flowtables containing uplink interfaces and refuse to start.
- **FR-CT-3** The documentation MUST describe, without promising recovery: expired or flushed entries (the next packet that conntrack accepts as new is routed as a new connection, possibly through another uplink, and the connection usually breaks); entry allocation failure under table exhaustion (packets may be dropped by the kernel); invalid packets (not tracked as new; not marked).
- **FR-CT-4** Conntrack zones other than the default zone are not supported on uplink and downlink interfaces in 2.0 (documented limitation).
- **FR-CT-5** **Control-plane compatibility**: FTR MUST NOT prevent the operating system from acquiring and maintaining uplink configuration, starting from no lease, no global address, no default route and an empty active set: DHCPv4 acquisition, renewal (except as stated below) and rebinding; DHCPv6 including prefix delegation; router solicitation and advertisement, duplicate address detection and neighbour discovery; PPP and PPPoE negotiation; the multicast and broadcast traffic these need; interface recreation and address expiry. Exception: a unicast DHCPv4 renewal towards an off-link server (provider relay) whose route lookup is not bound to the leased address (observed with ISC dhclient and dhcpcd) is unbound router-originated traffic: it is rejected while the active set is empty and balanced otherwise; the client then depends on the broadcast rebind at T2, which succeeds if the provider answers rebinds (with very short leases, some clients may let the lease expire before rebinding; observed with ISC dhclient and 2-minute leases, also without FTR). Spike S4 established that, apart from that exception, the listed functions work with the complete guard layout and an empty active set in the tested combinations (Linux 6.1, 6.12 and 7.1; systemd-networkd 252 and 257, NetworkManager 1.52, ISC dhclient, dhcpcd 9 and 10, the kernel's RA/SLAAC/DAD/ND, kea DHCPv6 with prefix delegation, pppd with rp-pppoe for IPv4): DHCPv4 discovery, requests and rebinding use packet sockets, on-link renewals and link-local traffic are covered by the main bypass, IPv6 multicast is routed by the local table, PPP control traffic is not IP-routed. No exception to the guard rules is needed for these mechanisms (Q15). Not yet tested, and covered by AS-44 and AS-35: IPv6 over PPPoE, NetworkManager with DHCPv6 prefix delegation, DHCPv6 with the server-unicast option. Clients that bind the renewal to the leased address (systemd-networkd, NetworkManager) use the address's source rule and path route, available within one second of the address and gateway events (FR-DISC-5).

### 4.9 Coexistence with network managers

- **FR-COEX-1** At startup and in `check-config`, FTR MUST read the effective systemd-networkd configuration (`networkd.conf` and drop-ins in `/etc`, `/run`, `/usr/lib`) when systemd-networkd is active, and refuse to start if `ManageForeignRoutingPolicyRules` or `ManageForeignRoutes` is enabled (explicitly or by default), with a message explaining the fix. Rationale (S4): with them enabled, networkd deletes FTR's rules on every link reconfiguration (252 and 257) and on restart (257), and FTR's routes on restart. `ManageForeignNextHops` (systemd 256 and later) needs no check, because FTR owns no nexthop objects and discovers routes that use single nexthop objects (FR-DISC-3). The documentation MUST include a compatibility matrix by systemd version.
- **FR-COEX-2** The documentation MUST include NetworkManager guidance (NetworkManager removes routes only in tables it manages; FTR's tables MUST NOT be used as NetworkManager `route-table` values).
- **FR-COEX-3** When no ownership conflict is active (FR-COEX-4), FTR MUST start restoring any of its artifacts removed or altered by a third party within one second of the netlink notification and, when the kernel operations succeed, complete the restoration within that second, logging an `artifact_repaired` event; when they fail, FR-REC-5 applies. Removals that the kernel performs itself as a consequence of an observed event are expected, are not counted as third-party removals (FR-COEX-4), and are handled by the normal planning path: routes of an interface that goes down or whose IPv6 configuration is reset, routes whose preferred source address is deleted, routes that use a deleted nexthop. Removals are attributed by the port id in the notification's message header (`nlmsghdr.nlmsg_pid`, not the netlink sender address, which is always the kernel: 0 means the kernel, FTR's own mutation socket means FTR, any other value a third party), correlated with the link and address events that explain kernel removals; removals that the kernel performs without any notification (S3: IPv4 routes on administrative down or on removal of their source address) are found by the re-reads of §12.2 and are kernel-initiated.
- **FR-COEX-4** If artifacts of the same kind are removed by a third party more than 3 times in 5 minutes, FTR MUST stop immediate repairs for that kind, set its status to `degraded` with reason `ownership_conflict`, emit an event, and repair only at each full reconciliation (FR-REC-6). The conflict is cleared, with an event, after two consecutive full reconciliations that find no third-party removal.

## 5. Uplink discovery and health

### 5.1 Discovery

- **FR-DISC-1** Interface identity is the configured interface name; FTR tracks its ifindex. When the interface disappears, its paths become not ready; when an interface with the same name appears (for example a PPP interface recreated with a new ifindex), discovery starts again and per-interface sysctls are re-applied.
- **FR-DISC-2** Two address sets are derived for each path:
  - **Local addresses**: the interface's addresses of the family with global scope that are not tentative or DAD-failed (temporary and deprecated addresses included, because they remain valid for existing and service traffic; for IPv4, primary and secondary addresses), plus a static `source` assigned to another interface (FR-DISC-6). Every local address gets a `from` rule and a source guard (FR-ROUTE-3).
  - **Source candidates**: the local addresses on the interface itself that are neither temporary nor deprecated. The **source** of the path, `source = "auto"` (default), is the candidate chosen by preferring permanent addresses over dynamic ones, then primary over secondary (IPv4), then the numerically lowest. With a static `source`, the path is ready only while that address is present on the router and not tentative, DAD-failed or deprecated.

  An address that belongs to the local addresses of two paths of the same family makes both paths not ready, with reason `address_conflict`; configuration validation MUST reject the same static `source` on two uplinks.
- **FR-DISC-3** Next hop, `gateway = "auto"` (default):
  - IPv4 point-to-point interfaces (`IFF_POINTOPOINT`): no gateway is needed and routes use `dev <iface>`.
  - Otherwise (including every IPv6 path, because the kernel rejects device-only members in IPv6 multipath routes): FTR considers default routes of the family, of type unicast, in the tables listed in `discovery_tables` (default `["main"]`), not installed by FTR, with an inline nexthop or inline multipath members that use the uplink interface, excluding members flagged `dead` or `linkdown`. It selects by lowest metric, then (IPv6) highest router preference, then order of `discovery_tables`, then numerically lowest gateway. Flags relevant to reachability (`onlink`) are preserved from the source route.
  - A route that references a nexthop object (`RTA_NH_ID`) is recognised by that attribute, although the kernel also dumps the resolved gateway and interface. A single (non-group) nexthop object with a gateway on the uplink interface is resolved and used like an inline nexthop; systemd-networkd installs Router Advertisement default routes this way by default (observed with 257; the option appeared in 256). The Observer (§12.2) also subscribes to nexthop notifications and dumps nexthop objects; when a nexthop object used by a discovered route changes or is deleted, the paths that depend on it are re-evaluated within the bound of FR-DISC-5. Resolution and nexthop notifications were not exercised by the spikes and are validated in M2 (AS-49). Routes that reference nexthop groups are not used; if they are the only candidates, the path is not ready and a warning recommends a static `gateway`.
  - The kernel changes the `dead` and `linkdown` flags of nexthops without notification; readiness is re-evaluated from the re-reads of §12.2 after link events.
  - The next hop is represented as (gateway address, ifindex); identical gateways on different uplinks (for example `fe80::1`) are therefore distinct.
  - An IPv6 path on a point-to-point interface (for example PPP) is ready only when a gateway is discovered (typically the peer's link-local address from its Router Advertisement) or configured.
- **FR-DISC-4** A static `gateway` is used as configured; the path is ready while the interface is up with carrier, has a usable source address, and the gateway is reachable on the interface: covered by a connected route of the interface in the main table, or declared with `gateway_onlink = true`.
- **FR-DISC-5** Discovery MUST be event-driven (§12.2). Any change of carrier, ifindex, address or gateway MUST be reported as an event (§8) and the first attempt to update FTR's artifacts MUST start within one second; when the kernel operations succeed, the update completes within one second, otherwise FR-REC-5 applies.
- **FR-DISC-6** IPv6 uplinks that have no global address of their own (prefix-delegation-only providers) are supported only with a static `source` assigned to another interface of the router (typically the LAN address taken from the delegated prefix) and `nat = "snat"`. Automatic handling is out of scope for 2.0.
- **FR-DISC-7** A path whose routes cannot be installed (the kernel rejects them) is not ready, with reason `route_install_failed`, the operation, errno and netlink extended acknowledgement in the event; installation is retried at each discovery change and full reconciliation.
- **FR-DISC-8** `check-config` and startup MUST warn when a downlink's connected prefixes are missing from the main table (for example because the address was configured with `noprefixroute` or into another table): replies towards that network would otherwise follow a path table to the provider.
- **FR-DISC-9** The `type = static | ppp` setting of 1.x disappears. 1.x issue #19 (DHCP uplinks) is solved by FR-DISC-3.

### 5.2 Probes

- **FR-PROBE-1** Each probe socket MUST be created non-blocking, bound to the path's source address, with `SO_BINDTODEVICE` set to the uplink interface and `SO_MARK` set to the encoded probe value of the uplink, all before the first packet is sent. Together with the probe rules (FR-ROUTE-3) and the path table, this implements INV-6. ICMP probes use raw sockets (`SOCK_RAW`), because ping sockets depend on `net.ipv4.ping_group_range`, which FTR must not change. A probe socket is tied to one interface index and one source address and is recreated when either changes. Probing of a path stops as soon as the path is not ready: guard rules do not stop device-bound IPv4 probes (§4.1.1). Probes MUST NOT depend on external binaries.
- **FR-PROBE-2** Probe types: `icmp` (ICMP echo / ICMPv6 echo, default) and `tcp` (TCP handshake to a given port, for links that filter ICMP; a SYN-ACK or a RST counts as a reply, a timeout as a loss). Targets are written as `icmp:ADDRESS`, `tcp:IPV4:PORT` or `tcp:[IPV6]:PORT`, are configured per family, and MUST be global unicast addresses that are neither local to the router nor inside a downlink prefix.
- **FR-PROBE-3** Replies MUST be validated: source address equal to the target; for ICMP, matching identifier (random per path), sequence number (incremented per attempt, wrapping allowed) and a random 16-byte payload token unique per attempt; for TCP, a SYN-ACK or a RST on the attempt's own socket; arrival before the attempt deadline. For IPv4 ICMP the checksum is verified in user space (raw sockets receive messages before the kernel validates it). ICMP errors and local errors (such as `ENETUNREACH`) count as losses, not replies, for both probe types; a reply is matched only to an attempt that is still open. Results of attempts started under a previous interface, address or configuration generation MUST be discarded and counted as **canceled**, not as losses.
- **FR-PROBE-4** Scheduling: rounds start every `interval` (default 5 s) at a fixed rate, per path, and never overlap. In a round, all targets are probed concurrently; each target gets up to `attempts` attempts (default 2), each waiting up to `timeout` (default 1 s), the next attempt being sent only after the previous one timed out. A target is **reachable** if any attempt got a valid reply. The round **passes** if at least `required_reachable` targets (default 2) are reachable. Without quality gates, a round ends as soon as its outcome is certain; with quality gates enabled for the path, every started attempt runs until it gets a reply or reaches its deadline, so that samples are not biased. A round lasts at most `timeout × attempts`. A TCP attempt is one socket; when `timeout` reaches the kernel's initial SYN retransmission timeout (1 s) it may carry a retransmitted SYN, and it still yields at most one sample. Validation MUST require `timeout × attempts < interval` and `required_reachable ≤ number of distinct targets`.
- **FR-PROBE-5** Each completed attempt is a **sample** (replied or lost, RTT if replied); canceled attempts are not samples. Optional quality gates per path, evaluated at the end of each round over the samples of the last `quality_window` rounds (default 6): loss ratio = lost samples / samples; RTT = median RTT of replied samples; jitter = median of absolute differences between consecutive RTTs of the same target. The loss gate is evaluated only with at least `quality_min_samples` samples (default 10); the RTT and jitter gates only with at least 5 replied samples or 5 RTT differences respectively. Validation MUST require `quality_min_samples ≤ targets × quality_window`. A round that passes reachability but violates a gate counts as **failed (degraded)**. Because old samples stay in the window, recovery from a degraded state takes at least `rise` rounds and until the window no longer violates the gate; the documentation MUST say so.
- **FR-PROBE-6** Default targets MUST be well-known anycast resolvers of at least three different operators for each family, and the documentation MUST explain why nearby hosts (such as the provider's own router) are bad targets (as in the 1.x README).

### 5.3 Health state machine

Each path is in one of two states: `down` or `up`. Health is independent of selection: a path can be `down` and still active when `all_down_policy` keeps it (§4.4).

- **FR-HEALTH-1** Initial state. Readiness is applied first: a path that is not ready starts `down`. For a ready path:
  - Warm start (a valid health checkpoint from the same boot, §12.3, taken less than 10 minutes earlier by `CLOCK_BOOTTIME`): the path starts in its checkpointed state with its hysteresis counters, and normal hysteresis applies.
  - Cold start (otherwise, including after a reboot): the path starts `up`; the first completed round sets the state directly, without hysteresis.

  This prevents a restart from briefly re-activating a path that was down.
- **FR-HEALTH-2** `up` → `down` after `fall` consecutive failed rounds (default 2). `down` → `up` after `rise` consecutive passed rounds (default 3).
- **FR-HEALTH-3** A path that stops being ready goes `down` immediately, without waiting for `fall`; when it becomes ready again, it needs `rise` passed rounds to go `up` (startup optimism applies only to cold start).
- **FR-HEALTH-4** Every transition records a reason (`probe_failed`, `degraded`, `carrier_lost`, `interface_removed`, `address_lost`, `address_conflict`, `gateway_lost`, `route_install_failed`, `probes_recovered`, `startup`) shown in events, the API and logs.
- **FR-HEALTH-5** Detection bounds with default settings, which acceptance tests MUST verify: loss of carrier or interface → path `down` and its routes withdrawn within 1 s; silent upstream failure → path `down` within `(fall + 1) × interval + timeout × attempts` (17 s with defaults). Removal from the active set follows from the state change according to §4.4 (a `down` path stays active only under `all_down_policy` with no healthy candidate).

## 6. NAT

- **FR-NAT-1** Per path, `nat` can be:
  - `masquerade`: source NAT to the address of the outgoing interface; works with dynamic addresses;
  - `snat`: source NAT to the static address given in `source` (MUST be static);
  - `none`: no NAT (routed setups).

  For IPv4 the default is `masquerade`. For IPv6 there is no default: `nat` MUST be set explicitly whenever IPv6 is enabled on an uplink, and the documentation MUST explain the trade-offs (with several providers, `none` only works if every provider routes the LAN prefix, which is rare; masquerade with a ULA LAN prefix gives transparent failover at the cost of end-to-end addressing).
- **FR-NAT-2** NAT applies only to traffic coming from downlinks and leaving through the uplink. Traffic forwarded between downlinks and router-originated traffic are never translated.
- **FR-NAT-3** Port forwarding (DNAT) remains the administrator's responsibility; INV-5 guarantees symmetric replies.
- **FR-NAT-4** If the administrator also performs source NAT on uplink interfaces, the earliest NAT chain to match decides. The documentation MUST say that `nat = "none"` must then be set, and `check-config` MUST warn when it finds `masquerade` or `snat` statements on uplink interfaces in other tables (best effort).

## 7. Firewall integration

### 7.1 Modes

- **FR-FW-1** `firewall.mode = "managed"` (default): FTR creates and owns the nftables table `inet fault_tolerant_router` and replaces it atomically (one transaction containing `add table`, `delete table`, and the full table) at startup, on reload and when reconciliation finds it missing or different (§12.2). It MUST NOT modify any other table.
- **FR-FW-2** `firewall.mode = "external"`: FTR performs no nftables mutations (read-only inspection, such as the checks of FR-CT-1, FR-CT-2 and FR-NAT-4, still happens). The administrator loads the ruleset produced by `fault-tolerant-router export-nft`. The daemon MUST log at startup that marking and NAT are the administrator's responsibility, and MUST check that a table with the expected name exists, warning if it does not.
- **FR-FW-3** Both modes MUST use the same generator, so that `export-nft` prints exactly what the managed mode installs, with comments explaining each rule.

### 7.2 Ruleset properties

- **FR-FW-4** The ruleset contains only the chains of §4.7 with the stated hook types and priorities, plus the NAT chain. It MUST NOT contain `drop`, `reject` or `accept` verdicts (INV-7); chains have policy `accept` and only use `return` to stop processing.
- **FR-FW-5** The ruleset MUST be generated from the configuration only, never from runtime state (health, addresses, active set). All runtime changes happen in routing (FR-ROUTE-3). Re-installing identical content during reconciliation is allowed.
- **FR-FW-6** The documentation MUST explain interactions with the administrator's ruleset: chains of other tables at the same hooks run independently in priority order; a `drop` anywhere drops; another writer of the same mark bits later in the pipeline breaks pinning; DNAT in prerouting at priority −100 runs after FTR's marking; rules of other tables that read or write conntrack marks must use priorities above −200, because at −200 they can run before the conntrack entry exists (S2).

## 8. Events and notifications

### 8.1 Events

- **FR-EV-1** Event types: `daemon_started`, `daemon_stopping`, `config_reloaded`, `reload_failed`, `path_state_changed`, `path_address_changed`, `path_gateway_changed`, `active_set_changed`, `uplink_drained`, `uplink_undrained`, `artifact_repaired`, `apply_failed`, `status_degraded`, `status_recovered`.
- **FR-EV-2** Every event has: sequence number (monotonic within a daemon run), instance identifier (random per daemon run), timestamp, type, uplink and family where applicable, old and new values, reason, and a human-readable message.
- **FR-EV-3** Events are logged and dispatched to notifiers through bounded queues; when a queue is full, the event is dropped for that notifier and a counter is incremented (INV-8).

### 8.2 Email

- **FR-MAIL-1** SMTP with implicit TLS, STARTTLS or plain (explicit opt-in), optional authentication, TLS via rustls with the system certificate store. The password MUST be read from a file (`password_file`), not from the main configuration.
- **FR-MAIL-2** Events are coalesced over `coalesce` (default 30 s) into one email listing every change. At most `max_per_hour` emails (default 20) are sent per hour, followed by one email saying that notifications are being suppressed.
- **FR-MAIL-3** A failed delivery is retried up to 3 times with exponential backoff (1, 5, 15 minutes), then dropped and logged.
- **FR-MAIL-4** `fault-tolerant-router notify-test` sends a test notification through every channel (1.x `email_test`).

### 8.3 Hooks

- **FR-HOOK-1** Hooks are external commands configured with an absolute executable path and an argument vector (no shell interpretation), and an optional list of event types.
- **FR-HOOK-2** The event is passed as JSON on stdin and as environment variables (`FTR_EVENT`, `FTR_UPLINK`, `FTR_FAMILY`, `FTR_OLD`, `FTR_NEW`, `FTR_REASON`); the rest of the environment is empty except `PATH=/usr/sbin:/usr/bin:/sbin:/bin`.
- **FR-HOOK-3** Hooks run as `hook_user` (default `nobody`) with its primary group, no supplementary groups, no capabilities, no inherited file descriptors other than stdin/stdout/stderr, in a new process group, with a timeout (default 10 s) after which the whole process group is killed. Concurrency is limited (default 4); stdout and stderr are captured up to 64 KiB each and logged with the exit status.
- **FR-HOOK-4** Hooks are fire-and-forget: they cannot veto or delay routing changes (INV-8).

## 9. Status API and CLI

- **FR-API-1** The daemon serves HTTP/1.1 with JSON bodies on a Unix socket (default `/run/fault-tolerant-router/api.sock`), owned by root and by group `api.group` (default `fault-tolerant-router`, created by the package), mode 0660. Membership of that group grants full control; the documentation MUST say so.
- **FR-API-2** Read endpoints: `GET /v1/status` (version, uptime, configuration digest, desired and applied generations, overall status `ok`/`degraded` with reasons, per-path state, reason, since, addresses, gateway, last round statistics, active sets, drain flags); `GET /v1/events?instance=ID&after=SEQ&limit=N&wait=SECONDS` (events from an in-memory ring buffer of 1000 entries; with `wait`, the request blocks up to 60 s until a newer event exists; the response carries the instance identifier, a `reset` flag when the requested instance differs from the current one or `after` is beyond the latest sequence number, in which case events are returned from the start of the buffer, and a `truncated` flag when `after` is older than the oldest buffered event).
- **FR-API-3** Write endpoints: `POST /v1/uplinks/{name}/drain` (body `{"force": bool}`, FR-SEL-4), `POST /v1/uplinks/{name}/undrain`, `POST /v1/uplinks/{name}/forget` (FR-MARK-4; refused while the uplink is configured), `POST /v1/reload` (response reports success, validation errors, or partial application with the failed steps).
- **FR-API-4** Limits: request bodies up to 64 KiB, at most 16 concurrent connections, 10 s per request (excluding the `wait` of events), at most 1000 events per response.
- **FR-API-5** The API is versioned (`/v1`), documented, and backward compatible within a major version.

CLI (single binary `fault-tolerant-router`):

| Command | Purpose |
|---|---|
| `run [--config PATH] [--dry-run]` | Run the daemon in the foreground. `--dry-run` computes and logs every artifact change without applying it and writes nothing (no kernel or nftables changes, no state files, no API or metrics listeners; read-only netlink observation and probes are allowed) (replaces 1.x `--demo`). |
| `check-config [--config PATH] [--offline]` | Validate the configuration; without `--offline`, also the system prerequisites (kernel, nftables, sysctls, networkd settings, collisions, flowtables). Exit non-zero on error. |
| `generate-config` | Print a commented example configuration. |
| `export-nft [--config PATH]` | Print the nftables ruleset (§7). |
| `status [--json]` | Show the daemon status through the API. |
| `events [--follow]` | Show recent events; `--follow` long-polls `GET /v1/events`. |
| `drain NAME [--force]` / `undrain NAME` | Runtime maintenance of an uplink. |
| `reload` | Reload the configuration (equivalent to SIGHUP). |
| `notify-test` | Send a test notification through every configured channel. |
| `forget-uplink NAME` | Release the persisted id binding of a removed uplink (FR-MARK-4). Takes the instance lock; when run while the daemon is running, it is forwarded through the API instead. |
| `cleanup [--config PATH]` | Remove every FTR artifact listed in the manifest and the configuration (1.x issue #22). Takes the instance lock, so it is refused while the daemon runs. |

## 10. Metrics

- **FR-MET-1** Optional Prometheus endpoint, disabled unless `metrics.listen` is set (for example `127.0.0.1:9750`). It MUST serve only `GET /metrics`, with the same connection limits as the API.
- **FR-MET-2** Metrics (labels in braces): `ftr_build_info{version}`, `ftr_status_degraded`, `ftr_path_up{uplink,family}`, `ftr_path_ready{uplink,family}`, `ftr_path_active{uplink,family}`, `ftr_uplink_drained{uplink}`, `ftr_path_rtt_seconds{uplink,family}`, `ftr_path_jitter_seconds{uplink,family}`, `ftr_path_loss_ratio{uplink,family}`, `ftr_path_transitions_total{uplink,family,to}`, `ftr_probe_samples_total{uplink,family,target,result}`, `ftr_artifact_repairs_total{kind}`, `ftr_apply_failures_total{kind}`, `ftr_events_dropped_total{notifier}`, `ftr_notifications_failed_total{channel}`.

## 11. Configuration

### 11.1 Format and lifecycle

- **FR-CFG-1** TOML, default path `/etc/fault-tolerant-router/config.toml`. The file MUST start with `version = 2`; unknown keys and unknown versions MUST be rejected with a precise message (file, line, key).
- **FR-CFG-2** Durations use human-readable strings (`"5s"`, `"500ms"`).
- **FR-CFG-3** On SIGHUP or `reload`, the new configuration is fully validated first; if invalid, the running configuration is kept and a `reload_failed` event is emitted. If valid, it is applied by reconciliation (§12.2), without restarting probes of unchanged paths and without affecting connections of unchanged uplinks.
- **FR-CFG-4** Structural settings (`fwmark_mask`, `table_base`, `rule_priority_base`, `route_protocol`, `firewall.mode`) cannot change on reload; the documentation describes the disruptive procedure (`cleanup`, then restart).
- **FR-CFG-5** The configuration file and its parent directories MUST be owned by root and not writable by group or others; otherwise the daemon refuses to start. A password file readable by group or others produces a warning.
- **FR-CFG-6** 1.x YAML configurations are not read. The documentation MUST include a mapping from every 1.x parameter to its 2.0 equivalent.

### 11.2 Schema

| Key | Type | Default | Constraints |
|---|---|---|---|
| `version` | integer | — | MUST be 2 |
| `routing.table_base` | integer | 1000 | 192 consecutive tables within 1–4294967294, excluding 253–255 |
| `routing.rule_priority_base` | integer | 1000 | ≥ 1, base + 699 < 32766 |
| `routing.route_protocol` | integer | 249 | 5–255 |
| `routing.fwmark_mask` | integer | `0x00ff0000` | exactly 8 contiguous bits |
| `routing.all_down_policy` | `"ready"` / `"keep"` | `"ready"` | |
| `routing.discovery_tables` | list of table names or ids | `["main"]` | MUST NOT intersect FTR's range |
| `routing.manage_sysctls` | bool | true | |
| `routing.reconcile_interval` | duration | `"60s"` | 10 s – 1 h |
| `routing.on_shutdown` | `"keep"` / `"cleanup"` | `"keep"` | |
| `firewall.mode` | `"managed"` / `"external"` | `"managed"` | |
| `firewall.nat_priority` | integer | 100 | −149 – 400 (strictly after the −150 postrouting marking chain) |
| `firewall.nft_path` | absolute path | `/usr/sbin/nft` | root-owned, not group/world writable |
| `downlink[].interface` | string | — | at least one downlink; unique; not an uplink |
| `uplink[].id` | integer | — | 1–63, unique, stable (FR-MARK-4) |
| `uplink[].name` | string | — | `[a-z0-9_-]{1,32}`, unique |
| `uplink[].description` | string | name | |
| `uplink[].interface` | string | — | unique across uplinks and downlinks |
| `uplink[].priority` | integer | none | 1–1000; absent means not eligible |
| `uplink[].weight` | integer | 1 | 1–256 |
| `uplink[].ipv4` / `uplink[].ipv6` | table | absent | absent means the family is disabled on this uplink; at least one per uplink |
| `uplink[].ipvX.source` | `"auto"` / address | `"auto"` | address of the matching family; static if `nat = "snat"` |
| `uplink[].ipvX.gateway` | `"auto"` / address | `"auto"` | address of the matching family |
| `uplink[].ipvX.gateway_onlink` | bool | false | only with a static `gateway` (FR-DISC-4) |
| `uplink[].ipvX.nat` | `"masquerade"` / `"snat"` / `"none"` | IPv4: `"masquerade"`; IPv6: required | |
| `uplink[].health` | table | — | per-uplink override of any `health` key |
| `health.interval` | duration | `"5s"` | 1 s – 5 min |
| `health.timeout` | duration | `"1s"` | `timeout × attempts < interval` |
| `health.attempts` | integer | 2 | 1–5 |
| `health.required_reachable` | integer | 2 | 1 – number of distinct targets |
| `health.fall` / `health.rise` | integer | 2 / 3 | 1–20 |
| `health.ipv4.targets` / `health.ipv6.targets` | list | built-in list | `icmp:ADDR`, `tcp:IPV4:PORT` or `tcp:[IPV6]:PORT`; family must match; no duplicates; FR-PROBE-2 restrictions |
| `health.quality.max_rtt` / `max_jitter` | duration | none | optional gates |
| `health.quality.max_loss` | float | none | 0 – 1 |
| `health.quality_window` | integer | 6 | 2–100 rounds |
| `health.quality_min_samples` | integer | 10 | 1 – targets × `quality_window` |
| `policy[].name` | string | — | unique |
| `policy[].family` | `"ipv4"` / `"ipv6"` | — | target uplink must enable it |
| `policy[].input_interface` | string | any downlink | MUST be a downlink |
| `policy[].source` / `destination` | prefix | any | family must match |
| `policy[].protocol` | `"tcp"` / `"udp"` / `"sctp"` / `"icmp"` / `"icmpv6"` | any | `icmp` only with IPv4, `icmpv6` only with IPv6; ports only with tcp/udp/sctp |
| `policy[].destination_port` | integer or `"A-B"` | any | 1–65535 |
| `policy[].uplink` | uplink name | — | MUST exist |
| `policy[].fallback` | `"balance"` / `"block"` | `"balance"` | |
| `notify.coalesce` | duration | `"30s"` | |
| `notify.email.*` | table | absent | `from`, `to`, `host`, `port`, `security` (`"tls"`/`"starttls"`/`"plain"`), `username`, `password_file`, `max_per_hour` |
| `notify.hook[]` | table | absent | `command` (absolute path + args), `events`, `timeout` |
| `notify.hook_user` | string | `"nobody"` | existing user |
| `api.socket` / `api.group` | path / group | see FR-API-1 | |
| `metrics.listen` | socket address | absent | |
| `state_dir` | path | `/var/lib/fault-tolerant-router` | |

### 11.3 Example

```toml
version = 2

[routing]
all_down_policy = "ready"

[[downlink]]
interface = "lan0"

[[downlink]]
interface = "dmz0"

[[uplink]]
id = 1
name = "fiber"
description = "Fiber 1 Gbps (provider A)"
interface = "wan0"
priority = 1
weight = 10

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"

[[uplink]]
id = 2
name = "fwa5g"
description = "5G FWA (provider B, CGNAT)"
interface = "wan1"
priority = 1
weight = 3

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"

[[uplink]]
id = 3
name = "metered"
description = "Metered LTE, last resort"
interface = "ppp0"
priority = 2

[uplink.ipv4]
nat = "masquerade"

[health]
interval = "5s"
timeout = "1s"
attempts = 2
required_reachable = 2

[health.ipv4]
targets = ["icmp:1.1.1.1", "icmp:8.8.8.8", "icmp:9.9.9.9", "icmp:208.67.222.222"]

[health.ipv6]
targets = ["icmp:2606:4700:4700::1111", "icmp:2001:4860:4860::8888", "icmp:2620:fe::fe"]

[[policy]]
name = "smtp-via-fiber"
family = "ipv4"
source = "192.168.1.25/32"
protocol = "tcp"
destination_port = 25
uplink = "fiber"
fallback = "block"

[notify.email]
from = "router@example.com"
to = ["admin@example.com"]
host = "smtp.example.com"
port = 587
security = "starttls"
username = "router@example.com"
password_file = "/etc/fault-tolerant-router/smtp-password"

[[notify.hook]]
command = ["/usr/local/bin/ftr-to-ntfy"]
events = ["path_state_changed", "active_set_changed"]

[metrics]
listen = "127.0.0.1:9750"
```

## 12. Architecture and implementation

### 12.1 Language and dependencies

- **IMPL-1** Rust, stable toolchain, edition 2024. Every crate of the project MUST declare `#![forbid(unsafe_code)]`; socket options use the safe APIs of `socket2` (`set_mark`, `bind_device`).
- **IMPL-2** Dependencies (netlink links, addresses, routes, rules and notifications, and sockets, confirmed by spikes S3 and S5; nexthop messages to be validated in M2): `tokio` (runtime, bounded channels, `AsyncFd` for raw sockets), `netlink-packet-route` for message types and `netlink-proto` / `netlink-sys` for transport, with exact versions pinned because these crates are pre-1.0 (`rtnetlink` at most for connection setup: its builders add duplicate rules on `replace()`, default to protocol `static` and hide header flags), `socket2` with feature `all`, `serde` + `toml`, `clap`, `tracing`, `hyper` (API and metrics), `lettre` with rustls (SMTP). FTR builds its own rule and route messages.
- **IMPL-3** nftables is driven by generating a ruleset in nft syntax (with all configuration-derived strings validated and every identifier quoted, since names such as `dnat` or `all` are keywords) and applying it with `nft -f -` from the configured `nft_path`, as one atomic transaction, with a 10 s deadline and bounded stderr capture. Rationale: the ruleset depends only on the configuration (FR-FW-5), the same text is what `export-nft` prints, and `nft` is present wherever nftables is used.
- **IMPL-4** No blocking work in the State task; subprocesses (nft, hooks) and SMTP run in separate tasks with deadlines.

### 12.2 Structure and reconciliation

```
 netlink events ──► Observer ──┐
                              ├──► State (single owner) ──► Planner ──► Reconciler ──► kernel / nft
 probe results ──► Prober ────┘          │      ▲
                                         │      └── API commands (drain, reload)
                                         └──► Event bus ──► log / email / hooks / API ring buffer / metrics
```

- **Observer**: subscribes to the netlink groups for links, addresses, routes, rules and nexthops on a socket that never sends requests (S3: `netlink-proto` matches replies by sequence number only, so a subscribed socket that also sends requests confuses notifications with replies); dumps and mutations use separate sockets. It performs a full dump after subscribing, buffering the notifications received meanwhile and applying them in order afterwards; honours `NLM_F_DUMP_INTR` wherever it is received (S3 observed it only on address dumps under churn, which does not prove it absent elsewhere) by retrying the dump a bounded number of times, then schedules a full resynchronisation; on `ENOBUFS` it discards its view and performs a full resynchronisation. Because the kernel does not notify every removal or nexthop flag change, it re-reads FTR's tables and the discovery tables after every link or address event of an uplink interface.
- **Prober**: one task per ready path; reports round results tagged with the path generation (FR-PROBE-3).
- **State**: a single task that owns all mutable state (health state machines, drain flags, configuration, generations) and receives messages from every other component.
- **Planner**: a pure function from (configuration, observed system, health and drain state) to the desired set of artifacts. It contains all the logic of §4 and is unit-tested exhaustively without a kernel.
- **Reconciler**: diffs desired against actual artifacts and applies changes. Each desired state has a generation number; the status API reports the desired and the last fully applied generation.

Reconciliation rules:

- **FR-REC-1 Cold installation** (no FTR artifacts present), in this order: (1) validate structural settings against the manifest and record the manifest (write-ahead, IMPL-5); (2) sysctls; (3) usable routes of all tables; (4) guard rules of the probe, path and policy-block classes (connections still carrying FTR marks from a previous installation may be rejected by them until step 5 installs their lookup rules; this is part of the installation phase, §4.1); (5) lookup rules in order of decreasing precedence: probe rules, main bypass, path rules, policy rules, `from` rules each followed by its source guard, balancing rule; (6) final guard; (7) nftables table (managed mode), which starts mark assignment. Until step 6 completes, traffic follows either the pre-existing routing or FTR's routing; the invariants of §4.1 hold from the end of step 7.
- **FR-REC-2 Runtime changes** (health, drain, active set, address, gateway) are applied only through route replacements and deletions and through the addition and removal of `from` rules with their source guards; when an address changes, rules for the new address are added before rules for the old one are removed; a source rule is added before its source guard, and a source guard is removed before its source rule.
- **FR-REC-3 Adding an uplink** on reload: record its binding in the manifest; its sysctls; its routes; its lookup rules (probe, path, policy, `from` rules each followed by its source guard); nftables table replacement including its assignments; finally its inclusion in the active set and policy tables. **Removing an uplink**: exclude it from the active set and empty its policy tables; nftables table replacement without its assignments; delete its lookup rules, `from` rules and source guards, each source guard before its source rule (connections still carrying its id are now rejected by the path guard); delete its routes. Its id stays reserved (FR-MARK-4).
- **FR-REC-4 Cleanup** (`cleanup`, or `on_shutdown = "cleanup"`) is the reverse of FR-REC-1: nftables table; final guard; lookup rules in order of increasing precedence (each source guard before its source rule); class guards; routes; sysctls restored per FR-SYS (only values still equal to what FTR set, using the baseline recorded in the manifest); manifest last. Cleanup is disruptive by definition.
- **FR-REC-5 Failures**: every step is idempotent; a failed step is logged, counted, reported as an `apply_failed` event with operation, errno and extended acknowledgement, and retried with exponential backoff (1 s to 60 s); steps that depend on a failed step (according to the orders above) are not attempted; retries of an obsolete generation are canceled when a newer desired generation exists. The status is `degraded` until the desired generation is fully applied. Because routes and guards precede the lookup rules that use them, and mark assignments follow the lookup rules that interpret them, a generation partially applied during active operation never violates the invariants (§4.1 phases). The API reports a drain or reload as complete only when the applied generation includes it; otherwise the response lists the failed steps.
- **FR-REC-6 Full reconciliation** (dump of rules, routes and the nftables table, comparison with the desired state, repair following the orders above) runs at startup, every `reconcile_interval` and after any observer resynchronisation. For the nftables table, the comparison uses the JSON listing (`nft -j list table`) recorded right after the last successful application, normalised by removing `metainfo` and every `handle`. Rules are created with `NLM_F_CREATE | NLM_F_EXCL` and never with `NLM_F_REPLACE`, which adds a duplicate rule; the protocol is part of a rule's identity; dumped rules are normalised before comparison (`FRA_SUPPRESS_PREFIXLEN` = `0xffffffff` means unset, a zero mark is dumped with `FRA_FWMASK` only, `unreachable` rules carry table 0); a single-nexthop route equals a one-member multipath route.
- **FR-REC-7** If an internal task terminates unexpectedly, the daemon MUST log the failure and exit with a non-zero status, relying on the service manager to restart it. Warm adoption (FR-REC-8) keeps pinned connections on ready paths unaffected by the restart, provided their artifacts are still intact.
- **FR-REC-8 Startup classification and warm adoption.** Before any mutation, FTR inventories its artifacts (rules and routes in its ranges, the nftables table in managed mode) and validates them against the manifest (IMPL-6). Then:
  - **nothing present**: cold installation (FR-REC-1). Connections may still carry FTR marks from a previous installation; their restoration and path rules route them as before once installation completes;
  - **complete and compatible**: adoption; the differences from the desired state are applied with the runtime and add/remove orders (FR-REC-2, FR-REC-3);
  - **partial** (some kinds missing, possibly with live mark assignments): missing routes and guards are installed first, then missing lookup rules in order of decreasing precedence, then the final guard, and the nftables table last if missing; nothing present and compatible is removed first.

  In external firewall mode, FTR's guarantees begin when both FTR's routing artifacts and the administrator-loaded ruleset are present; until FTR detects the expected table, the status is `degraded` with reason `external_ruleset_missing`.

- **FR-REC-9 Family handoff.** When the last path of a family is removed: (1) the family's paths leave the active set and policy tables; (2) the shared nftables table is replaced atomically with a version that no longer contains that family's rules, retaining the other family's rules unchanged; (3) that family's rules, guards and routes are removed in the order of FR-REC-4; (4) that family's sysctls are restored according to their baselines. The manifest, id reservations, the other family's artifacts and the sysctl baselines still needed are preserved.

### 12.3 State directory, ownership and lifecycle

- **IMPL-5** The state directory (`state_dir`, mode 0700) contains versioned files, each written atomically (temporary file, fsync, rename, fsync of the directory):
  - the **manifest**: structural settings, owned table and priority ranges, protocol, nftables table name, uplink id/name bindings (including reserved ids of removed uplinks), and the **baseline** of every sysctl FTR has changed, recorded the first time FTR changes it and kept across restarts until cleanup. The manifest is written before the kernel objects it describes are created (write-ahead);
  - the **drain state**;
  - the **health checkpoint**: boot identifier (`/proc/sys/kernel/random/boot_id`), `CLOCK_BOOTTIME` timestamp, configuration digest, and per path its identity (uplink id, family, ifindex, source, gateway), state, state-since, hysteresis counters, plus the active set of each family. It is written at every transition and at least every 30 s. A checkpoint is valid only with the same boot identifier, an age under 10 minutes and the same structural settings; a path's entry is used only if its uplink id, family, ifindex, source and gateway are unchanged, otherwise that path starts cold.
- **IMPL-6** At startup FTR takes an exclusive lock on `/run/fault-tolerant-router/lock`; a second instance, `cleanup` and `forget-uplink` MUST refuse to run while it is held. Then, before any mutation: if the manifest exists, its structural settings MUST equal the configuration's, otherwise startup fails with instructions (run `cleanup`, which uses the manifest, then start with the new settings); if the manifest is missing but FTR-tagged objects exist in the configured ranges, they are adopted only if consistent with the configuration, otherwise startup fails; a corrupt or unknown-version state file makes startup fail unless `run --reset-state` is given, which discards drain state and checkpoints but never the manifest's sysctl baseline unless the manifest itself is unreadable. Untagged objects in the ranges are collisions (FR-ROUTE-6).
- **IMPL-7** On SIGTERM/SIGINT, by default FTR leaves its artifacts in place (`on_shutdown = "keep"`), so that a restart or upgrade causes no outage; `on_shutdown = "cleanup"` removes them (FR-REC-4). `cleanup` uses the union of the manifest and the configuration, so that a changed configuration does not hide old artifacts.
- **IMPL-8** No panics in the daemon path: every fallible operation returns an error handled by the caller (FR-REC-5, FR-REC-7).
- **IMPL-9** Resource targets on a Raspberry Pi 4 with 4 uplinks, default settings and a release build, measured over 10 minutes excluding hook processes: under 1% of one CPU core on average, under 30 MB RSS.

### 12.4 Security

- **IMPL-10** The provided systemd unit MUST use sandboxing (`NoNewPrivileges`, `ProtectSystem=strict` with `ReadWritePaths` for the state and runtime directories, `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_KILL`, `SystemCallFilter=@system-service`) and `Restart=always`; acceptance tests MUST run against this unit (AS-34).
- **IMPL-11** The API socket is the only control surface; the metrics endpoint is read-only.

## 13. Future work (out of scope for 2.0)

- IPv6 prefix translation and automatic use of delegated prefixes; IPv6 multihoming without NAT.
- Policies for router-originated traffic.
- Nexthop objects and resilient nexthop groups.
- Additional probe types (DNS, HTTP with expected status); hot-standby uplinks probed less often to save metered traffic.
- Automatic conversion of 1.x configurations.

## 14. Verification

Correctness of a routing daemon can only be demonstrated by moving packets; acceptance is defined by tests.

### 14.1 Test levels

1. **Unit tests**: configuration parsing and validation, mark allocation, health state machine (with deterministic, synthetic probe results), active set decision table, planner output (golden tests on the desired artifacts for representative configurations), nftables generator output (golden tests).
2. **Integration tests in network namespaces**: a harness builds the topology of §14.2 with namespaces and veth pairs, runs the real binary in the router namespace and checks real traffic. They MUST run in CI on every push, on two environments: the CI runner's current kernel with a current nftables, and a virtual machine booted with the minimum supported kernel (6.1) and nftables (1.0.6), for example with virtme-ng.

### 14.2 Reference topology

An "internet" node hosting the probe targets (including the addresses of the default targets) and test servers for both families; three "provider" nodes (plain routing with DHCPv4/DHCPv6/RA; CGNAT; PPPoE); the router under test; a LAN client. Addresses use documentation and benchmarking prefixes (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`, `100.64.0.0/10`, `2001:db8::/32`). Failures are injected with `ip link`, nftables rules with deterministic patterns (for example dropping every third probe) and, for statistical scenarios only, `tc netem`.

### 14.3 Acceptance scenarios

Each scenario runs for IPv4 and for IPv6 unless stated otherwise, always with operating-system default routes present in the main table, so that leaks are observable. Results are measured on egress packets and flow continuity, not only on routing state. Rejection is verified by the absence of egress packets, not by the error seen by the client: the kernel rate-limits the ICMP errors of `unreachable` rules per source host with host-wide sysctls (`net.ipv4.route.error_cost`, `error_burst`), and a client can miss an error that arrives while `connect()` holds the socket (S2, harness). Time limits are measured from the injected kernel event to the observed route change. Statistical scenarios use 1,000 connections with distinct 5-tuples to at least 50 destinations and are repeated with 5 seeds.

| ID | Scenario | Expected result | Invariants |
|---|---|---|---|
| AS-01 | Two healthy uplinks, equal weights | Each uplink gets 45–55% of connections | INV-4 |
| AS-02 | Weights 3:1 | First uplink gets 70–80% | INV-4 |
| AS-03 | Long-lived TCP connection on A; B fails and recovers | Connection never interrupted | INV-2 |
| AS-04 | Carrier lost on A | A out of the active set within 1 s; new connections on B | INV-4 |
| AS-05 | Provider A disconnected upstream, link up | A removed within the FR-HEALTH-5 bound, reason `probe_failed` | INV-4 |
| AS-06 | Deterministic loss of 1 probe in 3 on A, gate `max_loss = 0.2` | A removed with reason `degraded`; restored after the pattern stops, within `rise` rounds plus window clearing | — |
| AS-07 | Link flapping every 2 s for 60 s | Transitions exactly as predicted by `fall`/`rise`; emails respect `coalesce` and `max_per_hour` | INV-8 |
| AS-08 | Priority groups 1 and 2; all of group 1 fails, then recovers | Group 2 takes over; back to group 1 after recovery | INV-4 |
| AS-09 | Inbound connection (DNAT to a LAN host) on each uplink, including a non-active and a drained one | Replies leave through the arrival uplink | INV-5 |
| AS-10 | DHCP lease change of address and gateway on A | Artifacts updated within 1 s; event emitted; connections on B unaffected | INV-2 |
| AS-11 | PPP uplink reconnects with a new address and new ifindex (IPv4) | As AS-10; per-interface sysctls re-applied | INV-2 |
| AS-12 | IPv6 fails on A while IPv4 stays healthy | Only the IPv6 path of A is removed | — |
| AS-13 | All paths fail probes but stay ready, `ready` policy, groups 1 and 2 | Group 1 candidates active; recovery when probes pass | INV-4 |
| AS-14 | All uplinks lose carrier | New connections rejected at the router (ICMP unreachable subject to the kernel's rate limits); no packet leaves via a non-FTR route | INV-3 |
| AS-15 | Policy to A with `fallback = "block"` and another with `"balance"`; connections opened before the failure; A fails; new connections; A recovers | New block-policy connections rejected and new balance-policy connections on B while A is down; connections opened before the failure stay on A (and fail with A); connections opened on B stay on B after A recovers | INV-2 |
| AS-16 | Drain A; drain all; undrain; restart while drained | No new connections or policy connections on A; existing ones continue; draining the last candidate needs `force`; drain survives restart | INV-2, INV-5 |
| AS-17 | Third party deletes FTR rules, routes and the nftables table | Restored within 1 s (rules, routes) or at the next reconciliation (table); repeated deletion leads to `degraded` and later recovery; invariants hold again after restoration | INV-3 |
| AS-18 | `kill -9` while a long-lived connection runs on healthy B and A is probe-unhealthy | Connection on B uninterrupted; A stays out of the active set after restart; no duplicate artifacts | INV-2 |
| AS-19 | Reload adding, removing and reordering uplinks; reusing an id | Connections of unchanged uplinks unaffected; id reuse rejected without `forget-uplink` | INV-2 |
| AS-20 | Invalid configuration on reload | Running configuration kept; `reload_failed` event | — |
| AS-21 | Router-originated traffic: unbound, bound to A's address, replies to inbound connections to the router; bound to A's interface (TCP and UDP, Ethernet and point-to-point uplink) with A in and outside the active set and with A's path route withdrawn | Unbound balanced; bound to the address uses A; replies via arrival uplink; bound to the interface never leaves through another interface, behaves as §4.1.1 describes for each family | INV-4, INV-5 |
| AS-22 | Retransmitted SYNs without answer and one-way UDP flows while the active set changes | Every packet of each flow leaves through the same uplink | INV-2 |
| AS-23 | `external` firewall mode with the exported ruleset loaded by hand | Same results as AS-01, AS-03, AS-09 | — |
| AS-24 | Another ruleset sets mark bits outside `fwmark_mask` | Preserved end to end | INV-7 |
| AS-25 | Hook sleeping 60 s; SMTP server unreachable | Routing changes unaffected; hook process group killed at timeout; email retried | INV-8 |
| AS-26 | More-specific routes in main (static /24 via LAN, VPN /1 routes) | Matching traffic follows main; other traffic unaffected | INV-1 |
| AS-27 | Failure injected after each step of the add/remove orders (FR-REC-3) and of runtime updates, during active operation, with continuous traffic of every kind; separately, cleanup (FR-REC-4) step by step | Active operation: no packet reaches a non-FTR table except through the main bypass, and no packet of a pinned or inbound connection leaves through a wrong uplink. Cleanup: artifacts removed in the documented order, foreign objects untouched | INV-1, INV-2, INV-3, INV-5, INV-7 |
| AS-28 | Identical gateway `fe80::1` on two uplinks; RA expiry of the default router on A | Both paths usable independently; A not ready after expiry | INV-6 |
| AS-29 | Probes while A is not in the active set, drained, and while a main route covers a probe target | Probes leave through A | INV-6 |
| AS-30 | With the active set empty and no OS default route able to mask errors, each case separately: inbound DNAT traffic, connections to router listeners, ICMP and TCP probe replies, for both families; IPv4-only negative control: ICMP probe replies with the probe source's `from` rule removed | Positive cases accepted by routing and reverse-path filtering (administrator firewall permitting); negative control rejected by IPv4 reverse-path filtering | INV-5, INV-6 |
| AS-31 | RELATED ICMP errors and path MTU discovery through the PPPoE uplink (MTU 1492) and through a bottleneck inside a provider with a full-size MSS advertised by the server | ICMP errors delivered; large transfers succeed | INV-2 |
| AS-32 | Conntrack flush during a long-lived connection | Behaviour as documented (FR-CT-3); daemon unaffected | — |
| AS-33 | Startup with a colliding foreign rule in the priority range; flowtable on an uplink; networkd with foreign-rule management enabled | Startup refused with a precise message | INV-7 |
| AS-34 | The packaged, sandboxed systemd unit | All other scenarios pass under it | — |
| AS-35 | IPv6 over PPP with a link-local gateway: the path joins and leaves a multi-member active set (single → multiple → single) | Route installation succeeds at every step | INV-4 |
| AS-36 | IPv6 and IPv4 active-set updates under a continuous stream of new connections, including updates rejected before any mutation and partial failures; the IPv6 failure after the first insertion is simulated (the reconciler's netlink layer fails the update and removes the route, since the kernel failure needs an allocation failure) | Before the transition boundary new connections use the previous set; after it, only members of the target set; after the simulated IPv6 failure the empty table is detected by the re-read, new connections are rejected and nothing leaks, and the retry restores the target set; pinned connections unaffected; status `degraded` until complete (FR-ROUTE-2) | INV-2, INV-4 |
| AS-37 | Long-lived connection on uplink C; C removed by reload (nftables regenerated); traffic continues in both directions; also a router-originated connection bound to C's interface | Packets of the connection rejected by the path guard, never balanced; packets of the interface-bound connection never leave through another interface (IPv4 may send them on-link through C, §4.1.1) | INV-2, INV-3 |
| AS-38 | Restart after more than 10 minutes without transitions while A is down but ready, with `all_down_policy = "keep"`; reboot | Warm start keeps A down and restores the previous active set; after reboot, cold start | — |
| AS-39 | Quality gates with zero loss and unequal target RTTs; IPv6 with the three default targets | No artificial loss; gates evaluated | — |
| AS-40 | Foreign rule with priority below `rule_priority_base`; missing local rule | Warning listing the foreign rule; startup refused without the local rule | INV-6 |
| AS-41 | Downlink prefix missing from main; static off-subnet gateway with and without `gateway_onlink` | Warning; path ready only with `gateway_onlink` | INV-1 |
| AS-42 | Router service reply from a secondary address of A with an empty active set; connection bound to A's address while A is drained | Reply leaves through A; bound connection uses A | INV-5 |
| AS-43 | `fwmark_mask` at bit offsets 0, 16 and 24 | All other scenarios of M1 pass with each mask | INV-7 |
| AS-44 | Router boot with FTR enabled before any uplink is configured: no lease, no global address, no default route, empty active set; with systemd-networkd, NetworkManager (including DHCPv6 prefix delegation) and ISC dhclient or dhcpcd; PPPoE for both families; a DHCPv6 server with the server-unicast option at a global off-link address (Renew sent by unicast, IPv6 variant in M2) | DHCPv4 acquire/renew/rebind, DHCPv6 with prefix delegation, RS/RA, DAD, ND and PPPoE negotiation succeed, except off-link unicast renewals by clients that do not bind them, which fall back to rebinding (FR-CT-5) | — |
| AS-45 | IPv4-only configuration; reload removing the last IPv6 path of a dual-stack configuration while a pinned IPv4 connection runs | No IPv6 artifact installed; on removal, IPv6 handed back as in FR-REC-9 and the IPv4 connection uninterrupted | INV-2, INV-7 |
| AS-46 | Crash injected between drain persistence, route changes and API response | After restart the persisted drain intent is in force | — |
| AS-47 | Startup with: intact artifacts and an expired checkpoint; partial artifacts with live marks and a recent checkpoint; external mode with the administrator's ruleset preloaded, and without it | Adoption or repair as in FR-REC-8; pinned connections whose artifacts remained intact are uninterrupted; connections on damaged paths are routed correctly once repaired; `external_ruleset_missing` while the ruleset is absent | INV-2 |
| AS-48 | Forwarded connection matching a balance policy whose source address equals a router address with a `from` rule (constructed case), target path down; IPv6, and IPv4 with `accept_local = 1` on the downlink (otherwise the kernel drops the packet as a martian) | Connection balanced, not caught by the source rule or guard | INV-4 |
| AS-49 | IPv6 uplink whose Router Advertisement default route uses a single nexthop object (systemd-networkd 257 defaults); the object's gateway changes, then the object is deleted; separately, a default route using a nexthop group | Path ready through the resolved gateway; gateway change applied and object deletion makes the path not ready within the FR-DISC-5 bound; the group route is not used and a warning recommends a static gateway | INV-6 |
| AS-50 | Connection arriving on an interface FTR does not manage whose replies leave through an uplink; normal outbound connections and probes alongside | Replies of the unassigned connection are not assigned a path; outbound connections get their path in postrouting; probes never assigned (§4.7) | — |

### 14.4 Quality gates in CI

`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo deny check` (licenses and security advisories), the namespace integration suite on both environments of §14.1, and release builds for every target of PLAT-3.

## 15. Spikes before implementation

Short, throw-away experiments (network namespaces or disposable virtual machines) that MUST be completed, with results written down, before the corresponding code is written. Each spike runs on Linux 6.1 with nftables 1.0.6 and on the latest stable kernel.

- **S1** Routing core: the rule layout of FR-ROUTE-3 with guard rules, encoded marks and zero-field source selectors, including device-bound lookups (`SO_BINDTODEVICE`) with empty tables and with a competing main default; IPv4 and IPv6 inline multipath updates, including IPv6 intermediate states and failures (FR-ROUTE-2) and IPv6 point-to-point members with link-local gateways (single → multiple → single); layer-4 hashing distribution; pinning of marked connections across updates; the activation, retirement and cleanup orders of FR-REC-1, FR-REC-3 and FR-REC-4 with traffic checked at every intermediate state; the startup cases of FR-REC-8 (intact artifacts with an expired checkpoint, partial artifacts with a recent checkpoint, preloaded external ruleset); local source address selection for unbound router traffic over a multipath route, for both families, including the FR-DISC-6 configuration.
- **S2** Mark lifecycle: the chains of §4.7 with constant-only mark operations; preservation of foreign bits; retransmitted SYNs, one-way UDP, RELATED ICMP; output route chain rerouting; `rp_filter = 2` + `src_valid_mark = 1` behaviour of AS-30.
- **S3** Rust netlink: create, dump, replace and delete rules and multipath routes, and receive notifications, with `rtnetlink`/`netlink-packet-route`; identify missing features and decide between upstream contributions and a bounded local implementation.
- **S4** Coexistence and control plane: `suppress_prefixlength 0` with DHCP- and RA-installed default routes in main, with systemd-networkd and NetworkManager; effect of networkd's foreign-object management settings; every item of FR-CT-5 starting from no lease, no global address, no default route and an empty active set, with all guard rules installed.
- **S5** Probes with `SO_BINDTODEVICE` + `SO_MARK` + bound source from Rust, ICMP and TCP, both families, with reply validation.

All five spikes were completed on Linux 6.1.0-53 with nftables 1.0.6 and on Linux 7.1.13 with nftables 1.1.3 (S4 also on 6.12 virtual machines); scripts, results and findings are in `spikes/`. Their conclusions are incorporated in v0.6.

## 16. Distribution and repository

- **DIST-1** Release artifacts: static binaries for every PLAT-3 target, `.deb` packages (systemd unit, `fault-tolerant-router` group, example configuration, man page), SHA-256 checksums, signed with GitHub artifact attestations.
- **DIST-2** Crate and binary are named `fault-tolerant-router`; the Rust library identifier is `fault_tolerant_router`. Packages do not ship a short alias. The license is MIT; `LICENSE` is replaced on the `v2` branch, and the README states that 1.x was GPL-2.0.
- **DIST-3** Documentation in `docs/`: installation, configuration reference, how FTR works (the 1.x README explanation updated, with hash-based multipath instead of round-robin), recipes (Debian with systemd-networkd, NetworkManager, PPPoE, Starlink/5G CGNAT, port forwarding, IPv6 choices including `accept_ra = 2` for kernel SLAAC on a router, nftables reverse-path filtering), troubleshooting (including the renewal behaviour of DHCPv4 clients towards off-link servers, FR-CT-5, router services unavailable while the active set is empty, and traffic bound to an interface, §4.1.1), migration from 1.x.
- **DIST-4** Repository: the existing GitHub repository is kept. The last Ruby commit is tagged `v1-ruby-final` and preserved on branch `legacy/ruby`. 2.0 is developed on branch `v2` and merged into `main` at release. The README explains the transition and links to the legacy branch.
- **DIST-5** Open 1.x issues are triaged at release: those solved by 2.0 (#7, #8, #14, #15, #19, #22) are closed with a reference; out-of-scope ones (#4, #5) are closed with an explanation; support requests (#23, #24, #27) are closed as obsolete.
- **DIST-6** A final release of the Ruby gem MAY be published only to update its description with a pointer to 2.0.

## 17. Milestones

1. **M0 — Spikes and harness**: spikes S1–S5; namespace test harness on both CI environments.
2. **M1 — IPv4 core**: configuration, state directory, observer, prober, health, planner, reconciler, managed and external firewall modes, CLI `run`, `check-config`, `export-nft`, `cleanup`, `forget-uplink`. Scenarios (IPv4), in the variants that need no M3 feature (no drain, no policies): AS-01–05, 08–11, 13, 14, 17–24, 26, 27, 29–33, 36–38, 40–45, 47, 50.
3. **M2 — IPv6**: the same scenarios for IPv6, plus AS-12, AS-28, AS-35 and AS-49.
4. **M3 — Operations**: API and remaining CLI, drain, policies, events, email, hooks, metrics, quality gates. Scenarios: AS-06, 07, 15, 16, 25, 39, 46, 48, and the drain and policy variants of AS-09, AS-27, AS-29 and AS-42.
5. **M4 — Release**: packaging, documentation, migration guide, AS-34, repository transition, 2.0.0.

## 18. Decisions log

- **Q1 (name)** — Decided: `fault-tolerant-router` for crate and binary, no short alias shipped (DIST-2).
- **Q2 (license)** — Decided: MIT for 2.0; 1.x stays GPL-2.0 on `legacy/ruby`. 2.0 reuses no 1.x code, and the only external 1.x contribution is a 4-line change to a configuration template.
- **Q3 (IPv6 NAT default)** — Decided: no default; explicit choice required (FR-NAT-1).
- **Q4 (mask size)** — Decided: 8-bit field, 2-bit class + 6-bit id, up to 63 uplinks (FR-MARK-2).
- **Q5 (drain persistence)** — Decided: persisted (FR-SEL-3).
- **Q6 (automatic delegated prefix)** — Decided: out of scope; IPv6 prefix translation deferred entirely (§1.3).
- **Q7 (minimum kernel)** — Decided: Linux 6.1 and nftables 1.0.6 (Debian 12 baseline) instead of 5.15, to reduce the compatibility matrix for a release expected in 2027.
- **Q8 (nexthop objects)** — Decided: inline multipath routes in 2.0 (FR-ROUTE-2), with an operational (not atomic) update requirement for IPv6; FTR owns no nexthop objects (future work). Amended after S4: discovery resolves single, non-group nexthop objects (FR-DISC-3), because systemd-networkd uses them for Router Advertisement routes (observed with 257; option introduced in 256).
- **Q9 (termination)** — Decided: guard rules with action `unreachable` per mark class plus a final guard, instead of terminal routes in each table (FR-ROUTE-1). Consequence: while FTR is installed, default routes of the main table are never used for traffic that enters FTR's rule sequence, including router-originated traffic. Corrected after S1: the original rationale (route-level rejects are skipped by device-constrained lookups) applies equally to rule-level rejects for IPv4 (§4.1.1); guard rules are kept for class fallthrough and a single final guard.
- **Q10 (policy fallback)** — Decided: policy-balance tables fall through to the balancing rule instead of copying the balancing route (FR-ROUTE-1).
- **Q11 (drain and bound traffic)** — Decided: router-originated traffic explicitly bound to an uplink address is not affected by drain (FR-SEL-3).
- **Q12 (IPv6 next hop)** — Decided: every IPv6 path needs a gateway address, also on point-to-point links (FR-DISC-3). Confirmed experimentally: the kernel rejects device-only members in IPv6 multipath routes.
- **Q13 (managed families)** — Decided: FTR installs artifacts only for families enabled on at least one uplink, and hands a family back to the operating system when its last path is removed (§4.3).
- **Q14 (guarantee phases)** — Decided: invariants hold during active operation; installation, repair and cleanup have their own, weaker guarantees (§4.1).
- **Q15 (control plane)** — Decided: no pre-emptive exemptions from the guard rules for control traffic; spike S4 determines whether any are needed (FR-CT-5). Confirmed by S4: none is needed.
- **Q16 (IPv6 multipath update)** — Decided after S1: keep `NLM_F_REPLACE` and document the empty-table outcome of a failure after the first insertion (FR-ROUTE-2). Alternative considered: make-before-break with metrics 100 and 101 alternating (verified to work); rejected because it holds two routes during each update and its deletion step exposes subsets of the previous set rather than of the target set.
- **Q17 (traffic bound to an interface)** — Decided after S1 and S5: router-originated traffic bound to an interface is an explicit decision, treated like address binding and excluded from INV-3 and INV-4 (§4.1.1); the kernel leaves no alternative for IPv4.

## Appendix A. Revision history

- v0.1 (2026-10-03): initial draft.
- v0.7 (2026-10-03): fifth external review of v0.6 (verdict NO) and sixth review of the result (verdict YES, acceptable as the M1 contract; its one minor finding, the explicit DHCPv6 server-unicast variant of AS-44, is included): interface-bound traffic also qualifies INV-2 and is exempt from drain without a connectivity guarantee (§4.1.1, FR-SEL-3, AS-21, AS-37); the IPv6 multipath failure state propagated to the phases, INV-4 and AS-36 (simulated failure); nexthop observation contract and M2 validation (§1.3, FR-DISC-3, §12.2, IMPL-2, AS-49); FR-CT-5 renewal exception made normative and tested scope separated from outstanding coverage (AS-44); original-direction assignment marked as a design amendment (AS-50); source rule order in FR-REC-3; port id field in FR-COEX-3; narrower wording on IPv6-only rejections, systemd 256 and interrupted dumps.
- v0.6 (2026-10-03): results of the M0 spikes S1–S5: traffic bound to an interface (§4.1.1, INV-3, INV-4, FR-ROUTE-1, Q9, Q17); IPv6 multipath failure outcome (FR-ROUTE-2, Q16); kernel VRF rule (FR-ROUTE-6); `ignore_routes_with_linkdown` and `src_valid_mark` rationale (FR-SYS-2); `accept_ra` warning (FR-SYS-3); untracked and non-unicast skips, original-direction assignment, stop after a policy match (§4.7); control plane needs no guard exception (FR-CT-5, Q15); networkd rationale (FR-COEX-1); removal attribution (FR-COEX-3); single nexthop objects in discovery (FR-DISC-3, Q8); probe sockets and validation (FR-PROBE-1, 3, 4); conntrack priority advice (FR-FW-6); netlink stack and observer (IMPL-2, §12.2); identifier quoting (IMPL-3); source rule/guard order (FR-REC-1, 2, 4); dump normalisation (FR-REC-6); netlink extended acknowledgement (PLAT-1); rejection measured on egress (§14.3, AS-14), AS-31, AS-48.
- v0.5 (2026-10-03): fourth external review accepted v0.4 as the M0 contract; fixes: scoped family handoff (FR-REC-9), installation-phase wording for surviving marks, conditional continuity in AS-47, qualified Q9.
- v0.4 (2026-10-03): revision after the third external review: guarantees by lifecycle phase; transition-boundary semantics for multipath updates; warm adoption and startup classification; zero-field selector on source rules so that policy fallback always reaches balancing; separate local-address and source-candidate sets; restoration rules for all 63 path values; managed families; control-plane compatibility requirement; durable drain intent; conditional repair deadlines; per-instance event cursor; AS-44 to AS-48.
- v0.3 (2026-10-03): revision after the second external review: guard rules instead of terminal routes; encoded mark values; policy fallthrough instead of copied routes; operational IPv6 multipath update requirement; IPv6 paths require a gateway; explicit cold installation, uplink addition/removal and cleanup orders; scoped invariants; source rules for every usable address and drain exemption for bound traffic; health checkpoints and warm start by boot identifier; unbiased quality sampling; write-ahead manifest and structural validation on restart; NAT priority constraint; foreign earlier rules; `nhid` discovery excluded; nine new acceptance scenarios.
- v0.2 (2026-10-03): revision after the first external review: explicit invariants; mark classes and lifecycle; stable uplink ids; terminal unreachable routes; static rules with route-only runtime changes; probe precedence; active-set decision table; reconciliation and ownership model; conntrack and offload requirements; networkd/NetworkManager coexistence; reduced scope (no IPv6 prefix translation, no router-originated policies, no nexthop objects, root only); minimum kernel 6.1; expanded acceptance scenarios.
