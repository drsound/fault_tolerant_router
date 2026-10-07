# S4 — Coexistence and control plane

Spike S4 of SPEC.md §15: FR-CT-5 (control-plane compatibility), FR-COEX-1 and FR-COEX-2 (systemd-networkd and NetworkManager), FR-SYS-3 (Router Advertisements), and the `suppress_prefixlength 0` main bypass (INV-1) with operating-system default routes in the main table.

## Result in one paragraph

With the complete FR-ROUTE-3 rule layout installed for both families, empty FTR tables (empty active set, no ready path) and the §4.7 marking table loaded, every control-plane function listed in FR-CT-5 worked from a cold state (no lease, no global address, no default route) on Linux 6.1, 6.12 and 7.1, with systemd-networkd 252 and 257, NetworkManager 1.52, ISC dhclient, dhcpcd 9 and 10, the kernel's own RA/SLAAC/DAD/ND/MLD, kea DHCPv6 with prefix delegation and pppd/rp-pppoe. Acquisition times are the same with and without the guards. **No exception to the guard rules is needed (Q15 confirmed).** The only control-plane traffic that does not get through is a unicast DHCPv4 renewal towards an off-link server (provider DHCP relay) whose route lookup is not bound to the leased address (ISC dhclient and dhcpcd; systemd-networkd and NetworkManager bind); it follows the balancing table like any unbound router-originated traffic, and the client keeps its lease through the broadcast rebind at T2. The spike also found four specification issues: systemd-networkd ≥ 256 installs RA default routes through nexthop objects unless `ManageForeignNextHops=no` (FR-DISC-3 ignores such routes), the kernel's VRF `l3mdev` rule sits at priority 1000 inside FTR's default rule range (FR-ROUTE-6), forwarding = 1 (FR-SYS-1) silently disables kernel RA processing on uplinks with the default `accept_ra = 1` (FR-SYS-3), and several expected kernel-side removals of FTR routes must not be counted as third-party removals (FR-COEX-3/4).

## Environments

| Environment | Kernel | nftables | Service manager / clients |
|---|---|---|---|
| Debian 12 (namespaces) | 6.1.0-53 | 1.0.6 | systemd-networkd 252.39 (isolated instance in a namespace), ISC dhclient 4.4.3-P1, dhcpcd 9.4.1, radvd 2.19, kea-dhcp6 2.2.0, pppd 2.4.9, rp-pppoe 4.0, dnsmasq 2.90 |
| Debian 13 + trixie-backports (namespaces) | 7.1.13 | 1.1.3 | systemd-networkd 257.13 (isolated instance), ISC dhclient 4.4.3-P1, dhcpcd 10.1.0, radvd 2.20, kea-dhcp6 2.6.3, pppd 2.5.2, rp-pppoe 4.0, dnsmasq 2.91 |
| Debian 13 virtual machines | 6.12.111 | 1.1.3 | router with systemd-networkd 257.13 managing its uplinks; a second router-like host with NetworkManager 1.52.1 managing its uplinks; pppd 2.5.2 |

Virtual-machine topology: a router with two Ethernet uplinks (provider A: DHCPv4 server and RA with the M and O flags plus kea DHCPv6 with prefix delegation of /60s; provider B: DHCPv4 behind CGNAT and RA), one PPPoE uplink (provider C, IPv4 only, rp-pppoe server, CHAP) and a LAN; an "internet" host behind the providers. The NetworkManager host is attached to the same two Ethernet provider segments. Management traffic of every host runs in a separate VRF, which turned out to matter (see FR-ROUTE-6 below).

Namespace topology (`control-plane-netns.sh`): `s4-rtr` (router under test) with uplinks `wana` (veth) and `wanc` (veth, PPPoE) and a dummy `lan`; `s4-ispa` (dnsmasq DHCPv4 server or relay, radvd with M and O flags, kea DHCPv6 with IA_NA and IA_PD, "internet" addresses on a dummy); `s4-dsrv` (off-link DHCPv4 server behind the relay); `s4-ispc` (rp-pppoe server).

## Files

| File | Purpose |
|---|---|
| `ftr-rules.sh` | Installs/removes the FR-ROUTE-3 layout (SPEC defaults: base 1000, tables 1000+, protocol 249, mask `0x00ff0000`); `sync` derives the dynamic part (path routes, `from` rules and source guards) from the kernel state as FTR would |
| `ftr-nft.sh` | Prints a minimal §4.7 marking table (restore for all 63 path values, inbound assignment, outgoing assignment in postrouting, probe class skip); no policies, no NAT |
| `watch-up.sh` | Measures when an uplink gets its IPv4 address, IPv4 default route, non-tentative global IPv6 address and IPv6 default route, and reports `IpOutNoRoutes`/`Ip6OutNoRoutes` (a packet rejected by a guard increments them) |
| `count-artifacts.sh` | Counts FTR-tagged rules and routes per family |
| `control-plane-netns.sh` | FR-CT-5 suite in namespaces: phases `ra dhclient4 dhcpcd4 dhcpcd6 dhclient6 relay pppoe expiry`, plus `relaybase` (dhclient rebind timing; `NOFTR=1` runs it without FTR artifacts) |
| `networkd-foreign.sh` | Effect of networkd's `ManageForeign*` settings on FTR artifacts on a host whose uplinks networkd manages |
| `networkd-netns.sh` | The same with a private systemd-networkd instance in a namespace (private D-Bus, read-only `/sys` so that it does not wait for udev, private `/etc` copy with a machine-id), to test the installed systemd version without touching the host |
| `nm-foreign.sh` | Effect of NetworkManager operations on FTR artifacts |
| `accept-ra.sh` | Kernel RA processing with forwarding = 1 and `accept_ra` 1 or 2 |

All scripts run as root on disposable hosts; the namespace scripts only create `s4-*` namespaces.

## FR-CT-5 results

### Namespaces, Linux 6.1 and 7.1 (`control-plane-netns.sh`)

Identical results on both kernels:

| Phase | What happened with the guards installed | Result |
|---|---|---|
| `ra` | Kernel RS, RA, SLAAC, DAD (4 NS from `::`), MLD reports (12), gateway neighbour resolution, ping from the SLAAC address through the path table, provider pinging the router's global address; no `Ip6OutNoRoutes` increment. RA default route after 1.5–2.1 s, DAD complete after 2.6–4.0 s | pass |
| `dhclient4` | ISC dhclient: acquisition in ~3 s, unicast renewal at T1 to the on-link server, broadcast rebinding at T2 after renewals were blocked at the provider | pass |
| `dhcpcd4` | dhcpcd: same | pass |
| `dhcpcd6` | dhcpcd: IA_NA + IA_PD from kea in 3–4 s, delegated /60 assigned to `lan`, Renew (multicast) at T1, Rebind at T2 after Renew messages were dropped at the provider | pass |
| `dhclient6` | ISC dhclient `-6 -N -P`: IA_NA + IA_PD, Renew, Rebind | pass |
| `relay` | Off-link DHCPv4 server behind a relay: see "Unicast renewal to an off-link DHCPv4 server" below | see below |
| `pppoe` | PPPoE discovery, LCP/IPCP without authentication in ~3 s, LCP echo every 2 s, pppd restarted: `ppp0` recreated with a new ifindex and a new address | pass |
| `expiry` | All DHCP requests dropped at the provider: lease expired and dhclient removed the address; after unblocking, INIT (broadcast) reacquired it in 5–6 s | pass |

### Virtual machines, Linux 6.12, systemd-networkd 257

Cold start: uplinks taken down (addresses, leases and default routes gone), FTR layout and marking table installed, uplinks brought up. Time to milestones (two runs each):

| | IPv4 address and default | IPv6 default route | IPv6 global address, DAD done |
|---|---|---|---|
| with guards and marking | 221–227 ms | 2.3–3.4 s | 4.2–5.0 s |
| without FTR artifacts | 220 ms | 2.3–2.9 s | 3.3–4.7 s |

The IPv6 numbers vary with the RS delay and DAD timers, not with the guards; no `IpOutNoRoutes`/`Ip6OutNoRoutes` increment was caused by networkd. Further checks, all passing with the guards installed:

- DHCPv4 (60 s leases): unicast renewal at T1 (`192.0.2.178.68 > 192.0.2.1.67`), broadcast rebinding from `0.0.0.0` at T2 when the provider dropped unicast requests, expiry with the server unreachable and reacquisition when it came back.
- DHCPv6 with prefix delegation (`DHCP=yes`, `PrefixDelegationHint=::/60`, `DHCPPrefixDelegation=yes` on the LAN): IA_NA /128 and a delegated /60 (LAN address from it), Renew to `ff02::1:2`, Rebind when Renew messages were dropped, expiry ("DHCPv6 lease lost") and reacquisition. networkd installs `unreachable <delegated prefix> proto dhcp` in main, which the main bypass applies to unassigned parts of the delegated prefix, as intended.
- RA: networkd processes RAs in user space (kernel `accept_ra = 0`), so forwarding = 1 does not affect it.
- PPPoE (pppd 2.5.2, CHAP): session up in ~220 ms, `from` rule ping through the path table, pppd restart recreated `ppp0` with a new ifindex (16 → 17) and a new address.
- A `fib:fib_table_lookup` trace showed networkd's DHCPv4 renewal using a socket bound to the leased address and to the uplink (`oif 3 … 192.0.2.178/68 -> 192.0.2.1/67`), resolved by the main table (connected route).

### NetworkManager 1.52.1, Linux 6.12

Cold activation with the guards and the marking table installed: IPv4 address and default route in 190 ms, IPv6 default route in 2.3 s, DHCPv6 /128 and SLAAC address in 3.7 s; DHCPv4 unicast renewal, DHCPv6 Renew and Rebind seen over 75 s. NetworkManager processes RAs in user space (`accept_ra = 0`) and installed plain (`via`) default routes, not nexthop objects.

### Why no exception is needed

Observed or established for each mechanism:

- DHCPv4 discovery, requests in INIT/REBOOT and rebinding are sent through packet sockets (the rebind broadcasts come from `0.0.0.0`; `ss -0` shows dhclient's `p_raw` socket on the uplink), which bypass IP routing entirely.
- DHCPv4 unicast renewals to an on-link server are covered by the uplink's connected route in main, hence by the main bypass (INV-1), before any guard.
- IPv6 control traffic to multicast destinations (RS, NS for DAD and address resolution, MLD, DHCPv6 Solicit/Renew/Rebind to `ff02::1:2`) is resolved by the `multicast ff00::/8 dev <uplink>` routes of the local table at priority 0; replies to link-local addresses are covered by `fe80::/64` in main (main bypass). Neighbour discovery and MLD messages generated by the kernel are not routed through the rules at all (the kernel's ndisc and MLD code allocate their destination entry on the device without a FIB rule lookup; stated from knowledge of the kernel, not traced in this spike, and consistent with the results).
- PPPoE discovery uses packet sockets and PPP control protocols (LCP, CHAP, IPCP) run on the PPP channel, not over IP; the peer route is a connected route in main.
- Address expiry, interface recreation and lease loss are kernel or client-internal events that need no packets.

### Unicast renewal to an off-link DHCPv4 server

Many providers run their DHCP servers behind relays: the server identifier is not on the uplink's subnet, so the renewal at T1 is a unicast packet that the main bypass does not cover and that falls into FTR's rules. Six cases were run on both kernels with a dnsmasq relay on the provider and an off-link dnsmasq server (2-minute leases, so T1 = 60 s and T2 = 105 s after the last acknowledgement):

| Client | FTR state | Unicast renewal at T1 | Lease |
|---|---|---|---|
| dhclient | no `from` rule, no path route, empty active set | rejected at the router (final guard; `IpOutNoRoutes` increments) | kept by the broadcast rebind at T2 |
| dhcpcd | same | rejected at the router (nothing sent) | kept by the rebind |
| dhcpcd | `from` rule and path route present, empty active set | rejected at the router: the lookup has no source address, so the `from` rule does not match | kept by the rebind |
| dhclient | same | rejected at the router, same reason | kept by the rebind |
| dhcpcd | as above plus a balancing route (non-empty active set) | sent through the balancing table and acknowledged by the server | kept |
| dhclient | same | sent through the balancing table and acknowledged | kept |

How each client sends its renewal (`ss`, and `fib:fib_table_lookup` traces that show the source address and output interface of each lookup):

| Client | Renewal socket | Matches the `from` rule |
|---|---|---|
| systemd-networkd 257 | bound to the leased address and the uplink (`oif 3 … 192.0.2.178/68 -> 192.0.2.1/67`) | yes |
| NetworkManager 1.52.1 (internal client) | UDP socket connected to the server, bound to `192.0.2.107%wana:68` (lookups with source and `oif`) | yes |
| ISC dhclient 4.4.3-P1 | unbound `0.0.0.0:68`, no device | no |
| dhcpcd 10.1.0 (traced) and 9.4.1 (same cycle results) | holds a socket bound to the leased address, but the renewal's route lookup has source `0.0.0.0` and no device (privilege-separated send path) | no |

Conclusions:

- A client that binds its renewal to the leased address (systemd-networkd, NetworkManager) matches the address's `from` rule and leaves through the path table, as soon as FTR has derived the `from` rule and the path route (FR-DISC-5: within one second of the address and gateway events), also with an empty active set. An on-link server works for every client through the main bypass.
- For ISC dhclient and dhcpcd, the renewal towards an off-link server is unbound router-originated traffic: rejected by the final guard when the active set is empty, balanced over the active set otherwise, possibly through another uplink, from which a server inside provider A's network is generally unreachable.
- In every case the lease survives through the broadcast rebind at T2 (packet socket): renewals fail, rebinding succeeds, and the only cost is that the lease is extended at T2 instead of T1. If the provider's relay does not answer broadcasts, the lease would expire; nothing of that kind was observed or is typical.
- With the 2-minute test leases, dhclient lost its lease in 2 of the 6 dhclient cycles of the final run: its first rebind broadcast went out after the 120 s expiry. The `relaybase` phase shows this is dhclient's retransmission schedule, not FTR: with renewals silently dropped at the provider and no FTR artifacts, the first rebind left 107–120 s after acquisition; with FTR rejecting the renewals locally, 106–121 s (three runs per kernel each; T2 is 105 s). With real lease durations the interval between T2 and expiry is an eighth of the lease (hours for a day-long lease), so the effect is limited to absurdly short leases.
- A guard exception is not justified: it would have to choose an uplink for an unbound packet, which only the payload (`ciaddr`) reveals. The documentation should describe the behaviour per client.

## suppress_prefixlength 0 with OS default routes in main

On the networkd router, with DHCP default routes on both Ethernet uplinks (metrics 100 and 200), RA default routes on both, the guards installed and an empty active set:

- router-originated `ip route get 198.18.100.1` and `2001:db8:100::1`: `Network is unreachable` (final guard), although main has default routes;
- `192.0.2.1`, `100.64.0.1` (connected) and `2001:db8:a:ffff::1` (RA on-link prefix): resolved by main through the main bypass;
- forwarded from the LAN: same, and the LAN client receives ICMP "no route" for the off-link IPv6 destination.

Default routes in main never satisfy a lookup that enters FTR's rule sequence, and non-default routes always do (INV-1, INV-3).

## systemd-networkd foreign-object management (FR-COEX-1)

Each operation was performed with the FTR layout and path routes installed; counts are FTR rules / FTR routes per family before and after.

| Operation | 257, defaults (VM) | 257, `ManageForeign…=no` (VM) | 252, defaults (namespace) | 252, `ManageForeign…=no` (namespace) |
|---|---|---|---|---|
| restart of systemd-networkd | **all FTR rules deleted (both families); FTR routes on managed links deleted** (routes on the unmanaged `ppp0` kept) | nothing deleted | IPv4 path route deleted (by the kernel, see below); rules kept | same as defaults |
| `networkctl reload` | nothing | nothing | nothing | nothing |
| `networkctl reconfigure wana` | **all FTR rules deleted**; `wana` path route deleted | `wana` IPv4 path route deleted by the kernel | **all FTR rules deleted**; path routes deleted by the kernel | path routes deleted by the kernel only |
| `networkctl renew`, `forcerenew` | nothing | nothing | nothing | nothing |
| link down/up | path routes deleted by the kernel | same | same | same |

`rules-only` (`ManageForeignRoutingPolicyRules=yes`, routes `no`) deleted rules but not routes; `routes-only` deleted routes but not rules: the two settings act independently. The systemd 257 isolated instance in a namespace reproduced the virtual-machine results for rules and routes, so the namespace method is valid for the 252 measurements.

"Deleted by the kernel" means the kernel removed an FTR route as a consequence of an address or link event (an IPv4 route is deleted when its preferred source address is deleted; IPv6 routes on a device are flushed when IPv6 is reset on it). Examples observed: `networkctl reconfigure` drops and re-adds the DHCPv4 address; systemd-networkd 252 drops and re-acquires the DHCPv4 address on restart, and so does 257 when started by hand in a namespace (but not when restarted by systemd on the virtual machine, presumably because the service keeps its state across the restart) (`ip monitor` shows the address deletion before the route deletion); NetworkManager's reapply of a changed profile resets IPv6 on the device.

Documentation cross-check: the systemd 252 and 257 manual pages (`networkd.conf(5)`, read from the installed systems and from the 257.13 source) both say that `ManageForeignRoutingPolicyRules=` and `ManageForeignRoutes=` default to yes and remove rules/routes "not configured in .network files", except rules with protocol `kernel`, and routes with protocol `kernel` (plus `dhcp`/`static` depending on `KeepConfiguration=`). `ManageForeignNextHops=` exists since systemd 256 (documented as "v256") and also defaults to yes. Context7 had no entry for `networkd.conf`; these claims are from the manual pages shipped with each version and agree with the experiments. The documentation does not say when the removal happens; the experiments show restart (257) and any link reconfiguration (252 and 257).

### systemd-networkd ≥ 256 and nexthop objects (affects FR-DISC-3)

With `ManageForeignNextHops=yes` (the default), systemd-networkd 257 installs the RA default route through a nexthop object:

```
default nhid 214704473 via fe80::4c4d:e7ff:feca:434e dev wana proto ra metric 1024 expires 1799sec pref medium
id 214704473 via fe80::4c4d:e7ff:feca:434e dev wana scope link proto ra
```

Observed on the 7.1 namespace instance with default settings and on the 6.12 router as soon as `ManageForeignNextHops=no` was removed from its configuration; with `ManageForeignNextHops=no` the routes are plain `via` routes. The 257.13 source (`src/network/networkd-ndisc.c`, `ndisc_set_route_nexthop()`) uses a nexthop object for an RA gateway only when `manage_foreign_nexthops` is true. systemd 252 has no such code and installs plain routes. DHCPv4 default routes are plain in all versions tested. NetworkManager 1.52.1 installs plain routes.

FR-DISC-3 excludes routes that reference nexthop objects, so on a stock Debian 13 (or any distribution with systemd ≥ 256/257) using systemd-networkd's RA client, every IPv6 path with `gateway = "auto"` would be not ready. FR-COEX-1 does not currently check `ManageForeignNextHops`.

### Compatibility matrix (for the documentation)

| systemd | `ManageForeignRoutingPolicyRules` | `ManageForeignRoutes` | `ManageForeignNextHops` | Required configuration |
|---|---|---|---|---|
| 246–248 | not available | default yes | not available | `ManageForeignRoutes=no`; foreign-rule behaviour not verified |
| 249–255 (Debian 12: 252) | default yes; deletes FTR rules on link reconfiguration | default yes; deletes FTR routes | not available | both `=no` |
| ≥ 256 (Debian 13: 257) | default yes; deletes FTR rules on restart and link reconfiguration | default yes; deletes FTR routes on restart | default yes; RA default routes become nexthop objects | all three `=no` (or FTR resolves nexthop objects, see amendments) |

The 246–248 row comes from the systemd NEWS file (`ManageForeignRoutes=` added in 246, `ManageForeignRoutingPolicyRules=` in 249) and was not tested; versions before 246 are older than any distribution meeting PLAT-1 and were not considered.

## NetworkManager (FR-COEX-2)

| Operation (1.52.1) | Effect on FTR rules | Effect on FTR routes |
|---|---|---|
| restart of NetworkManager, `nmcli general reload`, `nmcli connection reload`, `nmcli device reapply` (unchanged profile) | none | none |
| `nmcli connection up` of an active profile, `down` + `up`, link down/up | none | path route deleted by the kernel (address removed and re-added) |
| 40 s of DHCPv4/DHCPv6 renewals | none | none |
| reapply of a changed profile | none | IPv6 path route deleted by the kernel (IPv6 reset on the device) |
| profile with `ipv4.routing-rules` added and removed | none (only its own rule was removed) | none |
| profile with `ipv4.route-table 1001` (an FTR table) | none | NetworkManager added its own DHCP default and subnet routes into table 1001 next to FTR's route: a collision |

This agrees with the NetworkManager documentation (via Context7, `nm-settings-nmcli`/`nm-settings-dbus`): with `route-table` 0 (the default), NetworkManager adds routes to main and "avoids deleting extraneous routes" in other tables; an explicitly set table is synchronised. Guidance for the documentation: never use FTR's tables as `ipv4.route-table`/`ipv6.route-table` or in `ipv4.routing-rules`/`ipv6.routing-rules`, and leave the global `ipv4.route-table`/`ipv6.route-table` defaults of `NetworkManager.conf` unset or outside FTR's range. No NetworkManager setting needs to be refused at startup; FR-ROUTE-6's collision check catches a profile that writes into FTR's tables.

## FR-SYS-3 (Router Advertisements)

`accept-ra.sh`, both kernels, forwarding = 1:

| `accept_ra` | SLAAC address | RA default route |
|---|---|---|
| 1 (kernel default) | none | none |
| 2 | yes | yes |

FR-SYS-1 sets `net.ipv6.conf.all.forwarding = 1`, which propagates to every interface; from then on the kernel ignores RAs on interfaces with `accept_ra = 1`. A setup that relies on kernel SLAAC (for example ifupdown `inet6 auto`, or a bare kernel) loses its IPv6 default route as soon as FTR starts, while systemd-networkd and NetworkManager are unaffected (user-space RA clients, `accept_ra = 0`). FR-SYS-3 rightly forbids FTR from changing `accept_ra`, but its 30 s warning only fires after the damage; the cause is predictable at startup.

RA default routes appeared 1.5–5.3 s after the link came up (kernel, networkd and NetworkManager): the 30 s threshold of FR-SYS-3 is comfortable.

## Other observations

- The kernel installs the VRF rule `1000: from all lookup [l3mdev-table] proto kernel` for both families when the first VRF device is created (management VRFs are common on routers, and every virtual machine of this test used one). It is inside FTR's default rule range (1000–1699) and is not tagged with `route_protocol`, so FR-ROUTE-6 as written makes FTR refuse to start on any host with a VRF. The rule is harmless to FTR: it matches only traffic of VRF-enslaved devices, and FTR uses priorities from B + 1. Management traffic in the VRF kept working throughout every test with FTR's guards installed.
- With an empty active set, router services that are not bound to an uplink address (systemd-resolved, NTP, package updates) fail with "network unreachable" even though main has default routes. This is the intended consequence of Q9 and FR-ROUTE-4, but administrators will notice it during uplink outages; the documentation should say so.
- FTR routes are deleted by the kernel, not by a third party, in all the cases listed under "Deleted by the kernel" above. They are reported by netlink exactly like a third-party deletion. The Observer must attribute them to the preceding address/link notification, or FR-COEX-4 would see an "ownership conflict" during ordinary DHCP or NetworkManager operations.

## Proposed SPEC amendments

1. **FR-CT-5**: record S4's outcome: no guard exception is needed. Add the documented exception to "FTR MUST NOT prevent…": unicast DHCPv4 renewals whose route lookup is not bound to the leased address (observed with ISC dhclient and dhcpcd) are unbound router-originated traffic (FR-ROUTE-3, INV-4); towards an off-link server they are rejected (empty active set) or balanced, and the lease is kept by rebinding at T2. Clients that bind to the leased address depend on FTR's `from` rule and path route, which FR-DISC-5 provides within one second.
2. **FR-DISC-3**: accept default routes that reference a single, non-group nexthop object (`nhid`) whose nexthop has a gateway and uses the uplink interface, by resolving the object (RTM_GETNEXTHOP); keep ignoring nexthop groups. systemd-networkd ≥ 256 uses such routes for RA gateways by default. Update the decisions log (Q8) accordingly: FTR still installs no nexthop objects of its own.
3. **FR-COEX-1**: also read `ManageForeignNextHops=` (systemd ≥ 256). If FR-DISC-3 is amended as above, `ManageForeignNextHops=yes` needs no warning (FTR owns no nexthop objects); otherwise FTR MUST refuse to start or warn for IPv6 uplinks with `gateway = "auto"`. State in the requirement that, with `ManageForeignRoutingPolicyRules=yes`, networkd deletes FTR's rules on restart (257) and on every link reconfiguration (252 and 257), which justifies refusing to start. Add the compatibility matrix above to the documentation.
4. **FR-ROUTE-6**: exclude from the collision check the kernel's `l3mdev` rule (action `l3mdev`, protocol `kernel`) at any priority inside the range, list it in the startup/check-config warning of foreign rules, or move the default `rule_priority_base` away from 1000. Excluding the `l3mdev` rule is preferable: it is kernel-owned, matches only VRF traffic, and its priority 1000 is also the kernel default that other tools avoid.
5. **FR-SYS-3**: when `manage_sysctls = true` (or IPv6 forwarding is already 1), startup and `check-config` MUST warn for each IPv6 path with `gateway = "auto"` whose uplink has `accept_ra = 1`, explaining that forwarding disables kernel RA processing and that `accept_ra = 2` (or a user-space RA client) is required. `accept_ra = 0` is normal with systemd-networkd and NetworkManager and needs no warning by itself (the existing 30 s warning still covers "no RA at all").
6. **FR-COEX-3 / FR-COEX-4**: list the kernel-induced removals explicitly (routes whose preferred source is deleted, routes of a device whose IPv6 is reset or that goes down, routes using a deleted nexthop) and require that they be attributed to the triggering notification and handled by the planner, never counted towards the ownership-conflict threshold.
7. **Documentation (DIST-3)**: renewal behaviour of DHCPv4 clients towards off-link servers (systemd-networkd and NetworkManager renew through the path; dhclient and dhcpcd fall back to rebinding); router services unavailable while the active set is empty; NetworkManager guidance of FR-COEX-2 as above; `accept_ra = 2` for kernel SLAAC on a router.

## Open points

- Intermediate systemd versions (253–256) were not run; the matrix rows rely on NEWS and on the 257 source. Whether 256 already uses nexthop objects for RA routes is inferred from the option's introduction, not tested.
- NetworkManager with DHCPv6 prefix delegation (`ipv6.method shared` on the LAN) and NetworkManager's IPv6 "dhcp"-only mode were not tested.
- PPPoE with IPv6 (IPv6CP plus RA over PPP) was not tested here; the lab provider for PPPoE is IPv4-only. AS-35 needs it.
- DHCPv6 with the server-unicast option (Renew sent to a global server address) was not tested; kea does not send it by default and RFC 8415bis deprecates it.
