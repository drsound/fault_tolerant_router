# M0 spikes

Throw-away experiments required by SPEC.md §15 before the corresponding code is written. Each spike lives in its own directory with the scripts or crates that reproduce it and a `README.md` that records the environment, what was tested, the observed behaviour and the resulting conclusions or proposed amendments to SPEC.md (by requirement identifier).

Every spike runs on two environments:

| Environment | Distribution | Kernel | nftables | iproute2 |
|---|---|---|---|---|
| minimum | Debian 12 | 6.1.0-53 | 1.0.6 | 6.1.0 |
| latest | Debian 13 with trixie-backports | 7.1.13 | 1.1.3 | 6.15.0 |

S4 additionally uses full virtual machines for the parts that need a real service manager (systemd-networkd, NetworkManager) and real providers (DHCPv4, DHCPv6, RA, PPPoE).

Scripts must run as root on a disposable Linux host. They create network namespaces whose names start with the spike identifier (for example `s1-router`) and remove them on exit; they never touch the host namespace unless their README says so. Rust crates are standalone (not part of a workspace), use edition 2024 and declare `#![forbid(unsafe_code)]` (IMPL-1).

| Spike | Directory | Status |
|---|---|---|
| S1 Routing core | `s1-routing-core/` | done |
| S2 Mark lifecycle | `s2-mark-lifecycle/` | done |
| S3 Rust netlink | `s3-netlink/` | done |
| S4 Coexistence and control plane | `s4-control-plane/` | done |
| S5 Probes | `s5-probes/` | done |

## Open points carried into M1–M3

Spike findings that remain to be covered, with the milestone where they belong. SPEC.md v0.7 already assigns the acceptance scenarios.

| Point | Source | Where |
|---|---|---|
| IPv6 over PPPoE (IPv6CP, RA over PPP, link-local gateway); the test provider for PPPoE is IPv4-only and needs IPv6 | S4 | M2, AS-35, AS-44 |
| NetworkManager with DHCPv6 prefix delegation | S4 | M2, AS-44 |
| DHCPv6 server-unicast Renew to a global off-link server | S4 | M2, AS-44 |
| systemd 253–256 not tested; compatibility matrix rows for them come from NEWS and the 257 source | S4 | M4 documentation (FR-COEX-1 matrix) |
| Resolution of single nexthop objects and nexthop notifications; `netlink-packet-route` nexthop messages not yet validated | S3, S4 | M2, AS-49 |
| Postrouting assignment only in the original direction (design amendment, not tested) | S2 | M1, AS-50 |
| Simulated IPv6 multipath failure after the first insertion (kernel failure needs an allocation failure) | S1 | M1 (IPv4 part), M2, AS-36 |
| Rejection checks by egress counters; ICMP errors of `unreachable` rules are rate-limited by host-wide sysctls (`net.ipv4.route.error_cost`, `error_burst`) that a namespace cannot change | S2, harness | M1, every rejection scenario (AS-14, AS-15, AS-16, AS-27) |
| IPv6 client misses the first ICMPv6 error of a rejected connection (cause not established; lock-drop counter suggests the IPv4 cause) | S2 | M2 |
| Multicast and broadcast skip (`meta pkttype`) exercised only indirectly | S2 | M1 |
| Flowtable bypass behind FR-CT-2 known from documentation only | S2 | M1, AS-33 |
| Whether interrupted route or rule dumps can silently skip entries (the design relies on reconciliation either way) | S3 | M1, observer tests |
| Upstream contributions to offer, none blocking: `netlink-proto` reply matching by port id, extended-ack parsing in `netlink-packet-core`, `rtnetlink` `RuleAddRequest::replace()` documentation | S3 | any time |
| Probe result tagging by path generation and cancellation (FR-PROBE-3); quality gates (FR-PROBE-5) barely exercised | S5 | M1 (generations), M3 (quality gates, AS-06, AS-39) |
| IPv6 leak detection in the harness: no route realms for IPv6, so leaks are detected with egress counters and route lookups only | harness | M2 |
| Harness scaffolding `route_lan_via` (rule priority 90, table 90) to remove once the daemon routes the LAN | harness | M1 |
| Root `Cargo.toml` workspace to extend with the daemon crate | harness | M1 |
| `LICENSE` is still the GPL-2.0 text of 1.x while the workspace declares MIT (DIST-2 replaces it on `v2`) | review of the repository | M1 or earlier |
| nftables 1.1.3 is the newest version tested (latest available in Debian backports), not the newest upstream release | environments | M1 CI (the runner's nftables) |
