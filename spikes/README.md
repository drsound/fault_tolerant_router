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
| Simulated IPv6 multipath failure after the first insertion (kernel failure needs an allocation failure) | S1 | M1 (IPv4 part), M2, AS-36 |
| Rejection checks by egress counters; ICMP errors of `unreachable` rules are rate-limited by host-wide sysctls (`net.ipv4.route.error_cost`, `error_burst`) that a namespace cannot change | S2, harness | M1, every rejection scenario (AS-14, AS-15, AS-16, AS-27) |
| IPv6 client misses the first ICMPv6 error of a rejected connection (cause not established; lock-drop counter suggests the IPv4 cause) | S2 | M2 |
| Upstream contributions to offer, none blocking: `netlink-proto` reply matching by port id, extended-ack parsing in `netlink-packet-core`, `rtnetlink` `RuleAddRequest::replace()` documentation | S3 | any time |
| IPv6 leak detection in the harness: no route realms for IPv6, so leaks are detected with egress counters and route lookups only | harness | M2 |
| Software flowtables: S2 (t10) found that they keep pinning but leave offloaded packets without FTR's packet mark, and that a flowtable listing only downlinks also offloads one direction of uplink traffic; FR-CT-2 (refusal for uplinks) needs a decision | S2 | M1, AS-33 |
| Deterministic observer tests for interrupted dumps (forced small batches, a change injected after the first batch), as proposed by S3 `dumpskip` | S3 | M1 |
| Quality gates (FR-PROBE-5) barely exercised | S5 | M3, AS-06, AS-39 |
| Harness scaffolding `route_lan_via` (rule priority 90, table 90) to remove once the daemon routes the LAN | harness | M1 |

## Resolved at the start of M1

- Postrouting assignment only in the original direction (AS-50): verified by S2 `t8` on both environments; without the condition, replies of connections arriving on unmanaged interfaces are pinned to the uplink they leave through and die with it.
- Multicast and broadcast skips: exercised directly by S2 `t9`; non-unicast traffic arriving through tunnels has packet type `host` and subnet-directed broadcasts reach postrouting, so the generator now also skips them by destination address.
- Interrupted dumps: S3 `dumpskip` shows that rule and route dumps can omit or repeat entries without `NLM_F_DUMP_INTR` on both kernels; the observer merges by identity and confirms absences before acting on them, and the reconciler treats `EEXIST`, `ENOENT` and `ESRCH` as the wanted state.
- Probe results are tagged with the path generation; the daemon discards rounds of older generations and aborts a prober as soon as its path changes or stops being ready.
- The root workspace contains the daemon crate `crates/fault-tolerant-router`; `LICENSE` is the MIT text.
- The current-environment CI job builds the newest upstream nftables (1.1.7, `tests/ci/build-nftables.sh`); the generated ruleset also loads with 1.0.6 and 1.1.3.
