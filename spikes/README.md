# Spikes

Experiments run before the code was written, to establish the kernel, nftables and Rust library behaviour that [SPEC.md](../SPEC.md) relies on (§15, "Experimental basis"). Requirements that rest on one of these observations cite it by identifier (S1–S5).

Each spike lives in its own directory with the scripts or crates that reproduce it and a `README.md` that records the environment, what was tested, the observed behaviour and the conclusions, including the changes to the specification they led to (by requirement identifier). The conclusions are incorporated in SPEC.md; the READMEs record the findings as they were observed, so a requirement may since have been refined. They were written before the project was renamed PolyWAN: "FTR", `fault-tolerant-router` and the scripts' `ftr` names are the names of that time.

| Spike | Directory | Question |
|---|---|---|
| S1 Routing core | `s1-routing-core/` | The rule layout with guard rules and encoded marks, device-bound lookups, IPv4 and IPv6 multipath updates and their failures, hashing, pinning, the installation and cleanup orders |
| S2 Mark lifecycle | `s2-mark-lifecycle/` | The nftables chains with constant-only mark operations, foreign bits, retransmissions, one-way UDP, RELATED ICMP, reverse-path filtering, non-unicast traffic, flowtables |
| S3 Rust netlink | `s3-netlink/` | Rules, multipath routes, notifications, errors and interrupted dumps with the Rust netlink crates |
| S4 Coexistence and control plane | `s4-control-plane/` | The main bypass with operating-system default routes, systemd-networkd and NetworkManager, DHCP, Router Advertisements and PPPoE with every guard rule installed |
| S5 Probes | `s5-probes/` | ICMP and TCP probes bound to an interface, a mark and a source, from safe Rust, with reply validation |

## Environments

Every spike ran on two environments:

| Environment | Distribution | Kernel | nftables | iproute2 |
|---|---|---|---|---|
| minimum | Debian 12 | 6.1.0-53 | 1.0.6 | 6.1.0 |
| latest | Debian 13 with trixie-backports | 7.1.13 | 1.1.3 | 6.15.0 |

S4 also used full virtual machines (Linux 6.12) for the parts that need a real service manager (systemd-networkd, NetworkManager) and real providers (DHCPv4, DHCPv6, RA, PPPoE).

## Running them

Scripts must run as root on a disposable Linux host. They create network namespaces whose names start with the spike identifier (for example `s1-router`) and remove them on exit; they never touch the host namespace unless their README says so. Rust crates are standalone (not part of the workspace), use edition 2024 and declare `#![forbid(unsafe_code)]`.

## Open points

What the spikes left open, none of it needed for 2.0:

- Upstream contributions to offer (S3): `netlink-proto` reply matching by port id, extended-ack parsing in `netlink-packet-core`, `rtnetlink` `RuleAddRequest::replace()` documentation.
- Relaxing FR-CT-2 for software flowtables (S2). First, on both environments and families, with full-interface and downlink-only flowtables, and with egress assertions instead of client timeouts:
  1. AS-37 with the FR-REC-3 intermediate states;
  2. gateway and source replacement, path withdrawal and re-creation, main-bypass routes;
  3. policies, drain and UDP (AS-15, AS-16, AS-22) with re-admission after invalidation;
  4. AS-30 and router traffic with fast-path hits, IPv6 mark-aware reverse-path filtering;
  5. bridge, VLAN and PPPoE setups, including the direct transmit mode that skips route validation.
