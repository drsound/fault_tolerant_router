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
| S2 Mark lifecycle | `s2-mark-lifecycle/` | in progress |
| S3 Rust netlink | `s3-netlink/` | done |
| S4 Coexistence and control plane | `s4-control-plane/` | in progress |
| S5 Probes | `s5-probes/` | done |
