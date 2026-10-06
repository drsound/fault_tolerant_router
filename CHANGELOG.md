# Changelog

The notable changes of every PolyWAN release. Versions follow [Semantic Versioning](https://semver.org/): within a major version, the configuration, the command line, the `/v1` API and the metric names stay compatible. Fault Tolerant Router 1.x, the Ruby daemon, has no entries here; it is preserved on the `legacy/ruby` branch.

## 2.0.0 (unreleased)

PolyWAN 2.0 is a ground-up rewrite in Rust of Fault Tolerant Router, under a new name. It keeps the idea of 1.x, new connections spread over the healthy uplinks with the kernel's multipath routing and every connection kept on the uplink it started on, and brings it up to date with the Linux networking of 2026. The contract it is built and tested against is `SPEC.md` in the source tree.

### What it does

- Balances new outgoing connections across the healthy uplinks of the best priority group, by weight, with hash-based multipath routing; keeps every connection on its uplink with connection marks and policy routing, and answers inbound connections through the uplink they arrived on.
- Treats IPv4 and IPv6 as independent: an uplink can be healthy for one family and failed for the other. IPv6 with masquerade, source NAT to a static address, or no NAT.
- Works with static, DHCP, SLAAC and PPP uplinks without per-type configuration: it observes through netlink what systemd-networkd, NetworkManager, ifupdown or pppd configure, and coexists with the operating system's own default routes.
- Probes every uplink through its own interface (ICMP echo or TCP handshakes) with configurable thresholds, and optional quality gates on loss, latency and jitter.
- Marks packets and applies optional source NAT in an nftables table it owns and replaces atomically, or, in external mode, in a ruleset the administrator loads (`polywan export-nft`); it never adds filtering verdicts.
- Policies that route selected traffic through a chosen uplink; drain and undrain of an uplink.
- A status API on Unix sockets (a read-only status socket and a control socket for the `polywan` group), the commands `status`, `events`, `drain`, `undrain`, `reload`, `notify-test`, `cleanup` and `forget-uplink`, Prometheus metrics, event hooks, and email through the system's sendmail interface (msmtp is the documented configuration).
- A sandboxed systemd unit with readiness notification, synchronous `systemctl reload` and exit status 78 for a configuration that refuses startup.
- Static binaries for x86_64, aarch64 and armv7 (musl), and Debian packages for amd64, arm64 and armhf with the unit, the `polywan` group, a man page, shell completions and a commented example configuration (also printed by `polywan generate-config`).

### Coming from 1.x

- The configuration is TOML at `/etc/polywan/config.toml`, written anew from the example: 1.x YAML is not read, and there is no migration guide.
- iptables rules integrated by hand and a main table without default routes are no longer needed.
- Names, paths, the nftables table, the API group, environment variables and metrics are all `polywan`; no alias with the old name is installed.
- The license is MIT OR Apache-2.0; 1.x was GPL-2.0.
- The `fault_tolerant_router` Ruby gem is not developed any more.

### Upgrades and downgrades

- An upgrade within 2.x keeps the routing in place: the default `routing.on_shutdown = "keep"` leaves the artifacts installed while the daemon restarts, and the package restarts only a running daemon.
- The state files (`/var/lib/polywan`) carry a format version. A daemon that finds a manifest or a drain state of a version it does not know refuses to start (exit status 1), so a downgrade to an older release that does not know the newer format needs `polywan cleanup` with the newer release first, then the older release, which starts from an empty state. `polywan run --reset-state` discards such files instead, at the cost of the recorded sysctl baseline.
- Changing a structural setting (`fwmark_mask`, `table_base`, `rule_priority_base`, `route_protocol`, `firewall.mode`) or an uplink's identity needs `polywan cleanup` and a restart, as the refused startup explains.
