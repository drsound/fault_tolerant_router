# testbed

Network namespace test harness for PolyWAN 2.0 (SPEC.md §14.1–14.2). It builds the reference topology out of network namespaces and veth pairs, gives the router under test real providers (DHCPv4, DHCPv6, Router Advertisements, CGNAT, PPPoE), and offers the helpers that acceptance tests need: commands inside namespaces, failure injection, traffic with per-connection uplink attribution, and leak detection.

## Topology

```text
                        inet (probe targets, test servers)
                 isp-a /        | isp-b         \ isp-c
               ispa            ispb              ispc
    DHCPv4/v6 + RA |   CGNAT + RA |       PPPoE    |
               wana            wanb              wanc (ppp0)
                   \            |               /
                            router  (under test)
                               | lan
                             client
```

Each node is a namespace named `tb-<run>-<node>` (`inet`, `ispa`, `ispb`, `ispc`, `router`, `client`), where `<run>` is a random run identifier, so that several runs can share a host. The address plan uses only the prefixes listed in §14.2 and is documented in `src/plan.rs`:

- the internet node hosts the default probe targets (1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222, 2606:4700:4700::1111, 2001:4860:4860::8888, 2620:fe::fe) on a dummy interface, and answers on every address of 198.18.100.0/24 and 2001:db8:ff00::/64 (local routes), so tests can use hundreds of distinct destinations;
- provider A serves 192.0.2.0/24 by DHCPv4 and 2001:db8:a:ffff::/64 by SLAAC (dnsmasq); its stateful DHCPv6 service is available to scenarios that run a DHCPv6 client, the default router configuration uses SLAAC only;
- provider B serves 100.64.0.0/24 by DHCPv4, translated to 198.18.0.6 (CGNAT), and 2001:db8:b:ffff::/64 by SLAAC; scenarios that need DHCPv6 with prefix delegation start a kea server there (`Topology::start_dhcpv6_server`, `src/dhcpv6.rs`) that leases addresses of 2001:db8:b:ffff::1000–1fff and /60 prefixes of 2001:db8:b:100::/56, and announces the server-unicast option at 2001:db8:b:fffe::1, outside the uplink's on-link prefix;
- provider C runs a PPPoE server (IPv4 only, MTU 1492) giving 203.0.113.10–19;
- the LAN is 198.51.100.0/24 and 2001:db8:1::/64.

The router gets its uplink configuration the way an operating system would: `udhcpc` for DHCPv4 leases, kernel SLAAC (`accept_ra = 2`) for IPv6, `pppd` for PPPoE. Its main table therefore holds operating-system default routes for every uplink (metrics 100, 200 and 300), as the acceptance scenarios require so that leaks are observable.

## Helpers

- `Topology::build(Options)`, `Topology::ns(Node)`, `Ns::run/ip/sh/nft/sysctl/spawn`: build the topology and run commands in any node. Dropping the `Topology` kills every process of the run, deletes its namespaces and removes its working directory (`/tmp/polywan-testbed/<run>`).
- Failure injection (`src/inject.rs`): carrier loss (`carrier_down`), router interface down (`router_link`), provider disconnected upstream with the link up (`upstream_down`), deterministic nftables drop patterns in a provider (`drop_probe_echoes(uplink, 3)` drops every third echo request towards the probe targets; `provider_rules` for anything else), `tc netem` (`netem`), PPPoE session reset with a new `ppp0` ifindex (`pppoe_reset`), DHCP renewal (`dhcp_renew`).
- Traffic (`src/traffic.rs`): `connect_many` opens N TCP or UDP connections with distinct 5-tuples from a node to up to 254 destinations and reports, for each, the outcome (`ok`, `unreachable`, `refused`, `timeout`) and the source address seen by the server, from which `ConnResult::uplink` attributes the egress uplink; `start_flow` runs a long-lived TCP flow and reports its longest stall (`FlowReport::continuous`); `udp_send` sends a one-way UDP flow from a fixed source port, attributed through the server log (`server_events`); `ping` distinguishes reply, ICMP unreachable and timeout.
- Leak detection: every operating-system default route of the router carries realm 99, and the harness table `ip tb_observe` counts IPv4 packets routed by such a route (`ipv4_leaks`); any non-zero count while PolyWAN is installed violates INV-3. IPv6 routes have no realm, so for IPv6 the harness offers per-uplink egress counters (`egress_packets`, table `inet tb_egress`) for scenarios where no packet may leave, plus route lookups with `ip -6 route get`.
- The daemon under test runs in the router namespace with `start_daemon(binary, args, env)`; the binary path is a parameter.
- `testbed::polywan` runs the daemon under test (`POLYWAN_DAEMON_BIN`) for the acceptance scenarios (`tests/m1.rs`): configuration and state under `/run/polywan-tests/<run>`, start, reload, stop, kill, CLI commands, its log. `Polywan::set_env` passes environment variables to the daemon's test hooks, compiled with the `test-hooks` feature that `run-suite.sh` enables: `POLYWAN_TEST_BOOTTIME_SHIFT_MS` (boot-time clock moved forward), `POLYWAN_TEST_GATEWAY_WARNING_MS` (delay of the FR-SYS-3 warning about an IPv6 path without a discovered gateway, 30 s otherwise) and `POLYWAN_TEST_FAULTS` (a control file holding n lets the next n reconciler or cleanup steps succeed and fails the following ones until it is removed).
- `Topology::start_dhcpv6_client` runs the router's DHCPv6 client on B (dhcpcd in manager mode, which alone honours the server-unicast option, or ISC dhclient where dhcpcd is not installed; `POLYWAN_TEST_DHCPV6_CLIENT` chooses), asking for an address and a prefix whose first /64 goes to the LAN. dhcpcd gets private `/run/dhcpcd` and `/var/lib/dhcpcd` in the mount namespace of `ip netns exec`; kea-dhcp6 and dhclient run as copies outside their AppArmor profiles.
- `Options::uplink_clients = false` builds the topology without starting `udhcpc` and `pppd`; `Topology::start_uplink_clients` starts them later. `Topology::netns_etc(node)` is the node's `/etc/netns/<namespace>` directory, whose entries `ip netns exec` mounts over `/etc`.
- The harness's own checks (`tests/netns.rs`) run without the daemon: they steer LAN traffic through one uplink with a rule and a table outside PolyWAN's default ranges (priority 90, table 90) and masquerade it.

## Running

Requirements: Linux, root, iproute2, nftables, dnsmasq (`dnsmasq-base`), `udhcpc`, `ppp`, `pppoe` (rp-pppoe), `kea-dhcp6` (`kea-dhcp6-server`, its service disabled), dhcpcd or ISC dhclient, iputils `ping`, `tc`, the `veth`, `dummy`, `pppoe`, `sch_netem` and nftables NAT kernel modules; `jq` and `musl-tools` for `tests/vm/run-suite.sh`.

Unit tests need nothing special: `cargo test`. The namespace tests are marked `#[ignore]` and need root:

```sh
tests/vm/run-suite.sh --host            # this host's kernel and nftables (uses sudo)
sudo tests/vm/build-rootfs.sh /var/tmp/rootfs-bookworm
tests/vm/run-suite.sh --vm /var/tmp/rootfs-bookworm   # Linux 6.1 + nftables 1.0.6 in virtme-ng
```

`run-suite.sh` builds the test binaries as static musl executables, so the same binaries run on the host and inside the Debian 12 guest; arguments after `--` go to the test binary (for example a test name filter). The VM mode needs `virtme-ng` (validated with 1.35), `qemu-system-x86`, `busybox-static` and KVM.

Manual use:

```sh
cargo build -p testbed
sudo target/debug/polywan-testbed up            # prints the run identifier
sudo target/debug/polywan-testbed exec RUN router ip route
sudo target/debug/polywan-testbed exec RUN client ping 198.18.100.1
sudo target/debug/polywan-testbed down RUN      # or: down --all
```

Environment variables: `POLYWAN_TESTBED_BIN` (path of `polywan-testbed`, used to run the test agents inside namespaces), `POLYWAN_TESTBED_DIR` (root of the working directories, default `/tmp/polywan-testbed`), `POLYWAN_TESTBED_KEEP=1` (keep the namespaces of a failed test for inspection).

## Environment notes

- ICMP errors for packets rejected by routing rules (`unreachable` guards) are rate-limited per source host by `ip_error()`, configured by the host-wide sysctls `net.ipv4.route.error_cost` and `net.ipv4.route.error_burst` (one per second after a small burst by default), which cannot be changed from a namespace. On Linux 6.1 a burst of three rejected connections already loses ICMP errors (7.1 delivered them in the same test); tests that expect an ICMP error for every rejected IPv4 connection must space them or set these sysctls on a disposable test host. The harness disables the per-namespace ICMP rate limits (`icmp_ratelimit`, `icmp_msgs_per_sec`) in every node unless `Options::icmp_ratelimit` is set.
- The client's LAN interface has a 1 ms egress delay. Without it, the round trip through the namespaces takes microseconds and an ICMP error can reach a connecting TCP socket while `connect()` still owns it; the kernel then records only a soft error and the connection fails at the SYN retransmission one second later (observed with IPv6).
- Only the router performs duplicate address detection; the other nodes disable it to start quickly. The router's `net.ipv4.conf.default.rp_filter` is 2 (the systemd default) and `all.rp_filter` is 0, set before its interfaces are created, because new namespaces inherit IPv4 settings from the host.
- `udhcpc` is used instead of ISC `dhclient`, whose AppArmor profile on Debian and Ubuntu forbids the per-run script, lease and pid paths. The PPPoE server runs in user mode because the kernel-mode plugin path compiled into `pppoe-server` differs across rp-pppoe versions; the router side uses the kernel `pppoe.so` plugin.
- Ubuntu confines dnsmasq with AppArmor; the CI workflow disables that profile on the runner, since dnsmasq keeps its files in the run directory.
- The harness changes nothing in the host namespace except loading kernel modules.
