# PolyWAN

[![PayPal donate button](https://img.shields.io/badge/paypal-donate-yellow.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=96LFVQRFGRPFW&lc=GB&item_name=Alessandro%20Zarrilli&item_number=polywan&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donate_SM%2egif%3aNonHosted "Donate once-off to this project using PayPal")

*Formerly Fault Tolerant Router.*

Do you have several internet connections, from different providers, on one Linux router? Do you want to use all of their bandwidth and stay online when some of them fail? PolyWAN is a daemon for exactly that.

## Status

PolyWAN 2.0 is a ground-up rewrite in Rust, under development on this branch (`v2`). It has not been released yet: there are no packages, and configuration, command line and paths may still change until 2.0.0. The contract the code is built and tested against is [SPEC.md](SPEC.md); the milestones are recorded in [milestones/](milestones/).

| Milestone | Scope | State |
|---|---|---|
| M1 | IPv4 core: configuration, discovery, probes, health, routing, nftables, `run`, `check-config`, `export-nft`, `cleanup`, `forget-uplink` | complete |
| M2 | IPv6 | complete |
| M3 | Operations: status API and the rest of the command line, drain, policies, events, email, hooks, Prometheus metrics, quality gates | in progress |
| M4 | Release: packages, documentation, migration guide from 1.x | planned |

Version 1.x, the Ruby daemon published as the `fault_tolerant_router` gem, is preserved on the `legacy/ruby` branch and the `v1-ruby-final` tag. It is no longer developed.

## What it does

PolyWAN runs on a general-purpose Linux distribution (Debian, Ubuntu, Fedora, Arch, Raspberry Pi OS, a virtual machine, …) used as a router or firewall with two or more uplinks: fibre plus a 5G or Starlink backup, two lines in an office, a metered line kept for emergencies.

- New outgoing connections from the internal networks are spread over the healthy uplinks with the kernel's multipath routing, according to weights and priority groups: a lower priority group is used only when no uplink of a better one is usable.
- Every connection keeps the uplink it started on for its whole life, and inbound connections are answered through the uplink they arrived on (connection marks plus policy routing).
- Each uplink is probed through its own interface (ICMP echo or TCP handshakes to well-known public hosts), so that "link up but provider cut off from the internet" is detected; failed uplinks leave the multipath route and come back when they recover.
- IPv4 and IPv6 are independent: an uplink can be healthy for one family and failed for the other.
- Uplinks can be static, DHCP, SLAAC/Router Advertisement or PPP. PolyWAN does not configure interfaces: it observes what the operating system (systemd-networkd, NetworkManager, ifupdown, pppd, …) does, through netlink, and coexists with the operating system's own default routes.
- Marking and optional source NAT live in an nftables table that PolyWAN owns and replaces atomically, or, in external mode, in a ruleset the administrator loads (`polywan export-nft`). PolyWAN never adds filtering verdicts and never touches objects it does not own.
- Coming with M3: a status API on a Unix socket and the commands that use it (`status`, `events`, `drain`, `undrain`, `reload`, `notify-test`), policies that send matching traffic through a given uplink, link quality gates (loss, latency, jitter), email notifications, event hooks and Prometheus metrics.

How it works, in detail, is in [SPEC.md](SPEC.md) §4 (routing model), §5 (discovery and health) and §7 (firewall integration).

## Requirements

- Linux 6.1 or later, on x86_64, aarch64 or armv7.
- nftables 1.0.6 or later, for the managed firewall mode.
- Root privileges. A systemd unit with sandboxing will ship with the packages; systemd is not required at runtime.

## Building and trying it

There are no release binaries yet. With a Rust toolchain (1.89 or later):

```sh
cargo build --release -p polywan
target/release/polywan generate-config > config.toml   # a commented example
target/release/polywan check-config --config config.toml
target/release/polywan export-nft --config config.toml # the ruleset of the managed mode
sudo target/release/polywan run --config config.toml --dry-run
```

`run --dry-run` computes and logs every change without applying it. The default configuration path is `/etc/polywan/config.toml`, the state directory `/var/lib/polywan`. `polywan cleanup` removes everything PolyWAN installed.

## Testing

Every functional requirement is verified by acceptance scenarios that move real packets through network namespaces: a router, a client, three providers (DHCP, CGNAT and PPPoE, dual-stack) and an internet with probe targets. `tests/vm/run-suite.sh --host` builds and runs the whole suite on the running kernel (as root, through sudo); `tests/vm/run-suite.sh --vm ROOTFS` runs it in a virtme-ng virtual machine booted from a root filesystem made by `tests/vm/build-rootfs.sh`, which is how CI covers Debian 12 (Linux 6.1, nftables 1.0.6). The harness is described in [crates/testbed/README.md](crates/testbed/README.md).

## Coming from Fault Tolerant Router 1.x

2.0 does not read 1.x YAML configurations, and it no longer needs hand-integrated iptables rules or a main table without default routes. The release will include a migration guide with the 2.0 equivalent of every 1.x parameter. Fault Tolerant Router 1.x was featured on [Slashdot](http://linux.slashdot.org/story/15/03/03/1910206/linux-and-multiple-internet-uplinks-a-new-tool) in 2015.

## License

PolyWAN 2.0 is licensed under either of the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license ([LICENSE-MIT](LICENSE-MIT)), at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions. Fault Tolerant Router 1.x (the Ruby code on the `legacy/ruby` branch) was released under the GNU General Public License v2.0.

## Author

Alessandro Zarrilli (Firenze, Italy), alessandro@zarrilli.net
