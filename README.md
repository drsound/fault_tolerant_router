# PolyWAN

[![CI](https://github.com/drsound/polywan/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/drsound/polywan/actions/workflows/ci.yml?query=branch%3Amain) [![Latest release](https://img.shields.io/github/v/release/drsound/polywan)](https://github.com/drsound/polywan/releases/latest) [![crates.io](https://img.shields.io/crates/v/polywan.svg)](https://crates.io/crates/polywan) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license) [![PayPal donate button](https://img.shields.io/badge/paypal-donate-yellow.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=96LFVQRFGRPFW&lc=GB&item_name=Alessandro%20Zarrilli&item_number=polywan&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donate_SM%2egif%3aNonHosted "Donate once-off to this project using PayPal")

*Formerly Fault Tolerant Router.*

## In brief

Multi-WAN routing and failover for Linux.

PolyWAN spreads new connections over several internet uplinks from different providers, takes a failed one out of use and puts it back when it recovers.

## What it does

PolyWAN is a daemon for a general-purpose Linux distribution (Debian, Ubuntu, Fedora, Arch, Raspberry Pi OS, a virtual machine, etc.) used as a router or firewall with two or more internet uplinks: fibre plus a 5G or Starlink backup, two lines in an office, a metered line kept for emergencies.

It routes the traffic of at least one internal network (a downlink), and the router's own connections are balanced and fail over too.

- **Load balancing**: new outgoing connections are spread over the healthy uplinks with the kernel's *multipath routing*, according to weights and priority groups. A worse priority group is used only when no uplink of a better one is usable: that's how a metered line stays idle until it's really needed.
- **Failover**: an uplink that fails its health checks is taken out of the balancing, and put back when it recovers. New connections go over the remaining uplinks, while the connections that were using the failed one generally have to reconnect.
- **Health checks**: each uplink is probed through its own interface, with ICMP echo or TCP handshakes to well-known public hosts. This way an uplink that looks "up" while its provider is cut off from the internet is detected as failed. Optional quality gates also take out an uplink that loses too many packets or is too slow.
- **Sticky connections**: every connection keeps the uplink it started on for its whole life, and inbound connections are answered through the uplink they arrived on.
- **Dual stack**: IPv4 and IPv6 are independent, so an uplink can be healthy for one family and failed for the other.
- **Dynamic uplinks**: uplinks can be static, DHCP, SLAAC or PPP. PolyWAN doesn't configure interfaces: it observes what systemd-networkd, NetworkManager, ifupdown or pppd configure, and coexists with the operating system's own default routes.
- **Policies and maintenance**: policies send selected traffic through a chosen uplink, and an uplink can be drained before working on it.
- **Firewall**: marking and optional source NAT live in an nftables table owned by PolyWAN or, in external mode, in a ruleset you load yourself. PolyWAN never adds filtering verdicts and never touches objects it doesn't own.
- **Observability**: a status API and command line (`polywan status`, `events`, `drain`, `reload`, etc.), Prometheus metrics, event hooks and email notifications.
- **Packaging**: one static binary, Debian packages and a sandboxed systemd unit.

The details are in [How PolyWAN works](docs/how-it-works.md).

## Requirements

- Linux 6.1 or later, on x86_64, aarch64 or armv7.
- nftables 1.0.6 or later, for the managed firewall mode.
- Root privileges. systemd is the supported service manager, but it isn't required.

## Quick start

On Debian or Ubuntu, download the package for your architecture from the releases page, then:

```sh
apt install ./polywan_2.0.0-1_amd64.deb
install -D -m 0600 /usr/share/doc/polywan/examples/config.toml /etc/polywan/config.toml
# edit /etc/polywan/config.toml: your downlinks and uplinks
polywan check-config
systemctl enable --now polywan
polywan status
```

On other distributions, use the static binary: see [Installation](docs/installation.md).

## Documentation

- [Installation](docs/installation.md): packages, static binaries, the systemd unit, upgrades and removal.
- [Configuration reference](docs/configuration.md): every setting, with its default.
- [How PolyWAN works](docs/how-it-works.md): routing, health checks, nftables, guarantees.
- [Recipes](docs/recipes/): systemd-networkd, NetworkManager, PPPoE, CGNAT uplinks, port forwarding, IPv6, reverse-path filtering, larger setups.
- [API, command line and access](docs/api.md): the sockets, every command and endpoint, metrics.
- [Email notifications](docs/email.md): msmtp and how sending works.
- [Troubleshooting](docs/troubleshooting.md): by symptom.
- `man 8 polywan`: every command and option.

## Releases

Debian packages and static binaries are on the [releases page](https://github.com/drsound/polywan/releases), and the crate is on [crates.io](https://crates.io/crates/polywan). The changes of each release are listed in [CHANGELOG.md](CHANGELOG.md).

The code is built and tested against a specification: [SPEC.md](SPEC.md).

## Building

With a Rust toolchain (1.89 or later), `cargo install polywan` builds and installs the latest release from crates.io.

From the source:

```sh
cargo build --release -p polywan
target/release/polywan generate-config > config.toml   # the commented example
target/release/polywan check-config --offline --config config.toml
```

## Testing

Every functional requirement is verified by acceptance scenarios that move real packets through network namespaces: a router, a client, three providers (DHCP, CGNAT and PPPoE, all dual-stack) and an internet with the probe targets.

- `tests/vm/run-suite.sh --host` builds and runs the whole suite on the running kernel, as root (through sudo).
- `tests/vm/run-suite.sh --host --unit` does the same with the daemon running under the packaged systemd unit.
- `tests/vm/run-suite.sh --vm ROOTFS` runs the suite in a virtme-ng virtual machine, booted from a root filesystem made by `tests/vm/build-rootfs.sh`. That's how CI covers Debian 12 (Linux 6.1, nftables 1.0.6).

The test harness is described in [crates/testbed/README.md](crates/testbed/README.md).

## Coming from Fault Tolerant Router 1.x

PolyWAN 2.0 is a ground-up rewrite of Fault Tolerant Router in Rust. It keeps the purpose of 1.x, not its interface.

It doesn't read 1.x YAML configurations, so a 2.0 configuration has to be written anew, starting from the example it ships. However, it no longer needs hand-integrated iptables rules, nor a main routing table without default routes.

Version 1.x, the Ruby daemon published as the `fault_tolerant_router` gem, is preserved on the `legacy/ruby` branch and the `v1-ruby-final` tag. It's no longer developed.

## License

PolyWAN 2.0 is licensed under either of the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license ([LICENSE-MIT](LICENSE-MIT)), at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions. Fault Tolerant Router 1.x (the Ruby code on the `legacy/ruby` branch) was released under the GNU General Public License v2.0.

## Contact

Bugs and feature requests go to the [issues](https://github.com/drsound/polywan/issues), and security reports as described in [SECURITY.md](SECURITY.md).

PolyWAN is written and maintained by Alessandro Zarrilli (Firenze, Italy).
