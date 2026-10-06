# PolyWAN

[![PayPal donate button](https://img.shields.io/badge/paypal-donate-yellow.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=96LFVQRFGRPFW&lc=GB&item_name=Alessandro%20Zarrilli&item_number=polywan&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donate_SM%2egif%3aNonHosted "Donate once-off to this project using PayPal")

*Formerly Fault Tolerant Router.*

Do you have several internet connections, from different providers, on one Linux router? Do you want to use all of their bandwidth and stay online when some of them fail? PolyWAN is a daemon for exactly that.

## What it does

PolyWAN runs on a general-purpose Linux distribution (Debian, Ubuntu, Fedora, Arch, Raspberry Pi OS, a virtual machine, …) used as a router or firewall with two or more uplinks: fibre plus a 5G or Starlink backup, two lines in an office, a metered line kept for emergencies.

- New outgoing connections from the internal networks are spread over the healthy uplinks with the kernel's multipath routing, according to weights and priority groups: a worse priority group is used only when no uplink of a better one is usable.
- Every connection keeps the uplink it started on for its whole life, and inbound connections are answered through the uplink they arrived on.
- Each uplink is probed through its own interface (ICMP echo or TCP handshakes to well-known public hosts), so that "link up but provider cut off from the internet" is detected; optional quality gates also take out a link that loses too many packets or is too slow.
- IPv4 and IPv6 are independent: an uplink can be healthy for one family and failed for the other.
- Uplinks can be static, DHCP, SLAAC or PPP. PolyWAN does not configure interfaces: it observes what systemd-networkd, NetworkManager, ifupdown or pppd configure, and coexists with the operating system's own default routes.
- Policies send selected traffic through a chosen uplink; an uplink can be drained for maintenance.
- Marking and optional source NAT live in an nftables table that PolyWAN owns, or, in external mode, in a ruleset you load yourself. PolyWAN never adds filtering verdicts and never touches objects it does not own.
- A status API and command line (`polywan status`, `events`, `drain`, `reload`, …), Prometheus metrics, event hooks and email notifications.
- One static binary, Debian packages and a sandboxed systemd unit.

How it works is explained in [docs/how-it-works.md](docs/how-it-works.md).

## Status

PolyWAN 2.0 is a ground-up rewrite in Rust, developed on this branch (`v2`) and close to its release: [release candidates](https://github.com/drsound/polywan/releases) with packages and static binaries are published while 2.0.0 is prepared. The contract the code is built and tested against is [SPEC.md](SPEC.md); the changes are in [CHANGELOG.md](CHANGELOG.md).

Version 1.x, the Ruby daemon published as the `fault_tolerant_router` gem, is preserved on the `legacy/ruby` branch and the `v1-ruby-final` tag. It is no longer developed.

## Requirements

- Linux 6.1 or later, on x86_64, aarch64 or armv7.
- nftables 1.0.6 or later, for the managed firewall mode.
- Root privileges. systemd is the supported service manager, but not required.

## Documentation

- [Installation](docs/installation.md): packages, static binaries, the systemd unit, upgrades and removal.
- [Configuration reference](docs/configuration.md): every setting, with its default.
- [How PolyWAN works](docs/how-it-works.md): routing, health checks, nftables, guarantees.
- [Recipes](docs/recipes/): systemd-networkd, NetworkManager, PPPoE, CGNAT uplinks, port forwarding, IPv6, reverse-path filtering, larger setups.
- [API, command line and access](docs/api.md): the sockets, every command and endpoint, metrics.
- [Email notifications](docs/email.md): msmtp and how sending works.
- [Troubleshooting](docs/troubleshooting.md): by symptom.
- `man 8 polywan` for every command and option.

## Quick start

On Debian or Ubuntu, with the package of your architecture from the releases page:

```sh
apt install ./polywan_2.0.0-1_amd64.deb
install -D -m 0600 /usr/share/doc/polywan/examples/config.toml /etc/polywan/config.toml
# edit /etc/polywan/config.toml: your downlinks and uplinks
polywan check-config
systemctl enable --now polywan
polywan status
```

Other distributions use the static binary; see [installation](docs/installation.md).

## Building

With a Rust toolchain (1.89 or later):

```sh
cargo build --release -p polywan
target/release/polywan generate-config > config.toml   # the commented example
target/release/polywan check-config --offline --config config.toml
```

## Testing

Every functional requirement is verified by acceptance scenarios that move real packets through network namespaces: a router, a client, three providers (DHCP, CGNAT and PPPoE, dual-stack) and an internet with probe targets. `tests/vm/run-suite.sh --host` builds and runs the whole suite on the running kernel (as root, through sudo), and `--unit` runs it with the daemon under the packaged systemd unit; `tests/vm/run-suite.sh --vm ROOTFS` runs it in a virtme-ng virtual machine booted from a root filesystem made by `tests/vm/build-rootfs.sh`, which is how CI covers Debian 12 (Linux 6.1, nftables 1.0.6). The harness is described in [crates/testbed/README.md](crates/testbed/README.md).

## Coming from Fault Tolerant Router 1.x

2.0 keeps the purpose of 1.x, not its interface. It does not read 1.x YAML configurations, and it no longer needs hand-integrated iptables rules or a main table without default routes: a 2.0 configuration is written anew, starting from the example it ships. Fault Tolerant Router 1.x was featured on [Slashdot](http://linux.slashdot.org/story/15/03/03/1910206/linux-and-multiple-internet-uplinks-a-new-tool) in 2015.

## License

PolyWAN 2.0 is licensed under either of the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license ([LICENSE-MIT](LICENSE-MIT)), at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions. Fault Tolerant Router 1.x (the Ruby code on the `legacy/ruby` branch) was released under the GNU General Public License v2.0.

## Author

Alessandro Zarrilli (Firenze, Italy), alessandro@zarrilli.net
