# Debian with systemd-networkd

A Debian router whose interfaces systemd-networkd configures: two uplinks with DHCP and Router Advertisements, and a LAN. PolyWAN works with any systemd-networkd that keeps its hands off PolyWAN's rules and routes, which takes one setting.

## Keep systemd-networkd off PolyWAN's rules and routes

By default, systemd-networkd deletes every routing rule and route that its `.network` files do not describe, PolyWAN's included. PolyWAN refuses to start while systemd-networkd runs with that behaviour, and `polywan check-config` reports it. Turn it off with a drop-in, `/etc/systemd/networkd.conf.d/polywan.conf`:

```ini
[Network]
ManageForeignRoutingPolicyRules=no
ManageForeignRoutes=no
```

Then restart systemd-networkd (`systemctl restart systemd-networkd`), before starting PolyWAN: with the default settings, a restart is itself one of the moments when it deletes foreign rules and routes.

What the settings do, by version:

| systemd | `ManageForeignRoutingPolicyRules` | `ManageForeignRoutes` | `ManageForeignNextHops` |
|---|---|---|---|
| 246–248 | does not exist | default `yes`: deletes PolyWAN's routes | does not exist |
| 249–255 (Debian 12: 252) | default `yes`: deletes PolyWAN's rules whenever a link is reconfigured | default `yes`: deletes PolyWAN's routes | does not exist |
| 256 and later (Debian 13: 257) | default `yes`: deletes PolyWAN's rules when systemd-networkd restarts and whenever a link is reconfigured | default `yes`: deletes PolyWAN's routes when systemd-networkd restarts | default `yes`: Router Advertisement default routes use nexthop objects |

Set both `ManageForeignRoutingPolicyRules=no` and `ManageForeignRoutes=no` with every version that has them (with 246–248, `ManageForeignRoutes=no`; those versions are older than any distribution with Linux 6.1 and were not tested). `ManageForeignNextHops` needs no change: PolyWAN owns no nexthop objects, and it follows Router Advertisement default routes through the single nexthop objects that systemd-networkd 256 and later creates. The behaviour of the 252 and 257 rows was observed during PolyWAN's development; the other rows come from systemd's release notes.

PolyWAN reads the effective configuration (`networkd.conf` and its drop-ins in `/etc`, `/run`, `/usr/local/lib` and `/usr/lib`) at startup and in `check-config`, whenever systemd-networkd runs in its network namespace.

## The interfaces

`/etc/systemd/network/10-wan0.network`, the first uplink:

```ini
[Match]
Name=wan0

[Network]
DHCP=ipv4
IPv6AcceptRA=yes

[DHCPv4]
RouteMetric=100

[IPv6AcceptRA]
RouteMetric=100
```

`/etc/systemd/network/10-wan1.network`, the second, with `Name=wan1` and route metrics of 200. Distinct metrics keep the main table tidy; PolyWAN finds each uplink's default route by its interface, whatever the metric.

systemd-networkd handles Router Advertisements itself, with the kernel's `accept_ra = 0`, so IPv6 forwarding, which PolyWAN enables, does not stop it. Its DHCPv4 client sends renewals from the leased address, which PolyWAN routes through the uplink that holds it, also while no uplink is in the active set.

`/etc/systemd/network/20-lan0.network`, the LAN, with a private IPv4 network and a unique local (ULA) IPv6 prefix that systemd-networkd announces to the LAN's hosts:

```ini
[Match]
Name=lan0

[Network]
Address=192.168.1.1/24
Address=fd00:1::1/64
IPv6SendRA=yes

[IPv6Prefix]
Prefix=fd00:1::/64
```

LAN hosts then get IPv6 addresses from the ULA prefix, which PolyWAN masquerades behind each uplink's address. A DHCPv4 server for the LAN (`DHCPServer=yes`, or another server) is up to you.

## PolyWAN

`/etc/polywan/config.toml`:

```toml
[[downlink]]
interface = "lan0"

[[uplink]]
id = 1
name = "fiber"
interface = "wan0"
priority = 1
weight = 10

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"

[[uplink]]
id = 2
name = "cable"
interface = "wan1"
priority = 1
weight = 5

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"
```

Then `polywan check-config` and `systemctl enable --now polywan`.

## What was tested

PolyWAN's rules and routes were observed through every operation of systemd-networkd 252 (Debian 12) and 257 (Debian 13) with these settings: restarts, `networkctl reload`, `networkctl reconfigure`, `renew` and `forcerenew`, links going down and up. With the drop-in above, systemd-networkd deleted nothing of PolyWAN's; the only removals were those the kernel makes itself when an address or a link goes away, which PolyWAN expects and handles. The acceptance suite checks that PolyWAN refuses to start without the drop-in and starts with it, and follows Router Advertisement routes through nexthop objects as systemd-networkd 257 installs them.
