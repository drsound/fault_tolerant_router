# Starlink, 5G and other uplinks behind CGNAT

Satellite and mobile providers, and some fixed ones, give the router a private IPv4 address and translate it again in their network (carrier-grade NAT, typically from `100.64.0.0/10`). Their equipment usually acts as a router towards yours, with DHCP. PolyWAN handles such an uplink like any other DHCP uplink; what changes is what the uplink can do.

## What to expect

- **No inbound IPv4.** Connections from the internet cannot reach an address behind the provider's NAT, so port forwarding through this uplink works only if the provider offers it. Inbound IPv6 may work if the provider gives you public IPv6 addresses.
- **Outbound works normally.** PolyWAN masquerades your LAN behind the uplink's private address, and the provider translates it again.
- **Addresses change.** A new DHCP lease, a reboot of the provider's equipment, or a satellite handover can change the uplink's address. With masquerade, connections that used the old address break when it changes; new connections use the new address within a second.
- **Probes work.** ICMP and TCP probes leave through the uplink like any outgoing connection; CGNAT translates their replies back.

## The provider's equipment

Use it as a plain router towards yours: the router's uplink interface gets its address and default route by DHCP and, where the provider supports IPv6, by Router Advertisements and DHCPv6. If the equipment has a bridge or bypass mode (Starlink's router has one), your router gets the provider's addresses directly, with the same behaviour. A double NAT through the equipment's own router mode works too, at the cost of one more translation.

The exact behaviour of each provider's equipment (which addresses it hands out, whether it delegates an IPv6 prefix, how long its leases last) varies and was not tested with real equipment: the suite's CGNAT provider is a DHCP server handing out an address from `100.64.0.0/10` behind a NAT.

## Health checks for unstable links

Satellite and mobile links have higher and more variable latency than fixed lines, and brief interruptions (satellite handovers, cell changes) that last a few seconds. The defaults take an uplink down after two failed rounds of 5 seconds, which is usually right: an interruption long enough to fail two rounds also breaks connections. For an uplink that should ride out short interruptions, raise `fall`; for high latency, raise `timeout`, keeping `timeout × attempts` below `interval`:

```toml
[[uplink]]
id = 2
name = "starlink"
description = "Starlink, backup"
interface = "wan1"
priority = 2

[uplink.ipv4]

[uplink.ipv6]
nat = "masquerade"

[uplink.health]
timeout = "2s"
fall = 3
```

These values are a starting point, not a measured recommendation: watch `polywan events` for transitions and `polywan status` for the measured round-trip times and loss before tuning further.

## A metered backup

A mobile uplink with a data cap is best kept in a worse priority group, used only when every uplink of the better group fails:

```toml
[[downlink]]
interface = "lan0"

[[uplink]]
id = 1
name = "fiber"
interface = "wan0"
priority = 1

[uplink.ipv4]

[uplink.ipv6]
nat = "masquerade"

[[uplink]]
id = 2
name = "fwa5g"
description = "5G, metered"
interface = "wan1"
priority = 2

[uplink.ipv4]

[uplink.ipv6]
nat = "masquerade"
```

Its probes still run while it is idle: with the defaults, an ICMP echo request to each of the four IPv4 and three IPv6 targets every 5 seconds, each answered by a reply of the same size (44 bytes for IPv4, 64 for IPv6), plus retries of lost ones. That is about 9 KB a minute, or roughly 13 MB a day, before the provider's own overhead; keep it in mind on a plan billed by the megabyte, where fewer targets or a longer `interval` for this uplink reduce it. With the default `all_down_policy = "ready"`, if every uplink fails its checks at once (for example because the probe targets are unreachable), PolyWAN keeps using the best group rather than switching to the metered uplink.
