# IPv6 choices

IPv6 with several providers raises a question that IPv4 answers by default: which addresses do the LAN's hosts use, and what happens to them when an uplink fails? Each provider usually assigns its own prefix, valid only through its own network. PolyWAN supports three answers, chosen per path with `nat`, which has no default for IPv6.

## Masquerade with a ULA prefix (the usual choice)

The LAN uses a unique local prefix (ULA, `fd00::/8`, for example `fd00:1::/64`), which never changes, and PolyWAN masquerades it behind the address of whichever uplink each connection leaves through. This is what IPv4 does with private addresses, with the same trade-off: failover is transparent to the hosts and new connections simply use another uplink, but hosts are not reachable from the internet at their own addresses, and protocols that embed addresses suffer as they do with IPv4 NAT.

```toml
[[uplink]]
id = 1
name = "fiber"
interface = "wan0"
priority = 1

[uplink.ipv4]

[uplink.ipv6]
nat = "masquerade"
```

Announce the ULA prefix on the LAN with your Router Advertisement daemon (systemd-networkd's `IPv6SendRA=`, radvd, dnsmasq). Hosts prefer IPv4 over IPv6 when their only IPv6 address is a ULA (RFC 6724's default policy), so many will keep using IPv4 for internet destinations; that is harmless.

## No translation

With `nat = "none"`, LAN hosts use public addresses and PolyWAN only routes. This works only when every uplink in use accepts traffic from those addresses, which with several providers is rare:

- a prefix of your own (provider-independent space) announced through every provider;
- a single provider with IPv6 among several uplinks: give IPv6 only to that uplink, so that IPv6 never leaves through another.

A connection that leaves through one provider with a source address from another provider's prefix is normally dropped by that provider's filtering. Automatic handling of several delegated prefixes (announcing each to the LAN and withdrawing it when its uplink fails) is not something PolyWAN 2.0 does.

## Source NAT to a fixed address

`nat = "snat"` translates to a static `source` address, for example a stable address of a business line. It is also the only way to use an uplink whose provider assigns no address to the uplink interface and only delegates a prefix: take an address from the delegated prefix, assign it to the LAN interface, and use it as the path's source:

```toml
[[uplink]]
id = 2
name = "cable"
interface = "wan1"
priority = 1

[uplink.ipv4]

[uplink.ipv6]
source = "2001:db8:20:1::1"
nat = "snat"
```

The path is ready only while that address is present on the router. Requesting and assigning the delegated prefix is the job of your DHCPv6 client or network manager.

## Router Advertisements on the uplinks

PolyWAN enables IPv6 forwarding, and a forwarding Linux system ignores Router Advertisements on interfaces with the kernel's default `accept_ra = 1`. Uplinks configured by the kernel's own SLAAC (ifupdown's `inet6 auto`, or no network manager at all) therefore need `accept_ra = 2`, for example in `/etc/sysctl.d/90-uplinks.conf`:

```text
net.ipv6.conf.wan0.accept_ra = 2
net.ipv6.conf.wan1.accept_ra = 2
```

For interfaces created later, such as PPP links, set `net.ipv6.conf.default.accept_ra = 2` instead (see [PPPoE](pppoe.md)). systemd-networkd and NetworkManager process Router Advertisements themselves, with `accept_ra = 0`, and need nothing. PolyWAN never changes `accept_ra`; `check-config` and the daemon warn about every uplink with `gateway = "auto"` whose `accept_ra = 1` would leave it without a default route.

The acceptance suite configures its IPv6 uplinks through kernel SLAAC with `accept_ra = 2`, including over PPP, and masquerades its LAN prefix behind every uplink.

## DHCPv6 servers with the Server Unicast option

A provider's DHCPv6 server that tells clients to send their requests by unicast can make some clients fail to acquire or renew their addresses and prefixes through PolyWAN. The cases, the clients affected and the remedies are in [troubleshooting](../troubleshooting.md#dhcp-leases-not-renewed-or-not-acquired).
