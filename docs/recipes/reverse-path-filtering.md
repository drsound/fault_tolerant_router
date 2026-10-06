# Reverse-path filtering

A reverse-path filter drops packets whose source address would not be routed back through the interface they arrived on: spoofed packets from the internet claiming a LAN address, for example. With several uplinks and policy routing, the check must look at routing the way PolyWAN does, or it drops legitimate traffic.

## IPv4: the kernel's filter

For IPv4, PolyWAN sets the kernel's filter on each uplink to loose mode (`rp_filter = 2`) together with `src_valid_mark = 1`: a packet is accepted if any route leads back to its source, and the check uses the mark PolyWAN gives to the connection on arrival. Leave both as PolyWAN sets them; PolyWAN never changes `net.ipv4.conf.all.rp_filter`, which the kernel combines with each interface's value by taking the higher. Strict mode (`rp_filter = 1`) on an uplink would drop inbound traffic of connections whose replies PolyWAN routes by mark.

The `from` rules that PolyWAN installs for every uplink address also serve this check: replies to the probes carry no mark, and pass the check through the rule of the probe's source address. Do not remove or override those rules.

Loose mode does not stop spoofed internal addresses: a packet arriving on an uplink with the source address of a LAN host passes, because a route leads back to that address, through the LAN. Drop such packets with nftables, naming your uplinks and the IPv4 networks of your downlinks:

```nft
table inet antispoof {
	chain prerouting {
		type filter hook prerouting priority -140; policy accept;
		iifname { "wan0", "wan1" } ip saddr { 192.168.1.0/24 } drop
	}
}
```

## IPv6: an nftables filter

The kernel has no reverse-path filter for IPv6; nftables provides one with a `fib` lookup. It must include the packet mark in the lookup, and run after PolyWAN's prerouting chain (priority −150), which sets that mark:

```nft
table inet rpfilter {
	chain prerouting {
		type filter hook prerouting priority -140; policy accept;
		meta nfproto ipv6 fib saddr . mark . iif oif missing drop
	}
}
```

- `fib saddr . mark . iif oif missing` looks up the route back to the source, with the packet's mark, constrained to the arrival interface, and drops the packet when there is none. Thanks to the mark, inbound connections and the replies of outgoing ones pass through the uplink they belong to; thanks to PolyWAN's `from` rules, so do probe replies, which carry no mark.
- Neighbor discovery, Router Advertisements and duplicate address detection, including solicitations from the unspecified address, pass without exceptions.

Without the mark in the lookup (the common `fib saddr . iif oif missing drop`), the check ignores which uplink a connection belongs to. Traffic addressed to an uplink's own address still passes, through that address's `from` rule, but traffic for other addresses does not: with `nat = "none"`, for example, packets arriving on an uplink for a LAN host are checked against the balancing route, and dropped on every uplink but the one the hash happens to choose, and on all of them while the active set is empty.

## Linux 7.1: no IPv6 default route in the main table

Since Linux 7.1, nftables resolves the IPv6 `fib` expression through a kernel function, `fib6_lookup()`, that ignores the `suppress_prefixlength` setting of routing rules. That setting is what makes PolyWAN's main bypass rule skip the default routes of the main table. On these kernels, as long as the main table holds an IPv6 default route (as DHCPv6 clients, Router Advertisements and network managers normally install), the filter's lookup returns that route instead of PolyWAN's: it drops the probe replies of every uplink but that route's, so they are taken down, and inbound traffic and replies along with them. The kernel's own routing is not affected, only these lookups. Linux 7.0 and earlier are not affected.

On Linux 7.1, use the filter only with no IPv6 default route in the main table: configure each uplink's IPv6 `gateway` statically (usually the provider router's link-local address, which can change if the provider replaces its equipment) and keep the operating system from installing IPv6 default routes, for example with `net.ipv6.conf.IFACE.accept_ra_defrtr = 0` for the kernel's own Router Advertisement processing, `UseGateway=no` in the `[IPv6AcceptRA]` section of systemd-networkd, or `ipv6.never-default yes` in NetworkManager. Otherwise, do without an IPv6 reverse-path filter until the kernel is fixed.

## What was tested

This exact ruleset runs in the acceptance suite on Linux 6.1, 7.0 and 7.1, with static gateways, an empty active set and no default route of the operating system through PolyWAN's uplinks, the case where a wrong lookup shows. Other IPv6 default routes stay in the main table, except on 7.1, where none is left, as described above. Connections forwarded to a LAN server and connections to a service of the router through an uplink, ICMP and TCP probe replies, Router Advertisements and duplicate address detection on the uplinks, and outgoing connections from the LAN once an uplink is active again, all pass, and a packet arriving on an uplink with a LAN source address is dropped. The IPv4 rule above runs in the suite too: a packet arriving on an uplink with a LAN source address reaches the router without it, loose mode notwithstanding, and is dropped with it.
