# Port forwarding

PolyWAN does not forward ports itself: you write the DNAT rules in your own nftables table, as on any Linux router. What PolyWAN adds is that replies always leave through the uplink the connection arrived on, so a server on the LAN can be reached through every uplink at once, also through uplinks that are not in the active set or are drained, as long as they are ready.

## The ruleset

A web server on the LAN host `192.168.1.10` (`fd00:1::10` for IPv6), reachable on port 8080 of both uplinks, with a forwarding policy that drops what it does not allow:

```nft
table inet router {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname { "wan0", "wan1" } tcp dport 8080 dnat ip to 192.168.1.10:80
		iifname { "wan0", "wan1" } tcp dport 8080 dnat ip6 to [fd00:1::10]:80
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
		ct status dnat accept
		iifname "lan0" accept
	}
}
```

Load it with your other rules, for example from `/etc/nftables.conf`, and keep that file from deleting PolyWAN's table: with `flush ruleset` at its top (as in Debian's default file), every start, reload and stop of `nftables.service` removes PolyWAN's table too, which PolyWAN restores only at its next full reconciliation. Delete and recreate only your own tables instead:

```nft
table inet router
delete table inet router
```

followed by the table itself (the first line makes the second one work also when the table does not exist yet).

What matters for PolyWAN:

- DNAT runs at priority `dstnat` (−100), after PolyWAN's marking at −150, which is what makes the replies follow the arrival uplink. Do not move it before −150.
- The forward chain accepts the forwarded connections (`ct status dnat`) and the LAN's outgoing traffic; PolyWAN never accepts or drops anything itself.
- PolyWAN's own source NAT (`nat` of each path) applies only to connections from the downlinks, so it does not touch these inbound connections. If you also write source NAT rules for the uplinks yourself, set `nat = "none"` on those paths: the first NAT chain that matches decides.

## Through the uplinks

- **IPv4 behind CGNAT**: an uplink whose provider translates your address again (most 5G and satellite services) cannot receive inbound IPv4 connections, unless the provider forwards a port to you.
- **IPv6**: with masquerade, LAN hosts are reached through the uplinks' own addresses, as above; with `nat = "none"` and public addresses on the LAN, forward to the host's own address and only accept in the forward chain.
- **Uplinks reserved to inbound traffic**: an uplink without `priority` carries no new outgoing connections but receives inbound ones, and its replies leave through it.
- The router's own services (a VPN server, SSH) need no DNAT: PolyWAN answers connections to an uplink's address through that uplink.

## What was tested

This exact ruleset, with the interface names, addresses and ports of the test topology, runs in the acceptance suite for both families: inbound connections through two uplinks reach the LAN server, each answered through the uplink it arrived on, while the LAN's own connections keep working through the forward chain. The DNAT rules in the same form are also part of the scenarios that check inbound replies through every uplink, one outside the active set included, and with an empty active set.
