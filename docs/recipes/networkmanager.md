# NetworkManager

A router whose uplinks NetworkManager configures, for example on a distribution that uses it by default. NetworkManager removes routes only in the routing tables it manages, so PolyWAN and NetworkManager coexist without special settings, provided that NetworkManager is never given one of PolyWAN's tables.

## The rule

**Never use PolyWAN's routing tables in NetworkManager.** With the default `routing.table_base = 1000`, PolyWAN owns tables 1000 to 1191 for each family. Do not set `ipv4.route-table` or `ipv6.route-table` of a profile to one of them, do not name them in `ipv4.routing-rules` or `ipv6.routing-rules`, and leave the global defaults of `route-table` in `NetworkManager.conf` unset or outside that range. A profile that writes into PolyWAN's tables makes NetworkManager add its own routes there, next to PolyWAN's; PolyWAN then refuses to start, or reports the collision in `check-config`.

With `route-table` left at its default, NetworkManager puts each uplink's default route in the main table, where PolyWAN finds it, and does not touch other tables.

## The uplinks

```sh
nmcli connection add type ethernet ifname wan0 con-name wan0 \
  ipv4.method auto ipv4.route-metric 100 \
  ipv6.method auto ipv6.route-metric 100
nmcli connection add type ethernet ifname wan1 con-name wan1 \
  ipv4.method auto ipv4.route-metric 200 \
  ipv6.method auto ipv6.route-metric 200
```

NetworkManager handles Router Advertisements itself (`accept_ra = 0` in the kernel), so the IPv6 forwarding that PolyWAN enables does not affect it. Its internal DHCPv4 client sends renewals from the leased address, which PolyWAN routes through the uplink that holds it, also while no uplink is in the active set; its internal DHCPv6 client ignores the DHCPv6 Server Unicast option (see [troubleshooting](../troubleshooting.md#dhcp-leases-not-renewed-or-not-acquired)).

## The LAN

Configure the LAN with a static address:

```sh
nmcli connection add type ethernet ifname lan0 con-name lan0 \
  ipv4.method manual ipv4.addresses 192.168.1.1/24 \
  ipv6.method manual ipv6.addresses fd00:1::1/64
```

Do not use `ipv4.method shared` for the LAN: NetworkManager then translates the LAN's traffic itself, with its own NAT rules, in addition to PolyWAN's, and runs its own DHCP and DNS server. If you need NetworkManager's sharing anyway, set `nat = "none"` on PolyWAN's IPv4 paths; `check-config` warns when it finds source NAT in other nftables tables. A DHCP server and IPv6 Router Advertisements for the LAN are then up to you (for example dnsmasq or radvd).

## PolyWAN

```toml
[[downlink]]
interface = "lan0"

[[uplink]]
id = 1
name = "fiber"
interface = "wan0"
priority = 1

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"

[[uplink]]
id = 2
name = "lte"
interface = "wan1"
priority = 2

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"
```

## What was tested

PolyWAN's rules and routes were observed through NetworkManager 1.52.1's operations on its uplinks: restarts of NetworkManager, `nmcli general reload`, `nmcli connection reload`, `nmcli device reapply` with unchanged and changed profiles, `nmcli connection up` and `down`, links going down and up, DHCPv4 and DHCPv6 renewals, and routing rules of a profile added and removed. NetworkManager deleted nothing of PolyWAN's; the only removals were those the kernel makes itself when an address or a link goes away (a reapply of a changed profile resets IPv6 on the device), which PolyWAN expects and handles. A profile with `ipv4.route-table` set to one of PolyWAN's tables added NetworkManager's routes into it, as described above. NetworkManager 1.52.1 acquired its addresses, default routes and a delegated prefix with PolyWAN's rules installed and no uplink in the active set, and its internal DHCPv6 client ignored a server's Server Unicast option.
