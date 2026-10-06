# PPPoE

A DSL or fibre line that needs a PPPoE session from the router, next to other uplinks. pppd establishes the session and creates a PPP interface; PolyWAN follows that interface by name, also when pppd recreates it after a reconnection.

## pppd

`/etc/ppp/peers/dsl`, for a PPPoE session over the Ethernet interface `wan2` (the modem's port), always named `ppp0`:

```text
plugin pppoe.so
nic-wan2
user "customer@provider.example"
unit 0
noipdefault
nodefaultroute
+ipv6
persist
maxfail 0
holdoff 5
mtu 1492
mru 1492
lcp-echo-interval 10
lcp-echo-failure 3
```

The password goes in `/etc/ppp/chap-secrets` (or `pap-secrets`), readable by root only:

```text
"customer@provider.example" * "SECRET"
```

Start it with `pon dsl`, or at boot from `/etc/network/interfaces` (`auto dsl` / `iface dsl inet ppp` / `provider dsl`) or a systemd unit of your own.

- `unit 0` names the interface `ppp0`, so that the name in PolyWAN's configuration stays right across reconnections; another PPP link on the router takes another unit number.
- `nodefaultroute`: PolyWAN needs no default route for IPv4 over a point-to-point link; it routes through `ppp0` directly. pppd's `defaultroute` is harmless if you want one, for the router's own use when PolyWAN is stopped.
- `persist`, `maxfail 0` and `holdoff` make pppd reconnect forever; `lcp-echo-interval` and `lcp-echo-failure` make it notice a dead session in about 30 seconds. PolyWAN's probes usually notice it first and take the uplink out of use.
- Debian 12's pppd (2.4.9) also accepts `plugin rp-pppoe.so`; `pppoe.so` is the name since pppd 2.5.

## IPv6 over PPP

With `+ipv6`, pppd negotiates link-local addresses; the provider then sends Router Advertisements over the link, and the kernel must process them to configure an address and the default route. Because PolyWAN enables IPv6 forwarding, the kernel ignores Router Advertisements on interfaces with the default `accept_ra = 1`; and because `ppp0` is created anew at each connection, the setting must be the default for new interfaces. In `/etc/sysctl.d/90-ppp-ra.conf`:

```text
net.ipv6.conf.default.accept_ra = 2
```

This applies to every interface created afterwards, which is what a router normally wants on its uplinks; interfaces whose IPv6 a network manager configures (with `accept_ra = 0`) are unaffected. PolyWAN's IPv6 path on `ppp0` becomes ready once the provider's router has announced itself, with its link-local address as the gateway.

## PolyWAN

The PPPoE line as a third uplink, the last resort, next to two Ethernet uplinks:

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
name = "cable"
interface = "wan1"
priority = 1

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"

[[uplink]]
id = 3
name = "dsl"
interface = "ppp0"
priority = 2

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"
```

The uplink's interface is `ppp0`, not `wan2`: the Ethernet interface under the session carries no IP traffic of its own and is neither an uplink nor a downlink.

## MTU

A PPPoE session has an MTU of 1492. Path MTU discovery works through PolyWAN: the ICMP errors that report a smaller MTU belong to their connection and follow its uplink. Many routers also clamp the TCP maximum segment size of connections through the PPPoE link, which avoids depending on those ICMP errors; this is your firewall's job and was not part of PolyWAN's tests:

```text
table inet mss {
	chain forward {
		type filter hook forward priority mangle; policy accept;
		oifname "ppp0" tcp flags syn tcp option maxseg size set rt mtu
	}
}
```

## What was tested

The acceptance suite runs a PPPoE uplink with pppd (`plugin pppoe.so`, `unit 0`, `noipdefault`, `+ipv6`, `persist`, MTU 1492) against an rp-pppoe server, on Debian 12, Debian 13 and Ubuntu 26.04, with kernel SLAAC through `net.ipv6.conf.default.accept_ra = 2`: IPv4 and IPv6 over the session, a path joining and leaving a multi-member active set, reconnections that recreate `ppp0`, ICMP errors and path MTU discovery through the 1492-byte link. In the suite, pppd's `ip-up` script also installs a default route through `ppp0`, as `defaultroute` would.
