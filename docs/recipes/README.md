# Recipes

Complete configurations for common setups, each with the operating system's side. Every PolyWAN configuration shown in these pages is validated by the test suite against the parser, and each page says what was tested and what is guidance only.

- [Debian with systemd-networkd](systemd-networkd.md): the one setting systemd-networkd needs, with a compatibility table by systemd version.
- [NetworkManager](networkmanager.md): profiles for the uplinks and the LAN, and the routing tables to stay away from.
- [PPPoE](pppoe.md): pppd for a DSL or fibre line, IPv6 over PPP, MTU.
- [Starlink, 5G and other uplinks behind CGNAT](cgnat.md): what changes, health checks for unstable links, a metered backup.
- [Port forwarding](port-forwarding.md): DNAT to LAN servers through every uplink, with a forwarding firewall.
- [IPv6 choices](ipv6.md): masquerade with ULA, no translation, source NAT, Router Advertisements on the uplinks.
- [Reverse-path filtering](reverse-path-filtering.md): the IPv4 settings PolyWAN uses and an nftables filter for IPv6.
- [Larger setups](larger-setups.md): four uplinks, a DMZ, policies, notifications and metrics.
