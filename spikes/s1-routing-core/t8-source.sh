#!/usr/bin/env bash
# S1 / FR-DISC-2, FR-DISC-6, INV-4, AS-21, AS-42: local source address
# selection for unbound router-originated traffic over the multipath
# balancing route, both families, with a secondary IPv4 address; consistency
# between source address and egress uplink; the FR-DISC-6 configuration (IPv6
# uplink without a global address, static source on the LAN, snat).
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
trap topo_down EXIT
topo_up
nsr ip addr add 192.0.2.3/24 dev wana        # secondary address of A
for f in 4 6; do ftr_install $f 1 2 3; done
rule_from 4 1 192.0.2.3; guard_from 4 192.0.2.3
ftr_nft 1 2 3

# Mismatch counters: router-originated packets (tcp/udp port 7) leaving an
# uplink with a source address that does not belong to that uplink's path.
mm_up() {
  nsr nft -f - <<EOF
table inet mm {
  counter m4 {}
  counter m6 {}
  chain post {
    type filter hook postrouting priority 300; policy accept;
    iifname "lan" return
    th dport 7 oifname "wana" ip saddr != { 192.0.2.2, 192.0.2.3 } counter name m4
    th dport 7 oifname "wanb" ip saddr != 198.51.100.2 counter name m4
    th dport 7 oifname "wanc" ip saddr != 203.0.113.2 counter name m4
    th dport 7 oifname "wana" ip6 saddr != 2001:db8:a::2 counter name m6
    th dport 7 oifname "wanb" ip6 saddr != { 2001:db8:b::2, 2001:db8:b:1::1 } counter name m6
    th dport 7 oifname "wanc" ip6 saddr != 2001:db8:c::2 counter name m6
  }
}
EOF
}
mm() { nsr nft -j list counters table inet mm | python3 -c 'import json,sys; c={o["counter"]["name"]:o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}; print(c["m4"], c["m6"])'; }
mm_up
d4() { local i; for i in $(seq 1 50); do echo 198.18.100.$i; done; }
d6() { local i; for i in $(seq 1 50); do echo 2001:db8:100::$i; done; }

echo "== unbound router-originated connections over the balancing route"
r=$(nsr $PEER conn $(d4) --count 300 --local | peer_uplink)
check "v4 TCP: sources spread over A, B, C primaries; secondary never chosen ($r)" '"A": [0-9]+, "B": [0-9]+, "C": [0-9]+' "$r"
check "v4 TCP: secondary 192.0.2.3 not used for unbound traffic" '^$' "$(echo "$r" | grep -o '192\.0\.2\.3' || true)"
r=$(nsr $PEER conn $(d6) --count 300 --local | peer_uplink)
check "v6 TCP: sources spread over A, B, C ($r)" '"A": [0-9]+, "B": [0-9]+, "C": [0-9]+' "$r"
r=$(nsr $PEER udp $(d4) --count 100 | peer_uplink)
check "v4 unconnected UDP: sources spread ($r)" '"A": [0-9]+, "B": [0-9]+, "C": [0-9]+' "$r"
r=$(nsr $PEER udp $(d6) --count 100 | peer_uplink)
check "v6 unconnected UDP: sources spread ($r)" '"A": [0-9]+, "B": [0-9]+, "C": [0-9]+' "$r"
check "source address always matches the egress uplink (mismatch v4 v6)" '^0 0$' "$(mm)"

echo "== bound to an address (AS-42)"
r=$(nsr $PEER conn 198.18.100.1 --src 192.0.2.3 --count 5)
check "v4 bound to A's secondary address: via A, seen as 192.0.2.3" '"192.0.2.3": 5' "$r"
balance 4
r=$(nsr $PEER conn 198.18.100.1 --src 192.0.2.3 --count 5)
check "v4 bound to A's secondary address with an empty active set: still via A" '"192.0.2.3": 5' "$r"
r=$(nsr $PEER conn 198.18.100.1 --count 5)
check "v4 unbound with an empty active set: rejected" 'ENETUNREACH|EHOSTUNREACH' "$r"
balance 4 1 2 3

echo "== FR-DISC-6: IPv6 uplink B without a global address, static source on the LAN, snat"
r_rule_del 6 pref $((B + 564)) from 2001:db8:b::2 fwmark "0/$MASK" unreachable
r_rule_del 6 pref $((B + 502)) from 2001:db8:b::2 fwmark "0/$MASK" lookup $((T + 2))
nsr ip -6 addr del 2001:db8:b::2/64 dev wanb
nsr ip -6 addr add fe80::2/64 dev wanb
nsr ip -6 addr add 2001:db8:b:1::1/64 dev lan          # from the delegated prefix
ip -n "$P-b" -6 route add 2001:db8:b:1::/64 via fe80::2 dev cust
SRC6[2]=2001:db8:b:1::1
for tb in $((T + 2)) $((T + 66)) $((T + 130)); do path_route 6 2 $tb; done
check "v6 path route of B with a source on another interface accepted" "src 2001:db8:b:1::1" "$(nsr ip -6 route show table $((T + 2)))"
rule_from 6 2 2001:db8:b:1::1; guard_from 6 2001:db8:b:1::1
ftr_nft_text 1 2 3 | sed 's|    iifname "lan" oifname "wanb" masquerade|    iifname "lan" oifname "wanb" meta nfproto ipv4 masquerade\n    iifname "lan" oifname "wanb" meta nfproto ipv6 snat ip6 to 2001:db8:b:1::1|' |
  { echo "add table inet fault_tolerant_router"; echo "delete table inet fault_tolerant_router"; cat; } | nsr nft -f -
nsr nft reset counters table inet mm >/dev/null
r=$(nsc $PEER conn $(d6) --count 90 | peer_uplink)
check "v6 forwarded: B used with the snat source ($r)" '"2001:db8:b:1::1": [0-9]+' "$r"
r=$(nsr $PEER conn $(d6) --count 300 --local | peer_uplink)
note "v6 unbound router traffic, sources: $r"
check "v6 unbound router traffic: source always matches egress (mismatch v4 v6)" '^0 0$' "$(mm)"
r=$(nsr $PEER conn 2001:db8:100::1 --src 2001:db8:b:1::1 --count 5)
check "v6 bound to the static source: via B" '"2001:db8:b:1::1": 5' "$r"
r=$(nsc $PEER conn 2001:db8:b:1::1 --port 22 --count 1 --timeout 0.5)
check "v6 LAN host reaches the static source address; the reply follows the main bypass, not the source rule" 'ECONNREFUSED' "$r"
summary
