#!/usr/bin/env bash
# S1 / FR-ROUTE-1: device-bound (SO_BINDTODEVICE) router-originated traffic
# with FTR tables empty or without the bound uplink, with real packets.
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
trap topo_down EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
ftr_nft 1 2 3

cap() { # cap IFACE SECONDS FILTER -> background tcpdump writing to $P-cap-IFACE
  nsr timeout "$2" tcpdump -lni "$1" -c 20 "$3" >"/tmp/$P-cap-$1" 2>/dev/null & CAP_PID=$!
  sleep 0.5
}
# call capwait in the main shell before $(seen IFACE): a subshell cannot wait
capwait() { wait "$CAP_PID" || true; }
seen() { cat "/tmp/$P-cap-$1" | cut -d' ' -f2- | sort | uniq -c | sort -rn | head -3 | tr '\n' ';'; }

echo "== IPv4"
balance 4 2 3
cap wana 3 "arp or icmp or tcp port 7"
r=$(nsr $PEER conn 198.18.100.9 --device wana | peer_uplink)
check "v4 TCP connect bound to wana, A not in the active set: connects via A (source rule after on-link source selection)" '"A": 1' "$r"
capwait; note "wana: $(seen wana)"

cap wana 3 "arp or udp port 7"
r=$(nsr $PEER udp 198.18.100.9 --device wana --timeout 1)
check "v4 unconnected UDP bound to wana, A not in the active set: no reply (sent on-link)" '"timeout": 1' "$r"
capwait; note "wana: $(seen wana)"

balance 4
route_del 4 $((T + 3)); route_del 4 $((T + 67)); route_del 4 $((T + 131))
cap wanc 3 "udp port 7"
r=$(nsr $PEER udp 198.18.100.9 --device wanc --timeout 1 | peer_uplink)
check "v4 UDP bound to point-to-point wanc, all wanc tables and balancing empty: sent on-link, reply dropped by rp_filter (path guard)" '"timeout": 1' "$r"
capwait; note "wanc: $(seen wanc)"

leaks_reset
cap wanx 3 "arp or udp port 7"
r=$(nsr $PEER udp 198.18.100.9 --device wanx --timeout 1); capwait
note "v4 UDP bound to non-FTR wanx: $r; wanx: $(seen wanx); leak sink counters v4 v6 = $(leaks)"
check "v4 UDP bound to non-FTR wanx is only ARPed on-link (no IP packet reaches the sink)" '^0 ' "$(leaks)"

cap wanc 3 "udp port 7"
r=$(nsr $PEER udp 198.18.100.9 --unicast-if wanc --timeout 1)
capwait
check "v4 UDP with IP_UNICAST_IF wanc, all wanc tables and balancing empty: also sent on-link" "IP 203\.0\.113\.2\.[0-9]+ > 198\.18\.100\.9\.7" "$(seen wanc)"

echo "== IPv6"
balance 6 2 3
r=$(nsr $PEER conn 2001:db8:100::9 --device wana)
check "v6 TCP connect bound to wana, A not in the active set: source taken from wana, then source rule -> via A" '"2001:db8:a::2": 1' "$r"
r=$(nsr $PEER conn 2001:db8:100::9 --device wana --src 2001:db8:a::2 | peer_uplink)
check "v6 TCP connect bound to wana and A's address: via A" '"A": 1' "$r"
balance 6
route_del 6 $((T + 3))
r=$(nsr $PEER udp 2001:db8:100::9 --device wana --timeout 1 | peer_uplink)
check "v6 unconnected UDP bound to wana, A not in the active set: via A (source rule)" '"A": 1' "$r"
r=$(nsr $PEER udp 2001:db8:100::9 --device wanc --timeout 1)
check "v6 UDP bound to wanc, all wanc tables empty: rejected (source guard)" 'ENETUNREACH|EHOSTUNREACH' "$r"
r=$(nsr $PEER udp 2001:db8:100::9 --unicast-if wanc --timeout 1)
check "v6 UDP with IPV6_UNICAST_IF wanc, all wanc tables empty: rejected" 'ENETUNREACH|EHOSTUNREACH' "$r"
summary
