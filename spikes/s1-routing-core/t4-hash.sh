#!/usr/bin/env bash
# S1 / FR-ROUTE-5, AS-01, AS-02: layer-4 multipath hashing distribution of
# forwarded connections (1000 connections, distinct 5-tuples, 50
# destinations), both families; behaviour of members whose link loses
# carrier before FTR withdraws them (ignore_routes_with_linkdown).
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
trap topo_down EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2; done
ftr_nft 1 2

dsts() { local i; for i in $(seq 1 50); do [ "$1" = 4 ] && echo "198.18.100.$i" || echo "2001:db8:100::$i"; done; }
share() { # share JSON UPLINK -> percentage of successful connections
  python3 -c 'import json,sys; d=json.loads(sys.argv[1])["peers"]; t=sum(d.values()); print(round(100*d.get(sys.argv[2],0)/t) if t else 0)' "$1" "$2"
}
SPORT=20000
run() { # run FAM -> JSON with peers mapped to uplink names
  local r; r=$(nsc $PEER conn $(dsts "$1") --count 1000 --sport $SPORT --timeout 2 | peer_uplink)
  SPORT=$((SPORT + 1000)); echo "$r"
}

for f in 4 6; do
  WEIGHT[1]=1; WEIGHT[2]=1; balance $f 1 2
  r=$(run $f); a=$(share "$r" A)
  check "v$f weights 1:1 -> A gets 45-55% ($r)" "^(4[5-9]|5[0-5])$" "$a"
  WEIGHT[1]=3; balance $f 1 2
  r=$(run $f); a=$(share "$r" A)
  check "v$f weights 3:1 -> A gets 70-80% ($r)" "^(7[0-9]|80)$" "$a"
  WEIGHT[1]=1; balance $f 1 2
done

echo "== carrier loss on A before FTR reacts (route still lists A)"
for lk in 0 1; do
  for f in 4 6; do
    if [ $f = 4 ]; then nsr sysctl -qw net.ipv4.conf.all.ignore_routes_with_linkdown=$lk
    else nsr sysctl -qw net.ipv6.conf.all.ignore_routes_with_linkdown=$lk; fi
  done
  ip -n "$P-a" link set cust down; sleep 0.5
  for f in 4 6; do
    note "v$f table: $(nsr ip $(fam_flag $f) route show table $T | tr -s ' \n\t' ' ' | sed 's/ pref medium//')"
    r=$(nsc $PEER conn $(dsts $f | head -20) --count 100 --sport $SPORT --timeout 0.5 | peer_uplink); SPORT=$((SPORT + 100))
    if [ $lk = 1 ]; then check "v$f ignore_routes_with_linkdown=1: all new connections on B" '"errors": \{\}, "peers": \{"B": 100\}' "$r"
    else check "v$f ignore_routes_with_linkdown=0: connections hashed to A fail" '"errors": \{.+\}' "$r"; fi
  done
  ip -n "$P-a" link set cust up; sleep 2
  for f in 4 6; do path_route $f 1 $((T + 1)); balance $f 1 2; done
done
summary
