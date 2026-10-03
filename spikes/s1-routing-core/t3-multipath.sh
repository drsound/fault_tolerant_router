#!/usr/bin/env bash
# S1 / FR-ROUTE-2, Q12, AS-35, AS-36: inline multipath updates with
# NLM_F_REPLACE in the balancing table, intermediate states (netlink
# notifications) and failures, both families; IPv6 point-to-point members
# with link-local gateways.
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
MON=/tmp/$P-mon
trap 'kill $MONPID 2>/dev/null || true; topo_down' EXIT
topo_up
nsr sysctl -qw net.ipv6.conf.wanb.keep_addr_on_down=1
# The kernel deletes the routes of an interface that goes down; put B back.
wanb_up() { nsr ip link set wanb up; sleep 1; path_route 4 2 $((T + 2)); path_route 6 2 $((T + 2)); }
for f in 4 6; do ftr_install $f 1 2 3; done
ftr_nft 1 2 3

nsr ip monitor route >"$MON" 2>&1 & MONPID=$!
sleep 0.3
mark_mon() { MONPOS=$(wc -l <"$MON"); }
# New notifications since mark_mon, one per line (multipath members joined).
events() {
  sleep 0.3
  tail -n +$((MONPOS + 1)) "$MON" | awk '/^[ \t]/ { line = line " " $0; next } { if (line != "") print line; line = $0 } END { if (line != "") print line }' |
    sed -E 's/[ \t]+/ /g; s/proto 249 //; s/metric 100 //; s/pref medium//' || true
}
show() { nsr ip "$(fam_flag "$1")" route show table "$T" | tr -s ' \n\t' ' ' | sed 's/ pref medium//'; }
nh() { # nh FAM ID -> nexthop words
  local f=$1 id=$2
  if [ "$f" = 4 ] && [ -z "${GW4[$id]}" ]; then echo "nexthop dev ${IFACE[$id]} weight ${WEIGHT[$id]}"
  elif [ "$f" = 4 ]; then echo "nexthop via ${GW4[$id]} dev ${IFACE[$id]} weight ${WEIGHT[$id]}"
  else echo "nexthop via ${GW6[$id]} dev ${IFACE[$id]} weight ${WEIGHT[$id]}"; fi
}
replace_raw() { local f=$1; shift; nsr ip "$(fam_flag "$f")" route replace default table "$T" metric 100 proto "$PROTO" "$@" 2>&1; }
step() { # step FAM DESCRIPTION EXPECTED_TABLE_REGEX -- nexthop words...
  local f=$1 d=$2 exp=$3; shift 4
  mark_mon
  local out; out=$(replace_raw "$f" "$@") || true
  check "v$f $d" "$exp" "$(show "$f")"
  [ -z "$out" ] || note "kernel: $out"
  [ -z "$out" ] || note "table after: $(show "$f")"
  events | while read -r l; do note "event: $l"; done
}

for f in 4 6; do
  echo "== IPv$f updates"
  balance $f 1
  step $f "single A -> A,B" "nexthop via .* dev wana .*nexthop via .* dev wanb" -- $(nh $f 1) $(nh $f 2)
  step $f "A,B -> A,B,C" "dev wana .*dev wanb .*dev wanc" -- $(nh $f 1) $(nh $f 2) $(nh $f 3)
  step $f "A,B,C -> B,C (first member removed)" "^default proto 249 metric 100 nexthop via [^ ]+ dev wanb weight 1 nexthop (via [^ ]+ )?dev wanc weight 1 *$" -- $(nh $f 2) $(nh $f 3)
  step $f "B,C -> C (single, multipath to plain)" "^default (via fe80::1 )?dev wanc" -- $(nh $f 3)
  step $f "C -> A,C (plain to multipath)" "dev wana .*dev wanc" -- $(nh $f 1) $(nh $f 3)
  WEIGHT[1]=3
  step $f "A,C weights 1:1 -> 3:1" "dev wana weight 3 .*dev wanc weight 1" -- $(nh $f 1) $(nh $f 3)
  WEIGHT[1]=1
  step $f "A,C -> A,C unchanged (idempotent replace)" "dev wana .*dev wanc" -- $(nh $f 1) $(nh $f 3)

  echo "== IPv$f failures (previous route must survive when nothing was mutated)"
  balance $f 1 2
  before=$(show $f)
  if [ $f = 4 ]; then bad="nexthop via 10.99.0.1 dev wana"; else bad="nexthop via 2001:db8:99::1 dev wana"; fi
  step $f "A,B -> B + off-link gateway (no onlink): rejected" "^$(echo "$before" | sed 's/[.]/[.]/g')$" -- $(nh $f 2) $bad
  step $f "A,B -> B + nonexistent device: rejected" "^$(echo "$before" | sed 's/[.]/[.]/g')$" -- $(nh $f 2) nexthop via "$( [ $f = 4 ] && echo 192.0.2.1 || echo fe80::1)" dev nosuchdev
  step $f "A,B -> B,B (duplicate member)" ".*" -- $(nh $f 2) $(nh $f 2)
  step $f "-> B,C,C (duplicate after a valid member)" ".*" -- $(nh $f 2) $(nh $f 3) $(nh $f 3)
  if [ $f = 6 ]; then
    step 6 "A,B -> device-only member (Q12): rejected" ".*" -- $(nh 6 1) nexthop dev wanc
    balance 6 1 2
    nsr ip link set wanb down
    step 6 "A,B -> A,B with wanb down" ".*" -- $(nh 6 1) $(nh 6 2)
    wanb_up
  else
    nsr ip link set wanb down
    step 4 "A,B -> A,B with wanb down" ".*" -- $(nh 4 1) $(nh 4 2)
    wanb_up
  fi
  balance $f 1 2
  mark_mon; route_del $f "$T"
  check "v$f withdraw (delete by exact key) empties the table" "^ *$" "$(show $f)"
  events | while read -r l; do note "event: $l"; done
done

echo "== IPv6 make-before-break alternative (two metrics, no replace)"
balance 6 1 2
mark_mon
nsr ip -6 route add default table "$T" metric 101 proto "$PROTO" $(nh 6 2) $(nh 6 3)
check "v6 new set added at metric 101: lookups still use metric 100 (A,B)" "metric 100" "$(rget -6 route get 2001:db8:100::1 from fd00:1::2 iif lan)"
r=$(nsr ip -6 route del default table "$T" metric 100 proto "$PROTO" 2>&1 || true)
check "v6 old route deleted by exact key: lookups use the new set" "metric 101" "$(rget -6 route get 2001:db8:100::1 from fd00:1::2 iif lan)"
check "v6 table holds only the new set" "^default proto 249 metric 101 nexthop via fe80::1 dev wanb weight 1 nexthop via fe80::1 dev wanc weight 1 $" "$(show 6)"
events | while read -r l; do note "event: $l"; done
nsr ip -6 route del default table "$T" metric 101 proto "$PROTO"

echo "== IPv6 point-to-point member with link-local gateway (AS-35)"
balance 6
for set in "3" "1 3" "1 2 3" "3" "2 3" "3"; do
  balance 6 $set 2>&1 | sed 's/^/     kernel: /'
  check "v6 active set {$set} installed" "dev wanc" "$(show 6)"
  r=$(nsc $PEER conn 2001:db8:100::1 2001:db8:100::2 2001:db8:100::3 --count 12 2>&1 | peer_uplink)
  note "connections: $r"
done
summary
