#!/usr/bin/env bash
# S1 / FR-ROUTE-1, FR-ROUTE-3: rule layout with guard rules, encoded marks and
# zero-field source selectors, checked with route lookups for every class,
# both families. Operating-system default routes (best one via the leak sink
# wanx) stay in main throughout.
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
trap topo_down EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
nsr ip route add 172.16.0.0/16 via 10.1.0.2 dev lan          # static route in main
nsr ip -6 route add fd00:99::/48 via fd00:1::2 dev lan

FOREIGN=0x01000001   # bits outside the FTR field, must not matter
m() { printf '0x%08x' $(( $(enc "$1") | ${2:-0} )); }
UNREACH='unreachable|Network is unreachable|No route to host'

for f in 4 6; do
  if [ $f = 4 ]; then D=198.18.100.9; C=10.1.0.2; S=192.0.2.2; SB=198.51.100.2; ST=172.16.1.1; G1='via 192.0.2.1 dev wana'; DX=wanx
  else D=2001:db8:100::9; C=fd00:1::2; S=2001:db8:a::2; SB=2001:db8:b::2; ST=fd00:99::1; G1='via fe80::1 dev wana'; DX=wanx; fi
  fl=$(fam_flag $f)
  fwd() { rget $fl route get "$D" from "$C" iif lan "$@"; }
  echo "== IPv$f forwarded"
  check "v$f unmarked -> balancing table" "dev wan[abc] table $T" "$(fwd mark 0)"
  check "v$f path 1 -> path table 1" "$G1 table $((T + 1))" "$(fwd mark "$(m 1)")"
  check "v$f path 1 with foreign bits -> path table 1" "$G1 table $((T + 1))" "$(fwd mark "$(m 1 $FOREIGN)")"
  check "v$f path 5 (never configured) -> path guard" "$UNREACH" "$(fwd mark "$(m 5)")"
  check "v$f path 63 -> path guard" "$UNREACH" "$(fwd mark "$(m 63)")"
  check "v$f probe 1 -> path table 1" "$G1 table $((T + 1))" "$(fwd mark "$(m 0x41)")"
  check "v$f probe 5 -> probe guard" "$UNREACH" "$(fwd mark "$(m 0x45)")"
  check "v$f policy-balance 1 -> policy table" "$G1 table $((T + 65))" "$(fwd mark "$(m 0x81)")"
  check "v$f policy-block 1 -> policy table" "$G1 table $((T + 129))" "$(fwd mark "$(m 0xc1)")"
  check "v$f policy-block 5 -> policy-block guard" "$UNREACH" "$(fwd mark "$(m 0xc5)")"
  check "v$f policy-balance 5 (unconfigured) -> balancing" "table $T" "$(fwd mark "$(m 0x85)")"
  check "v$f path 1 to connected LAN -> main (INV-1)" "dev lan" "$(rget $fl route get "$C" from "$D" iif wana mark "$(m 1)")"
  check "v$f path 1 to static main route -> main (INV-1)" "via .* dev lan" "$(rget $fl route get "$ST" from "$C" iif lan mark "$(m 1)")"

  route_del $f $((T + 65)); route_del $f $((T + 129))
  check "v$f policy-balance 1, empty table -> falls through to balancing" "table $T" "$(fwd mark "$(m 0x81)")"
  check "v$f policy-block 1, empty table -> policy-block guard" "$UNREACH" "$(fwd mark "$(m 0xc1)")"
  if [ $f = 4 ]; then
    check "v4 AS-48: forwarded packet with a router address as source is a martian" "Invalid argument" "$(rget $fl route get "$D" from "$S" iif lan mark "$(m 0x81)")"
    nsr sysctl -qw net.ipv4.conf.lan.accept_local=1
  fi
  check "v$f AS-48: policy-balance from a router address, empty table -> balancing" "table $T" "$(rget $fl route get "$D" from "$S" iif lan mark "$(m 0x81)")"
  [ $f = 6 ] || nsr sysctl -qw net.ipv4.conf.lan.accept_local=0
  route_del $f $((T + 1))
  check "v$f path 1, empty path table -> path guard, not moved" "$UNREACH" "$(fwd mark "$(m 1)")"
  path_route $f 1 $((T + 1)); path_route $f 1 $((T + 65)); path_route $f 1 $((T + 129))

  echo "== IPv$f router-originated"
  out() { rget $fl route get "$D" "$@"; }
  check "v$f unbound -> balancing" "dev wan[abc] table $T" "$(out)"
  check "v$f bound to A's address -> path table 1" "$G1 table $((T + 1))" "$(out from "$S")"
  check "v$f bound to B's address -> path table 2" "dev wanb table $((T + 2))" "$(out from "$SB")"
  check "v$f probe mark 1 -> path table 1" "$G1 table $((T + 1))" "$(out mark "$(m 0x41)")"
  check "v$f SO_BINDTODEVICE wana, unbound -> wana member of balancing" "dev wana table $T" "$(out oif wana)"
  balance $f 2 3
  check "v$f SO_BINDTODEVICE wana, A not in balancing" ".*" "$(out oif wana)"; note "$(out oif wana)"
  check "v$f SO_BINDTODEVICE wanx (non-FTR uplink)" ".*" "$(out oif wanx)"; note "$(out oif wanx)"
  route_del $f $((T + 1))
  check "v$f bound to A's address, empty path table -> source guard" "$UNREACH" "$(out from "$S")"
  check "v$f probe 1, empty path table -> probe guard" ".*" "$(out mark "$(m 0x41)")"; note "$(out mark "$(m 0x41)")"
  check "v$f probe 1 + SO_BINDTODEVICE wana, empty path table" ".*" "$(out mark "$(m 0x41)" oif wana)"; note "$(out mark "$(m 0x41)" oif wana)"
  nsr ip $fl route add unreachable default table $T metric 200 proto $PROTO
  check "v$f SO_BINDTODEVICE wana, A not in balancing, unreachable route in balancing table" ".*" "$(out oif wana)"; note "$(out oif wana)"
  nsr ip $fl route del unreachable default table $T metric 200 proto $PROTO
  balance $f
  check "v$f unbound, empty balancing -> final guard (main default ignored)" "$UNREACH" "$(out)"
  check "v$f SO_BINDTODEVICE wana, all FTR tables empty" ".*" "$(out oif wana)"; note "$(out oif wana)"
  check "v$f forwarded, empty balancing -> final guard" "$UNREACH" "$(fwd mark 0)"
  path_route $f 1 $((T + 1)); balance $f 1 2 3
done
summary
