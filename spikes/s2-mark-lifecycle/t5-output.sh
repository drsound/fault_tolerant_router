#!/usr/bin/env bash
# S2 / §4.7 step 2, INV-5: a case where only the output route chain gives the
# right uplink. Provider A routes to the router an address configured on
# another interface (not a local address of any path, so no source rule
# applies); with the active set {B}, the router's replies to connections that
# arrived through A must leave through A. Control: without the output chain
# they follow the balancing route through B. Both families.
set -euo pipefail
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
nsr ip link add svc type dummy
nsr ip link set svc up
nsr ip addr add 198.18.200.1/32 dev svc
nsr ip addr add 2001:db8:200::1/128 dev svc
ip -n "$P-a" route add 198.18.200.1/32 via 192.0.2.2
ip -n "$P-a" -6 route add 2001:db8:200::1/128 via 2001:db8:a::2
ip -n "$P-i" route add 198.18.200.0/24 via 198.18.1.2
ip -n "$P-i" -6 route add 2001:db8:200::/48 via 2001:db8:ff01::2
for f in 4 6; do ftr_install $f 1 2 3; done
ip netns exec "$P-r" $PEER serve >/dev/null 2>&1 &
sleep 0.3

for variant in with-output-chain without-output-chain; do
  if [ $variant = with-output-chain ]; then s2_nft 1 2 3; else S2_NO_OUTPUT=1 s2_nft 1 2 3; fi
  for f in 4 6; do
    [ $f = 4 ] && SVC=198.18.200.1 || SVC=2001:db8:200::1
    balance $f 2
    nsr conntrack -F >/dev/null 2>&1 || true
    chk_up "meta nfproto ipv$f meta l4proto tcp ct original ip$( [ $f = 6 ] && echo 6) daddr $SVC"
    r=$(nsi $PEER conn "$SVC" --count 5 --timeout 2)
    c=$(chk)
    note "v$f $variant: $r; replies via a=$(cval "$c" r_fin_if_wana) b=$(cval "$c" r_fin_if_wanb); conntrack path $(ctmark $f -d "$SVC" | tr -s ' ' | head -c 20)"
    if [ $variant = with-output-chain ]; then
      check "v$f replies of the router leave through the arrival uplink A" "^[1-9][0-9]* 0$" "$(cval "$c" r_fin_if_wana) $(cval "$c" r_fin_if_wanb)"
    else
      check "v$f control without the output chain: replies follow balancing through B" "^0 [1-9][0-9]*$" "$(cval "$c" r_fin_if_wana) $(cval "$c" r_fin_if_wanb)"
    fi
  done
done
summary
