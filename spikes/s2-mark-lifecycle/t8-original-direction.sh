#!/usr/bin/env bash
# S2 / AS-50, §4.7 step 3.2: the postrouting assignment applies only in the
# original direction. A remote host behind the unmanaged interface wanx opens
# connections to the router and to a LAN host; its address is reachable only
# through the balancing table, so the replies leave through an FTR uplink.
# Those replies must not be assigned a path. Controls: outbound connections
# from the LAN are assigned in postrouting, inbound connections on an uplink in
# prerouting, probes never. Negative control without the direction condition:
# the replies are assigned the uplink and the connection becomes pinned to it.
# Both families.
set -euo pipefail
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
# Remote host R (198.18.150.5, 2001:db8:150::5) lives in the leak namespace:
# it sends through wanx and receives through a link to the internet.
nsx nft delete table inet leak
veth "$P-x" core "$P-i" px
ip -n "$P-x" addr add 198.18.9.2/30 dev core
ip -n "$P-x" addr add 2001:db8:ff09::2/64 dev core
ip -n "$P-i" addr add 198.18.9.1/30 dev px
ip -n "$P-i" addr add 2001:db8:ff09::1/64 dev px
ip -n "$P-i" route add 198.18.150.0/24 via 198.18.9.2
ip -n "$P-i" -6 route add 2001:db8:150::/48 via 2001:db8:ff09::2
ip -n "$P-x" link add rh type dummy
ip -n "$P-x" link set rh up
ip -n "$P-x" addr add 198.18.150.5/32 dev rh
ip -n "$P-x" addr add 2001:db8:150::5/128 dev rh
ip -n "$P-x" route add 10.1.0.0/24 via 100.127.0.2
ip -n "$P-x" -6 route add fd00:1::/64 via 2001:db8:dead::2
for f in 4 6; do ftr_install $f 1 2 3; done
portfwd_up
ip netns exec "$P-c" $PEER serve >/dev/null 2>&1 &
ip netns exec "$P-r" $PEER serve >/dev/null 2>&1 &
sleep 0.3
eq() { [ "$(cval "$1" "$2")" = "$(cval "$1" "$3")" ] && [ "$(cval "$1" "$2")" != 0 ] && echo yes || echo "no ($2=$(cval "$1" "$2") $3=$(cval "$1" "$3"))"; }

fam() { # sets the addresses of family $1
  if [ "$1" = 4 ]; then R=198.18.150.5; RX=100.127.0.2; CL=10.1.0.2; D=198.18.100.81; RB=198.51.100.2; T1=1.1.1.1; SA=192.0.2.2; I=ip
  else R=2001:db8:150::5; RX=2001:db8:dead::2; CL=fd00:1::2; D=2001:db8:100::81; RB=2001:db8:b::2; T1=2606:4700:4700::1111; SA=2001:db8:a::2; I=ip6; fi
}
# unmanaged FAM DST LABEL: connections from R to DST through wanx, active set {A};
# leaves the observation in $c and the conntrack marks in $m
unmanaged() {
  balance "$1" 1
  nsr conntrack -F >/dev/null 2>&1 || true
  chk_up "meta nfproto ipv$1 meta l4proto tcp ct original $I saddr $R"
  r=$(nsx $PEER conn "$2" --src "$R" --count 3 --timeout 2)
  c=$(chk); m=$(ctmark "$1" -s "$R")
  check "v$1 $3: connections from R through wanx answered" '"errors": \{\}' "$r"
  note "$c"
  check "v$1 $3: replies leave through uplink A" yes "$(eq "$c" r_fin_all r_fin_if_wana)"
}
# pinned FAM: long flow from R to the LAN host; A leaves the active set and its
# path table is emptied (A not ready). Prints the flow summary and the replies
# per uplink after the change.
pinned() {
  balance "$1" 1
  nsr conntrack -F >/dev/null 2>&1 || true
  rm -f "/tmp/$P-ready"
  ip netns exec "$P-x" $PEER long "$CL" --src "$R" --period 0.1 --fail-after 2 --ready "/tmp/$P-ready" >"/tmp/$P-long" &
  local lp=$! i
  for i in $(seq 1 30); do [ -e "/tmp/$P-ready" ] && break; sleep 0.1; done
  sleep 0.5
  chk_up "meta nfproto ipv$1 meta l4proto tcp ct original $I saddr $R"
  balance "$1" 2; route_del "$1" $((T + 1))
  sleep 3
  kill "$lp" 2>/dev/null || true; wait "$lp" 2>/dev/null || true
  local cc; cc=$(chk)
  echo "$(cat "/tmp/$P-long") replies-after-change a=$(cval "$cc" r_fin_if_wana) b=$(cval "$cc" r_fin_if_wanb)"
  path_route "$1" 1 $((T + 1)); balance "$1" 1 2 3
}

echo "######## amended generator (ct direction original in postrouting)"
s2_nft 1 2 3
check "postrouting assignment rules carry the direction condition" "^3$" "$(nsr nft list chain inet fault_tolerant_router postrouting | grep -c 'oifname .* ct direction original ct mark set')"
for f in 4 6; do
  fam $f
  echo "== IPv$f connection from an unmanaged interface to the router, replies through A"
  unmanaged $f "$RX" router
  check "v$f router: replies carry no path value after postrouting (packet and conntrack mark)" yes "$(eq "$c" r_post_all r_post_m0) $(eq "$c" r_post_all r_post_c0)"
  check "v$f router: conntrack entries carry no path value" "^(0x0 )+$" "$m"
  echo "== IPv$f connection from an unmanaged interface to a LAN host, replies forwarded through A"
  unmanaged $f "$CL" forwarded
  check "v$f forwarded: original packets never marked" yes "$(eq "$c" o_pre_all o_pre_m0)"
  check "v$f forwarded: replies carry no path value after postrouting (packet and conntrack mark)" yes "$(eq "$c" r_post_all r_post_m0) $(eq "$c" r_post_all r_post_c0)"
  check "v$f forwarded: conntrack entries carry no path value" "^(0x0 )+$" "$m"
  echo "== IPv$f long flow from R to the LAN host while A leaves the active set and becomes not ready"
  r=$(pinned $f)
  note "$r"
  check "v$f unassigned flow survives: its replies follow the balancing route to B" '"error": null.* a=0 b=[1-9]' "$r"

  echo "== IPv$f controls"
  balance $f 1
  nsr conntrack -F >/dev/null 2>&1 || true
  chk_up "meta nfproto ipv$f meta l4proto tcp ct original proto-dst 7 ct original $I saddr $CL"
  r=$(nsc $PEER conn "$D" --count 2 | peer_uplink); c=$(chk)
  check "v$f outbound from the LAN via A ($r)" '"A": 2' "$r"
  check "v$f outbound: path 1 assigned in postrouting (first packet unmarked in prerouting)" "yes [1-9]" "$(eq "$c" o_post_all o_post_c1) $(cval "$c" o_pre_m0)"
  check "v$f outbound: conntrack entries carry path 1" "^(0x1 )+$" "$(ctmark $f -p tcp --dport 7 -s "$CL")"
  chk_up "meta nfproto ipv$f meta l4proto tcp ct original proto-dst 8007"
  r=$(nsi $PEER conn "$RB" --port 8007 --count 2); c=$(chk)
  check "v$f inbound through B answered" '"errors": \{\}' "$r"
  check "v$f inbound: every original packet carries path 2 after prerouting, replies leave through B" "yes yes" "$(eq "$c" o_pre_all o_pre_m2) $(eq "$c" r_fin_all r_fin_if_wanb)"
  chk_up "meta nfproto ipv$f ct original $I daddr $T1"
  r=$(nsr $S2TOOL ping "$T1" --mark "$(enc 0x41)" --device wana --src "$SA" --count 2)
  r2=$(nsr $PEER conn "$T1" --mark "$(enc 0x41)" --device wana --src "$SA" --count 2); c=$(chk)
  check "v$f ICMP and TCP probes answered" '"lost": 0.*"errors": \{\}' "$r $r2"
  check "v$f probes keep the probe value after postrouting; replies unmarked" "yes 0" "$(eq "$c" o_post_all o_post_m65) $(cval "$c" r_pre_m1)"
  check "v$f probes: conntrack entries carry no path value" "^(0x0 )+$" "$(ctmark $f -d "$T1")"
  balance $f 1 2 3
done

echo "######## negative control: postrouting assignment without the direction condition"
S2_NO_DIRECTION=1 s2_nft 1 2 3
for f in 4 6; do
  fam $f
  echo "== IPv$f (control) connection from an unmanaged interface to the router"
  unmanaged $f "$RX" router
  check "v$f router (control): replies are assigned path 1 in postrouting" yes "$(eq "$c" r_post_all r_post_c1)"
  check "v$f router (control): conntrack entries carry path 1" "^(0x1 )+$" "$m"
  echo "== IPv$f (control) connection from an unmanaged interface to a LAN host"
  unmanaged $f "$CL" forwarded
  check "v$f forwarded (control): the first reply is assigned path 1, later packets restored" "^yes [1-9]" "$(eq "$c" r_post_all r_post_c1) $(cval "$c" o_pre_m1)"
  check "v$f forwarded (control): conntrack entries carry path 1" "^(0x1 )+$" "$m"
  echo "== IPv$f (control) long flow while A leaves the active set and becomes not ready"
  r=$(pinned $f)
  note "$r"
  check "v$f control: the flow is pinned to A and fails at the path guard" '"error": "(timeout|ETIMEDOUT|TimeoutError)".* b=0' "$r"
done
summary
