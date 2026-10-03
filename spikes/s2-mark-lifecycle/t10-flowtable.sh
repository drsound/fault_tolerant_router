#!/usr/bin/env bash
# S2 / FR-CT-2, AS-33: software flowtables (flow add @ft in an administrator's
# forward chain) and the mark lifecycle. For an outbound flow (LAN host via A)
# and an inbound flow (port forwarding through B), observed after FTR's chains
# (chk), at the egress hook of every interface (packet marks as they leave) and
# in conntrack (offload flag, conntrack mark): whether offloaded packets still
# traverse FTR's chains, which mark they leave with, and what happens to
# pinning when the active set changes and when the pinned path stops being
# ready. Flowtable variants: none (baseline), LAN and uplinks, downlinks only
# (LAN and a second downlink "dmz"); wildcard and missing device names. Both
# families.
set -euo pipefail
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down; ip netns del $P-d 2>/dev/null || true' EXIT
topo_up
# Second downlink: host 10.2.0.2 / fd00:2::2 behind router interface dmz.
ip netns del "$P-d" 2>/dev/null || true
ip netns add "$P-d"; ip -n "$P-d" link set lo up
sysctls "$P-d" net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
veth "$P-r" dmz "$P-d" lan
ip -n "$P-r" addr add 10.2.0.1/24 dev dmz; ip -n "$P-r" addr add fd00:2::1/64 dev dmz
ip -n "$P-d" addr add 10.2.0.2/24 dev lan; ip -n "$P-d" addr add fd00:2::2/64 dev lan
ip -n "$P-d" route add default via 10.2.0.1; ip -n "$P-d" -6 route add default via fd00:2::1
for f in 4 6; do ftr_install $f 1 2 3; done
portfwd_up
ip netns exec "$P-c" $PEER serve >/dev/null 2>&1 &
ip netns exec "$P-d" $PEER serve >/dev/null 2>&1 &
s2_nft 1 2 3
sleep 0.5

# Administrator's flowtable over DEVICES (none: no flowtable).
ft_up() {
  nsr nft delete table inet adminft 2>/dev/null || true
  [ "$1" = none ] && return
  nsr nft -f - <<EOF
table inet adminft {
  flowtable ft { hook ingress priority 0; devices = { $1 }; }
  chain fastpath {
    type filter hook forward priority 0; policy accept;
    meta l4proto { tcp, udp } flow add @ft
  }
}
EOF
}
# Egress counters of the test flow (its unique client port at either end) per
# interface, split into "FTR field empty" (z) and "FTR field set" (m).
EGDEV="wana wanb wanc lan dmz"
eg_up() {
  local d
  nsr nft delete table netdev eg 2>/dev/null || true
  {
    echo "table netdev eg {"
    for d in $EGDEV; do echo "  counter ${d}_z {}"; echo "  counter ${d}_m {}"; done
    for d in $EGDEV; do
      echo "  chain e_$d {"
      echo "    type filter hook egress device \"$d\" priority 0; policy accept;"
      echo "    tcp sport $1 meta mark & $MASK == 0 counter name ${d}_z"
      echo "    tcp dport $1 meta mark & $MASK == 0 counter name ${d}_z"
      echo "    tcp sport $1 meta mark & $MASK != 0 counter name ${d}_m"
      echo "    tcp dport $1 meta mark & $MASK != 0 counter name ${d}_m"
      echo "  }"
    done
    echo "}"
  } | nsr nft -f -
}
eg() { nsr nft -j list counters table netdev eg | python3 -c '
import json, sys
c = {o["counter"]["name"]: o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}
print(" ".join(f"{k}={v}" for k, v in sorted(c.items()) if v))'; }
# ICMP destination unreachable messages sent by the router so far
unr_now() {
  if [ "$1" = 4 ]; then nsr awk '/^Icmp:/ { if (++n == 1) { for (i = 1; i <= NF; i++) if ($i == "OutDestUnreachs") k = i } else print $k }' /proc/net/snmp
  else nsr awk '$1 == "Icmp6OutDestUnreachs" { print $2 }' /proc/net/snmp6; fi
}
# snap FAM PORT PEER: one line with the packets of the flow seen by FTR's
# chains (both directions), egress counts, the conntrack offload flag and FTR
# value, the ICMP unreachables sent by the router and the neighbour entry of
# PEER on the router; counters are reset, so each snapshot covers one phase.
snap() {
  local c e o u n
  c=$(chk); e=$(eg); u=$(unr_now "$1")
  o=$(nsr conntrack -L -f "ipv$1" -p tcp --sport "$2" 2>/dev/null | head -1)
  n=$(nsr ip "-$1" neigh show to "$3" 2>/dev/null | awk '{ print $2 "_" $3 "_" $NF }' | head -1)
  nsr nft reset counters table inet chk >/dev/null; nsr nft reset counters table netdev eg >/dev/null
  echo "ftr_pre=$(( $(cval "$c" o_pre_all) + $(cval "$c" r_pre_all) )) ftr_post=$(( $(cval "$c" o_post_all) + $(cval "$c" r_post_all) )) $e offload=$(echo "$o" | grep -c OFFLOAD || true) ct=$(echo "$o" | grep -o 'mark=[0-9]*' | cut -d= -f2 | while read -r m; do printf '0x%x' $(( m >> SHIFT & 0xff )); done) unreach=$(( u - $(cat "/tmp/$P-unr") )) neigh=${n:-none}"
  echo "$u" >"/tmp/$P-unr"
}
# flow FAM KIND NEWSET NOTREADY: long flow (KIND out: LAN host via the active
# set; in: internet host through B's port forwarding; dmz: LAN host to the dmz
# host) from a unique client port; then the active set becomes NEWSET, then
# path NOTREADY loses its route (not ready). One snapshot per phase, then the
# flow summary.
echo 45000 >"/tmp/$P-sport"
flow() {
  local f=$1 kind=$2 newset=$3 nr=$4 lp dst port cmdns peer sp
  sp=$(cat "/tmp/$P-sport"); echo $((sp + 1)) >"/tmp/$P-sport"
  if [ "$kind" = out ]; then
    cmdns=c; port=7; [ $f = 4 ] && dst=198.18.100.95 || dst=2001:db8:100::95; peer=$dst
  elif [ "$kind" = in ]; then
    cmdns=i; port=8007; [ $f = 4 ] && dst=198.51.100.2 || dst=2001:db8:b::2
    [ $f = 4 ] && peer=198.18.2.1 || peer=2001:db8:ff02::1
  else
    cmdns=c; port=7; [ $f = 4 ] && dst=10.2.0.2 || dst=fd00:2::2; peer=$dst
  fi
  nsr conntrack -F >/dev/null 2>&1 || true
  nsr ip "-$f" neigh flush to "$peer" 2>/dev/null || true
  chk_up "meta nfproto ipv$f meta l4proto tcp ct original proto-src $sp"
  eg_up "$sp"
  unr_now "$f" >"/tmp/$P-unr"
  rm -f "/tmp/$P-ready"
  ip netns exec "$P-$cmdns" $PEER long "$dst" --port $port --sport "$sp" --period 0.1 --fail-after 2 --ready "/tmp/$P-ready" >"/tmp/$P-long" &
  lp=$!
  for _ in $(seq 1 30); do [ -e "/tmp/$P-ready" ] && break; sleep 0.1; done
  sleep 1
  echo "start   $(snap "$f" "$sp" "$peer")"
  sleep 1.5
  echo "steady  $(snap "$f" "$sp" "$peer")"
  balance "$f" $newset
  sleep 1.5
  echo "active  $(snap "$f" "$sp" "$peer")"
  [ -z "$nr" ] || route_del "$f" $((T + nr))
  sleep 2.5
  echo "notrdy  $(snap "$f" "$sp" "$peer")"
  kill "$lp" 2>/dev/null || true; wait "$lp" 2>/dev/null || true
  echo "result  $(cat "/tmp/$P-long")"
  [ -z "$nr" ] || path_route "$f" "$nr" $((T + nr))
  balance "$f" 1 2 3
  sleep 0.5
}
line() { echo "$1" | grep "^$2 "; }
w() { local x; x=$(line "$1" "$2"); cval "${x#* }" "$3"; }

for variant in none "lan, wana, wanb" "lan, dmz"; do
  echo "######## flowtable devices: $variant"
  ft_up "$variant"
  [ "$variant" = none ] || note "$(nsr nft list flowtables | tr -s ' \t\n' ' ')"
  for f in 4 6; do
    echo "== IPv$f outbound flow via A; active set {A} -> {B}; then A not ready"
    balance $f 1
    r=$(flow $f out 2 1); note "${r//$'\n'/$'\n'     }"
    case $variant in
      none)
        check "v$f baseline: every packet traverses FTR's chains" "^[1-9]" "$(w "$r" steady ftr_pre)"
        check "v$f baseline: packets leave A with the FTR field set" "^[1-9][0-9]* 0$" "$(w "$r" steady wana_m) $(w "$r" steady wana_z)"
        ;;
      "lan, wana, wanb")
        check "v$f offloaded: conntrack entry flagged OFFLOAD, path 1" "^1 0x1$" "$(w "$r" steady offload) $(w "$r" steady ct)"
        check "v$f offloaded: no packet traverses FTR's chains" "^0 0$" "$(w "$r" steady ftr_pre) $(w "$r" steady ftr_post)"
        check "v$f offloaded: packets leave A with the FTR field empty" "^0 [1-9]" "$(w "$r" steady wana_m) $(w "$r" steady wana_z)"
        check "v$f offloaded: after the active set change packets still leave through A only" "^[1-9][0-9]* 0$" "$(( $(w "$r" active wana_m) + $(w "$r" active wana_z) )) $(( $(w "$r" active wanb_m) + $(w "$r" active wanb_z) ))"
        ;;
      "lan, dmz")
        check "v$f downlinks only: conntrack entry flagged OFFLOAD" "^1 0x1$" "$(w "$r" steady offload) $(w "$r" steady ct)"
        check "v$f downlinks only: original packets (LAN ingress) bypass FTR's chains, replies do not" "^[1-9][0-9]* [1-9][0-9]* [1-9]" "$(w "$r" steady ftr_pre) $(w "$r" steady wana_z) $(w "$r" steady lan_m)"
        ;;
    esac
    check "v$f after A stops being ready the pinned flow fails (path guard), never moved to B" '"error": "(timeout|ETIMEDOUT)"' "$(line "$r" result)"
    echo "== IPv$f inbound flow through B (port forwarding); active set {A} -> {C}; then B not ready"
    balance $f 1
    r=$(flow $f in 3 2); note "${r//$'\n'/$'\n'     }"
    case $variant in
      none) check "v$f baseline: replies leave B with the FTR field set" "^[1-9]" "$(w "$r" steady wanb_m)";;
      "lan, wana, wanb")
        check "v$f offloaded: OFFLOAD, path 2, no packet in FTR's chains, replies leave B unmarked" "^1 0x2 0 0 [1-9]" "$(w "$r" steady offload) $(w "$r" steady ct) $(w "$r" steady ftr_pre) $(w "$r" steady wanb_m) $(w "$r" steady wanb_z)"
        ;;
      "lan, dmz")
        check "v$f downlinks only: replies (LAN ingress) offloaded and leave B unmarked" "^1 0x2 [1-9][0-9]* 0 [1-9]" "$(w "$r" steady offload) $(w "$r" steady ct) $(w "$r" steady ftr_pre) $(w "$r" steady wanb_m) $(w "$r" steady wanb_z)"
        ;;
    esac
    check "v$f after B stops being ready the pinned inbound flow fails, never moved" '"error": "(timeout|ETIMEDOUT)"' "$(line "$r" result)"
    if [ "$variant" = "lan, dmz" ]; then
      echo "== IPv$f flow between the downlinks (LAN -> dmz)"
      r=$(flow $f dmz "1 2 3" ""); note "${r//$'\n'/$'\n'     }"
      check "v$f LAN -> dmz offloaded in both directions, no packet in FTR's chains" "^1 0 0" "$(w "$r" steady offload) $(w "$r" steady ftr_pre) $(w "$r" steady ftr_post)"
    fi
  done
done

echo "######## flowtable device names: JSON form, wildcard, missing device"
ft_up "lan"
note "JSON with one device: $(nsr nft -j list flowtables | python3 -c 'import json, sys; print(" ".join(json.dumps(o["flowtable"]["dev"]) for o in json.load(sys.stdin)["nftables"] if "flowtable" in o))')"
for devs in 'lan, "wan*"' 'lan, "nosuch0"'; do
  if out=$(ft_up "$devs" 2>&1); then
    note "{ $devs } accepted: $(nsr nft -j list flowtables | python3 -c 'import json, sys; print(" ".join(json.dumps(o["flowtable"]["dev"]) for o in json.load(sys.stdin)["nftables"] if "flowtable" in o))')"
    if [ "$devs" = 'lan, "wan*"' ]; then
      balance 4 1
      r=$(flow 4 out 1 ""); note "${r//$'\n'/$'\n'     }"
      check "quoted \"wan*\" is a literal device name: replies from wana are not offloaded" "^1 [1-9][0-9]* [1-9]" "$(w "$r" steady offload) $(w "$r" steady ftr_pre) $(w "$r" steady wana_z)"
    else
      nsr ip link add nosuch0 type dummy
      check "a flowtable hook is attached to the missing device once it appears" "nf_flow_offload" "$(nsr nft list hooks 2>&1 | grep -A1 'device nosuch0' || true)"
      nsr ip link del nosuch0
    fi
  else
    note "{ $devs } rejected: $(echo "$out" | head -1)"
    check "{ $devs } rejected by this kernel or nftables version" "Error" "$out"
  fi
done
ft_up none
summary
