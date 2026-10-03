#!/bin/sh
# Install or remove the FR-ROUTE-3 rule layout (SPEC v0.5) with empty FTR
# tables, as FTR would leave it with an empty active set and no ready path.
#
# Usage: ftr-rules.sh install|remove|sync|show
#   install  static rules and guards for every family in FAMILIES
#   sync     (re)derive the dynamic part from the current kernel state, as FTR
#            would: path table routes for ready paths and "from" rules with
#            source guards for local addresses (FR-DISC-2, FR-ROUTE-3)
#   remove   delete every rule and route tagged with PROTO in the ranges
#
# Environment (defaults are SPEC defaults, uplinks match the S4 topology):
#   UPLINKS="1:wana 2:wanb 3:ppp0"   id:interface pairs
#   FAMILIES="4 6"  B=1000  T=1000  PROTO=249  MASK=0x00ff0000
#   IP="ip"         prefix, e.g. "ip netns exec s4-rtr ip"
set -eu
UPLINKS=${UPLINKS:-"1:wana 2:wanb 3:ppp0"}
FAMILIES=${FAMILIES:-"4 6"}
B=${B:-1000}; T=${T:-1000}; PROTO=${PROTO:-249}; MASK=${MASK:-0x00ff0000}
IP=${IP:-ip}

shift_of() { m=$(($1)); s=0; while [ $((m & 1)) -eq 0 ]; do m=$((m >> 1)); s=$((s + 1)); done; echo $s; }
SHIFT=$(shift_of "$MASK")
enc() { printf '0x%08x' $(( ($1) << SHIFT )); }
FM="$(enc 0xff)"            # mask
CLASS="$(enc 0xc0)"         # class mask

rule() { f=$1; shift; $IP -$f rule add "$@" protocol "$PROTO"; }

install_family() {
  f=$1
  for u in $UPLINKS; do id=${u%%:*}
    rule $f priority $((B + id)) fwmark "$(enc $((0x40 + id)))/$FM" lookup $((T + id))
  done
  rule $f priority $((B + 64)) fwmark "$(enc 0x40)/$CLASS" unreachable
  rule $f priority $((B + 100)) lookup main suppress_prefixlength 0
  for u in $UPLINKS; do id=${u%%:*}
    rule $f priority $((B + 200 + id)) fwmark "$(enc "$id")/$FM" lookup $((T + id))
  done
  for k in 0 1 2 3 4 5; do
    rule $f priority $((B + 264)) fwmark "$(enc $((1 << k)))/$(enc $((0xc0 + (1 << k))))" unreachable
  done
  for u in $UPLINKS; do id=${u%%:*}
    rule $f priority $((B + 300 + id)) fwmark "$(enc $((0x80 + id)))/$FM" lookup $((T + 64 + id))
    rule $f priority $((B + 400 + id)) fwmark "$(enc $((0xc0 + id)))/$FM" lookup $((T + 128 + id))
  done
  rule $f priority $((B + 464)) fwmark "$(enc 0xc0)/$CLASS" unreachable
  rule $f priority $((B + 600)) lookup "$T"
  rule $f priority $((B + 699)) unreachable
}

remove_family() {
  f=$1
  $IP -$f rule show | awk -v lo="$B" -v hi=$((B + 699)) -F: '$1 >= lo && $1 <= hi {print $1}' | sort -u | while read -r p; do
    while $IP -$f rule del priority "$p" protocol "$PROTO" 2>/dev/null; do :; done
  done
  t=$T; while [ $t -le $((T + 191)) ]; do $IP -$f route flush table $t proto "$PROTO" 2>/dev/null || true; t=$((t + 1)); done
}

# Default route of the interface in main (FR-DISC-3, simplified: lowest metric).
gw_of() { $IP -$1 route show default dev "$2" 2>/dev/null | grep -v "proto $PROTO" | sed -n 's/.* via \([^ ]*\).*/\1/p' | head -1; }

sync_family() {
  f=$1
  # drop dynamic part: from rules, source guards, path routes
  for p in $(seq $((B + 501)) $((B + 564))); do
    while $IP -$f rule del priority "$p" protocol "$PROTO" 2>/dev/null; do :; done
  done
  for u in $UPLINKS; do id=${u%%:*}; dev=${u#*:}
    $IP -$f route flush table $((T + id)) proto "$PROTO" 2>/dev/null || true
    $IP link show "$dev" >/dev/null 2>&1 || continue
    addrs=$($IP -$f -o addr show dev "$dev" scope global 2>/dev/null | grep -v -e tentative -e dadfailed | awk '{print $4}' | cut -d/ -f1)
    [ -n "$addrs" ] || continue
    src=$($IP -$f -o addr show dev "$dev" scope global 2>/dev/null | grep -v -e tentative -e dadfailed -e temporary -e deprecated | awk '{print $4}' | cut -d/ -f1 | head -1)
    for a in $addrs; do
      rule $f priority $((B + 500 + id)) from "$a" fwmark "0/$FM" lookup $((T + id))
      rule $f priority $((B + 564)) from "$a" fwmark "0/$FM" unreachable
    done
    gw=$(gw_of $f "$dev")
    if $IP link show "$dev" | grep -q POINTOPOINT && [ "$f" = 4 ]; then
      $IP -4 route replace default dev "$dev" src "$src" metric 100 table $((T + id)) proto "$PROTO"
    elif [ -n "$gw" ] && [ -n "$src" ]; then
      $IP -$f route replace default via "$gw" dev "$dev" src "$src" metric 100 table $((T + id)) proto "$PROTO"
    fi
  done
}

case ${1:-} in
  install) for f in $FAMILIES; do install_family $f; done ;;
  remove)  for f in $FAMILIES; do remove_family $f; done ;;
  sync)    for f in $FAMILIES; do sync_family $f; done ;;
  show)    for f in $FAMILIES; do echo "== IPv$f rules"; $IP -$f rule show; t=$T; while [ $t -le $((T + 191)) ]; do r=$($IP -$f route show table $t 2>/dev/null); [ -z "$r" ] || echo "table $t: $r"; t=$((t + 1)); done; done ;;
  *) echo "usage: $0 install|remove|sync|show" >&2; exit 2 ;;
esac
