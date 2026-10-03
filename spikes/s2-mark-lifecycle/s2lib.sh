# S2 helpers, sourced after ../lib/netns.sh.
S2_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
S2TOOL="python3 $S2_DIR/s2tool.py"

# Refined §4.7 ruleset. Differences from ftr_nft_text in ../lib/netns.sh:
# untracked and non-unicast packets are skipped (§4.7 last paragraph, §4.8);
# policies (S2_POLICIES, one rule per line, already encoded) end with return;
# the postrouting assignment applies only in the original direction (§4.7 3.2).
# Control experiments only: S2_NO_OUTPUT=1 omits the output chain;
# S2_NO_DIRECTION=1 omits "ct direction original" from postrouting;
# S2_NO_NONUNICAST=1 omits the non-unicast skips of both chains.
# S2_NONUNICAST_ADDR=1 adds the address-based skips proposed by t9: in
# prerouting multicast, limited and subnet-directed broadcast destinations
# (tunnels deliver them as pkttype host), in postrouting subnet-directed
# broadcast destinations of the egress interface.
s2_nft_text() {
  local id
  echo "table inet fault_tolerant_router {"
  echo "  chain prerouting {"
  echo "    type filter hook prerouting priority -150; policy accept;"
  echo "    ct state untracked return"
  [ "${S2_NO_NONUNICAST:-0}" = 1 ] || echo "    meta pkttype != host return"
  for id in $(seq 1 63); do
    echo "    ct mark & $MASK == $(enc "$id") meta mark set meta mark & $NOTMASK | $(enc "$id") return"
  done
  if [ "${S2_NONUNICAST_ADDR:-0}" = 1 ]; then
    echo "    ip daddr { 224.0.0.0/4, 255.255.255.255 } return"
    echo "    ip6 daddr ff00::/8 return"
    echo "    meta nfproto ipv4 fib daddr type broadcast return"
  fi
  for id in "$@"; do
    echo "    iifname \"${IFACE[$id]}\" ct direction original ct mark set ct mark & $NOTMASK | $(enc "$id") meta mark set meta mark & $NOTMASK | $(enc "$id") return"
  done
  [ -z "${S2_POLICIES:-}" ] || echo "$S2_POLICIES"
  echo "  }"
  if [ "${S2_NO_OUTPUT:-0}" != 1 ]; then
    echo "  chain output {"
    echo "    type route hook output priority -150; policy accept;"
    echo "    meta mark & $CLASS == $(enc 0x40) return"
    echo "    ct state untracked return"
    for id in $(seq 1 63); do
      echo "    ct mark & $MASK == $(enc "$id") meta mark set meta mark & $NOTMASK | $(enc "$id") return"
    done
    echo "  }"
  fi
  echo "  chain postrouting {"
  echo "    type filter hook postrouting priority -150; policy accept;"
  echo "    meta mark & $CLASS == $(enc 0x40) return"
  echo "    ct state untracked return"
  if [ "${S2_NO_NONUNICAST:-0}" != 1 ]; then
    echo "    ip daddr { 224.0.0.0/4, 255.255.255.255 } return"
    echo "    ip6 daddr ff00::/8 return"
  fi
  echo "    ct mark & $MASK != 0 return"
  [ "${S2_NONUNICAST_ADDR:-0}" != 1 ] || echo "    meta nfproto ipv4 fib daddr . oif type broadcast return"
  local dir="ct direction original "
  [ "${S2_NO_DIRECTION:-0}" != 1 ] || dir=
  for id in "$@"; do
    echo "    oifname \"${IFACE[$id]}\" ${dir}ct mark set ct mark & $NOTMASK | $(enc "$id") meta mark set meta mark & $NOTMASK | $(enc "$id") return"
  done
  echo "  }"
  echo "  chain nat {"
  echo "    type nat hook postrouting priority 100; policy accept;"
  for id in "$@"; do
    echo "    iifname \"lan\" oifname \"${IFACE[$id]}\" masquerade"
  done
  echo "  }"
  echo "}"
}
s2_nft() {
  { echo "add table inet fault_tolerant_router"; echo "delete table inet fault_tolerant_router"; s2_nft_text "$@"; } | nsr nft -f -
}

# policy FAMILY MATCH VALUE -> one prerouting rule (FR-POL-1, §4.7 1.3)
policy() {
  echo "    iifname \"lan\" meta nfproto ipv$1 $2 meta mark set meta mark & $NOTMASK | $(enc "$3") return"
}

# Administrator's port forwarding on every uplink: router:8007 -> client:7,
# router:8009/udp -> client:9 (closed, the client answers port unreachable).
portfwd_up() {
  nsr nft -f - <<'EOF'
table inet admin {
  chain portfwd {
    type nat hook prerouting priority -100; policy accept;
    iifname { "wana", "wanb", "wanc" } meta nfproto ipv4 tcp dport 8007 dnat ip to 10.1.0.2:7
    iifname { "wana", "wanb", "wanc" } meta nfproto ipv6 tcp dport 8007 dnat ip6 to [fd00:1::2]:7
    iifname { "wana", "wanb", "wanc" } meta nfproto ipv4 udp dport 8009 dnat ip to 10.1.0.2:9
    iifname { "wana", "wanb", "wanc" } meta nfproto ipv6 udp dport 8009 dnat ip6 to [fd00:1::2]:9
  }
}
EOF
}

# --------------------------------------------------------------- observation
# chk_up MATCH: table "chk" counting packets that match MATCH at four points,
# split by conntrack direction (o/r), by FTR field value of the packet mark (m)
# and of the conntrack mark (c), and by egress interface at the end:
#   pre  prerouting -140 (after FTR's prerouting chain)
#   out  output -140 (after FTR's output route chain)
#   post postrouting -140 (after FTR's postrouting chain, before NAT)
#   fin  postrouting 300 (after NAT)
CHK_VALUES="0 1 2 3 65 66 129 193"
chk_up() {
  local match=$1 h d k v o hook prio
  nsr nft delete table inet chk 2>/dev/null || true
  {
    echo "table inet chk {"
    for h in pre out post fin; do for d in o r; do
      echo "  counter ${d}_${h}_all {}"
      for k in m c; do for v in $CHK_VALUES; do echo "  counter ${d}_${h}_${k}${v} {}"; done; done
      for o in wana wanb wanc wanx lan; do echo "  counter ${d}_${h}_if_$o {}"; done
    done; done
    for h in pre out post fin; do
      case $h in pre) hook="filter hook prerouting"; prio=-140;; out) hook="filter hook output"; prio=-140;;
        post) hook="filter hook postrouting"; prio=-140;; fin) hook="filter hook postrouting"; prio=300;; esac
      echo "  chain $h {"
      echo "    type $hook priority $prio; policy accept;"
      for d in o r; do
        local dir; [ $d = o ] && dir=original || dir=reply
        echo "    $match ct direction $dir counter name ${d}_${h}_all"
        for v in $CHK_VALUES; do
          echo "    $match ct direction $dir meta mark & $MASK == $(enc "$v") counter name ${d}_${h}_m$v"
          echo "    $match ct direction $dir ct mark & $MASK == $(enc "$v") counter name ${d}_${h}_c$v"
        done
        if [ $h != pre ]; then for o in wana wanb wanc wanx lan; do
          echo "    $match ct direction $dir oifname \"$o\" counter name ${d}_${h}_if_$o"
        done; fi
      done
      echo "  }"
    done
    echo "}"
  } | nsr nft -f -
}
# chk: non-zero counters as "name=value" words, sorted
chk() {
  nsr nft -j list counters table inet chk | python3 -c '
import json, sys
c = {o["counter"]["name"]: o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}
print(" ".join(f"{k}={v}" for k, v in sorted(c.items()) if v))'
}
# cval WORDS NAME -> value of NAME in the output of chk (0 if absent)
cval() { local w; for w in $1; do [ "${w%%=*}" = "$2" ] && { echo "${w#*=}"; return; }; done; echo 0; }

ctmark() { # ctmark FAMILY CONNTRACK-FILTER... -> FTR field values of matching entries
  nsr conntrack -L -f "ipv$1" "${@:2}" 2>/dev/null | grep -o "mark=[0-9]*" | cut -d= -f2 |
    while read -r m; do printf '0x%x ' $(( m >> SHIFT & 0xff )); done
}
