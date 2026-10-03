# Shared network namespace topology for spikes S1 and S2.
# Source it after setting P (namespace prefix, e.g. "s1"). Requires root.
#
#  client --lan-- router --wana-- provA --\
#                        --wanb-- provB ---- inet (targets, servers)
#                        --wanc== provC --/   (wanc: GRE over ulc, IFF_POINTOPOINT)
#                        --wanx-- leak        (OS default route with the best metric;
#                                              any packet arriving there is a leak)
#
# Uplink ids: 1 = wana, 2 = wanb, 3 = wanc. Router addresses:
#   wana 192.0.2.2/24 gw 192.0.2.1        2001:db8:a::2/64 gw fe80::1
#   wanb 198.51.100.2/24 gw 198.51.100.1  2001:db8:b::2/64 gw fe80::1
#   wanc 203.0.113.2 peer 203.0.113.1     2001:db8:c::2/64 gw fe80::1 (peer link-local)
#   wanx 100.127.0.2/24 gw .1             2001:db8:dead::2/64 gw 2001:db8:dead::1
#   lan  10.1.0.1/24                      fd00:1::1/64
# client 10.1.0.2, fd00:1::2. Internet servers: any address of 198.18.100.0/24
# and 2001:db8:100::/64 (port 7, peer.py serve) plus the default probe targets.

: "${P:?set P to the namespace prefix}"
LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PEER="python3 $LIB_DIR/peer.py"

# FTR structural settings (defaults of SPEC.md §11.2).
B=${B:-1000}             # rule_priority_base
T=${T:-1000}             # table_base
PROTO=${PROTO:-249}      # route_protocol
SHIFT=${SHIFT:-16}       # trailing zeros of fwmark_mask
MASK=$(printf '0x%08x' $(( 0xff << SHIFT )))
NOTMASK=$(printf '0x%08x' $(( ~(0xff << SHIFT) & 0xffffffff )))
CLASS=$(printf '0x%08x' $(( 0xc0 << SHIFT )))
enc() { printf '0x%08x' $(( $1 << SHIFT )); }

declare -A IFACE=([1]=wana [2]=wanb [3]=wanc)
declare -A GW4=([1]=192.0.2.1 [2]=198.51.100.1 [3]=)
declare -A SRC4=([1]=192.0.2.2 [2]=198.51.100.2 [3]=203.0.113.2)
declare -A GW6=([1]=fe80::1 [2]=fe80::1 [3]=fe80::1)
declare -A SRC6=([1]=2001:db8:a::2 [2]=2001:db8:b::2 [3]=2001:db8:c::2)
declare -A WEIGHT=([1]=1 [2]=1 [3]=1)

nsr() { ip netns exec "$P-r" "$@"; }
nsc() { ip netns exec "$P-c" "$@"; }
nsi() { ip netns exec "$P-i" "$@"; }
nsx() { ip netns exec "$P-x" "$@"; }
nsp() { local n=$1; shift; ip netns exec "$P-$n" "$@"; }

sysctls() { local ns=$1; shift; for kv in "$@"; do ip netns exec "$ns" sysctl -qw "$kv"; done; }

veth() { # veth NS_A IF_A NS_B IF_B
  ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
  ip -n "$1" link set "$2" up
  ip -n "$3" link set "$4" up
}

topo_down() {
  local n
  for n in r c i a b C x; do
    ip netns pids "$P-$n" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$P-$n" 2>/dev/null || true
  done
}

topo_up() {
  topo_down
  local n
  for n in r c i a b C x; do
    ip netns add "$P-$n"
    ip -n "$P-$n" link set lo up
    sysctls "$P-$n" net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
      net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0 \
      net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
  done
  # The client is a host, not a router.
  sysctls "$P-c" net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0

  veth "$P-c" lan "$P-r" lan
  veth "$P-r" wana "$P-a" cust
  veth "$P-r" wanb "$P-b" cust
  veth "$P-r" ulc "$P-C" ulc
  veth "$P-r" wanx "$P-x" sink
  veth "$P-a" core "$P-i" pa
  veth "$P-b" core "$P-i" pb
  veth "$P-C" core "$P-i" pc

  # client
  ip -n "$P-c" addr add 10.1.0.2/24 dev lan
  ip -n "$P-c" addr add fd00:1::2/64 dev lan
  ip -n "$P-c" route add default via 10.1.0.1
  ip -n "$P-c" -6 route add default via fd00:1::1

  # router
  ip -n "$P-r" addr add 10.1.0.1/24 dev lan
  ip -n "$P-r" addr add fd00:1::1/64 dev lan
  ip -n "$P-r" addr add 192.0.2.2/24 dev wana
  ip -n "$P-r" addr add 2001:db8:a::2/64 dev wana
  ip -n "$P-r" addr add 198.51.100.2/24 dev wanb
  ip -n "$P-r" addr add 2001:db8:b::2/64 dev wanb
  ip -n "$P-r" addr add 10.255.3.2/30 dev ulc
  ip -n "$P-r" link add wanc type gre local 10.255.3.2 remote 10.255.3.1 ttl 64
  ip -n "$P-r" link set wanc addrgenmode none
  ip -n "$P-r" link set wanc up
  ip -n "$P-r" addr add 203.0.113.2 peer 203.0.113.1 dev wanc
  ip -n "$P-r" addr add 2001:db8:c::2/64 dev wanc
  ip -n "$P-r" addr add fe80::2/64 dev wanc
  ip -n "$P-r" addr add 100.127.0.2/24 dev wanx
  ip -n "$P-r" addr add 2001:db8:dead::2/64 dev wanx
  local i
  for i in wana wanb wanc; do
    sysctls "$P-r" "net.ipv4.conf.$i.rp_filter=2" "net.ipv4.conf.$i.src_valid_mark=1"
  done
  sysctls "$P-r" net.ipv4.fib_multipath_hash_policy=1 net.ipv6.fib_multipath_hash_policy=1

  # providers: A and B on a LAN segment, C on GRE; each routes to inet
  ip -n "$P-a" addr add 192.0.2.1/24 dev cust
  ip -n "$P-a" addr add 2001:db8:a::1/64 dev cust
  ip -n "$P-a" addr add fe80::1/64 dev cust
  ip -n "$P-b" addr add 198.51.100.1/24 dev cust
  ip -n "$P-b" addr add 2001:db8:b::1/64 dev cust
  ip -n "$P-b" addr add fe80::1/64 dev cust
  ip -n "$P-C" addr add 10.255.3.1/30 dev ulc
  ip -n "$P-C" link add tun type gre local 10.255.3.1 remote 10.255.3.2 ttl 64
  ip -n "$P-C" link set tun addrgenmode none
  ip -n "$P-C" link set tun up
  ip -n "$P-C" addr add 203.0.113.1 peer 203.0.113.2 dev tun
  ip -n "$P-C" addr add 2001:db8:c::1/64 dev tun
  ip -n "$P-C" addr add fe80::1/64 dev tun
  local k p
  for k in 1 2 3; do
    p=$(echo a b C | cut -d' ' -f$k)
    ip -n "$P-$p" addr add "198.18.$k.2/30" dev core
    ip -n "$P-$p" addr add "2001:db8:ff0$k::2/64" dev core
    ip -n "$P-$p" route add default via "198.18.$k.1"
    ip -n "$P-$p" -6 route add default via "2001:db8:ff0$k::1"
    ip -n "$P-i" addr add "198.18.$k.1/30" dev "p$(echo a b c | cut -d" " -f$k)"
    ip -n "$P-i" addr add "2001:db8:ff0$k::1/64" dev "p$(echo a b c | cut -d" " -f$k)"
  done
  ip -n "$P-i" route add 192.0.2.0/24 via 198.18.1.2
  ip -n "$P-i" route add 198.51.100.0/24 via 198.18.2.2
  ip -n "$P-i" route add 203.0.113.0/24 via 198.18.3.2
  ip -n "$P-i" -6 route add 2001:db8:a::/48 via 2001:db8:ff01::2
  ip -n "$P-i" -6 route add 2001:db8:b::/48 via 2001:db8:ff02::2
  ip -n "$P-i" -6 route add 2001:db8:c::/48 via 2001:db8:ff03::2
  ip -n "$P-C" route add 203.0.113.0/24 dev tun
  ip -n "$P-C" -6 route add 2001:db8:c::/48 dev tun

  # internet: probe targets and AnyIP server ranges
  ip -n "$P-i" link add tg type dummy
  ip -n "$P-i" link set tg up
  for a in 1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222; do ip -n "$P-i" addr add "$a/32" dev tg; done
  for a in 2606:4700:4700::1111 2001:4860:4860::8888 2620:fe::fe; do ip -n "$P-i" addr add "$a/128" dev tg; done
  ip -n "$P-i" route add local 198.18.100.0/24 dev lo
  ip -n "$P-i" -6 route add local 2001:db8:100::/64 dev lo
  nsi sysctl -qw net.ipv6.ip_nonlocal_bind=1
  ip netns exec "$P-i" $PEER serve >/dev/null 2>&1 &

  # leak sink: answers nothing, counts everything that is not ARP/ND/MLD
  ip -n "$P-x" addr add 100.127.0.1/24 dev sink
  ip -n "$P-x" addr add 2001:db8:dead::1/64 dev sink
  nsx nft -f - <<'EOF'
table inet leak {
  counter v4 {}
  counter v6 {}
  chain in {
    type filter hook prerouting priority 0; policy drop;
    meta nfproto ipv4 counter name v4
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report, mld2-listener-report } accept
    meta nfproto ipv6 counter name v6
  }
}
EOF

  # OS default routes in main, as DHCP/RA would install them; wanx wins.
  ip -n "$P-r" route add default via 100.127.0.1 dev wanx metric 10
  ip -n "$P-r" route add default via 192.0.2.1 dev wana metric 1024
  ip -n "$P-r" route add default via 198.51.100.1 dev wanb metric 1025
  ip -n "$P-r" route add default dev wanc metric 1026
  ip -n "$P-r" -6 route add default via 2001:db8:dead::1 dev wanx metric 10
  ip -n "$P-r" -6 route add default via fe80::1 dev wana metric 1024
  ip -n "$P-r" -6 route add default via fe80::1 dev wanb metric 1025
  ip -n "$P-r" -6 route add default via fe80::1 dev wanc metric 1026
  sleep 0.5
}

leaks() { # prints "v4 v6" packet counts seen by the leak sink
  nsx nft -j list counters table inet leak |
    python3 -c 'import json,sys; d={o["counter"]["name"]:o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}; print(d["v4"], d["v6"])'
}
leaks_reset() { nsx nft reset counters table inet leak >/dev/null; }

# ---------------------------------------------------------------- FTR artifacts
fam_flag() { [ "$1" = 6 ] && echo -6 || echo -4; }
r_rule() { local f=$1; shift; nsr ip "$(fam_flag "$f")" rule add "$@" protocol "$PROTO"; }
r_rule_del() { local f=$1; shift; nsr ip "$(fam_flag "$f")" rule del "$@" protocol "$PROTO"; }

path_route() { # path_route FAM ID TABLE  (replace)
  local f=$1 id=$2 tb=$3
  if [ "$f" = 4 ]; then
    if [ -n "${GW4[$id]}" ]; then
      nsr ip -4 route replace default via "${GW4[$id]}" dev "${IFACE[$id]}" src "${SRC4[$id]}" table "$tb" metric 100 proto "$PROTO"
    else
      nsr ip -4 route replace default dev "${IFACE[$id]}" src "${SRC4[$id]}" table "$tb" metric 100 proto "$PROTO"
    fi
  else
    nsr ip -6 route replace default via "${GW6[$id]}" dev "${IFACE[$id]}" src "${SRC6[$id]}" table "$tb" metric 100 proto "$PROTO"
  fi
}
route_del() { nsr ip "$(fam_flag "$1")" route del default table "$2" metric 100 proto "$PROTO" 2>/dev/null || true; }

balance() { # balance FAM ID... (empty list withdraws the route)
  local f=$1; shift
  if [ $# -eq 0 ]; then route_del "$f" "$T"; return; fi
  local nh=() id
  for id in "$@"; do
    if [ "$f" = 4 ]; then
      if [ -n "${GW4[$id]}" ]; then nh+=(nexthop via "${GW4[$id]}" dev "${IFACE[$id]}" weight "${WEIGHT[$id]}")
      else nh+=(nexthop dev "${IFACE[$id]}" weight "${WEIGHT[$id]}"); fi
    else
      nh+=(nexthop via "${GW6[$id]}" dev "${IFACE[$id]}" weight "${WEIGHT[$id]}")
    fi
  done
  nsr ip "$(fam_flag "$f")" route replace default table "$T" metric 100 proto "$PROTO" "${nh[@]}"
}

# Rules of FR-ROUTE-3, one function per row.
rule_probe()      { r_rule "$1" pref $((B + $2)) fwmark "$(enc $((0x40 + $2)))/$MASK" lookup $((T + $2)); }
guard_probe()     { r_rule "$1" pref $((B + 64)) fwmark "$(enc 0x40)/$CLASS" unreachable; }
rule_main()       { r_rule "$1" pref $((B + 100)) lookup main suppress_prefixlength 0; }
rule_path()       { r_rule "$1" pref $((B + 200 + $2)) fwmark "$(enc "$2")/$MASK" lookup $((T + $2)); }
guard_path()      { local k; for k in 0 1 2 3 4 5; do r_rule "$1" pref $((B + 264)) fwmark "$(enc $((1 << k)))/$(enc $((0xc0 + (1 << k))))" unreachable; done; }
rule_polbal()     { r_rule "$1" pref $((B + 300 + $2)) fwmark "$(enc $((0x80 + $2)))/$MASK" lookup $((T + 64 + $2)); }
rule_polblk()     { r_rule "$1" pref $((B + 400 + $2)) fwmark "$(enc $((0xc0 + $2)))/$MASK" lookup $((T + 128 + $2)); }
guard_polblk()    { r_rule "$1" pref $((B + 464)) fwmark "$(enc 0xc0)/$CLASS" unreachable; }
rule_from()       { r_rule "$1" pref $((B + 500 + $2)) from "$3" fwmark "0/$MASK" lookup $((T + $2)); }
guard_from()      { r_rule "$1" pref $((B + 564)) from "$2" fwmark "0/$MASK" unreachable; }
rule_balance()    { r_rule "$1" pref $((B + 600)) lookup "$T"; }
guard_final()     { r_rule "$1" pref $((B + 699)) unreachable; }

ftr_src() { [ "$1" = 4 ] && echo "${SRC4[$2]}" || echo "${SRC6[$2]}"; }

# Cold installation (FR-REC-1 steps 3-6) for FAM over uplink ids; the
# balancing table gets all ids. STEP_HOOK, if set, runs after every step.
ftr_install() {
  local f=$1; shift
  local id
  hook() { [ -z "${STEP_HOOK:-}" ] || "$STEP_HOOK" "$f" "$1"; }
  for id in "$@"; do path_route "$f" "$id" $((T + id)); path_route "$f" "$id" $((T + 64 + id)); path_route "$f" "$id" $((T + 128 + id)); done
  balance "$f" "$@"; hook routes
  guard_probe "$f"; guard_path "$f"; guard_polblk "$f"; hook class-guards
  for id in "$@"; do rule_probe "$f" "$id"; done; hook probe-rules
  rule_main "$f"; hook main-bypass
  for id in "$@"; do rule_path "$f" "$id"; done; hook path-rules
  for id in "$@"; do rule_polbal "$f" "$id"; rule_polblk "$f" "$id"; done; hook policy-rules
  for id in "$@"; do rule_from "$f" "$id" "$(ftr_src "$f" "$id")"; guard_from "$f" "$(ftr_src "$f" "$id")"; done; hook from-rules
  rule_balance "$f"; hook balancing-rule
  guard_final "$f"; hook final-guard
}

# Remove every FTR rule and route of FAM (by protocol and ranges).
ftr_flush() {
  local f=$1 fl
  fl=$(fam_flag "$f")
  nsr ip "$fl" rule flush protocol "$PROTO" 2>/dev/null || true
  # 'ip rule flush' keeps nothing tagged with the protocol; double-check.
  local tb
  for tb in $(seq "$T" $((T + 191))); do nsr ip "$fl" route flush table "$tb" 2>/dev/null || true; done
}

# --------------------------------------------------------- nftables (§4.7 draft)
# ftr_nft UPLINK_IDS... -- managed table with the mark lifecycle; downlink "lan".
# Policies are passed through NFT_POLICIES (raw nft statements for the
# prerouting chain, already encoded).
ftr_nft_text() {
  local id
  echo "table inet fault_tolerant_router {"
  echo "  chain prerouting {"
  echo "    type filter hook prerouting priority -150; policy accept;"
  for id in $(seq 1 63); do
    echo "    ct mark & $MASK == $(enc "$id") meta mark set meta mark & $NOTMASK | $(enc "$id") return"
  done
  for id in "$@"; do
    echo "    iifname \"${IFACE[$id]}\" ct direction original ct mark set ct mark & $NOTMASK | $(enc "$id") meta mark set meta mark & $NOTMASK | $(enc "$id") return"
  done
  echo "${NFT_POLICIES:-}"
  echo "  }"
  echo "  chain output {"
  echo "    type route hook output priority -150; policy accept;"
  echo "    meta mark & $CLASS == $(enc 0x40) return"
  for id in $(seq 1 63); do
    echo "    ct mark & $MASK == $(enc "$id") meta mark set meta mark & $NOTMASK | $(enc "$id") return"
  done
  echo "  }"
  echo "  chain postrouting {"
  echo "    type filter hook postrouting priority -150; policy accept;"
  echo "    meta mark & $CLASS == $(enc 0x40) return"
  echo "    ct mark & $MASK != 0 return"
  for id in "$@"; do
    echo "    oifname \"${IFACE[$id]}\" ct mark set ct mark & $NOTMASK | $(enc "$id") meta mark set meta mark & $NOTMASK | $(enc "$id") return"
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
ftr_nft() {
  { echo "add table inet fault_tolerant_router"; echo "delete table inet fault_tolerant_router"; ftr_nft_text "$@"; } | nsr nft -f -
}
ftr_nft_del() { nsr nft delete table inet fault_tolerant_router 2>/dev/null || true; }

# ------------------------------------------------------------------ assertions
PASS=0; FAIL=0
check() { # check DESCRIPTION EXPECTED ACTUAL  (EXPECTED is an ERE matched against ACTUAL)
  if [[ "$3" =~ $2 ]]; then PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"
  else FAIL=$((FAIL + 1)); printf 'FAIL %s\n     expected /%s/\n     got      %s\n' "$1" "$2" "$3"; fi
}
note() { printf '     %s\n' "$*"; }
summary() { printf '\n%s: %d passed, %d failed (kernel %s, %s)\n' "${0##*/}" "$PASS" "$FAIL" "$(uname -r)" "$(nft --version)"; [ "$FAIL" -eq 0 ]; }

# One-line route lookup result: "via GW dev IF table T" or the error.
rget() { nsr ip "$@" 2>&1 | head -1 | sed -E 's/ +/ /g; s/ uid [0-9]+//; s/ cache.*//'; }

# Which uplink did the internet see? (masqueraded peer address -> uplink name)
peer_uplink() {
  sed -e 's/192\.0\.2\.2/A/g; s/198\.51\.100\.2/B/g; s/203\.0\.113\.2/C/g' \
      -e 's/2001:db8:a::2/A/g; s/2001:db8:b::2/B/g; s/2001:db8:c::2/C/g'
}

# ---------------------------------------------------- egress observation matrix
# Counts, after NAT, the UDP probes of 'matrix' per egress interface:
# dport 9 = forwarded from the client, dport 10 = originated by the router.
obs_up() {
  local k o
  {
    echo "table inet obs {"
    for k in f4 f6 r4 r6; do for o in wana wanb wanc wanx; do echo "  counter ${k}_$o {}"; done; done
    echo "  chain post {"
    echo "    type filter hook postrouting priority 300; policy accept;"
    for k in f4 f6 r4 r6; do
      for o in wana wanb wanc wanx; do
        echo "    meta nfproto ipv${k:1} udp dport $([ "${k:0:1}" = f ] && echo 9 || echo 10) oifname \"$o\" counter name ${k}_$o"
      done
    done
    echo "  }"
    echo "}"
  } | nsr nft -f -
}
# The next source port is kept in a file: matrix usually runs in $(...).
MATRIX_SPORT_FILE=/tmp/$P-matrix-sport
echo 30000 >"$MATRIX_SPORT_FILE"
# matrix [N] -> "f4 A/B/C/X/lost f6 ... r4 ... r6 ..." for N datagrams per kind,
# each a new flow (fresh source port, destination cycling over 20 addresses).
matrix() {
  local n=${1:-20} d4=() d6=() i MATRIX_SPORT
  MATRIX_SPORT=$(cat "$MATRIX_SPORT_FILE")
  for i in $(seq 1 20); do d4+=("198.18.100.$((100 + i))"); d6+=("2001:db8:100::$((100 + i))"); done
  nsr nft reset counters table inet obs >/dev/null
  nsc $PEER send "${d4[@]}" --port 9 --count "$n" --sport "$MATRIX_SPORT" >/dev/null
  nsc $PEER send "${d6[@]}" --port 9 --count "$n" --sport "$MATRIX_SPORT" >/dev/null
  nsr $PEER send "${d4[@]}" --port 10 --count "$n" --sport "$MATRIX_SPORT" >/dev/null
  nsr $PEER send "${d6[@]}" --port 10 --count "$n" --sport "$MATRIX_SPORT" >/dev/null
  i=$((MATRIX_SPORT + n)); [ $i -lt 64000 ] || i=30000; echo $i >"$MATRIX_SPORT_FILE"
  sleep 0.2
  nsr nft -j list counters table inet obs | python3 -c '
import json, sys
n = int(sys.argv[1])
c = {o["counter"]["name"]: o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}
out = []
for k in ("f4", "f6", "r4", "r6"):
    v = [c[f"{k}_wan{x}"] for x in "abcx"]
    out.append("%s %d/%d/%d/%d/%d" % (k, *v, n - sum(v)))
print(" ".join(out))' "$n"
}
