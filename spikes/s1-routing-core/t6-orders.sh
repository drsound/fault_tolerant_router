#!/usr/bin/env bash
# S1 / FR-REC-1, FR-REC-3, FR-REC-4, AS-27, AS-37: cold installation, uplink
# addition and removal, cleanup, step by step, with new forwarded and
# router-originated flows of both families measured after every step and
# long-lived pinned flows running across the add/remove orders.
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
obs_up
nsi $PEER serve --port 8 >/dev/null 2>&1 &
# Flow C (server port 8) is counted per egress interface: it must never leave
# through anything but wanc.
for o in wana wanb wanc wanx; do
  nsr nft add counter inet obs "fc_$o"
  nsr nft add rule inet obs post tcp dport 8 oifname "\"$o\"" counter name "fc_$o"
done
fc() { nsr nft -j list counters table inet obs | python3 -c 'import json,sys; c={o["counter"]["name"]:o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}; print(" ".join(str(c["fc_"+x]) for x in ("wana","wanb","wanc","wanx")))'; }

flow_start() { # flow_start NAME DST PORT
  rm -f "/tmp/$P-$1.ready" "/tmp/$P-$1.out"
  ip netns exec "$P-c" $PEER long "$2" --port "$3" --period 0.1 --fail-after 2 --ready "/tmp/$P-$1.ready" >"/tmp/$P-$1.out" 2>&1 &
  eval "PID_$1=$!"
  local i; for i in $(seq 1 30); do [ -e "/tmp/$P-$1.ready" ] && return 0; sleep 0.1; done
  echo "flow $1 did not start"; return 1
}
alive() { local p; eval "p=\$PID_$1"; kill -0 "$p" 2>/dev/null && echo alive || echo dead; }
flow_stop() { local p; eval "p=\$PID_$1"; kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; }
flow_result() { peer_uplink <"/tmp/$P-$1.out"; }

# m_ok MATRIX REGEX-PER-KIND: every kind (f4 f6 r4 r6) must match "kind REGEX"
m_ok() { local k; for k in f4 f6 r4 r6; do [[ "$1" =~ $k\ $2 ]] || return 1; done; }
snap() { # snap DESCRIPTION REGEX
  local m; m=$(matrix 20)
  check "$1: $m" "^ok$" "$(m_ok "$m" "$2" && echo ok || echo "no")"
}
FTR_ONLY='[0-9]+/[0-9]+/[0-9]+/0/0'     # A/B/C used, nothing leaked or rejected
EITHER='[0-9]+/[0-9]+/[0-9]+/[0-9]+/0'  # pre-existing routing (X) or FTR, nothing rejected

echo "== FR-REC-1 cold installation (both families, uplinks 1 2 3)"
snap "0 before installation: pre-existing routing" '0/0/0/20/0'
both() { local f; for f in 4 6; do "$@" $f; done; }        # both FUNC: FUNC 4; FUNC 6
both_bal() { local f; for f in 4 6; do balance $f "$@"; done; }
both_del() { local f; for f in 4 6; do r_rule_del $f "$@"; done; }
s_routes()  { local id; for id in 1 2 3; do path_route $1 $id $((T + id)); path_route $1 $id $((T + 64 + id)); path_route $1 $id $((T + 128 + id)); done; balance $1 1 2 3; }
s_guards()  { guard_probe $1; guard_path $1; guard_polblk $1; }
s_probe()   { local id; for id in 1 2 3; do rule_probe $1 $id; done; }
s_path()    { local id; for id in 1 2 3; do rule_path $1 $id; done; }
s_policy()  { local id; for id in 1 2 3; do rule_polbal $1 $id; rule_polblk $1 $id; done; }
s_from()    { local id; for id in 1 2 3; do rule_from $1 $id "$(ftr_src $1 $id)"; guard_from $1 "$(ftr_src $1 $id)"; done; }
both s_routes;     snap "1 routes" "$EITHER"
both s_guards;     snap "2 class guards" "$EITHER"
both s_probe;      snap "3 probe rules" "$EITHER"
both rule_main;    snap "4 main bypass" "$EITHER"
both s_path;       snap "5 path rules" "$EITHER"
both s_policy;     snap "6 policy rules" "$EITHER"
both s_from;       snap "7 source rules and source guards" "$EITHER"
both rule_balance; snap "8 balancing rule" "$FTR_ONLY"
both guard_final;  snap "9 final guard" "$FTR_ONLY"
ftr_nft 1 2 3;     snap "10 nftables table" "$FTR_ONLY"

echo "== FR-REC-3 removing uplink C with pinned flows on A, B and C"
both_bal 1;       flow_start A 198.18.100.201 7
both_bal 2;       flow_start B 198.18.100.202 7
both_bal 3;       flow_start C 198.18.100.203 8
both_bal 1 2 3
note "flow C egress counters a/b/c/x: $(fc)"
r_pol_empty() { route_del $1 $((T + 67)); route_del $1 $((T + 131)); }
r_rules() { local f=$1; r_rule_del $f pref $((B + 3)) fwmark "$(enc 0x43)/$MASK" lookup $((T + 3)); r_rule_del $f pref $((B + 203)) fwmark "$(enc 3)/$MASK" lookup $((T + 3))
  r_rule_del $f pref $((B + 303)) fwmark "$(enc 0x83)/$MASK" lookup $((T + 67)); r_rule_del $f pref $((B + 403)) fwmark "$(enc 0xc3)/$MASK" lookup $((T + 131))
  r_rule_del $f pref $((B + 564)) from "$(ftr_src $f 3)" fwmark "0/$MASK" unreachable; r_rule_del $f pref $((B + 503)) from "$(ftr_src $f 3)" fwmark "0/$MASK" lookup $((T + 3)); }
for f in 4 6; do balance $f 1 2; r_pol_empty $f; done
snap "R1 excluded from active set, policy tables emptied" '[0-9]+/[0-9]+/0/0/0'
check "R1 flows A B C alive" "alive alive alive" "$(alive A) $(alive B) $(alive C)"
ftr_nft 1 2
snap "R2 nftables without C's assignments" '[0-9]+/[0-9]+/0/0/0'
sleep 0.5
check "R2 flows A B C alive (restoration rules cover every id)" "alive alive alive" "$(alive A) $(alive B) $(alive C)"
both r_rules
snap "R3 C's lookup rules, source rule and guard deleted" '[0-9]+/[0-9]+/0/0/0'
sleep 3
check "R3 flows A B alive, flow C rejected by the path guard (AS-37)" "alive alive dead" "$(alive A) $(alive B) $(alive C)"
for f in 4 6; do route_del $f $((T + 3)); done
snap "R4 C's routes deleted" '[0-9]+/[0-9]+/0/0/0'
check "flow C never left through another interface (counters a b c x)" '^0 0 [0-9]+ 0$' "$(fc)"
note "flow C egress counters a/b/c/x: $(fc)"
flow_stop C; note "flow C: $(flow_result C)"

echo "== FR-REC-3 adding uplink C back while flows on A and B run"
for f in 4 6; do path_route $f 3 $((T + 3)); done
snap "A1 C's path routes" '[0-9]+/[0-9]+/0/0/0'
for f in 4 6; do rule_probe $f 3; rule_path $f 3; rule_polbal $f 3; rule_polblk $f 3; rule_from $f 3 "$(ftr_src $f 3)"; guard_from $f "$(ftr_src $f 3)"; done
snap "A2 C's lookup rules, source rule and guard" '[0-9]+/[0-9]+/0/0/0'
ftr_nft 1 2 3
snap "A3 nftables with C's assignments" '[0-9]+/[0-9]+/0/0/0'
for f in 4 6; do path_route $f 3 $((T + 67)); path_route $f 3 $((T + 131)); balance $f 1 2 3; done
snap "A4 C in the active set and policy tables" "$FTR_ONLY"
check "flows A B alive throughout" "alive alive" "$(alive A) $(alive B)"
flow_stop A; flow_stop B
check "flow A: no error, gaps < 0.5 s" '"error": null, "max_gap": 0\.[0-4]' "$(flow_result A)"
check "flow B: no error, gaps < 0.5 s" '"error": null, "max_gap": 0\.[0-4]' "$(flow_result B)"

echo "== FR-REC-4 cleanup, with foreign objects present"
nsr ip rule add pref 900 fwmark 0x5/0xff lookup 2000
nsr ip -6 rule add pref 900 fwmark 0x5/0xff lookup 2000
nsr ip route add 192.0.2.128/25 via 192.0.2.1 table 2000
nsr ip -6 route add 2001:db8:a:8000::/49 via fe80::1 dev wana table 2000
nsr nft add table inet foreign
foreign() { echo "$(nsr ip rule show pref 900 | wc -l)$(nsr ip -6 rule show pref 900 | wc -l)$(nsr ip route show table 2000 | wc -l)$(nsr ip -6 route show table 2000 | wc -l)$(nsr nft list tables | grep -c foreign)"; }
c_from() { local id; for id in 1 2 3; do r_rule_del $1 pref $((B + 564)) from "$(ftr_src $1 $id)" fwmark "0/$MASK" unreachable; r_rule_del $1 pref $((B + 500 + id)) from "$(ftr_src $1 $id)" fwmark "0/$MASK" lookup $((T + id)); done; }
c_policy() { local id; for id in 1 2 3; do r_rule_del $1 pref $((B + 400 + id)) fwmark "$(enc $((0xc0 + id)))/$MASK" lookup $((T + 128 + id)); r_rule_del $1 pref $((B + 300 + id)) fwmark "$(enc $((0x80 + id)))/$MASK" lookup $((T + 64 + id)); done; }
c_path() { local id; for id in 1 2 3; do r_rule_del $1 pref $((B + 200 + id)) fwmark "$(enc $id)/$MASK" lookup $((T + id)); done; }
c_probe() { local id; for id in 1 2 3; do r_rule_del $1 pref $((B + id)) fwmark "$(enc $((0x40 + id)))/$MASK" lookup $((T + id)); done; }
c_guards() { local k; r_rule_del $1 pref $((B + 64)) fwmark "$(enc 0x40)/$CLASS" unreachable; r_rule_del $1 pref $((B + 464)) fwmark "$(enc 0xc0)/$CLASS" unreachable
  for k in 0 1 2 3 4 5; do r_rule_del $1 pref $((B + 264)) fwmark "$(enc $((1 << k)))/$(enc $((0xc0 + (1 << k))))" unreachable; done; }
c_routes() { local tb; for tb in $(seq $T $((T + 191))); do route_del $1 $tb; done; }
ftr_nft_del;                                                   snap "C1 nftables table deleted" "$FTR_ONLY"
both_del pref $((B + 699)) unreachable;                 snap "C2 final guard" "$FTR_ONLY"
both_del pref $((B + 600)) lookup "$T";                 snap "C3 balancing rule" "$EITHER"
both c_from;                                                   snap "C4 source guards then source rules" "$EITHER"
both c_policy;                                                 snap "C5 policy rules" "$EITHER"
both c_path;                                                   snap "C6 path rules" "$EITHER"
both_del pref $((B + 100)) lookup main suppress_prefixlength 0; snap "C7 main bypass" '0/0/0/20/0'
both c_probe;                                                  snap "C8 probe rules" '0/0/0/20/0'
both c_guards;                                                 snap "C9 class guards" '0/0/0/20/0'
both c_routes;                                                 snap "C10 routes" '0/0/0/20/0'
check "no FTR rule or route left" "^0 0 0$" "$(nsr ip rule show | grep -c "proto 249") $(nsr ip -6 rule show | grep -c "proto 249") $(for tb in $(seq $T $((T + 191))); do nsr ip route show table $tb; nsr ip -6 route show table $tb; done 2>/dev/null | wc -l)"
check "foreign rules, routes and nftables table untouched" "^11111$" "$(foreign)"
summary
