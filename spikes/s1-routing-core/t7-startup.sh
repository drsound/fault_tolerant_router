#!/usr/bin/env bash
# S1 / FR-REC-8, AS-18, AS-47: kernel side of the startup cases. A daemon
# crash leaves artifacts in place (intact case); partial artifacts with live
# marks are repaired in the FR-REC-8 order (routes and guards, lookup rules by
# decreasing precedence, final guard, nftables table last). Pinned flows are
# observed during the damage and after the repair.
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
obs_up
for f in 4 6; do ftr_install $f 1 2 3; done
ftr_nft 1 2 3
for o in wana wanb wanc wanx; do
  nsr nft add counter inet obs "fa_$o"
  nsr nft add rule inet obs post tcp dport 8 oifname "\"$o\"" counter name "fa_$o"
done
fa() { nsr nft -j list counters table inet obs | python3 -c 'import json,sys; c={o["counter"]["name"]:o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}; print(" ".join(str(c["fa_"+x]) for x in ("wana","wanb","wanc","wanx")))'; }
fa_reset() { local o; for o in wana wanb wanc wanx; do nsr nft reset counter inet obs "fa_$o" >/dev/null; done; }
nsi $PEER serve --port 8 >/dev/null 2>&1 &

flow_start() { # flow_start NAME DST PORT
  rm -f "/tmp/$P-$1.ready" "/tmp/$P-$1.out"
  ip netns exec "$P-c" $PEER long "$2" --port "$3" --period 0.1 --fail-after 30 --ready "/tmp/$P-$1.ready" >"/tmp/$P-$1.out" 2>&1 &
  eval "PID_$1=$!"
  local i; for i in $(seq 1 30); do [ -e "/tmp/$P-$1.ready" ] && return 0; sleep 0.1; done
  echo "flow $1 did not start"; return 1
}
alive() { local p; eval "p=\$PID_$1"; kill -0 "$p" 2>/dev/null && echo alive || echo "dead: $(cat "/tmp/$P-$1.out")"; }
flow_stop() { local p; eval "p=\$PID_$1"; kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; }
flow_result() { peer_uplink <"/tmp/$P-$1.out"; }
both_bal() { local f; for f in 4 6; do balance $f "$@"; done; }
del_path_rule() { r_rule_del $1 pref $((B + 201)) fwmark "$(enc 1)/$MASK" lookup $((T + 1)); }
del_guards() { local k; r_rule_del $1 pref $((B + 64)) fwmark "$(enc 0x40)/$CLASS" unreachable; r_rule_del $1 pref $((B + 464)) fwmark "$(enc 0xc0)/$CLASS" unreachable
  for k in 0 1 2 3 4 5; do r_rule_del $1 pref $((B + 264)) fwmark "$(enc $((1 << k)))/$(enc $((0xc0 + (1 << k))))" unreachable; done; }

# pinned NAME: start a flow pinned to A while A is the only active member, then
# leave A out of the active set so that any misrouted packet is visible.
pinned() { both_bal 1; flow_start "$1" "$D" 8; both_bal 2 3; sleep 0.5; }

for f in 4 6; do
  [ $f = 4 ] && D=198.18.100.211 || D=2001:db8:100::211
  echo "== IPv$f, flows pinned to A (server port 8) with A outside the active set"

  echo "-- damage 1: A's path rule missing, guards intact"
  pinned d1$f
  del_path_rule $f; fa_reset; sleep 2
  check "v$f flow blocked by the path guard, never moved (a b c x)" '^0 0 0 0$' "$(fa)"
  note "new flows while damaged: $(matrix 20)"
  rule_path $f 1; sleep 3
  check "v$f flow resumes on A after repair (a b c x)" '^[1-9][0-9]* 0 0 0$' "$(fa)"
  check "v$f flow survived" "^alive$" "$(alive d1$f)"
  flow_stop d1$f

  echo "-- damage 2: A's path rule and all class guards missing (FR-REC-8 order violated)"
  pinned d2$f
  del_path_rule $f; del_guards $f; fa_reset; sleep 2
  check "v$f flow falls to balancing and leaves via another uplink (a b c x)" '^0 ([1-9][0-9]* [0-9]+|[0-9]+ [1-9][0-9]*) 0$' "$(fa)"
  guard_probe $f; guard_path $f; guard_polblk $f   # FR-REC-8: guards first
  rule_path $f 1; sleep 1
  check "v$f moving the connection broke it" "dead" "$(alive d2$f)"
  flow_stop d2$f

  echo "-- damage 3: nftables table missing, routing intact (repair phase)"
  pinned d3$f
  ftr_nft_del; fa_reset; sleep 2
  note "flow egress while the table is missing (a b c x): $(fa); flow $(alive d3$f | cut -c1-40)"
  note "new flows while the table is missing: $(matrix 20)"
  ftr_nft 1 2 3; sleep 1
  check "v$f conntrack marks survived the table deletion" "mark=$(( $(enc 1) ))" "$(nsr conntrack -L -f ipv$f -p tcp --dport 8 2>/dev/null | head -1)"
  note "flow after repair: $(alive d3$f | cut -c1-80)"
  flow_stop d3$f
  check "v$f new flows correct after repair" '^f4 0/[0-9]+/[0-9]+/0/0 f6 0/[0-9]+/[0-9]+/0/0' "$(matrix 20)"
  both_bal 1 2 3
done
summary
