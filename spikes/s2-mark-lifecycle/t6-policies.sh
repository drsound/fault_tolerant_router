#!/usr/bin/env bash
# S2 / FR-POL-1..3, INV-2, AS-15 core: policy to A with fallback balance (tcp
# port 7) and fallback block (tcp port 8), active set {B, C}. Connections
# opened before A's policy tables empty stay on A; new ones are balanced or
# rejected; after A's policy tables are restored, connections opened on B or
# C stay there. Both families.
set -euo pipefail
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
ip netns exec "$P-i" $PEER serve --port 8 >/dev/null 2>&1 &
export S2_POLICIES="$(policy 4 'ip daddr 198.18.100.0/24 tcp dport 7' 0x81)
$(policy 4 'ip daddr 198.18.100.0/24 tcp dport 8' 0xc1)
$(policy 6 'ip6 daddr 2001:db8:100::/64 tcp dport 7' 0x81)
$(policy 6 'ip6 daddr 2001:db8:100::/64 tcp dport 8' 0xc1)"
s2_nft 1 2 3

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
pol_tables() { # pol_tables FAM on|off -> A's policy tables populated or empty
  if [ "$2" = on ]; then path_route $1 1 $((T + 65)); path_route $1 1 $((T + 129)); else route_del $1 $((T + 65)); route_del $1 $((T + 129)); fi
}

for f in 4 6; do
  if [ $f = 4 ]; then D=198.18.100.71; DS="198.18.100.72 198.18.100.73 198.18.100.74 198.18.100.75"; else D=2001:db8:100::71; DS="2001:db8:100::72 2001:db8:100::73 2001:db8:100::74 2001:db8:100::75"; fi
  echo "== IPv$f"
  balance $f 2 3
  r=$(nsc $PEER conn $DS --count 8 | peer_uplink)
  check "v$f balance policy: new connections via A although A is not in the active set ($r)" '"peers": \{"A": 8\}' "$r"
  r=$(nsc $PEER conn $DS --port 8 --count 8 | peer_uplink)
  check "v$f block policy: new connections via A ($r)" '"peers": \{"A": 8\}' "$r"
  flow_start bal$f "$D" 7; flow_start blk$f "$D" 8
  pol_tables $f off                                    # A unhealthy or drained
  sleep 1
  check "v$f flows opened before stay alive on A" "alive alive" "$(alive bal$f) $(alive blk$f)"
  r=$(nsc $PEER conn $DS --count 8 | peer_uplink)
  check "v$f balance policy, A's table empty: new connections balanced over B, C ($r)" '"errors": \{\}, "peers": \{"B": [0-9]+, "C": [0-9]+\}|"errors": \{\}, "peers": \{"[BC]": 8\}' "$r"
  chk_up "meta nfproto ipv$f meta l4proto tcp ct original proto-dst 8 ct state new"
  r=$(nsc $PEER conn $DS --port 8 --count 4 --timeout 2.5 | peer_uplink); c=$(chk)
  check "v$f block policy, A's table empty: new connections fail ($r)" '"errors": \{("E(HOST|NET)UNREACH": [0-9]+(, )?|"timeout": [0-9]+(, )?)+\}, "peers": \{\}' "$r"
  check "v$f ... and none of their packets leaves through any uplink" "^0 0 0 0$" "$(cval "$c" o_fin_if_wana) $(cval "$c" o_fin_if_wanb) $(cval "$c" o_fin_if_wanc) $(cval "$c" o_fin_if_wanx)"
  flow_start later$f "$D" 7
  up=$(ctmark $f -p tcp --dport 7 --state ESTABLISHED | tr ' ' '\n' | grep -v 0x1 | head -1)
  note "flow opened during the fallback pinned to path $up"
  pol_tables $f on                                     # A healthy again
  sleep 1
  check "v$f after A's tables return, the fallback flow is still on path $up" "$up" "$(ctmark $f -p tcp --dport 7 --state ESTABLISHED | tr ' ' '\n' | grep -v 0x1 | head -1)"
  r=$(nsc $PEER conn $DS --count 4 | peer_uplink)
  check "v$f new balance-policy connections via A again" '"peers": \{"A": 4\}' "$r"
  for n in bal$f blk$f later$f; do flow_stop $n; done
  check "v$f balance-policy flow on A: no error" '"error": null.*"peer": "A"' "$(flow_result bal$f)"
  check "v$f block-policy flow on A: no error" '"error": null.*"peer": "A"' "$(flow_result blk$f)"
  check "v$f fallback flow: no error, not on A" '"error": null.*"peer": "[BC]"' "$(flow_result later$f)"
  balance $f 1 2 3
done
summary
