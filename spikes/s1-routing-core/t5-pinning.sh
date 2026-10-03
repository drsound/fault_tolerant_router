#!/usr/bin/env bash
# S1 / INV-2, INV-5, AS-03, AS-09, AS-37: pinning of marked connections across
# active-set updates, withdrawal of the path route, inbound connections on an
# uplink outside the active set; both families.
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
ftr_nft 1 2 3
# Administrator's port forwarding on every uplink: router:8007 -> client:7
nsr nft -f - <<'EOF'
table inet admin {
  chain portfwd {
    type nat hook prerouting priority -100; policy accept;
    iifname { "wana", "wanb", "wanc" } meta nfproto ipv4 tcp dport 8007 dnat ip to 10.1.0.2:7
    iifname { "wana", "wanb", "wanc" } meta nfproto ipv6 tcp dport 8007 dnat ip6 to [fd00:1::2]:7
  }
}
EOF
nsc $PEER serve >/dev/null 2>&1 &

declare -A ID=([A]=1 [B]=2 [C]=3)
others() { local x; for x in 1 2 3; do [ "$x" = "$1" ] || printf '%s ' "$x"; done; }

flow_start() { # flow_start NS DST NAME
  rm -f "/tmp/$P-$3.ready" "/tmp/$P-$3.out"
  ip netns exec "$P-$1" $PEER long "$2" ${4:+--port $4} --period 0.1 --fail-after 2 --ready "/tmp/$P-$3.ready" >"/tmp/$P-$3.out" 2>&1 &
  eval "PID_$3=$!"
  local i; for i in $(seq 1 30); do [ -e "/tmp/$P-$3.ready" ] && return 0; sleep 0.1; done
  echo "flow $3 did not start"; return 1
}
# flow_stop must run in the main shell (a subshell cannot wait for the flow).
flow_stop() { local p; eval "p=\$PID_$1"; kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; }
flow_result() { peer_uplink <"/tmp/$P-$1.out"; }

for f in 4 6; do
  if [ $f = 4 ]; then D=198.18.100.77; else D=2001:db8:100::77; fi
  echo "== IPv$f outbound flow"
  flow_start c "$D" out$f
  sleep 0.5
  # Which uplink did the flow use? Ask the server with a second look at conntrack.
  up=$(nsr conntrack -L -f ipv$f -p tcp --dport 7 --state ESTABLISHED 2>/dev/null | grep -o "mark=[0-9]*" | head -1 | cut -d= -f2)
  id=$(( up >> SHIFT & 0xff )); note "flow pinned to path id $id (ct mark $up)"
  balance $f $(others $id); sleep 1
  check "v$f flow keeps working after its uplink leaves the active set" "running" "$(kill -0 "$(eval echo \$PID_out$f)" 2>/dev/null && echo running)"
  balance $f; sleep 1
  check "v$f flow keeps working with an empty active set" "running" "$(kill -0 "$(eval echo \$PID_out$f)" 2>/dev/null && echo running)"
  flow_stop out$f; r=$(flow_result out$f)
  check "v$f flow summary: no error, gaps < 0.5 s" '"error": null, "max_gap": 0\.[0-4]' "$r"
  balance $f 1 2 3

  flow_start c "$D" cut$f
  sleep 0.5
  up=$(nsr conntrack -L -f ipv$f -p tcp --dport 7 --state ESTABLISHED 2>/dev/null | grep -o "mark=[0-9]*" | tail -1 | cut -d= -f2)
  id=$(( up >> SHIFT & 0xff ))
  leaks_reset
  route_del $f $((T + id)); sleep 3
  flow_stop cut$f; r=$(flow_result cut$f)
  check "v$f path route of the flow withdrawn: flow stops (rejected, not moved)" '"error": "(timeout|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|TimeoutError)"' "$r"
  check "v$f ... and nothing leaked" '^0 0$' "$(leaks)"
  others_before=$(nsr conntrack -L -f ipv$f -p tcp --dport 7 2>/dev/null | grep -c ESTABLISHED || true)
  note "established entries left: $others_before"
  path_route $f $id $((T + id))

  echo "== IPv$f inbound via B while B is outside the active set (INV-5)"
  balance $f 1 3
  if [ $f = 4 ]; then R=198.51.100.2; else R=2001:db8:b::2; fi
  flow_start i "$R" in$f 8007
  sleep 1
  flow_stop in$f; r=$(flow_result in$f)
  check "v$f inbound flow through B answered (replies leave via B)" '"error": null' "$r"
  balance $f
  flow_start i "$R" in$f 8007
  sleep 1
  flow_stop in$f; r=$(flow_result in$f)
  check "v$f inbound flow through B with an empty active set" '"error": null' "$r"
  balance $f 1 2 3
done
summary
