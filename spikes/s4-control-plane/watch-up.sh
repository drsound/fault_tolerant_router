#!/bin/sh
# Report when an uplink reaches each control-plane milestone after a trigger.
# Usage: watch-up.sh IFACE TIMEOUT_S [v4] [v6] -- trigger command...
# Prints elapsed milliseconds for: IPv4 address, IPv4 default route,
# non-tentative global IPv6 address, IPv6 default route; and the change of
# IpOutNoRoutes / Ip6OutNoRoutes (packets that found no route, e.g. a guard).
dev=$1; to=$2; shift 2; want4=; want6=
while [ "$1" != "--" ]; do case $1 in v4) want4=1;; v6) want6=1;; esac; shift; done; shift
IP=${IP:-ip}
ms() { echo $(( $(date +%s%N) / 1000000 )); }
noroutes() { ${NS:-} nstat -az IpOutNoRoutes Ip6OutNoRoutes 2>/dev/null | awk 'NR>1{printf "%s=%s ", $1, $2}'; }
before=$(noroutes)
t0=$(ms); "$@"
a4=; r4=; a6=; r6=
while [ $(( $(ms) - t0 )) -lt $((to * 1000)) ]; do
  e=$(( $(ms) - t0 ))
  if [ -n "$want4" ]; then
    [ -z "$a4" ] && $IP -4 -o addr show dev "$dev" scope global 2>/dev/null | grep -q inet && { a4=$e; echo "ipv4 address: ${e} ms"; }
    [ -z "$r4" ] && $IP -4 route show default dev "$dev" 2>/dev/null | grep -vq "proto 249" && $IP -4 route show default dev "$dev" | grep -q . && { r4=$e; echo "ipv4 default route: ${e} ms"; }
  fi
  if [ -n "$want6" ]; then
    [ -z "$a6" ] && $IP -6 -o addr show dev "$dev" scope global 2>/dev/null | grep -v tentative | grep -q inet6 && { a6=$e; echo "ipv6 global address (DAD done): ${e} ms"; }
    [ -z "$r6" ] && $IP -6 route show default dev "$dev" 2>/dev/null | grep -q via && { r6=$e; echo "ipv6 default route: ${e} ms"; }
  fi
  if { [ -z "$want4" ] || { [ -n "$a4" ] && [ -n "$r4" ]; }; } && { [ -z "$want6" ] || { [ -n "$a6" ] && [ -n "$r6" ]; }; }; then break; fi
  sleep 0.2
done
echo "no-route counters before: $before"
echo "no-route counters after:  $(noroutes)"
