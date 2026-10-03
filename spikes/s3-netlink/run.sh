#!/bin/sh
# Spike S3: run the netlink checks inside a disposable namespace.
# Usage: run.sh [BINARY] [TEST]   (TEST: all, rules, routes, extack, notify, inspect, implicit, dumpintr, enobufs, dumpskip, install)
# S3_DUMPSKIP_CASES=name,... limits the dumpskip group to some cases.
set -eu
BIN=$(readlink -f "${1:-./s3-netlink}")
TEST=${2:-all}
NS=s3-a
cleanup() { ip netns del "$NS" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip netns add "$NS"
x() { ip netns exec "$NS" "$@"; }
x ip link set lo up
x sysctl -qw net.ipv6.conf.all.forwarding=1
x ip link add d1 type dummy
x ip link add d2 type dummy
for d in d1 d2; do x sysctl -qw net.ipv6.conf.$d.addr_gen_mode=0; done
x ip link set d1 up
x ip link set d2 up
x ip addr add 192.0.2.2/24 dev d1
x ip addr add 198.51.100.2/24 dev d2
x ip addr add 2001:db8:1::2/64 dev d1 nodad
x ip addr add 2001:db8:2::2/64 dev d2 nodad
# IPv4 point-to-point (IFF_POINTOPOINT, no gateway needed) and a GRE point-to-point link with an IPv6 link-local address.
x ip link add p0 type ipip local 192.0.2.2 remote 192.0.2.1
x ip link set p0 up
x ip addr add 203.0.113.2 peer 203.0.113.1/32 dev p0
x ip link add g6 type gre local 198.51.100.2 remote 198.51.100.1
x sysctl -qw net.ipv6.conf.g6.addr_gen_mode=0 2>/dev/null || true
x ip link set g6 up
x ip addr add fe80::2/64 dev g6 nodad
# A veth pair to observe carrier loss (v1 loses carrier when v1p goes down).
x ip link add v1 type veth peer name v1p
x sysctl -qw net.ipv6.conf.v1.addr_gen_mode=0
x ip link set v1p up
x ip link set v1 up
x ip addr add 100.64.0.2/24 dev v1
x ip addr add 2001:db8:3::2/64 dev v1 nodad
# Operating-system default routes in main, as in every acceptance scenario.
x ip route add default via 192.0.2.1 dev d1 proto dhcp metric 100
x ip -6 route add default via fe80::1 dev d1 proto ra metric 1024 pref high
# A default route that references a nexthop object (FR-DISC-3 must recognise and skip it).
x ip nexthop add id 7 via 192.0.2.1 dev d1
x ip route add default nhid 7 table 3005 metric 50
echo "## $(uname -r), $(ip -V)"
x "$BIN" "$TEST"
if [ "$TEST" = install ]; then
  x ip -4 rule show
  x ip -6 rule show
  x ip -4 route show table all proto 249
  x ip -6 route show table all proto 249
fi
