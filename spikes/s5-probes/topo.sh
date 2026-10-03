#!/usr/bin/env bash
# Namespace topology for spike S5. Usage: topo.sh up|down
#
#   s5-r (router)                 s5-isp (upstream, hosts the probe targets on dummy "tg")
#   up1 192.0.2.2/24  ----------- u1 192.0.2.1/24      2001:db8:1::2/64 ... 2001:db8:1::1/64, fe80::1
#       2001:db8:1::2/64, fe80::2   \
#                                    d1 (macvlan, moved to s5-dcy) 192.0.2.3/24, 2001:db8:1::3/64, fe80::3
#   up2 198.51.100.2/24 --------- u2 198.51.100.1/24   2001:db8:2::2/64 ... 2001:db8:2::1/64, fe80::1
#
# Router main table (operating-system routes that must not affect probes):
#   default via the uplink 2 gateway; 8.8.8.8/32 and 2001:4860:4860::8888/128 via the decoy on
#   uplink 1 (main route covering a probe target, same interface, other next hop);
#   9.9.9.9/32 and 2620:fe::fe/128 via uplink 2 (main route covering a target, other interface).
# FTR artifacts of FR-ROUTE-3 relevant to probes, B = 1000, mask 0x00ff0000, uplink ids 1 and 2.
set -euo pipefail

R=s5-r I=s5-isp D=s5-dcy
B=1000 TB=1000 MASK=0x00ff0000 PROTO=249

down() {
  for n in $R $I $D; do
    ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del $n 2>/dev/null || true
  done
}

# path_routes FAMILY: install the path table routes of both uplinks (FR-ROUTE-3 table_base + id).
path_routes() {
  if [ "$1" = 4 ]; then
    ip -n $R -4 route replace default via 192.0.2.1 dev up1 src 192.0.2.2 metric 100 proto $PROTO table $((TB + 1))
    ip -n $R -4 route replace default via 198.51.100.1 dev up2 src 198.51.100.2 metric 100 proto $PROTO table $((TB + 2))
  else
    ip -n $R -6 route replace default via fe80::1 dev up1 src 2001:db8:1::2 metric 100 proto $PROTO table $((TB + 1))
    ip -n $R -6 route replace default via fe80::1 dev up2 src 2001:db8:2::2 metric 100 proto $PROTO table $((TB + 2))
  fi
}

# from_rules add|del: B+500+id source rules and B+564 source guards for the uplink addresses.
from_rules() {
  local op=$1
  for spec in "4 192.0.2.2 1" "4 198.51.100.2 2" "6 2001:db8:1::2 1" "6 2001:db8:2::2 2"; do
    set -- $spec
    ip -n $R -"$1" rule "$op" pref $((B + 500 + $3)) from "$2" fwmark 0/$MASK lookup $((TB + $3)) proto $PROTO
    ip -n $R -"$1" rule "$op" pref $((B + 564)) from "$2" fwmark 0/$MASK unreachable proto $PROTO
  done
}

ftr_rules() {
  for f in 4 6; do
    for id in 1 2; do
      ip -n $R -$f rule add pref $((B + id)) fwmark $(printf '0x%08x' $(((0x40 + id) << 16)))/$MASK lookup $((TB + id)) proto $PROTO
    done
    ip -n $R -$f rule add pref $((B + 64)) fwmark 0x00400000/0x00c00000 unreachable proto $PROTO
    ip -n $R -$f rule add pref $((B + 100)) lookup main suppress_prefixlength 0 proto $PROTO
    ip -n $R -$f rule add pref $((B + 600)) lookup $TB proto $PROTO
    ip -n $R -$f rule add pref $((B + 699)) unreachable proto $PROTO
  done
  from_rules add
}

nft_counters() {
  ip netns exec $I nft -f - <<'EOF'
table inet s5 {
  counter u1_v4_echo {}
  counter u1_v4_syn {}
  counter u1_v4_badsrc {}
  counter u1_v6_echo {}
  counter u1_v6_syn {}
  counter u1_v6_badsrc {}
  counter u2_v4_echo {}
  counter u2_v4_syn {}
  counter u2_v4_badsrc {}
  counter u2_v6_echo {}
  counter u2_v6_syn {}
  counter u2_v6_badsrc {}
  chain count {
    type filter hook prerouting priority -300; policy accept;
    iifname "u1" icmp type echo-request counter name "u1_v4_echo"
    iifname "u1" tcp flags & (syn | ack) == syn counter name "u1_v4_syn"
    iifname "u1" ip saddr != 192.0.2.2 meta l4proto { icmp, tcp } counter name "u1_v4_badsrc"
    iifname "u1" icmpv6 type echo-request counter name "u1_v6_echo"
    iifname "u1" meta nfproto ipv6 tcp flags & (syn | ack) == syn counter name "u1_v6_syn"
    iifname "u1" ip6 saddr != 2001:db8:1::2 icmpv6 type echo-request counter name "u1_v6_badsrc"
    iifname "u1" ip6 saddr != 2001:db8:1::2 meta l4proto tcp counter name "u1_v6_badsrc"
    iifname "u2" icmp type echo-request counter name "u2_v4_echo"
    iifname "u2" meta nfproto ipv4 tcp flags & (syn | ack) == syn counter name "u2_v4_syn"
    iifname "u2" ip saddr != 198.51.100.2 meta l4proto { icmp, tcp } counter name "u2_v4_badsrc"
    iifname "u2" icmpv6 type echo-request counter name "u2_v6_echo"
    iifname "u2" meta nfproto ipv6 tcp flags & (syn | ack) == syn counter name "u2_v6_syn"
    iifname "u2" ip6 saddr != 2001:db8:2::2 icmpv6 type echo-request counter name "u2_v6_badsrc"
    iifname "u2" ip6 saddr != 2001:db8:2::2 meta l4proto tcp counter name "u2_v6_badsrc"
  }
  # TCP blackhole for the third target, so that a TCP attempt can time out.
  chain blackhole {
    type filter hook prerouting priority -200; policy accept;
    ip daddr 9.9.9.9 tcp dport 443 drop
    ip6 daddr 2620:fe::fe tcp dport 443 drop
  }
  # Per-test injections (flushed by the tests).
  chain inject_out {
    type filter hook output priority 0; policy accept;
  }
}
EOF
  ip netns exec $D nft -f - <<'EOF'
table inet s5 {
  counter d1_v4 {}
  counter d1_v6 {}
  chain count {
    type filter hook prerouting priority -300; policy accept;
    meta l4proto { icmp, tcp } meta nfproto ipv4 counter name "d1_v4"
    icmpv6 type echo-request counter name "d1_v6"
    meta nfproto ipv6 meta l4proto tcp counter name "d1_v6"
  }
}
EOF
}

up() {
  down
  for n in $R $I $D; do
    ip netns add $n
    ip -n $n link set lo up
  done
  ip link add up1 netns $R type veth peer name u1 netns $I
  ip link add up2 netns $R type veth peer name u2 netns $I
  ip -n $I link add d1 link u1 type macvlan mode bridge
  ip -n $I link set d1 netns $D
  ip -n $I link add tg type dummy

  # Static, non-tentative link-local addresses only.
  for spec in "$R up1" "$R up2" "$I u1" "$I u2" "$D d1"; do
    set -- $spec
    ip -n "$1" link set "$2" addrgenmode none
  done
  ip netns exec $R sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
    net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
  # arp_ignore=1: like a real provider router, the upstream does not answer ARP on u1/u2 for the
  # target addresses of its dummy interface (the not-ready tests toggle it to emulate proxy ARP).
  ip netns exec $I sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf.all.arp_ignore=1
  for d in up1 up2; do
    ip netns exec $R sysctl -qw net.ipv4.conf.$d.rp_filter=2 net.ipv4.conf.$d.src_valid_mark=1
  done

  ip -n $R addr add 192.0.2.2/24 dev up1
  ip -n $R addr add 2001:db8:1::2/64 dev up1 nodad
  ip -n $R addr add fe80::2/64 dev up1 nodad
  ip -n $R addr add 198.51.100.2/24 dev up2
  ip -n $R addr add 2001:db8:2::2/64 dev up2 nodad
  ip -n $R addr add fe80::2/64 dev up2 nodad
  ip -n $I addr add 192.0.2.1/24 dev u1
  ip -n $I addr add 2001:db8:1::1/64 dev u1 nodad
  ip -n $I addr add fe80::1/64 dev u1 nodad
  ip -n $I addr add 198.51.100.1/24 dev u2
  ip -n $I addr add 2001:db8:2::1/64 dev u2 nodad
  ip -n $I addr add fe80::1/64 dev u2 nodad
  ip -n $D addr add 192.0.2.3/24 dev d1
  ip -n $D addr add 2001:db8:1::3/64 dev d1 nodad
  ip -n $D addr add fe80::3/64 dev d1 nodad
  for a in 1.1.1.1/32 8.8.8.8/32 9.9.9.9/32 2606:4700:4700::1111/128 2001:4860:4860::8888/128 2620:fe::fe/128; do
    case $a in *:*) ip -n $I addr add $a dev tg nodad ;; *) ip -n $I addr add $a dev tg ;; esac
  done
  for spec in "$R up1" "$R up2" "$I u1" "$I u2" "$I tg" "$D d1"; do
    set -- $spec
    ip -n "$1" link set "$2" up
  done

  # Operating-system routes in the router main table.
  ip -n $R route add default via 198.51.100.1 dev up2
  ip -n $R route add 8.8.8.8/32 via 192.0.2.3 dev up1
  ip -n $R route add 9.9.9.9/32 via 198.51.100.1 dev up2
  ip -n $R -6 route add default via fe80::1 dev up2
  ip -n $R -6 route add 2001:4860:4860::8888/128 via 2001:db8:1::3 dev up1
  ip -n $R -6 route add 2620:fe::fe/128 via fe80::1 dev up2

  path_routes 4
  path_routes 6
  ftr_rules
  nft_counters

  # TCP listener on every target address, port 443 (port 444 stays closed: RST).
  ip netns exec $I setsid ncat -lk 443 </dev/null >/dev/null 2>&1 &
}

# Sourced by run.sh for the helper functions; executed directly for manual use.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
  esac
fi
