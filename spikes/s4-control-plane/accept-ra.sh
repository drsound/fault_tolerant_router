#!/bin/bash
# FR-SYS-3: kernel RA processing on a forwarding router. For accept_ra 1 and 2,
# with forwarding = 1 (FR-SYS-1), report whether a SLAAC address and an RA
# default route appear within 15 s. Namespaces: s4-ra-isp, s4-ra-rtr.
set -u
cleanup() { ip netns del s4-ra-isp 2>/dev/null; ip netns del s4-ra-rtr 2>/dev/null; rm -rf /tmp/s4-ra; }
trap cleanup EXIT
for ar in 1 2; do
  cleanup; mkdir -p /tmp/s4-ra
  ip netns add s4-ra-isp; ip netns add s4-ra-rtr
  ip link add wana netns s4-ra-rtr type veth peer name isp0 netns s4-ra-isp
  I="ip netns exec s4-ra-isp"; R="ip netns exec s4-ra-rtr"
  $I sysctl -qw net.ipv6.conf.all.forwarding=1; $I ip link set isp0 up; $I ip addr add 2001:db8:a:ffff::1/64 dev isp0
  printf 'interface isp0 { AdvSendAdvert on; MinRtrAdvInterval 3; MaxRtrAdvInterval 5; prefix 2001:db8:a:ffff::/64 { }; };\n' > /tmp/s4-ra/radvd.conf
  $I radvd -C /tmp/s4-ra/radvd.conf -p /tmp/s4-ra/radvd.pid -m logfile -l /tmp/s4-ra/radvd.log
  $R sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv6.conf.wana.accept_ra=$ar
  $R ip link set wana up
  sleep 15
  a=$($R ip -6 -o addr show dev wana scope global | awk '{print $4}')
  d=$($R ip -6 route show default)
  echo "forwarding=1 accept_ra=$ar: address=${a:-none} default=${d:-none}"
  kill "$(cat /tmp/s4-ra/radvd.pid)" 2>/dev/null
done
