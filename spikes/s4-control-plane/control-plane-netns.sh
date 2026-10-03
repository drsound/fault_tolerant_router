#!/bin/bash
# FR-CT-5 control-plane checks in network namespaces, with the full FR-ROUTE-3
# layout (guards, empty balancing table) and the §4.7 marking table installed
# in the router namespace before any uplink has a lease, an address or a
# default route.
#
# Namespaces: s4-rtr (router under test), s4-ispa (DHCPv4 dnsmasq, RA radvd,
# DHCPv6 kea with prefix delegation, DHCPv4 relay to s4-dsrv), s4-dsrv
# (off-link DHCPv4 server behind the relay), s4-ispc (PPPoE server).
#
# Usage: control-plane-netns.sh [phase ...]
#   phases: ra dhclient4 dhcpcd4 dhcpcd6 dhclient6 relay pppoe expiry (default: all),
#           relaybase (dhclient rebind timing; NOFTR=1 runs without FTR artifacts)
# Requires: dnsmasq, radvd, kea-dhcp6, isc-dhcp-client, dhcpcd, pppoe, ppp, tcpdump.
set -u
cd "$(dirname "$0")"
HERE=$(pwd)
W=/tmp/s4-cp
R="ip netns exec s4-rtr"
A="ip netns exec s4-ispa"
C="ip netns exec s4-ispc"
S="ip netns exec s4-dsrv"
export UPLINKS="1:wana 3:ppp0" DOWNLINKS="lan"

log() { printf '%s %s\n' "$(date +%T)" "$*"; }
result() { printf '%s RESULT %-10s %-4s %s\n' "$(date +%T)" "$1" "$2" "$3"; }
noroutes() { $R nstat -az IpOutNoRoutes Ip6OutNoRoutes 2>/dev/null | awk 'NR>1{printf "%s=%s ", $1, $2}'; }
killpid() { [ -f "$1" ] && kill "$(cat "$1")" 2>/dev/null; rm -f "$1"; }

teardown() {
  for p in "$W"/*.pid; do [ -e "$p" ] && killpid "$p"; done
  pkill -f "$W/" 2>/dev/null
  for n in s4-rtr s4-ispa s4-ispc s4-dsrv; do
    for pid in $(ip netns pids "$n" 2>/dev/null); do kill "$pid" 2>/dev/null; done
  done
  sleep 1
  for n in s4-rtr s4-ispa s4-ispc s4-dsrv; do ip netns del "$n" 2>/dev/null; done
  rm -rf /etc/netns/s4-rtr
}

setup() {
  teardown; rm -rf "$W"; mkdir -p "$W"
  for n in s4-rtr s4-ispa s4-ispc s4-dsrv; do ip netns add $n; ip netns exec $n ip link set lo up; done
  # dhclient-script and pppd hooks must not touch the host resolv.conf
  mkdir -p /etc/netns/s4-rtr; echo "nameserver 192.0.2.1" > /etc/netns/s4-rtr/resolv.conf
  ip link add wana netns s4-rtr type veth peer name isp0 netns s4-ispa
  ip link add wanc netns s4-rtr type veth peer name isp0 netns s4-ispc
  ip link add srv0 netns s4-ispa type veth peer name srv0 netns s4-dsrv
  $R ip link add lan type dummy
  $R ip link set lan up; $R ip addr add 10.91.1.1/24 dev lan; $R ip addr add fd00:91:1::1/64 dev lan
  $R sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
  for i in wana wanc; do $R sysctl -qw net.ipv4.conf.$i.rp_filter=2 net.ipv4.conf.$i.src_valid_mark=1; done
  # Kernel RA processing on a forwarding router needs accept_ra = 2 (FR-SYS-3: the OS's job)
  $R sysctl -qw net.ipv6.conf.wana.accept_ra=2
  $A sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
  $A ip link set isp0 up; $A ip link set srv0 up
  $A ip addr add 192.0.2.1/24 dev isp0; $A ip addr add 2001:db8:a:ffff::1/64 dev isp0
  $A ip addr add 198.51.100.1/24 dev srv0
  # off-link "internet" addresses used to test routing through the path tables
  $A ip link add inet type dummy; $A ip link set inet up
  $A ip addr add 198.18.100.1/32 dev inet; $A ip addr add 2001:db8:100::1/128 dev inet
  $A ip route add 203.0.113.0/24 via 198.51.100.67 2>/dev/null || true
  $S ip link set srv0 up; $S ip addr add 198.51.100.67/24 dev srv0; $S ip route add default via 198.51.100.1
  $C ip link set isp0 up
  $A tcpdump -l -nni isp0 -tttt 'udp port 67 or udp port 68 or udp port 546 or udp port 547 or icmp6 or (ip6 and ip6[6] == 0)' > "$W/isp.log" 2>/dev/null &
  echo $! > "$W/tcpdump.pid"
  # FTR layout with empty tables, then the marking table
  if [ -z "${NOFTR:-}" ]; then
    IP="$R ip" ./ftr-rules.sh install
    ./ftr-nft.sh | $R nft -f -
  fi
  log "FTR layout installed: $($R ip rule | grep -c 'proto 249') IPv4 rules, $($R ip -6 rule | grep -c 'proto 249') IPv6 rules; no-route counters $(noroutes)"
}

block() { # block DHCP traffic at the provider: block v4unicast|v4all|v6renew|v6all|none
  $A nft delete table inet s4_block 2>/dev/null
  case $1 in
    none) return ;;
    v4unicast) rule='iifname "isp0" ip daddr != 255.255.255.255 udp dport 67 counter drop' ;;
    v4all) rule='iifname "isp0" udp dport 67 counter drop' ;;
    v6renew) rule='iifname "isp0" udp dport 547 @th,64,8 5 counter drop' ;;
    v6all) rule='iifname "isp0" udp dport 547 counter drop' ;;
  esac
  printf 'table inet s4_block {\n chain pre { type filter hook prerouting priority -10; policy accept;\n %s\n }\n}\n' "$rule" | $A nft -f -
}

wait_for() { # wait_for SECONDS command...
  local t=$1; shift
  for _ in $(seq 1 $((t * 5))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
  return 1
}
has_v4() { $R ip -4 -o addr show dev wana scope global | grep -q inet; }
has_v6na() { $R ip -6 -o addr show dev wana scope global | grep -v tentative | grep -q "2001:db8:a:ffff::1[0-9a-f]\{3\}/128"; }
v4addr() { $R ip -4 -o addr show dev wana scope global | awk '{print $4}' | cut -d/ -f1 | head -1; }
mark() { wc -l < "$W/isp.log"; }
since() { tail -n +"$(( $1 + 1 ))" "$W/isp.log"; }

start_dnsmasq() { # start_dnsmasq server|relay
  killpid "$W/dnsmasq.pid"; killpid "$W/dnsmasq-srv.pid"
  if [ "$1" = server ]; then
    $A dnsmasq --pid-file="$W/dnsmasq.pid" --interface=isp0 --bind-interfaces --port=0 \
      --dhcp-range=192.0.2.100,192.0.2.199,2m --dhcp-option=3,192.0.2.1 --dhcp-leasefile="$W/dnsmasq.leases" \
      --log-dhcp --log-facility="$W/dnsmasq.log"
  else
    # relay on the provider router, server off-link: renewals go unicast to 198.51.100.67
    $S dnsmasq --pid-file="$W/dnsmasq-srv.pid" --interface=srv0 --bind-interfaces --port=0 \
      --dhcp-range=192.0.2.100,192.0.2.199,255.255.255.0,2m --dhcp-option=3,192.0.2.1 \
      --dhcp-leasefile="$W/dnsmasq-srv.leases" --log-dhcp --log-facility="$W/dnsmasq-srv.log"
    $A dnsmasq --pid-file="$W/dnsmasq.pid" --interface=isp0 --bind-interfaces --port=0 \
      --dhcp-relay=192.0.2.1,198.51.100.67 --log-facility="$W/dnsmasq.log"
  fi
}

start_radvd() {
  cat > "$W/radvd.conf" <<EOF
interface isp0 {
  AdvSendAdvert on; MinRtrAdvInterval 3; MaxRtrAdvInterval 10;
  AdvManagedFlag on; AdvOtherConfigFlag on; AdvDefaultLifetime 1800;
  prefix 2001:db8:a:ffff::/64 { AdvOnLink on; AdvAutonomous on; };
};
EOF
  chmod 0644 "$W/radvd.conf"
  $A radvd -C "$W/radvd.conf" -p "$W/radvd.pid" -m logfile -l "$W/radvd.log"
}

start_kea() {
  # A copy of the binary runs unconfined by the distribution's AppArmor profile.
  cp "$(command -v kea-dhcp6)" "$W/kea-dhcp6"
  cat > "$W/kea-dhcp6.conf" <<EOF
{ "Dhcp6": {
  "interfaces-config": { "interfaces": [ "isp0" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "renew-timer": 30, "rebind-timer": 50, "preferred-lifetime": 60, "valid-lifetime": 90,
  "subnet6": [ { "id": 1, "subnet": "2001:db8:a:ffff::/64", "interface": "isp0",
    "pools": [ { "pool": "2001:db8:a:ffff::1000-2001:db8:a:ffff::1fff" } ],
    "pd-pools": [ { "prefix": "2001:db8:a:100::", "prefix-len": 56, "delegated-len": 60 } ] } ],
  "loggers": [ { "name": "kea-dhcp6", "output_options": [ { "output": "stdout" } ], "severity": "INFO" } ] } }
EOF
  KEA_LOCKFILE_DIR=none KEA_PIDFILE_DIR="$W" $A "$W/kea-dhcp6" -c "$W/kea-dhcp6.conf" > "$W/kea.log" 2>&1 &
  echo $! > "$W/kea.pid"
}

uplink_reset() { # bring wana down and up again without addresses
  $R ip link set wana down; $R ip -4 addr flush dev wana; $R ip -6 addr flush dev wana scope global
  $R ip link set wana up
}

phase_ra() {
  log "phase ra: kernel RS/RA, SLAAC, DAD, ND, MLD (accept_ra=2)"
  start_radvd
  local m0; m0=$(mark); local before; before=$(noroutes)
  uplink_reset
  NS="$R" IP="$R ip" ./watch-up.sh wana 30 v6 -- true | grep -v counters
  local ns_dad rs ra mld
  rs=$(since "$m0" | grep -c "router solicitation")
  ra=$(since "$m0" | grep -c "router advertisement")
  ns_dad=$(since "$m0" | grep "IP6 :: >" | grep -c "neighbor solicitation")
  mld=$(since "$m0" | grep -c "multicast listener report")
  log "RS=$rs RA=$ra DAD-NS=$ns_dad MLD-reports=$mld"
  IP="$R ip" ./ftr-rules.sh sync
  local a6; a6=$($R ip -6 -o addr show dev wana scope global | grep -v tentative | awk '{print $4}' | cut -d/ -f1 | head -1)
  if $R ping -6 -c 2 -W 1 -I "$a6" 2001:db8:100::1 >/dev/null 2>&1; then nd=ok; else nd=fail; fi
  log "gateway neighbour: $($R ip -6 neigh show dev wana | grep -m1 fe80) ; bound ping through path table: $nd"
  if $A ping -6 -c 1 -W 1 "$a6" >/dev/null 2>&1; then inb=ok; else inb=fail; fi
  log "provider -> router global address (reply via main bypass, on-link prefix): $inb"
  log "no-route counters before: $before after: $(noroutes)"
  if [ -n "$a6" ] && [ "$rs" -gt 0 ] && [ "$ns_dad" -gt 0 ] && [ "$nd" = ok ] && [ "$inb" = ok ] && $R ip -6 route show default dev wana | grep -q "proto ra"; then
    result ra PASS "SLAAC address $a6, RA default route, DAD and ND completed with guards installed"
  else
    result ra FAIL "see log above"
  fi
}

count_since() { since "$1" | grep -c "$2"; }
poll_count() { # poll_count SECONDS MARK PATTERN: wait until PATTERN appears after MARK
  local t=$1 m=$2 pat=$3
  for _ in $(seq 1 "$t"); do [ "$(count_since "$m" "$pat")" -gt 0 ] && return 0; sleep 1; done
  return 1
}

rtr_stop_all() { # stop every process left in the router namespace by previous phases
  local p left=""
  for p in $(ip netns pids s4-rtr 2>/dev/null); do left="$left $(ps -o comm= -p "$p")"; kill "$p" 2>/dev/null; done
  [ -n "$left" ] && log "stopped leftover processes in s4-rtr:$left"
  sleep 1
}

dhcp4_cycle() { # dhcp4_cycle NAME START_CMD PIDFILE   (EXPECT_RENEW=0: renewal must fail at the router)
  local name=$1 start=$2 pidfile=$3 expect=${EXPECT_RENEW:-1}
  local m0 m1 t0 addr renew=0 rebind=0 acks=0 present before
  rtr_stop_all; block none; uplink_reset
  m0=$(mark); t0=$(date +%s)
  eval "$start"
  if ! wait_for 20 has_v4; then result "$name" FAIL "no lease within 20 s"; killpid "$pidfile"; return; fi
  addr=$(v4addr)
  log "$name: lease $addr after $(( $(date +%s) - t0 )) s; default: $($R ip -4 route show default dev wana | head -1)"
  if [ "${SYNC:-0}" = 1 ]; then
    # FTR reacts to the address and to the default route events; wait for both
    wait_for 10 sh -c "$R ip -4 route show default dev wana | grep -q via"
    IP="$R ip" ./ftr-rules.sh sync
    if [ "${BALANCE:-0}" = 1 ]; then
      $R ip -4 route replace default via 192.0.2.1 dev wana src "$addr" metric 100 table 1000 proto 249
    else
      $R ip -4 route flush table 1000 proto 249 2>/dev/null
    fi
    log "$name: path table: $($R ip -4 route show table 1001); balancing table: $($R ip -4 route show table 1000)"
  fi
  before=$(noroutes)
  # renewal at T1 (60 s for a 2 min lease): unicast to the server identifier
  poll_count 75 "$m0" "IP $addr.68 > [0-9.]*.67: BOOTP/DHCP, Request" && renew=1
  log "$name: unicast renew seen by the provider: $renew (after $(( $(date +%s) - t0 )) s); no-route counters $before -> $(noroutes)"
  if [ "$renew" = 1 ]; then
    sleep 2
    block v4unicast   # renewals now fail, rebinding (broadcast) starts at T2 after the last ACK
  fi
  m1=$(mark)
  poll_count 120 "$m1" "> 255.255.255.255.67: BOOTP/DHCP, Request" && rebind=1
  sleep 2
  acks=$(count_since "$m1" "> $addr.68: BOOTP/DHCP, Reply\|> 255.255.255.255.68: BOOTP/DHCP, Reply")
  has_v4 && present=yes || present=no
  log "$name: broadcast rebind seen: $rebind (after $(( $(date +%s) - t0 )) s), replies: $acks, address still present: $present"
  block none
  killpid "$pidfile"
  if [ "$renew" = "$expect" ] && [ "$rebind" = 1 ] && [ "$acks" -gt 0 ] && [ "$present" = yes ]; then
    if [ "$expect" = 1 ]; then result "$name" PASS "acquire, unicast renew and broadcast rebind with guards installed"
    else result "$name" PASS "unicast renew rejected at the router as expected; broadcast rebind kept the lease"; fi
  else
    result "$name" FAIL "renew=$renew (expected $expect) rebind=$rebind replies=$acks present=$present"
  fi
  $R ip -4 addr flush dev wana
}

phase_dhclient4() {
  log "phase dhclient4: ISC dhclient, on-link server"
  start_dnsmasq server
  dhcp4_cycle dhclient4 "$R dhclient -4 -d -v -pf $W/dhclient4.pid -lf $W/dhclient4.leases wana > $W/dhclient4.log 2>&1 &" "$W/dhclient4.pid"
}

phase_dhcpcd4() {
  log "phase dhcpcd4: dhcpcd, on-link server"
  start_dnsmasq server
  printf 'ipv4only\nnohook resolv.conf, timesyncd, ntp.conf, hostname\nnoarp\n' > "$W/dhcpcd4.conf"
  dhcp4_cycle dhcpcd4 "$R dhcpcd -4 -B -f $W/dhcpcd4.conf wana > $W/dhcpcd4.log 2>&1 & echo \$! > $W/dhcpcd4.pid" "$W/dhcpcd4.pid"
}

phase_relay() {
  log "phase relay: off-link DHCPv4 server behind a relay (unicast renew to 198.51.100.67)"
  start_dnsmasq relay
  local dhc="$R dhclient -4 -d -v -pf $W/dhclient4.pid -lf $W/dhclient4r.leases wana > $W/dhclient4r.log 2>&1 &"
  printf 'ipv4only\nnohook resolv.conf, timesyncd, ntp.conf, hostname\nnoarp\n' > "$W/dhcpcd4.conf"
  local dcd="$R dhcpcd -4 -B -f $W/dhcpcd4.conf wana > $W/dhcpcd4r.log 2>&1 & echo \$! > $W/dhcpcd4.pid"
  # (a) FTR has not derived the dynamic part (no "from" rule, no path route): renewal fails at the router
  SYNC=0 EXPECT_RENEW=0 dhcp4_cycle relay-dhclient-nosync "$dhc" "$W/dhclient4.pid"
  SYNC=0 EXPECT_RENEW=0 dhcp4_cycle relay-dhcpcd-nosync "$dcd" "$W/dhcpcd4.pid"
  # (b) normal operation, empty active set: "from" rule and path route present. Both clients
  # renew from sockets not bound to the leased address (dhclient: 0.0.0.0:68; dhcpcd: route
  # lookup with source 0.0.0.0), so the "from" rule does not match and the final guard rejects.
  SYNC=1 EXPECT_RENEW=0 dhcp4_cycle relay-dhcpcd-sync "$dcd" "$W/dhcpcd4.pid"
  SYNC=1 EXPECT_RENEW=0 dhcp4_cycle relay-dhclient-sync "$dhc" "$W/dhclient4.pid"
  # (c) as (b) with a non-empty active set: the unbound renewal follows the balancing table
  BALANCE=1 SYNC=1 EXPECT_RENEW=1 dhcp4_cycle relay-dhcpcd-balanced "$dcd" "$W/dhcpcd4.pid"
  BALANCE=1 SYNC=1 EXPECT_RENEW=1 dhcp4_cycle relay-dhclient-balanced "$dhc" "$W/dhclient4.pid"
  $R ip -4 route flush table 1000 proto 249 2>/dev/null
  IP="$R ip" ./ftr-rules.sh sync
}

dhcp6_cycle() { # dhcp6_cycle NAME START_CMD PIDFILE
  local name=$1 start=$2 pidfile=$3 m0 m1 renew=0 rebind=0 replies present pd t0
  rtr_stop_all; block none
  m0=$(mark); t0=$(date +%s)
  eval "$start"
  if ! wait_for 25 has_v6na; then result "$name" FAIL "no DHCPv6 address within 25 s"; killpid "$pidfile"; return; fi
  pd=$(grep -c "2001:db8:a:1[0-9a-f]*::/60" "$W/kea.log")
  log "$name: IA_NA $($R ip -6 -o addr show dev wana | grep -o '2001:db8:a:ffff::1[0-9a-f]*/128') after $(( $(date +%s) - t0 )) s, kea delegated-prefix log lines: $pd"
  poll_count 45 "$m0" "dhcp6 renew" && renew=1
  sleep 2; block v6renew; m1=$(mark)
  poll_count 70 "$m1" "dhcp6 rebind" && rebind=1
  sleep 2
  replies=$(count_since "$m1" "dhcp6 reply")
  has_v6na && present=yes || present=no
  log "$name: delegated prefix on lan: $($R ip -6 -o addr show dev lan scope global | grep -o '2001:db8:a:1[0-9a-f:]*/64' | tr '\n' ' ')"
  log "$name: renew=$renew rebind=$rebind (after $(( $(date +%s) - t0 )) s) replies-after-block=$replies address present: $present"
  block none; killpid "$pidfile"
  if [ "$renew" = 1 ] && [ "$rebind" = 1 ] && [ "$replies" -gt 0 ] && [ "$pd" -gt 0 ] && [ "$present" = yes ]; then
    result "$name" PASS "IA_NA + IA_PD acquire, renew, rebind with guards installed"
  else
    result "$name" FAIL "renew=$renew rebind=$rebind replies=$replies pd=$pd present=$present"
  fi
  $R ip -6 -o addr show dev wana | grep -o '2001:db8:a:ffff::1[0-9a-f]*/128' | while read -r a; do $R ip -6 addr del "$a" dev wana; done
}

phase_dhcpcd6() {
  log "phase dhcpcd6: dhcpcd IA_NA + IA_PD (kernel keeps RA processing)"
  [ -f "$W/radvd.pid" ] || start_radvd
  [ -f "$W/kea.pid" ] || start_kea
  wait_for 20 sh -c "$R ip -6 route show default dev wana | grep -q ra" || { uplink_reset; sleep 5; }
  printf 'ipv6only\nnoipv6rs\nnohook resolv.conf, timesyncd, ntp.conf, hostname\nduid\ninterface wana\n  ia_na 1\n  ia_pd 2 lan/1\n' > "$W/dhcpcd6.conf"
  dhcp6_cycle dhcpcd6 "$R dhcpcd -6 -B -f $W/dhcpcd6.conf wana > $W/dhcpcd6.log 2>&1 & echo \$! > $W/dhcpcd6.pid" "$W/dhcpcd6.pid"
}

phase_dhclient6() {
  log "phase dhclient6: ISC dhclient -6 -N -P"
  [ -f "$W/radvd.pid" ] || start_radvd
  [ -f "$W/kea.pid" ] || start_kea
  dhcp6_cycle dhclient6 "$R dhclient -6 -N -P -d -v -pf $W/dhclient6.pid -lf $W/dhclient6.leases wana > $W/dhclient6.log 2>&1 &" "$W/dhclient6.pid"
}

ppp_up() { $R ip -4 -o addr show dev ppp0 2>/dev/null | grep -q inet; }

phase_pppoe() {
  log "phase pppoe: PPPoE discovery, LCP, IPCP, LCP echo, interface recreation"
  printf 'noauth\nlcp-echo-interval 2\nlcp-echo-failure 3\nmtu 1492\nmru 1492\nnoipv6\n' > "$W/pppoe-server-options"
  $C pppoe-server -F -I isp0 -L 203.0.113.1 -R 203.0.113.10 -N 10 -O "$W/pppoe-server-options" > "$W/pppoe-server.log" 2>&1 &
  echo $! > "$W/pppoe-server.pid"
  $R ip link set wanc up
  local opts="plugin pppoe.so nic-wanc noauth noipdefault nodefaultroute noipv6 nodetach ifname ppp0 lcp-echo-interval 2 lcp-echo-failure 3 mtu 1492 mru 1492 ip-up-script /bin/true ip-down-script /bin/true"
  local before t0 idx1 idx2 echo_ok
  before=$(noroutes); t0=$(date +%s%N)
  $R pppd $opts > "$W/pppd.log" 2>&1 & echo $! > "$W/pppd.pid"
  if ! wait_for 20 ppp_up; then result pppoe FAIL "no IPCP address within 20 s"; return; fi
  log "pppoe: ppp0 $($R ip -br addr show dev ppp0 | awk '{print $3, $4, $5}') after $(( ($(date +%s%N) - t0) / 1000000 )) ms"
  IP="$R ip" ./ftr-rules.sh sync
  sleep 8   # several LCP echo intervals; failure would tear the link down
  ppp_up && echo_ok=yes || echo_ok=no
  local src; src=$($R ip -4 -o addr show dev ppp0 | awk '{print $4}' | cut -d/ -f1)
  $A ip route replace 203.0.113.0/24 via 198.51.100.67 2>/dev/null
  idx1=$($R cat /sys/class/net/ppp0/ifindex)
  killpid "$W/pppd.pid"; sleep 2
  $R pppd $opts > "$W/pppd2.log" 2>&1 & echo $! > "$W/pppd.pid"
  if wait_for 20 ppp_up; then idx2=$($R cat /sys/class/net/ppp0/ifindex); else idx2=none; fi
  IP="$R ip" ./ftr-rules.sh sync
  log "pppoe: link alive after LCP echoes: $echo_ok; ifindex $idx1 -> $idx2; address $($R ip -4 -o addr show dev ppp0 | awk '{print $4}')"
  log "pppoe: no-route counters before: $before after: $(noroutes)"
  killpid "$W/pppd.pid"; killpid "$W/pppoe-server.pid"
  if [ "$echo_ok" = yes ] && [ "$idx2" != none ] && [ "$idx1" != "$idx2" ]; then
    result pppoe PASS "PPPoE session, LCP echo and recreation with a new ifindex with guards installed"
  else
    result pppoe FAIL "echo=$echo_ok ifindex $idx1 -> $idx2"
  fi
}

phase_expiry() {
  log "phase expiry: DHCPv4 lease expiry and reacquisition (dhclient)"
  start_dnsmasq server
  block none; uplink_reset
  $R dhclient -4 -d -v -pf "$W/dhclient4.pid" -lf "$W/dhclient4e.leases" wana > "$W/dhclient4e.log" 2>&1 &
  if ! wait_for 20 has_v4; then result expiry FAIL "no lease"; return; fi
  log "expiry: lease $(v4addr), blocking every DHCP request"
  block v4all
  local gone=no back=no t0; t0=$(date +%s)
  wait_for 140 sh -c "! $R ip -4 -o addr show dev wana scope global | grep -q inet" && gone=yes
  log "expiry: address removed: $gone after $(( $(date +%s) - t0 )) s"
  block none; t0=$(date +%s)
  wait_for 90 has_v4 && back=yes
  log "expiry: reacquired: $back after $(( $(date +%s) - t0 )) s ($(v4addr))"
  killpid "$W/dhclient4.pid"
  if [ "$gone" = yes ] && [ "$back" = yes ]; then result expiry PASS "expiry removed the address; INIT reacquired it with guards installed"; else result expiry FAIL "gone=$gone back=$back"; fi
}

phase_relaybase() {
  # Baseline for the relay cases: when does dhclient start rebinding if its unicast
  # renewals are lost at the provider? Run with NOFTR=1 to compare with FTR's rejections.
  log "phase relaybase: dhclient rebind timing with renewals dropped at the provider (NOFTR=${NOFTR:-})"
  start_dnsmasq relay
  local i t0 m1 rb present
  for i in 1 2 3; do
    rtr_stop_all; block none; uplink_reset
    $R dhclient -4 -d -v -pf "$W/dhclient4.pid" -lf "$W/dhclient4b.leases" wana > "$W/dhclient4b.log" 2>&1 &
    wait_for 20 has_v4 || { log "relaybase $i: no lease"; continue; }
    t0=$(date +%s); block v4unicast; m1=$(mark); rb=none
    for _ in $(seq 1 150); do [ "$(count_since "$m1" "> 255.255.255.255.67: BOOTP/DHCP, Request")" -gt 0 ] && { rb=$(( $(date +%s) - t0 )); break; }; sleep 1; done
    sleep 3; has_v4 && present=yes || present=no
    log "relaybase $i: first rebind broadcast ${rb} s after the lease (expiry at 120 s), address present: $present"
  done
  block none; rtr_stop_all
}

phases=${*:-"ra dhclient4 dhcpcd4 dhcpcd6 dhclient6 relay pppoe expiry"}
trap teardown EXIT
log "kernel $(uname -r), $(nft --version), $(ip -V)"
setup
for p in $phases; do "phase_$p"; done
log "final FTR artifacts: $(IP="$R ip" ./count-artifacts.sh)"
