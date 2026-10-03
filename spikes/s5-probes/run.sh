#!/usr/bin/env bash
# Spike S5 test runner. Usage: run.sh [PATH_TO_s5-probes_BINARY]
# Runs as root on a disposable host; creates and removes the namespaces s5-r, s5-isp, s5-dcy.
set -uo pipefail
cd "$(dirname "$0")"
BIN=$(readlink -f "${1:-./s5-probes}")
source ./topo.sh
set +e
fails=0

counters() {
  for ns in $I $D; do
    ip netns exec $ns nft -j list counters | jq -r '.nftables[] | .counter? // empty | "\(.name) \(.packets)"'
  done
}
delta() { echo $(( $(awk -v n="$3" '$1==n{print $2}' <<<"$2") - $(awk -v n="$3" '$1==n{print $2}' <<<"$1") )); }
expect() {
  if [ "$2" = "$3" ]; then echo "PASS $1 ($2)"; else echo "FAIL $1: got $2, expected $3"; fails=$((fails + 1)); fi
}
expect_match() {
  if grep -Eq -- "$3" <<<"$2"; then echo "PASS $1"; else echo "FAIL $1 (no match for /$3/)"; fails=$((fails + 1)); fi
}
expect_nomatch() {
  if grep -Eq -- "$3" <<<"$2"; then echo "FAIL $1 (unexpected /$3/)"; fails=$((fails + 1)); else echo "PASS $1"; fi
}
# Full probe output goes to $PROBE_LOG (default: discarded); checks read it from stdout.
PROBE_LOG=${PROBE_LOG:-/dev/null}
probe() {
  echo "\$ s5-probes $*" >>"$PROBE_LOG"
  ip netns exec $R "$BIN" "$@" 2>&1 | tee -a "$PROBE_LOG"
}
rpf() { ip netns exec $R nstat -asz TcpExtIPReversePathFilter | awk '/IPReversePathFilter/{print $2}'; }
# leak_check BEFORE AFTER: nothing may reach the decoy or show a wrong source.
leak_check() {
  local c
  for c in d1_v4 d1_v6 u1_v4_badsrc u1_v6_badsrc u2_v4_badsrc u2_v6_badsrc; do
    expect "no packet on $c" "$(delta "$1" "$2" $c)" 0
  done
}
capture() { # capture FILE NS IFACE FILTER: background tcpdump, stopped by stop_capture
  ip netns exec "$2" tcpdump -l -nn -e -i "$3" "$4" >"$1" 2>/dev/null &
  CAP=$!
  sleep 0.5
}
stop_capture() { sleep 0.3; kill $CAP 2>/dev/null; wait $CAP 2>/dev/null; }

echo "kernel $(uname -r), $(nft --version), $(ip -V)"
trap down EXIT
up
sleep 1
ip netns exec $I ss -ltnH | sed 's/^/  listener: /'
TMP=$(mktemp -d)

for F in 4 6; do
  if [ $F = 4 ]; then
    S1=192.0.2.2 S2=198.51.100.2 T1=1.1.1.1 T2=8.8.8.8 T3=9.9.9.9 WRONG=1.0.0.1 FT=v4 GW1=192.0.2.1 GW2=198.51.100.1
    TCPT="$T1:443,$T2:444,$T3:443" TCP1="$T1:443"
  else
    S1=2001:db8:1::2 S2=2001:db8:2::2 T1=2606:4700:4700::1111 T2=2001:4860:4860::8888 T3=2620:fe::fe
    WRONG=2606:4700:4700::1001 FT=v6 GW1=fe80::1 GW2=fe80::1
    TCPT="[$T1]:443,[$T2]:444,[$T3]:443" TCP1="[$T1]:443"
  fi
  P1=(--dev up1 --src $S1 --mark 0x00410000)
  P2=(--dev up2 --src $S2 --mark 0x00420000)

  echo
  echo "=== IPv$F T1: ICMP probes of path 1; balancing table empty; competing main default and main routes covering targets; foreign ping on the same path"
  b=$(counters)
  capture $TMP/t1-$F.pcap.txt $R up1 "icmp or icmp6"
  ip netns exec $R ping -$F -q -c 6 -i 0.2 -I up1 -m $((0x00410000)) $T1 >/dev/null 2>&1 &
  bg=$!
  out=$(probe icmp "${P1[@]}" --targets $T1,$T2,$T3 --required 3 --no-early --rounds 2 --interval-ms 1500)
  wait $bg
  stop_capture
  a=$(counters)
  expect_match "socket options set before the first packet" "$out" "socket kind=icmp-raw dev=up1 mark=0x00410000 local=$S1|socket kind=icmp-raw dev=up1 mark=0x00410000 local=\[$S1\]"
  expect_match "both rounds pass" "$out" "summary rounds=2 passed=2"
  expect_match "foreign echo replies ignored" "$out" "ignored reason=foreign_id"
  expect "echo requests on uplink 1 (6 probes + 6 foreign pings)" "$(delta "$b" "$a" u1_${FT}_echo)" 12
  expect "echo requests on uplink 2" "$(delta "$b" "$a" u2_${FT}_echo)" 0
  leak_check "$b" "$a"
  mac_gw1=$(ip netns exec $I cat /sys/class/net/u1/address)
  expect "echo request frames captured on up1" "$(grep -c 'echo request' $TMP/t1-$F.pcap.txt)" 12
  expect "echo request frames not addressed to the uplink 1 gateway MAC" "$(grep 'echo request' $TMP/t1-$F.pcap.txt | grep -vc "> $mac_gw1,")" 0
  grep -E 'echo request' $TMP/t1-$F.pcap.txt | head -3 | sed 's/^/  capture: /'

  echo
  echo "=== IPv$F T2: balancing table holds only path 2; probes of path 1 and of path 2"
  ip -n $R -$F route replace default via $GW2 dev up2 metric 100 proto $PROTO table $TB
  b=$(counters)
  out=$(probe icmp "${P1[@]}" --targets $T1,$T2,$T3 --required 3)
  a=$(counters)
  expect_match "path 1 round passes" "$out" "result=pass"
  expect "path 1 probes on uplink 1" "$(delta "$b" "$a" u1_${FT}_echo)" 3
  expect "path 1 probes on uplink 2" "$(delta "$b" "$a" u2_${FT}_echo)" 0
  b=$(counters)
  out=$(probe icmp "${P2[@]}" --targets $T1,$T2,$T3 --required 3)
  a=$(counters)
  expect_match "path 2 round passes" "$out" "result=pass"
  expect "path 2 probes on uplink 2" "$(delta "$b" "$a" u2_${FT}_echo)" 3
  expect "path 2 probes on uplink 1" "$(delta "$b" "$a" u1_${FT}_echo)" 0
  leak_check "$b" "$a"
  ip -n $R -$F route del default table $TB

  echo
  echo "=== IPv$F T3: TCP probes of path 1: open port, closed port (RST), blackholed target"
  b=$(counters)
  out=$(probe tcp "${P1[@]}" --targets "$TCPT" --required 2 --timeout-ms 1000)
  a=$(counters)
  expect_match "SYN-ACK counts as a reply" "$out" "result=reply kind=syn-ack"
  expect_match "RST counts as a reply" "$out" "result=reply kind=rst"
  expect_match "blackholed target lost on attempt 2" "$out" "attempt=2 result=lost"
  expect_match "round passes with 2 of 3" "$out" "reachable=2/3 required=2 result=pass"
  # 1 SYN each for the answered targets, 2 attempts for the blackholed one; an attempt may carry a
  # kernel SYN retransmission because the initial SYN RTO (1 s) equals the attempt timeout.
  syn=$(delta "$b" "$a" u1_${FT}_syn)
  expect "SYNs on uplink 1 within 4..6 (got $syn)" "$(( syn >= 4 && syn <= 6 ))" 1
  expect "SYNs on uplink 2" "$(delta "$b" "$a" u2_${FT}_syn)" 0
  leak_check "$b" "$a"

  echo
  echo "=== IPv$F T4: reply validation with forged replies (kernel replies of the target dropped upstream)"
  if [ $F = 4 ]; then
    ip netns exec $I nft add rule inet s5 inject_out ip saddr $T1 icmp type echo-reply drop
  else
    ip netns exec $I nft add rule inet s5 inject_out ip6 saddr $T1 icmpv6 type echo-reply drop
  fi
  ip netns exec $I python3 ./forge.py $F u1 $T1 $S1 $WRONG >$TMP/forge-$F.txt 2>&1 &
  bg=$!
  sleep 0.5
  csum6_b=$(ip netns exec $R nstat -asz Icmp6InCsumErrors | awk '/Icmp6InCsumErrors/{print $2}')
  out=$(probe icmp "${P1[@]}" --targets $T1 --required 1 --attempts 2 --timeout-ms 1000)
  csum6_a=$(ip netns exec $R nstat -asz Icmp6InCsumErrors | awk '/Icmp6InCsumErrors/{print $2}')
  wait $bg
  sed 's/^/  /' $TMP/forge-$F.txt
  expect_match "wrong token rejected" "$out" "ignored reason=wrong_token"
  expect_match "wrong source rejected" "$out" "ignored reason=wrong_source from=$WRONG"
  if [ $F = 4 ]; then
    expect_match "bad checksum rejected in user space" "$out" "ignored reason=bad_checksum"
  else
    expect_nomatch "bad checksum never delivered to the socket" "$out" "bad_checksum"
    expect "kernel counted the ICMPv6 checksum error" "$((csum6_a - csum6_b))" 1
  fi
  expect_match "attempt 1 lost despite forged replies" "$out" "attempt=1 seq=[0-9]+ result=lost"
  expect_match "reply after the deadline ignored as late" "$out" "ignored reason=late"
  expect_match "attempt 2 accepted" "$out" "attempt=2 seq=[0-9]+ result=reply"
  ip netns exec $I nft flush chain inet s5 inject_out

  echo
  echo "=== IPv$F T5: early end of a round and canceled attempts (echo replies of target 3 dropped upstream)"
  if [ $F = 4 ]; then
    ip netns exec $I nft add rule inet s5 inject_out ip saddr $T3 icmp type echo-reply drop
  else
    ip netns exec $I nft add rule inet s5 inject_out ip6 saddr $T3 icmpv6 type echo-reply drop
  fi
  out=$(probe icmp "${P1[@]}" --targets $T1,$T2,$T3 --required 2 --timeout-ms 500)
  expect_match "early end leaves the attempt of target 3 canceled" "$out" "target=$T3 attempt=1 seq=[0-9]+ result=canceled"
  out=$(probe icmp "${P1[@]}" --targets $T1,$T2,$T3 --required 2 --timeout-ms 500 --no-early)
  expect_match "without early end, both attempts of target 3 are samples" "$out" "target=$T3 attempt=2 seq=[0-9]+ result=lost"
  ip netns exec $I nft flush chain inet s5 inject_out

  echo
  echo "=== IPv$F T6: reverse-path filtering of probe replies (rp_filter=2, src_valid_mark=1 on uplinks) without source rules"
  from_rules del
  r0=$(rpf)
  out=$(probe icmp "${P1[@]}" --targets $T1,$T2,$T3 --required 3 --no-early --timeout-ms 500)
  out_tcp=$(probe tcp "${P1[@]}" --targets "$TCP1" --required 1 --timeout-ms 500 --attempts 1)
  r1=$(rpf)
  if [ $F = 4 ]; then
    expect_match "target 1 (no covering route) lost without source rules" "$out" "target=$T1 attempt=2 seq=[0-9]+ result=lost"
    expect_match "target 2 (covered by a main route) still replies" "$out" "target=$T2 attempt=1 seq=[0-9]+ result=reply"
    expect_match "TCP SYN-ACK of target 1 dropped as well" "$out_tcp" "result=lost"
    expect "replies dropped by reverse-path filtering" "$(( r1 - r0 ))" 3
    ip -n $R -$F route replace default via $GW2 dev up2 metric 100 proto $PROTO table $TB
    out=$(probe icmp "${P1[@]}" --targets $T1 --required 1 --timeout-ms 500)
    expect_match "with a non-empty balancing table, loose mode accepts target 1 again" "$out" "result=pass"
    ip -n $R -$F route del default table $TB
  else
    expect_match "IPv6 has no rp_filter: all replies accepted" "$out" "reachable=3/3"
    expect_match "IPv6 TCP SYN-ACK accepted" "$out_tcp" "result=reply"
  fi
  from_rules add
  out=$(probe icmp "${P1[@]}" --targets $T1,$T2,$T3 --required 3 --timeout-ms 500)
  expect_match "with source rules every reply is accepted" "$out" "reachable=3/3"

  echo
  echo "=== IPv$F T7: termination of device-bound probes: path table empty (not ready), unconfigured probe value"
  # t7 LABEL EXPECT_ICMP_REGEX PROBE_ARGS...: one ICMP attempt with capture and leak checks.
  t7() {
    local label=$1 re=$2
    shift 2
    ip -n $R neigh flush dev up1 2>/dev/null
    b=$(counters)
    r0=$(rpf)
    capture $TMP/t7.txt $R up1 "arp or ((icmp or icmp6) and not ip6 multicast) or tcp"
    out=$(probe icmp "$@" --targets $T1 --required 1 --attempts 1 --timeout-ms 1000)
    stop_capture
    a=$(counters)
    echo "  [$label] $(grep -E 'send_error|result=' <<<"$out" | grep -v '^round' | head -2 | tr '\n' ' ')"
    echo "  [$label] upstream received $(delta "$b" "$a" u1_${FT}_echo) echo request(s) on uplink 1; reverse-path drops: $(( $(rpf) - r0 ))"
    grep -E 'ARP|echo' $TMP/t7.txt | head -4 | sed 's/^/  capture: /'
    expect_match "[$label] outcome" "$out" "$re"
    expect "[$label] nothing on uplink 2" "$(( $(delta "$b" "$a" u2_${FT}_echo) + $(delta "$b" "$a" u2_${FT}_syn) ))" 0
    leak_check "$b" "$a"
  }
  ip -n $R -$F route flush table $((TB + 1))
  if [ $F = 4 ]; then
    t7 "v4, path table empty, no proxy ARP upstream" "result=lost" "${P1[@]}"
    expect_match "[v4, path table empty] kernel treats the target as on-link and sends ARP on up1" "$(cat $TMP/t7.txt)" "who-has $T1 tell $S1"
    ip netns exec $I sysctl -qw net.ipv4.conf.all.arp_ignore=0
    t7 "v4, path table empty, proxy ARP upstream" "result=lost" "${P1[@]}"
    expect_match "[v4, path table empty, proxy ARP] echo request leaves on up1 directly to the target" "$(cat $TMP/t7.txt)" "$S1 > $T1: ICMP echo request"
  else
    t7 "v6, path table empty" "send_error=\"Network unreachable" "${P1[@]}"
  fi
  t7 "v$F, path table empty, without SO_BINDTODEVICE" "send_error=\"Network unreachable" "${P1[@]}" --no-device
  path_routes $F
  if [ $F = 4 ]; then
    t7 "v4, unconfigured probe value (id 5), proxy ARP upstream" "result=reply" --dev up1 --src $S1 --mark 0x00450000
    ip netns exec $I sysctl -qw net.ipv4.conf.all.arp_ignore=1
  else
    t7 "v6, unconfigured probe value (id 5)" "send_error=\"Network unreachable" --dev up1 --src $S1 --mark 0x00450000
  fi
  t7 "v$F, unconfigured probe value (id 5), without SO_BINDTODEVICE" "send_error=\"Network unreachable" --dev up1 --src $S1 --mark 0x00450000 --no-device

  echo
  echo "=== IPv$F T8: unprivileged ICMP sockets (SOCK_DGRAM) for comparison"
  out=$(probe dgram-check --src $S1 --target $T1 --dev up1)
  expect_match "default ping_group_range of a new namespace refuses ping sockets, also to root" "$out" "socket_error=\"Permission denied"
  ip netns exec $R sysctl -qw net.ipv4.ping_group_range="0 0"
  capture $TMP/t8-$F.txt $I u1 "icmp or icmp6"
  out=$(probe dgram-check --src $S1 --target $T1 --dev up1 --id 0x1234)
  stop_capture
  ip netns exec $R sysctl -qw net.ipv4.ping_group_range="1 0"
  grep -E 'echo (request|reply)' $TMP/t8-$F.txt | head -2 | sed 's/^/  capture: /'
  expect_match "kernel replaced the identifier with the bound port on the wire" "$(cat $TMP/t8-$F.txt)" "echo request, id 4660"
  expect_match "reply delivered with the bound identifier" "$out" "id=0x1234"
done

rm -rf "$TMP"
echo
echo "failures: $fails"
exit $((fails > 0))
