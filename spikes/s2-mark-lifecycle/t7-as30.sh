#!/usr/bin/env bash
# S2 / FR-SYS-2, INV-5, INV-6, AS-30: active set empty and no operating-system
# default route that could mask errors. Inbound DNAT traffic, connections to
# router listeners, ICMP and TCP probe replies are accepted by routing and
# reverse-path filtering (rp_filter = 2, src_valid_mark = 1), both families.
# IPv4 negative control: ICMP probe replies with the probe source's source
# rule removed are rejected by reverse-path filtering. Also src_valid_mark = 0.
set -euo pipefail
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
portfwd_up
s2_nft 1 2 3
ip netns exec "$P-c" $PEER serve >/dev/null 2>&1 &
ip netns exec "$P-r" $PEER serve >/dev/null 2>&1 &
for f in 4 6; do
  while nsr ip -$f route del default 2>/dev/null; do :; done
  balance $f
done
check "no default route left in main" "^0 0$" "$(nsr ip -4 route show default | wc -l | tr -d ' ') $(nsr ip -6 route show default | wc -l | tr -d ' ')"
rpdrops() { nsr nstat -az TcpExtIPReversePathFilter | awk '/IPReversePathFilter/ {print $2}'; }

cases() { # cases LABEL EXPECT-v4-DNAT EXPECT-v4-LISTENER EXPECT-v4-ICMP EXPECT-v4-TCP
  local f
  for f in 4 6; do
    if [ $f = 4 ]; then SA=192.0.2.2; T1=1.1.1.1; else SA=2001:db8:a::2; T1=2606:4700:4700::1111; fi
    local e1=ok e2=ok e3=ok e4=ok
    [ $f = 4 ] && { e1=$2; e2=$3; e3=$4; e4=$5; }
    local r
    r=$(nsi $PEER conn "$SA" --port 8007 --count 3 --timeout 1)
    check "v$f $1: inbound DNAT through A -> $e1" "$([ $e1 = ok ] && echo '"errors": \{\}' || echo '"errors": \{"timeout": 3\}')" "$r"
    r=$(nsi $PEER conn "$SA" --count 3 --timeout 1)
    check "v$f $1: connection to a router listener through A -> $e2" "$([ $e2 = ok ] && echo '"errors": \{\}' || echo '"errors": \{"timeout": 3\}')" "$r"
    r=$(nsr $S2TOOL ping "$T1" --mark "$(enc 0x41)" --device wana --src "$SA" --count 3)
    check "v$f $1: ICMP probe of A answered -> $e3" "$([ $e3 = ok ] && echo '"lost": 0' || echo '"lost": 3')" "$r"
    r=$(nsr $PEER conn "$T1" --mark "$(enc 0x41)" --device wana --src "$SA" --count 3 --timeout 1)
    check "v$f $1: TCP probe of A answered -> $e4" "$([ $e4 = ok ] && echo '"errors": \{\}' || echo '"errors": \{"timeout": 3\}')" "$r"
  done
}

nsr nstat -n >/dev/null
cases "rp_filter=2 src_valid_mark=1" ok ok ok ok
check "IPv4 reverse-path drops so far" "^0$" "$(rpdrops)"

echo "== IPv4 negative control: source rule (and its guard) of the probe source removed"
r_rule_del 4 pref $((B + 501)) from 192.0.2.2 fwmark "0/$MASK" lookup $((T + 1))
r=$(nsr $S2TOOL ping 1.1.1.1 --mark "$(enc 0x41)" --device wana --src 192.0.2.2 --count 3)
check "v4 ICMP probe replies rejected by reverse-path filtering (source guard)" '"lost": 3' "$r"
r_rule_del 4 pref $((B + 564)) from 192.0.2.2 fwmark "0/$MASK" unreachable
r=$(nsr $S2TOOL ping 1.1.1.1 --mark "$(enc 0x41)" --device wana --src 192.0.2.2 --count 3)
check "v4 ICMP probe replies rejected by reverse-path filtering (final guard)" '"lost": 3' "$r"
check "v4 reverse-path drops counted" "^[1-9]" "$(rpdrops)"
r=$(nsr $PEER conn 1.1.1.1 --mark "$(enc 0x41)" --device wana --src 192.0.2.2 --count 1 --timeout 1)
note "v4 TCP probe without the source rule: $r"
rule_from 4 1 192.0.2.2; guard_from 4 192.0.2.2

echo "== src_valid_mark = 0 on the uplinks"
for i in wana wanb wanc; do nsr sysctl -qw "net.ipv4.conf.$i.src_valid_mark=0"; done
nsr nstat -n >/dev/null
cases "src_valid_mark=0" fail ok ok ok
note "v4 reverse-path drops with src_valid_mark=0: $(rpdrops)"
summary
