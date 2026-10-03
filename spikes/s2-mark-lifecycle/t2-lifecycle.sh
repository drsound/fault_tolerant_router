#!/usr/bin/env bash
# S2 / §4.7, FR-MARK-5, FR-POL-2: mark lifecycle per packet, observed after
# each FTR chain: outbound assignment only in postrouting (conntrack mark =
# actual egress path, also for policy-marked connections), restoration of
# every packet in prerouting, inbound assignment on arrival, probe packets
# never assigned and their replies left unmarked. Both families.
set -euo pipefail
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
portfwd_up
ip netns exec "$P-c" $PEER serve >/dev/null 2>&1 &
ip netns exec "$P-i" $PEER serve --port 8 >/dev/null 2>&1 &
export S2_POLICIES="$(policy 4 'tcp dport 8' 0x81)
$(policy 6 'tcp dport 8' 0x81)"
s2_nft 1 2 3
eq() { [ "$(cval "$1" "$2")" = "$(cval "$1" "$3")" ] && [ "$(cval "$1" "$2")" != 0 ] && echo yes || echo "no ($2=$(cval "$1" "$2") $3=$(cval "$1" "$3"))"; }

for f in 4 6; do
  if [ $f = 4 ]; then D=198.18.100.31; RB=198.51.100.2; T1=1.1.1.1; SA=192.0.2.2; else D=2001:db8:100::31; RB=2001:db8:b::2; T1=2606:4700:4700::1111; SA=2001:db8:a::2; fi
  echo "== IPv$f outbound forwarded connection, active set {B}"
  balance $f 2
  nsr conntrack -F >/dev/null 2>&1 || true
  chk_up "meta nfproto ipv$f meta l4proto tcp ct original proto-dst 7"
  r=$(nsc $PEER conn "$D" --count 1 | peer_uplink); c=$(chk)
  check "v$f connection works via B ($r)" '"B": 1' "$r"
  note "$c"
  check "v$f first packet unmarked in prerouting (no assignment before routing)" "^[1-9]" "$(cval "$c" o_pre_m0)"
  check "v$f every later original packet restored in prerouting" "^$(( $(cval "$c" o_pre_all) - 1 ))$" "$(cval "$c" o_pre_m2)"
  check "v$f every reply packet restored in prerouting" yes "$(eq "$c" r_pre_all r_pre_m2)"
  check "v$f after postrouting every original packet carries path 2 in conntrack and packet marks" yes "$(eq "$c" o_post_all o_post_c2)"
  check "v$f ... packet mark" yes "$(eq "$c" o_post_all o_post_m2)"
  check "v$f conntrack entry marked with path 2" "0x2" "$(ctmark $f -p tcp --dport 7)"

  echo "== IPv$f policy-marked connection (policy-balance to A), active set {B}"
  chk_up "meta nfproto ipv$f meta l4proto tcp ct original proto-dst 8"
  r=$(nsc $PEER conn "$D" --port 8 --count 1 | peer_uplink); c=$(chk)
  check "v$f policy connection via A ($r)" '"A": 1' "$r"
  note "$c"
  check "v$f first packet carries the policy value 0x81 in the packet mark only" "^1 0$" "$(cval "$c" o_pre_m129) $(cval "$c" o_pre_c129)"
  check "v$f after postrouting: path value 1 (actual egress) in conntrack and packet marks" yes "$(eq "$c" o_post_all o_post_c1)"
  check "v$f conntrack entry marked with path 1, not the policy value" "0x1" "$(ctmark $f -p tcp --dport 8)"
  route_del $f $((T + 65))
  nsr conntrack -D -p tcp --dport 8 >/dev/null 2>&1 || true
  r=$(nsc $PEER conn "$D" --port 8 --count 1 | peer_uplink)
  check "v$f policy table of A empty: connection balanced via B ($r)" '"B": 1' "$r"
  check "v$f ... and its conntrack mark is path 2, the actual egress (FR-POL-2)" "0x2" "$(ctmark $f -p tcp --dport 8)"
  path_route $f 1 $((T + 65))

  echo "== IPv$f inbound connection through B, active set {A}"
  balance $f 1
  chk_up "meta nfproto ipv$f meta l4proto tcp ct original proto-dst 8007"
  nsr conntrack -F >/dev/null 2>&1 || true
  r=$(nsi $PEER conn "$RB" --port 8007 --count 1); c=$(chk)
  check "v$f inbound connection answered" '"errors": \{\}' "$r"
  note "$c"
  check "v$f every original packet carries path 2 after prerouting, the first included" yes "$(eq "$c" o_pre_all o_pre_m2)"
  check "v$f every reply packet restored on the downlink" yes "$(eq "$c" r_pre_all r_pre_m2)"
  check "v$f every reply leaves through B" yes "$(eq "$c" r_fin_all r_fin_if_wanb)"

  echo "== IPv$f probes (ICMP and TCP) of A, active set {B}"
  balance $f 2
  chk_up "meta nfproto ipv$f ct original ip$( [ $f = 6 ] && echo 6) daddr $T1"
  nsr conntrack -F >/dev/null 2>&1 || true
  r=$(nsr $S2TOOL ping "$T1" --mark "$(enc 0x41)" --device wana --src "$SA" --count 3)
  r2=$(nsr $PEER conn "$T1" --mark "$(enc 0x41)" --device wana --src "$SA" --count 2)
  c=$(chk)
  check "v$f ICMP probes answered ($r)" '"lost": 0, "replies": 3' "$r"
  check "v$f TCP probes answered" '"errors": \{\}' "$r2"
  note "$c"
  check "v$f probe packets keep the probe value after output and postrouting (never assigned)" yes "$(eq "$c" o_post_all o_post_m65)"
  check "v$f probe packets leave through A" yes "$(eq "$c" o_fin_all o_fin_if_wana)"
  check "v$f conntrack entries of probes carry no path value" "^(0x0 )+$" "$(ctmark $f -d "$T1")"
  check "v$f replies to probes are left unmarked" "^[1-9][0-9]* 0$" "$(cval "$c" r_pre_m0) $(cval "$c" r_pre_m65)"
  balance $f 1 2 3
done
summary
