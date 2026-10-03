#!/usr/bin/env bash
# S2 / FR-MARK-1, FR-MARK-3, INV-7, AS-24, AS-43 preview: another table writes
# packet and conntrack mark bits outside fwmark_mask before and after FTR's
# chains; those bits are preserved end to end, and FTR's routing and marking
# work unchanged, with the FTR field at bit offsets 0, 16 and 24.
set -euo pipefail
if [ "${1:-}" != --one ]; then
  rc=0
  for s in 0 16 24; do SHIFT=$s bash "$0" --one || rc=1; done
  exit $rc
fi
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
hex() { printf '0x%08x' "$1"; }
FM1=$(hex $(( 0x01010101 & NOTMASK )))   # packet bits written before FTR
FM2=$(hex $(( 0x08080808 & NOTMASK )))   # packet bits written after FTR
FC=$(hex $(( 0x02020202 & NOTMASK )))    # conntrack bits written before FTR
FS=$(hex $(( 0x10101010 & NOTMASK )))    # bits already in the socket mark of probes
FALL=$(hex $(( FM1 | FM2 )))
echo "######## fwmark_mask $MASK (offset $SHIFT): foreign packet bits $FM1 + $FM2, conntrack bits $FC, socket bits $FS"
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
portfwd_up
ip netns exec "$P-c" $PEER serve >/dev/null 2>&1 &
s2_nft 1 2 3
nsr nft -f - <<EOF
table inet other {
  chain pre_before { type filter hook prerouting priority -190; policy accept;
    meta mark set meta mark | $FM1
    ct state new ct mark set ct mark | $FC
  }
  chain out_before { type route hook output priority -190; policy accept;
    ct state new ct mark set ct mark | $FC
  }
  chain pre_after { type filter hook prerouting priority -100; policy accept;
    meta mark set meta mark | $FM2
  }
  chain post_after { type filter hook postrouting priority -100; policy accept;
    meta mark set meta mark | $FM2
  }
}
EOF
fx_up() { # count, after NAT, packets matching $1 that carry foreign bits $3 (default FM1|FM2) and the FTR value $2
  local want=${3:-$FALL}
  nsr nft delete table inet fx 2>/dev/null || true
  nsr nft -f - <<EOF
table inet fx {
  counter n_all {}
  counter n_ok {}
  chain fin { type filter hook postrouting priority 300; policy accept;
    $1 counter name n_all
    $1 meta mark & $want == $want meta mark & $MASK == $(enc "$2") counter name n_ok
  }
}
EOF
}
fx() { nsr nft -j list counters table inet fx | python3 -c 'import json,sys; c={o["counter"]["name"]:o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}; print(c["n_all"], c["n_ok"])'; }
ctraw() { nsr conntrack -L -f "ipv$1" "${@:2}" 2>/dev/null | grep -o "mark=[0-9]*" | cut -d= -f2 | while read -r m; do hex "$m"; printf ' '; done; }
same() { local a b; read -r a b <<<"$1"; [ "$a" = "$b" ] && [ "$a" != 0 ] && echo yes || echo "no ($1)"; }

for f in 4 6; do
  if [ $f = 4 ]; then D=198.18.100.41; RB=198.51.100.2; T1=8.8.8.8; SA=192.0.2.2; else D=2001:db8:100::41; RB=2001:db8:b::2; T1=2001:4860:4860::8888; SA=2001:db8:a::2; fi
  balance $f 2
  fx_up "meta nfproto ipv$f meta l4proto tcp ct original proto-dst 7 ct direction original" 2
  r=$(nsc $PEER conn "$D" --count 3 | peer_uplink)
  check "v$f outbound connections via B with foreign bits present ($r)" '"B": 3' "$r"
  check "v$f outbound packets leave with all foreign bits and path 2 (all ok)" yes "$(same "$(fx)")"
  check "v$f conntrack mark = foreign bits | path 2" "^($(hex $(( FC | $(enc 2) ))) )+$" "$(ctraw $f -p tcp --dport 7)"

  balance $f 1
  nsr conntrack -F >/dev/null 2>&1 || true
  fx_up "meta nfproto ipv$f meta l4proto tcp ct original proto-dst 8007 ct direction reply" 2
  r=$(nsi $PEER conn "$RB" --port 8007 --count 3)
  check "v$f inbound connections through B answered" '"errors": \{\}' "$r"
  check "v$f replies leave with all foreign bits and path 2" yes "$(same "$(fx)")"
  check "v$f conntrack mark of inbound = foreign bits | path 2" "^($(hex $(( FC | $(enc 2) ))) )+$" "$(ctraw $f -p tcp --dport 8007)"

  balance $f 2
  fx_up "meta nfproto ipv$f ct original ip$( [ $f = 6 ] && echo 6) daddr $T1 ct direction original" 0x41 "$(hex $(( FS | FM2 )))"
  r=$(nsr $S2TOOL ping "$T1" --mark "$(hex $(( FS | $(enc 0x41) )))" --device wana --src "$SA" --count 3)
  check "v$f probe of A with foreign bits in the socket mark answered" '"lost": 0' "$r"
  check "v$f probe packets keep foreign bits and the probe value" yes "$(same "$(fx)")"
  check "v$f probe conntrack mark has only the foreign conntrack bits" "^($FC )+$" "$(ctraw $f -d "$T1")"
  balance $f 1 2 3
done
summary
