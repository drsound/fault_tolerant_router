#!/usr/bin/env bash
# S2 / FR-MARK-3, FR-MARK-5, FR-FW-1, FR-FW-4, FR-REC-6: the §4.7 ruleset is
# accepted by nftables; mark writes are constant-only bitwise operations; no
# accept/drop/reject verdicts; what must be normalised for the comparison of
# FR-REC-6; atomic replacement keeps existing flows and NAT bindings.
set -euo pipefail
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
portfwd_up
ip netns exec "$P-c" $PEER serve >/dev/null 2>&1 &
export S2_POLICIES="$(policy 4 'ip saddr 10.1.0.0/24 ip daddr 198.18.100.0/24 tcp dport 25' 0xc1)
$(policy 6 'ip6 daddr 2001:db8:100::/64 udp dport 5060-5061' 0x82)"
TXT=/tmp/$P-ruleset.nft
s2_nft_text 1 2 3 >"$TXT"

echo "== syntax and bytecode"
check "ruleset accepted by nft (check mode)" "^ok$" "$(nsr nft -c -f "$TXT" >/dev/null 2>&1 && echo ok || nsr nft -c -f "$TXT" 2>&1 | head -3)"
s2_nft 1 2 3
nsr nft --debug=netlink -c -f "$TXT" >/tmp/$P-netlink.txt 2>&1 || true
bw=$(grep -c "bitwise reg" /tmp/$P-netlink.txt || true)
const=$(grep -cE "bitwise reg [0-9]+ = \( ?reg [0-9]+ & 0x[0-9a-f]+ ?\) \^ 0x[0-9a-f]+" /tmp/$P-netlink.txt || true)
note "bitwise operations: $bw, of which constant mask-and-xor: $const"
note "sample: $(grep -m1 -B2 -A1 "meta set mark" /tmp/$P-netlink.txt | tr -s ' \n' ' ')"
check "every bitwise operation is register & constant ^ constant (FR-MARK-3)" "^$bw$" "$const"
check "no bitwise operation combines two registers" "^0$" "$(grep -cE "bitwise reg [0-9]+ = .*reg [0-9]+.*reg [0-9]+" /tmp/$P-netlink.txt || true)"
check "no accept, drop or reject verdict in any rule (FR-FW-4)" "^0$" "$(nsr nft list table inet fault_tolerant_router | grep -v 'policy accept' | grep -cwE 'accept|drop|reject|queue|jump|goto' || true)"
note "rules in the table: $(nsr nft -a list table inet fault_tolerant_router | grep -c '# handle')"

echo "== traffic over every uplink (including the point-to-point one) with the refined ruleset"
for f in 4 6; do
  [ $f = 4 ] && DS="198.18.100.1 198.18.100.2 198.18.100.3" || DS="2001:db8:100::1 2001:db8:100::2 2001:db8:100::3"
  r=$(nsc $PEER conn $DS --count 30 | peer_uplink)
  check "v$f forwarded connections balanced over A, B, C ($r)" '"errors": \{\}, "peers": \{"A": [0-9]+, "B": [0-9]+, "C": [0-9]+\}' "$r"
done

echo "== JSON listing stability for FR-REC-6"
j1=$(nsr nft -j list table inet fault_tolerant_router)
s2_nft 1 2 3
j2=$(nsr nft -j list table inet fault_tolerant_router)
norm() { python3 -c '
import json, sys
d = json.load(sys.stdin)["nftables"]
out = []
for o in d:
    if "metainfo" in o:
        continue
    (k, v), = o.items()
    v = {x: y for x, y in v.items() if x != "handle"}
    out.append({k: v})
print(json.dumps(out, sort_keys=True))'; }
check "raw listings differ after re-applying identical text" "^differ$" "$([ "$j1" = "$j2" ] && echo same || echo differ)"
note "keys that differ: $(python3 -c '
import json, sys
a, b = (json.loads(x)["nftables"] for x in sys.argv[1:3])
diff = set()
for x, y in zip(a, b):
    (k, v), = x.items(); (_, w), = y.items()
    for key in set(v) | set(w):
        if v.get(key) != w.get(key): diff.add(k + "." + key)
print(sorted(diff), "objects", len(a), len(b))' "$j1" "$j2")"
check "listings equal once metainfo and handles are removed" "^same$" "$([ "$(echo "$j1" | norm)" = "$(echo "$j2" | norm)" ] && echo same || echo differ)"
nsr nft add rule inet fault_tolerant_router postrouting counter
check "a third-party change is detected after normalisation" "^differ$" "$([ "$(echo "$j1" | norm)" = "$(nsr nft -j list table inet fault_tolerant_router | norm)" ] && echo same || echo differ)"
s2_nft 1 2 3

echo "== atomic replacement with live flows and NAT bindings"
both_long() { # start an outbound flow (client) and an inbound flow (internet via B)
  rm -f /tmp/$P-o$1.ready /tmp/$P-i$1.ready
  ip netns exec "$P-c" $PEER long "$2" --period 0.05 --fail-after 2 --ready /tmp/$P-o$1.ready >/tmp/$P-o$1.out 2>&1 & eval "PO$1=$!"
  ip netns exec "$P-i" $PEER long "$3" --port 8007 --period 0.05 --fail-after 2 --ready /tmp/$P-i$1.ready >/tmp/$P-i$1.out 2>&1 & eval "PI$1=$!"
  local i; for i in $(seq 1 40); do [ -e /tmp/$P-o$1.ready ] && [ -e /tmp/$P-i$1.ready ] && return 0; sleep 0.1; done
  echo "flows did not start"; return 1
}
both_long 4 198.18.100.5 198.51.100.2
both_long 6 2001:db8:100::5 2001:db8:b::2
for i in $(seq 1 20); do
  if [ $((i % 2)) = 0 ]; then s2_nft 1 2 3; else S2_POLICIES="" s2_nft 1 2 3; fi
  sleep 0.1
done
for f in 4 6; do eval "kill \$PO$f \$PI$f"; eval "wait \$PO$f \$PI$f" || true; done
for f in 4 6; do
  check "v$f outbound NAT flow across 20 replacements: no error, gap < 0.5 s" '"error": null, "max_gap": 0\.[0-4]' "$(cat /tmp/$P-o$f.out)"
  check "v$f inbound DNAT flow across 20 replacements: no error, gap < 0.5 s" '"error": null, "max_gap": 0\.[0-4]' "$(cat /tmp/$P-i$f.out)"
done
summary
