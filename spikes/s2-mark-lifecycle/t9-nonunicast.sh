#!/usr/bin/env bash
# S2 / §4.7, §4.8: multicast and broadcast are never marked. UDP datagrams to
# limited, subnet-directed and multicast destinations arrive from the LAN, from
# an Ethernet uplink and through the GRE uplink, are sent by the router out of
# uplinks and the LAN, and are routed between the LAN and an uplink (multicast
# routing entry); a unicast datagram is sent to an L2 broadcast / multicast
# address. The LAN has a policy on the test ports, so a missing skip shows as a
# policy or path value. Every case runs with three generators: the current one
# (meta pkttype in prerouting, destination prefixes in postrouting), none of the
# skips (control), and the address-based skips proposed here. Unicast controls
# are marked by all three. Both families.
set -euo pipefail
P=s2; source "$(dirname "$0")/../lib/netns.sh"; source "$(dirname "$0")/s2lib.sh"
trap 'kill $(jobs -p) 2>/dev/null || true; topo_down' EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
portfwd_up
ip netns exec "$P-r" $PEER serve >/dev/null 2>&1 &
ip -n "$P-r" link set wanc multicast on
ip -n "$P-C" link set tun multicast on
export S2_POLICIES="$(policy 4 'udp dport 5000-6999' 0x81)
$(policy 6 'udp dport 5000-6999' 0x81)"

# pk_up PORT: counts the test packets by meta pkttype after FTR's prerouting
# and postrouting chains; pk prints the non-zero counters.
pk_up() {
  local h t
  nsr nft delete table inet pk 2>/dev/null || true
  {
    echo "table inet pk {"
    for h in pre post; do for t in host broadcast multicast; do echo "  counter ${h}_$t {}"; done; done
    for h in pre post; do
      echo "  chain $h {"
      echo "    type filter hook $([ $h = pre ] && echo prerouting || echo postrouting) priority -140; policy accept;"
      for t in host broadcast multicast; do echo "    udp dport $1 meta pkttype $t counter name ${h}_$t"; done
      echo "  }"
    done
    echo "}"
  } | nsr nft -f -
}
pk() { nsr nft -j list counters table inet pk | python3 -c '
import json, sys
c = {o["counter"]["name"]: o["counter"]["packets"] for o in json.load(sys.stdin)["nftables"] if "counter" in o}
print(" ".join(f"{k}={v}" for k, v in sorted(c.items()) if v) or "none")'; }
# vals: distinct non-zero FTR values seen in packet or conntrack marks, "-" if none
vals() { local v; v=$(echo "$c" | grep -oE '_[mc][1-9][0-9]*=' | grep -oE '[0-9]+' | sort -un | paste -sd, - || true); echo "${v:--}"; }

# Cases: FAMILY PORT EXPECTED(current) EXPECTED(no skips) EXPECTED(proposed) LABEL
# followed by the sending command. Expected: distinct FTR values in marks.
CASES=$(cat <<'EOF'
4 5001 - 129 - LAN host -> 255.255.255.255|nsc $S2TOOL dgram 255.255.255.255 --device lan
4 5002 - 129 - LAN host -> 10.1.0.255 (LAN subnet broadcast)|nsc $S2TOOL dgram 10.1.0.255 --device lan
4 5003 - 129 - LAN host -> 224.0.0.251|nsc $S2TOOL dgram 224.0.0.251 --device lan
4 5004 - 1 - provider A -> 255.255.255.255 on wana|nsp a $S2TOOL dgram 255.255.255.255 --device cust
4 5005 - 1 - provider A -> 192.0.2.255 (subnet broadcast of wana)|nsp a $S2TOOL dgram 192.0.2.255 --device cust
4 5006 - 1 - provider A -> 224.0.0.251 on wana|nsp a $S2TOOL dgram 224.0.0.251 --device cust
4 5007 3 3 - provider C -> 224.0.0.251 through GRE (wanc)|nsp C $S2TOOL dgram 224.0.0.251 --device tun
4 5008 3 3 - provider C -> 255.255.255.255 through GRE (wanc)|nsp C $S2TOOL dgram 255.255.255.255 --device tun
4 5009 - 1 - router -> 255.255.255.255 out of wana|nsr $S2TOOL dgram 255.255.255.255 --device wana
4 5010 1 1 - router -> 192.0.2.255 (subnet broadcast) out of wana|nsr $S2TOOL dgram 192.0.2.255 --device wana
4 5011 - 1 - router -> 224.0.0.251 out of wana|nsr $S2TOOL dgram 224.0.0.251 --device wana
4 5012 - 3 - router -> 224.0.0.251 out of wanc (GRE)|nsr $S2TOOL dgram 224.0.0.251 --device wanc
4 5013 - 129 - router -> 255.255.255.255 and 224.0.0.251 out of the LAN|nsr $S2TOOL dgram 255.255.255.255 --device lan; nsr $S2TOOL dgram 224.0.0.251 --device lan
4 5014 - 1,129 - routed multicast LAN host -> 239.1.2.3 forwarded out of wana|nsc $S2TOOL dgram 239.1.2.3 --device lan --ttl 8
4 5015 129 129 - LAN host -> 192.0.2.255 (wana's subnet broadcast), delivered locally|nsc $S2TOOL dgram 192.0.2.255
4 5016 1,129 1,129 - same with bc_forwarding: forwarded out of wana|bcfwd 1; nsc $S2TOOL dgram 192.0.2.255; bcfwd 0
4 5017 - 1 - provider A -> 192.0.2.2 (unicast) on the L2 broadcast address|l2bcast 4 on; nsp a $S2TOOL dgram 192.0.2.2; l2bcast 4 off
4 5018 1 1 1 control: provider A -> 192.0.2.2 unicast|nsp a $S2TOOL dgram 192.0.2.2
4 5019 3 3 3 control: provider C -> 203.0.113.2 unicast through GRE|nsp C $S2TOOL dgram 203.0.113.2
4 5020 1,129 1,129 1,129 control: LAN host -> internet unicast (forwarded, policy to A)|nsc $S2TOOL dgram 198.18.100.90
6 6001 - 129 - LAN host -> ff02::fb|nsc $S2TOOL dgram ff02::fb --device lan
6 6002 - 129 - LAN host -> ff02::1|nsc $S2TOOL dgram ff02::1 --device lan
6 6003 - 1 - provider A -> ff02::fb on wana|nsp a $S2TOOL dgram ff02::fb --device cust
6 6004 3 3 - provider C -> ff02::fb through GRE (wanc)|nsp C $S2TOOL dgram ff02::fb --device tun
6 6005 - 1 - router -> ff02::fb out of wana|nsr $S2TOOL dgram ff02::fb --device wana
6 6006 - 3 - router -> ff02::fb out of wanc (GRE)|nsr $S2TOOL dgram ff02::fb --device wanc
6 6007 - 129 - router -> ff02::fb out of the LAN|nsr $S2TOOL dgram ff02::fb --device lan
6 6008 - 1,129 - routed multicast LAN host -> ff0e::db8:1 forwarded out of wana|nsc $S2TOOL dgram ff0e::db8:1 --device lan --ttl 8
6 6009 - 1 - provider A -> 2001:db8:a::2 (unicast) on an L2 multicast address|l2bcast 6 on; nsp a $S2TOOL dgram 2001:db8:a::2; l2bcast 6 off
6 6010 1 1 1 control: provider A -> 2001:db8:a::2 unicast|nsp a $S2TOOL dgram 2001:db8:a::2
6 6011 3 3 3 control: provider C -> 2001:db8:c::2 unicast through GRE|nsp C $S2TOOL dgram 2001:db8:c::2
6 6012 1,129 1,129 1,129 control: LAN host -> internet unicast (forwarded, policy to A)|nsc $S2TOOL dgram 2001:db8:100::90
EOF
)
bcfwd() { sysctls "$P-r" "net.ipv4.conf.all.bc_forwarding=$1" "net.ipv4.conf.lan.bc_forwarding=$1"; }
l2bcast() { # l2bcast FAM on|off: provider A sends to the router's address on an L2 broadcast/multicast MAC
  if [ "$1" = 4 ]; then a=192.0.2.2; mac=ff:ff:ff:ff:ff:ff; else a=2001:db8:a::2; mac=33:33:00:00:00:01; fi
  if [ "$2" = on ]; then ip -n "$P-a" neigh replace "$a" lladdr "$mac" dev cust nud permanent
  else ip -n "$P-a" neigh del "$a" dev cust; fi
}
# Multicast routing entries (vif/mif 0 = lan, 1 = wana) for the routed cases.
ip netns exec "$P-r" $S2TOOL mroute 239.1.2.3 --src 10.1.0.2 --iif lan --oif wana >/dev/null &
ip netns exec "$P-r" $S2TOOL mroute ff0e::db8:1 --src fd00:1::2 --iif lan --oif wana >/dev/null &
sleep 0.5
note "multicast routing: $(nsr ip mroute show | tr -s ' \n' ' ') | $(nsr ip -6 mroute show | tr -s ' \n' ' ')"

for variant in current none proposed; do
  echo "######## generator: $variant"
  case $variant in
    current) s2_nft 1 2 3; col=3;;
    none) S2_NO_NONUNICAST=1 s2_nft 1 2 3; col=4;;
    proposed) S2_NONUNICAST_ADDR=1 s2_nft 1 2 3; col=5;;
  esac
  while IFS='|' read -r -u 3 head cmd; do
    set -- $head
    f=$1; port=$2; exp=${!col}; label=${head#* * * * * }
    chk_up "meta nfproto ipv$f udp dport $port"
    pk_up "$port"
    nsr conntrack -F >/dev/null 2>&1 || true
    eval "${cmd//\$S2TOOL/\$S2TOOL --port $port}" >/dev/null
    sleep 0.3
    c=$(chk); k=$(pk)
    seen=$(( $(cval "$c" o_pre_all) + $(cval "$c" o_out_all) ))
    [ $variant != current ] || note "v$f $port pkttype: $k; egress: $(echo "$c" | grep -oE 'o_fin_if_[a-z]+=[0-9]+' | paste -sd' ' -)"
    check "$variant v$f $port $label: FTR values {$exp}" "^seen [1-9][0-9]* values $exp$" "seen $seen values $(vals)"
  done 3<<<"$CASES"
done

echo "######## UDP and TCP to the router and to a port forwarding on an L2 broadcast / multicast address (current generator)"
s2_nft 1 2 3
for f in 4 6; do
  [ $f = 4 ] && RA=192.0.2.2 || RA=2001:db8:a::2
  l2bcast $f on
  nsr conntrack -F >/dev/null 2>&1 || true
  chk_up "meta nfproto ipv$f meta l4proto udp"
  r=$(nsp a $PEER udp "$RA" --count 2 --timeout 2); c=$(chk)
  check "v$f UDP to the router answered" '"errors": \{\}' "$r"
  check "v$f ... never assigned (pkttype not host), replies leave through A by the source rule" "^0 0 [1-9]" "$(cval "$c" o_pre_c1) $(cval "$c" r_post_c1) $(cval "$c" r_fin_if_wana)"
  r=$(nsp a $PEER conn "$RA" --count 1 --timeout 2)
  check "v$f TCP to the router fails (TCP discards packets whose pkttype is not host)" '"timeout": 1' "$r"
  r=$(nsp a $PEER conn "$RA" --port 8007 --count 1 --timeout 2)
  check "v$f port forwarding fails (the kernel forwards only pkttype host)" '"timeout": 1' "$r"
  l2bcast $f off
done
summary
