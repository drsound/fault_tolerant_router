#!/bin/sh
# Print a minimal nftables table implementing the mark lifecycle of SPEC v0.5
# §4.7 (no policies, no NAT), so that control-plane traffic is also exercised
# with mark assignment and restoration active. Usage: ftr-nft.sh | nft -f -
# Environment: UPLINKS="1:wana 2:wanb 3:ppp0" DOWNLINKS="lan" MASK=0x00ff0000
set -eu
UPLINKS=${UPLINKS:-"1:wana 2:wanb 3:ppp0"}
DOWNLINKS=${DOWNLINKS:-"lan"}
MASK=${MASK:-0x00ff0000}
m=$((MASK)); SHIFT=0; while [ $((m & 1)) -eq 0 ]; do m=$((m >> 1)); SHIFT=$((SHIFT + 1)); done
enc() { printf '0x%08x' $(( ($1) << SHIFT )); }
KEEP=$(printf '0x%08x' $(( ~MASK & 0xffffffff )))
FIELD=$(enc 0xff); CLASS=$(enc 0xc0); PROBE=$(enc 0x40)

restore() { # restore all 63 path values from ct mark into the packet mark
  id=1; while [ $id -le 63 ]; do
    v=$(enc $id)
    echo "    ct mark & $FIELD == $v meta mark set meta mark & $KEEP | $v return"
    id=$((id + 1))
  done
}

cat <<NFT
table inet fault_tolerant_router
delete table inet fault_tolerant_router
table inet fault_tolerant_router {
  chain prerouting {
    type filter hook prerouting priority -150; policy accept;
$(restore)
$(for u in $UPLINKS; do id=${u%%:*}; dev=${u#*:}; v=$(enc $id)
  echo "    iifname \"$dev\" ct direction original ct state != untracked meta mark set meta mark & $KEEP | $v ct mark set ct mark & $KEEP | $v return"; done)
  }
  chain output {
    type route hook output priority -150; policy accept;
    meta mark & $CLASS == $PROBE return
$(restore)
  }
  chain postrouting {
    type filter hook postrouting priority -150; policy accept;
    meta mark & $CLASS == $PROBE return
$(for u in $UPLINKS; do id=${u%%:*}; dev=${u#*:}; v=$(enc $id)
  echo "    oifname \"$dev\" ct state != untracked ct mark & $FIELD == 0 meta mark set meta mark & $KEEP | $v ct mark set ct mark & $KEEP | $v return"; done)
  }
}
NFT
