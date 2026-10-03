#!/usr/bin/env bash
# Smoke test: full FTR layout for both families, nftables lifecycle, traffic.
set -euo pipefail
P=s1; source "$(dirname "$0")/../lib/netns.sh"
trap topo_down EXIT
topo_up
for f in 4 6; do ftr_install $f 1 2 3; done
ftr_nft 1 2 3
leaks_reset
r=$(nsc $PEER conn 198.18.100.1 198.18.100.2 198.18.100.3 --count 30 | peer_uplink)
check "IPv4 forwarded connections balanced over A, B, C" '"A": [0-9]+.*"B": [0-9]+.*"C": [0-9]+' "$r"
r=$(nsc $PEER conn 2001:db8:100::1 2001:db8:100::2 --count 30 | peer_uplink)
check "IPv6 forwarded connections balanced over A, B, C" '"A": [0-9]+.*"B": [0-9]+.*"C": [0-9]+' "$r"
check "no leak" '^0 0$' "$(leaks)"
summary
