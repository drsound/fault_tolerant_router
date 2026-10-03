#!/bin/sh
# Effect of NetworkManager operations on FTR artifacts (rules and routes tagged
# with protocol 249 in FTR's tables). Runs on a host whose uplinks wana/wanb
# are managed by NetworkManager through profiles ftr-wana/ftr-wanb.
set -u
cd "$(dirname "$0")"
export UPLINKS="1:wana 2:wanb"
step() { printf '%-36s ' "$1"; ./count-artifacts.sh; }
reset() { ./ftr-rules.sh remove; ./ftr-rules.sh install; ./ftr-rules.sh sync; }
echo "NetworkManager $(NetworkManager --version)"
reset; step "initial"
systemctl restart NetworkManager; sleep 8; step "restart NetworkManager"
reset; nmcli general reload; sleep 3; step "nmcli general reload"
reset; nmcli connection reload; sleep 3; step "nmcli connection reload"
reset; nmcli device reapply wana >/dev/null; sleep 5; step "nmcli device reapply wana"
reset; nmcli connection up ftr-wana >/dev/null; sleep 8; step "nmcli connection up ftr-wana (again)"
reset; nmcli connection down ftr-wana >/dev/null; nmcli connection up ftr-wana >/dev/null; sleep 8; step "nmcli connection down+up ftr-wana"
reset; ip link set wana down; sleep 1; ip link set wana up; sleep 8; step "link down/up wana"
reset; sleep 40; step "40 s of DHCP renewals"
reset; nmcli connection modify ftr-wana ipv4.route-metric 101; nmcli device reapply wana >/dev/null; sleep 5; step "profile change + reapply"
nmcli connection modify ftr-wana ipv4.route-metric 100; nmcli device reapply wana >/dev/null
