#!/bin/sh
# Effect of systemd-networkd foreign-object management on FTR artifacts.
# Usage: networkd-foreign.sh default|no|rules-only|routes-only
# Runs on a host whose uplinks are managed by systemd-networkd, with the FTR
# layout installed (ftr-rules.sh install + sync). Restores the configuration
# file it changes. Uplink used for the actions: $DEV (default wana).
set -u
cd "$(dirname "$0")"
DEV=${DEV:-wana}
conf=/etc/systemd/networkd.conf.d/99-s4-foreign.conf
mkdir -p /etc/systemd/networkd.conf.d
saved=""
for f in /etc/systemd/networkd.conf.d/*.conf; do
  [ -e "$f" ] && [ "$f" != "$conf" ] && grep -q ManageForeign "$f" && { mv "$f" "$f.s4-disabled"; saved="$saved $f"; }
done
case $1 in
  default) rm -f "$conf" ;;
  no) printf '[Network]\nManageForeignRoutingPolicyRules=no\nManageForeignRoutes=no\n' > "$conf" ;;
  rules-only) printf '[Network]\nManageForeignRoutingPolicyRules=yes\nManageForeignRoutes=no\n' > "$conf" ;;
  routes-only) printf '[Network]\nManageForeignRoutingPolicyRules=no\nManageForeignRoutes=yes\n' > "$conf" ;;
esac
step() { printf '%-28s ' "$1"; ./count-artifacts.sh; }
reset() { ./ftr-rules.sh remove; ./ftr-rules.sh install; ./ftr-rules.sh sync; }
reset; step "initial"
systemctl restart systemd-networkd; sleep 4; step "restart networkd"
reset; networkctl reload; sleep 3; step "networkctl reload"
reset; networkctl reconfigure "$DEV"; sleep 6; step "networkctl reconfigure $DEV"
reset; ip link set "$DEV" down; sleep 1; ip link set "$DEV" up; sleep 6; step "link down/up $DEV"
reset; networkctl renew "$DEV"; sleep 3; step "networkctl renew $DEV"
reset; networkctl forcerenew "$DEV" 2>/dev/null; sleep 3; step "networkctl forcerenew $DEV"
rm -f "$conf"; for f in $saved; do mv "$f.s4-disabled" "$f"; done
systemctl restart systemd-networkd; sleep 4; reset; step "restored configuration"
