#!/bin/bash
# Run a private systemd-networkd (with a private D-Bus system bus) inside a
# network namespace, isolated from the host's networkd by a mount namespace,
# to test foreign-object management on the installed systemd version without
# touching the host network configuration.
#
# Topology: s4-nd-isp (dnsmasq: DHCPv4 + RA) <-veth-> s4-nd-rtr (networkd, FTR layout)
# Usage: networkd-netns.sh default|no
set -eu
cd "$(dirname "$0")"
mode=${1:-default}
HERE=$(pwd)
cleanup() {
  [ -f /tmp/s4-nd/networkd.pid ] && kill "$(cat /tmp/s4-nd/networkd.pid)" 2>/dev/null || true
  [ -f /tmp/s4-nd/dbus.pid ] && kill "$(cat /tmp/s4-nd/dbus.pid)" 2>/dev/null || true
  [ -f /tmp/s4-nd/dnsmasq.pid ] && kill "$(cat /tmp/s4-nd/dnsmasq.pid)" 2>/dev/null || true
  ip netns del s4-nd-rtr 2>/dev/null || true
  ip netns del s4-nd-isp 2>/dev/null || true
  rm -rf /tmp/s4-nd
}
trap cleanup EXIT
cleanup; mkdir -p /tmp/s4-nd
ip netns add s4-nd-isp; ip netns add s4-nd-rtr
ip link add wana netns s4-nd-rtr type veth peer name isp0 netns s4-nd-isp
I="ip netns exec s4-nd-isp"
$I ip link set lo up; $I ip link set isp0 up
$I ip addr add 192.0.2.1/24 dev isp0; $I ip addr add 2001:db8:a:ffff::1/64 dev isp0
$I sysctl -qw net.ipv6.conf.all.forwarding=1
$I dnsmasq --pid-file=/tmp/s4-nd/dnsmasq.pid --interface=isp0 --bind-interfaces --port=0 \
  --dhcp-range=192.0.2.100,192.0.2.199,2m --dhcp-option=3,192.0.2.1 \
  --enable-ra --dhcp-range=::,constructor:isp0,ra-only,10m --dhcp-leasefile=/tmp/s4-nd/leases

# The router side runs inside its own mount namespace: private /run/dbus,
# /run/udev, /run/systemd/netif and configuration directories, read-only /sys.
ip netns exec s4-nd-rtr unshare -m bash -s "$mode" "$HERE" <<'INNER'
set -eu
mode=$1; HERE=$2
mount --make-rprivate /
# networkd treats udev as unavailable (links initialized without udev) when /sys is read-only
mount -o remount,ro /sys
# private copy of /etc with a machine-id (DUIDs derive from it; some images lack one)
mkdir -p /tmp/s4-nd/etc; cp -a /etc/. /tmp/s4-nd/etc/; mount --bind /tmp/s4-nd/etc /etc
[ -s /etc/machine-id ] || cat /proc/sys/kernel/random/uuid | tr -d - > /etc/machine-id
for d in /run/dbus /run/udev /run/systemd/netif /run/systemd/network /etc/systemd/network /etc/systemd/networkd.conf.d; do
  mkdir -p "$d"; mount -t tmpfs -o mode=0755 tmpfs "$d"
done
mkdir -p /run/systemd/netif/links /run/systemd/netif/leases /run/systemd/netif/lldp
chown -R systemd-network:systemd-network /run/systemd/netif
cat > /etc/systemd/network/30-wana.network <<CFG
[Match]
Name=wana
[Network]
DHCP=ipv4
IPv6AcceptRA=yes
CFG
[ "$mode" = no ] && printf '[Network]\nManageForeignRoutingPolicyRules=no\nManageForeignRoutes=no\n' > /etc/systemd/networkd.conf.d/90-ftr.conf
ip link set lo up
dbus-daemon --system --fork --print-pid > /tmp/s4-nd/dbus.pid
ND=$(ls /lib/systemd/systemd-networkd /usr/lib/systemd/systemd-networkd 2>/dev/null | head -1)
start_nd() { "$ND" >/tmp/s4-nd/networkd.log 2>&1 & echo $! > /tmp/s4-nd/networkd.pid; }
stop_nd() { kill "$(cat /tmp/s4-nd/networkd.pid)"; sleep 1; }
start_nd
for i in $(seq 1 50); do ip -4 route show default | grep -q dhcp && break; sleep 0.2; done
sleep 4
cd "$HERE"
export UPLINKS="1:wana"
step() { printf '%-28s ' "$1"; ./count-artifacts.sh; }
reset() { ./ftr-rules.sh remove; ./ftr-rules.sh install; ./ftr-rules.sh sync; }
echo "systemd: $("$ND" --version 2>/dev/null | head -1 || systemctl --version | head -1)"
ip -br addr show wana; ip route show default; ip -6 route show default; ip nexthop show 2>/dev/null | sed "s/^/nexthop: /"
reset; step initial
ip -o monitor address route > /tmp/s4-nd/mon.txt & mon=$!; sleep 0.3
stop_nd; start_nd; sleep 5; step "restart networkd"
kill $mon; grep -c "^Deleted" /tmp/s4-nd/mon.txt | sed "s/^/  deletions during restart: /"; grep "^Deleted" /tmp/s4-nd/mon.txt | grep -E "inet |table 10" | head -4 | sed "s/^/  /"
reset; networkctl reload 2>&1 | head -1; sleep 3; step "networkctl reload"
reset; networkctl reconfigure wana 2>&1 | head -1; sleep 6; step "networkctl reconfigure wana"
reset; networkctl renew wana 2>&1 | head -1; sleep 3; step "networkctl renew wana"
reset; ip link set wana down; sleep 1; ip link set wana up; sleep 6; step "link down/up wana"
stop_nd
tail -15 /tmp/s4-nd/networkd.log
INNER
