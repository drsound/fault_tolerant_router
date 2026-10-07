#!/usr/bin/env bash
# The package lifecycle of SPEC.md DIST-1 on this host: install, upgrade,
# removal and purge of the polywan .deb, with the maintainer scripts run by
# dpkg as on a real system.
#
# Usage: lifecycle.sh [--hooks BINARY] [--suite BINDIR] DEB
#   --hooks BINARY  the daemon built with the test hooks (run-suite.sh
#                   builds one): a cleanup failing midway during removal
#   --suite BINDIR  the namespace suite built by run-suite.sh: AS-34's
#                   scenarios against the installed package
#
# Needs root on a disposable test host with systemd as PID 1, dpkg, nftables
# (>= 1.0.6), iproute2, flock, mmdebstrap and network access to the
# distribution's mirror (the chroot case). It installs and purges the
# package and deletes PolyWAN's state, configuration, lock and group, so it
# refuses to run where polywan is installed or configured already. The
# daemon only ever runs in the network namespace pkgr (a drop-in sets
# NetworkNamespacePath=), and every dpkg call that can run `polywan cleanup`
# runs inside it (nsenter --net, which keeps ischroot's answer), so the
# host's networking is never changed. The output lists every check; the
# exit status is 1 if one failed.
set -u

hooks= suite=
while [ $# -gt 1 ]; do
	case $1 in
	--hooks) hooks=$2; shift 2 ;;
	--suite) suite=$(cd "$2" && pwd); shift 2 ;;
	*) break ;;
	esac
done
if [ $# -ne 1 ] || [ ! -f "$1" ]; then
	echo "usage: $0 [--hooks BINARY] [--suite BINDIR] DEB" >&2
	exit 2
fi
deb=$(realpath "$1")
repo=$(cd "$(dirname "$0")/../.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "$0: needs root" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "$0: needs systemd as PID 1" >&2; exit 2; }
# `ip netns del` relies on systemd's shared mounts to remove a namespace.
[ "$(findmnt -no PROPAGATION /)" = shared ] || { echo "$0: / is not a shared mount" >&2; exit 2; }
if dpkg-query -W -f '${db:Status-Status}' polywan 2>/dev/null | grep -qv not-installed || [ -e /etc/polywan ] || [ -e /var/lib/polywan ]; then
	echo "$0: polywan is installed or configured on this host" >&2
	exit 2
fi

NS=pkgr INET=pkgi
CONFIG=/etc/polywan/config.toml
STATE=/var/lib/polywan
LOCK=/run/polywan/lock
UNIT=polywan.service
DROPIN=/etc/systemd/system/$UNIT.d
POLICY=/usr/sbin/policy-rc.d
CUSTOM_STATE=/var/lib/polywan-h4
CUSTOM_RUN=/run/polywan-h4
work=$(mktemp -d)
out=$work/out
failures=0
version=$(dpkg-deb -f "$deb" Version)
repacked=0

ok() { echo "  ok   $*"; }
bad() {
	echo "  FAIL $*"
	failures=$((failures + 1))
}
# check WHAT COMMAND...: the command succeeds.
check() {
	local what=$1
	shift
	if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi
}
# refute WHAT COMMAND...: the command fails.
refute() {
	local what=$1
	shift
	if "$@" >/dev/null 2>&1; then bad "$what"; else ok "$what"; fi
}
eq() { # eq WHAT GOT WANT
	if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: got '$2', want '$3'"; fi
}
said() { # said WHAT TEXT: the last command's output holds TEXT
	if grep -qF -- "$2" "$out"; then ok "$1"; else
		bad "$1: no '$2' in:"
		sed 's/^/         /' "$out"
	fi
}
quiet() { # quiet WHAT: the last command printed no polywan report
	if grep -q '^polywan:' "$out"; then
		bad "$1:"
		sed 's/^/         /' "$out"
	else ok "$1"; fi
}
section() { echo "== $*"; }

# In the router namespace: dpkg and the maintainer scripts, whose prerm
# runs `polywan cleanup`.
in_ns() { nsenter --net=/run/netns/$NS "$@"; }
pkg() { # pkg DPKG-ARGS...: dpkg, its output in $out, its exit status
	in_ns dpkg "$@" >"$out" 2>&1
}
maint() { # maint SCRIPT ARGS...: an installed maintainer script run again
	local script=$1
	shift
	DPKG_MAINTSCRIPT_PACKAGE=polywan DPKG_MAINTSCRIPT_NAME=$script \
		in_ns "/var/lib/dpkg/info/polywan.$script" "$@" >"$out" 2>&1
}
# upgrade: the package again with a newer version each time.
upgrade() {
	repacked=$((repacked + 1))
	local v=$version+h4.$repacked dir=$work/repack
	rm -rf "$dir"
	dpkg-deb -R "$deb" "$dir"
	sed -i "s/^Version: .*/Version: $v/" "$dir/DEBIAN/control"
	dpkg-deb --root-owner-group -Znone -b "$dir" "$work/polywan_$v.deb" >/dev/null
	rm -rf "$dir"
	pkg -i "$work/polywan_$v.deb"
}
prop() { systemctl show -p "$1" --value $UNIT; }
active() { systemctl is-active $UNIT 2>/dev/null; }
enabled() { systemctl is-enabled $UNIT 2>/dev/null; }
# PolyWAN's rules and routes in the namespace (route protocol 249, the
# default), plus its nftables table.
artifacts() {
	local n
	n=$(( $(ip -n $NS -d -4 rule show | grep -c 'proto 249') + $(ip -n $NS -d -6 rule show | grep -c 'proto 249') +
		$(ip -n $NS -4 route show table all proto 249 | grep -c .) + $(ip -n $NS -6 route show table all proto 249 | grep -c .) ))
	ip netns exec $NS nft list table inet polywan >/dev/null 2>&1 && n=$((n + 1))
	echo "$n"
}
manifest() { [ -e $STATE/manifest.json ]; }
# The service started in the namespace: refused if the drop-in is not in
# effect, so that the daemon never touches the host's networking.
start() {
	[ "$(prop NetworkNamespacePath)" = /run/netns/$NS ] || {
		bad "the namespace drop-in is not in effect; not starting"
		return 1
	}
	systemctl start $UNIT
}

topology() {
	ip netns add $NS
	ip netns add $INET
	ip -n $NS link set lo up
	ip -n $INET link set lo up
	ip link add wan0 netns $NS type veth peer name up0 netns $INET
	ip -n $NS link add lan0 type dummy
	ip -n $NS addr add 192.0.2.2/24 dev wan0
	ip -n $NS link set wan0 up
	ip -n $NS addr add 10.0.0.1/24 dev lan0
	ip -n $NS link set lan0 up
	ip -n $INET addr add 192.0.2.1/24 dev up0
	ip -n $INET link set up0 up
	ip -n $INET addr add 198.51.100.1/32 dev lo
	ip -n $NS route add default via 192.0.2.1 dev wan0 proto static
	mkdir -p $DROPIN
	printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' $NS >$DROPIN/netns.conf
	systemctl daemon-reload
}
# The default configuration: one uplink in the namespace.
configure() { # configure [EXTRA-TOP-LEVEL [EXTRA-TABLES]]
	mkdir -p /etc/polywan
	cat >$CONFIG <<EOF
${1:-}
[firewall]
nft_path = "$(command -v nft)"
[[downlink]]
interface = "lan0"
[[uplink]]
id = 1
name = "a"
interface = "wan0"
priority = 1
[uplink.ipv4]
nat = "masquerade"
[health]
interval = "1s"
timeout = "300ms"
required_reachable = 1
[health.ipv4]
targets = ["icmp:198.51.100.1"]
${2:-}
EOF
	chmod 0600 $CONFIG
}
# Everything this script creates, also after an interrupted run.
reset() {
	rm -f $POLICY
	[ -n "${holder:-}" ] && kill "$holder" 2>/dev/null
	systemctl unmask $UNIT >/dev/null 2>&1
	systemctl stop $UNIT >/dev/null 2>&1
	if dpkg-query -W polywan >/dev/null 2>&1; then
		# Its prerm cleans up: never outside the namespace.
		[ -e /run/netns/$NS ] || topology >/dev/null 2>&1
		in_ns sh -c "[ -x /usr/bin/polywan ] && [ -e $CONFIG ] && polywan cleanup" >/dev/null 2>&1
		in_ns dpkg -P polywan >/dev/null 2>&1
	fi
	rm -rf $DROPIN /etc/polywan $STATE /run/polywan $CUSTOM_STATE $CUSTOM_RUN
	systemctl daemon-reload
	systemctl reset-failed $UNIT >/dev/null 2>&1
	getent group polywan >/dev/null && groupdel polywan
	ip netns del $NS 2>/dev/null
	ip netns del $INET 2>/dev/null
	true
}
fresh() { # a clean host with the topology, the package installed and configured
	reset
	topology
	pkg -i "$deb" || bad "dpkg -i: $(cat "$out")"
	configure
}
# Install again, clean up offline, purge: the documented recovery.
recover() {
	pkg -i "$deb" || bad "reinstall: $(cat "$out")"
	in_ns polywan cleanup >"$out" 2>&1
	check "recovery: polywan cleanup succeeds" [ $? -eq 0 ]
	eq "recovery: no artifacts" "$(artifacts)" 0
	refute "recovery: no manifest" manifest
	pkg -P polywan
	refute "recovery: purge deletes $STATE" test -e $STATE
}
lock_inode() { stat -c %i $LOCK; }
# The host's routing and firewall, for the chroot case.
host_net() {
	ip -4 rule show
	ip -6 rule show
	ip -4 route show table all
	ip -6 route show table all | sed 's/ expires [0-9]*sec//'
	# Without counters, which other traffic moves (a CI runner's firewall).
	nft -s list ruleset
}

trap 'reset; rm -rf "$work"' EXIT

section "fresh install (DIST-1): group, files, nothing enabled or started"
reset
topology
check "dpkg -i succeeds" pkg -i "$deb"
gid=$(getent group polywan | cut -d: -f3)
check "the polywan group is a system group" test "${gid:-1000}" -lt 1000
for f in /usr/bin/polywan /usr/lib/systemd/system/$UNIT /usr/lib/sysusers.d/polywan.conf \
	/usr/share/man/man8/polywan.8.gz /usr/share/doc/polywan/copyright \
	/usr/share/doc/polywan/changelog.gz /usr/share/doc/polywan/THIRD-PARTY-LICENSES.gz \
	/usr/share/bash-completion/completions/polywan; do
	check "$f installed" test -f $f
done
check "the example is what generate-config prints" cmp -s <(polywan generate-config) /usr/share/doc/polywan/examples/config.toml
eq "the unit is not enabled" "$(enabled)" disabled
eq "the unit is not started" "$(active)" inactive
refute "no state directory" test -e $STATE
refute "no configuration" test -e /etc/polywan
check "postinst configure again succeeds" maint postinst configure "$version"
check "and a third time" maint postinst configure "$version"
eq "one polywan group" "$(grep -c '^polywan:' /etc/group)" 1
eq "still not enabled" "$(enabled)" disabled
eq "still not started" "$(active)" inactive

section "upgrades keep enablement and masking and restart only a running daemon"
configure
systemctl enable $UNIT >/dev/null 2>&1
start
eq "started" "$(active)" active
check "PolyWAN's routing installed in the namespace" [ "$(artifacts)" -gt 0 ]
pid=$(prop MainPID)
check "upgrade while running succeeds" upgrade
eq "running after the upgrade" "$(active)" active
now=$(prop MainPID)
check "restarted by the upgrade" test "$now" != "$pid" -a "$now" != 0
eq "still enabled" "$(enabled)" enabled
systemctl stop $UNIT
check "upgrade while stopped succeeds" upgrade
eq "stopped after the upgrade" "$(active)" inactive
eq "still enabled" "$(enabled)" enabled
systemctl disable $UNIT >/dev/null 2>&1
check "upgrade while disabled succeeds" upgrade
eq "still disabled" "$(enabled)" disabled
eq "not started" "$(active)" inactive
systemctl mask $UNIT >/dev/null 2>&1
check "upgrade while masked succeeds" upgrade
eq "still masked" "$(enabled)" masked
eq "not started" "$(active)" inactive
systemctl unmask $UNIT >/dev/null 2>&1

section "policy-rc.d denies: no restart on upgrade, no stop on removal, purge keeps the state"
start
pid=$(prop MainPID)
printf '#!/bin/sh\nexit 101\n' >$POLICY
chmod 0755 $POLICY
check "upgrade succeeds" upgrade
eq "not restarted" "$(prop MainPID)" "$pid"
check "removal succeeds" pkg -r polywan
said "cleanup skipped while the daemon runs" "polywan.service is still running"
eq "the daemon still runs" "$(active)" active
check "its routing stays" [ "$(artifacts)" -gt 0 ]
check "purge succeeds" pkg -P polywan
said "purge reports the held lock" "the instance lock is held"
check "the manifest stays" manifest
rm -f $POLICY
systemctl stop $UNIT
check "the manifest stays after the stop" manifest
recover
check "/etc/polywan is never purged" test -e $CONFIG
check "the group stays" getent group polywan

section "removal with a valid configuration: stop and cleanup"
fresh
start
check "removal succeeds" pkg -r polywan
quiet "nothing reported"
eq "stopped" "$(active)" inactive
eq "no artifacts" "$(artifacts)" 0
refute "no manifest" manifest
check "purge succeeds" pkg -P polywan
refute "purge after a successful cleanup deletes $STATE" test -e $STATE

section "maintainer scripts run again: already stopped, already cleaned"
fresh
start
check "prerm remove succeeds" maint prerm remove
eq "stopped" "$(active)" inactive
eq "no artifacts" "$(artifacts)" 0
refute "no manifest" manifest
check "prerm remove again succeeds" maint prerm remove
quiet "nothing reported"
check "removal succeeds" pkg -r polywan
quiet "nothing reported"
check "postrm purge succeeds" maint postrm purge
refute "$STATE deleted" test -e $STATE
check "postrm purge again succeeds" maint postrm purge
quiet "nothing reported"
check "purge succeeds" pkg -P polywan
quiet "nothing reported"

section "removal without a configuration"
fresh
start
systemctl stop $UNIT
mv $CONFIG $work/config.toml
check "removal succeeds" pkg -r polywan
said "cleanup skipped" "$CONFIG does not exist"
said "with recovery instructions" "run: polywan cleanup"
check "the routing stays" [ "$(artifacts)" -gt 0 ]
check "the manifest stays" manifest
mv $work/config.toml $CONFIG
recover

section "removal with an invalid configuration"
fresh
start
systemctl stop $UNIT
cp $CONFIG $work/config.toml
echo 'bogus = 1' >>$CONFIG
check "removal succeeds" pkg -r polywan
said "cleanup failed" "cleanup failed (see above); the manifest in $STATE is kept"
check "the manifest stays" manifest
pkg -P polywan
said "purge keeps the state" "it holds a manifest"
cp $work/config.toml $CONFIG
recover

if [ -n "$hooks" ]; then
	section "a cleanup failing midway (the daemon with test hooks)"
	fresh
	start
	systemctl stop $UNIT
	# Fails after the nftables table, rules and routes are removed, before
	# the sysctls are restored and the manifest deleted.
	install -m 0755 "$hooks" /usr/bin/polywan
	echo "match:restore sysctls" >$work/faults
	POLYWAN_TEST_FAULTS=$work/faults pkg -r polywan
	check "removal succeeds" [ $? -eq 0 ]
	said "the injected failure" "failure injected before restore sysctls"
	said "reported" "cleanup failed (see above)"
	eq "the routing is gone" "$(artifacts)" 0
	check "the manifest stays" manifest
	pkg -P polywan
	said "purge keeps the manifest" "it holds a manifest"
	check "the manifest stays" manifest
	recover
fi

section "the instance lock held by an offline command: a service start and a purge"
fresh
start
systemctl stop $UNIT
inode=$(lock_inode)
# The lock the offline commands take (flock(2) on the file), held by the
# process that the shell's exec replaces.
(flock -n 9 && exec sleep 600) 9<$LOCK &
holder=$!
sleep 0.5
systemctl start $UNIT >"$out" 2>&1
check "the start fails" [ $? -ne 0 ]
check "the daemon refused the lock" journalctl -u $UNIT --since "-1min" -o cat --grep "instance lock"
eq "the lock file is the same" "$(lock_inode)" "$inode"
check "removal succeeds" pkg -r polywan
said "cleanup refused by the lock" "held by another instance"
said "reported" "cleanup failed (see above)"
check "purge succeeds" pkg -P polywan
said "purge reports the held lock" "the instance lock is held"
check "the manifest stays" manifest
eq "the lock file is the same" "$(lock_inode)" "$inode"
check "the lock holder was not disturbed" kill -0 $holder
kill $holder
wait $holder 2>/dev/null
holder=
recover

section "custom state and socket paths are kept through removal and purge"
fresh
mkdir -m 0700 $CUSTOM_STATE
mkdir -m 0755 $CUSTOM_RUN
echo kept >$CUSTOM_STATE/marker
cat >$DROPIN/paths.conf <<EOF
[Service]
ReadWritePaths=$CUSTOM_STATE $CUSTOM_RUN
ExecReload=
ExecReload=/usr/bin/polywan reload --socket $CUSTOM_RUN/api.sock
EOF
systemctl daemon-reload
configure "state_dir = \"$CUSTOM_STATE\"" "[api]
socket = \"$CUSTOM_RUN/api.sock\"
status_socket = \"$CUSTOM_RUN/status.sock\""
start
eq "started" "$(active)" active
check "the manifest is in $CUSTOM_STATE" test -e $CUSTOM_STATE/manifest.json
check "reload through the custom socket" systemctl reload $UNIT
check "removal succeeds" pkg -r polywan
quiet "nothing reported"
eq "no artifacts" "$(artifacts)" 0
refute "cleanup used the custom manifest" test -e $CUSTOM_STATE/manifest.json
check "purge succeeds" pkg -P polywan
check "$CUSTOM_STATE kept" test -f $CUSTOM_STATE/marker
check "$CUSTOM_RUN kept" test -d $CUSTOM_RUN
refute "$STATE deleted" test -e $STATE

section "install into a chroot without systemd running (mmdebstrap)"
reset
. /etc/os-release
case $ID in
debian) mirror=http://deb.debian.org/debian ;;
ubuntu) mirror=http://archive.ubuntu.com/ubuntu ;;
*) mirror= ;;
esac
before=$(host_net)
# Removal inside the chroot meets a manifest and a configuration: its
# cleanup must be skipped, not run against the host's networking.
cat >$work/in-chroot.sh <<EOF
set -u
root=\$1
log() { echo "\$*" >>$work/chroot.log; }
chroot "\$root" ischroot; log "ischroot \$?"
log "group \$(chroot "\$root" getent group polywan | cut -d: -f1)"
log "unit \$(test -f "\$root/usr/lib/systemd/system/$UNIT" && echo installed)"
log "enabled \$(ls "\$root"/etc/systemd/system/*/$UNIT 2>/dev/null | wc -l)"
mkdir -p "\$root/etc/polywan" "\$root$STATE"
cp $CONFIG "\$root$CONFIG"
echo '{}' >"\$root$STATE/manifest.json"
chroot "\$root" dpkg -r polywan >>$work/chroot.log 2>&1; log "remove \$?"
chroot "\$root" dpkg -P polywan >>$work/chroot.log 2>&1; log "purge \$?"
log "state \$(test -e "\$root$STATE/manifest.json" && echo kept)"
EOF
configure
# In a mount namespace of its own: mmdebstrap 1.5 makes every mount private
# in root mode (`mount --make-rprivate /`), which would stop the host's
# mounts from propagating, network namespaces' included.
unshare --mount mmdebstrap --variant=apt --include=systemd,nftables --include="$deb" \
	--hook-dir=/usr/share/mmdebstrap/hooks/file-mirror-automount \
	--customize-hook="sh $work/in-chroot.sh \"\$1\"" \
	"$VERSION_CODENAME" "$work/chroot" $mirror >"$out" 2>&1
rc=$?
check "mmdebstrap installs the package" [ $rc -eq 0 ]
[ $rc -eq 0 ] || tail -20 "$out"
cp "$work/chroot.log" "$out" 2>/dev/null
said "ischroot sees the chroot" "ischroot 0"
said "the group is created in the chroot" "group polywan"
said "the unit is installed" "unit installed"
said "not enabled" "enabled 0"
said "removal skips cleanup" "may not be the target system's (a chroot or an alternative root)"
said "removal succeeds" "remove 0"
said "purge keeps the manifest" "purge 0"
said "the manifest stays" "state kept"
refute "no polywan group on the host" getent group polywan
refute "no unit on the host" test -e /usr/lib/systemd/system/$UNIT
eq "the host's rules, routes and nftables unchanged" "$(host_net)" "$before"
eq "the host's mounts still propagate" "$(findmnt -no PROPAGATION /)" shared
rm -rf "$work/chroot"

if [ -n "$suite" ]; then
	section "AS-34 against the installed package"
	fresh
	(cd "$repo" && tests/vm/run-suite.sh --host --unit --installed --bindir "$suite" -- as34) >"$out" 2>&1
	check "AS-34's scenarios pass" [ $? -eq 0 ]
	grep -E '^test .* \.\.\. ' "$out" | grep -v ignored | sed 's/^/         /'
fi

echo "== $failures failed"
[ $failures -eq 0 ]
