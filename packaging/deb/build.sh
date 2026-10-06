#!/bin/sh
# build.sh ARCH BINARY OUTDIR: the PolyWAN package for ARCH (amd64, arm64 or
# armhf) from the static BINARY of that architecture (SPEC.md DIST-1),
# written to OUTDIR. A plain dpkg-deb build: every file of the package is
# listed here, and the maintainer scripts next to this one supply the
# lifecycle that debhelper would. Needs cargo (the man page and the shell
# completions come from `cargo xtask`), dpkg-deb, gzip and GNU coreutils.
# Timestamps come from SOURCE_DATE_EPOCH, or the last commit's.
set -eu

if [ $# -ne 3 ]; then
	echo "usage: $0 ARCH BINARY OUTDIR" >&2
	exit 2
fi
arch=$1 binary=$2 out=$3
case $arch in
amd64 | arm64 | armhf) ;;
*)
	echo "$0: unknown architecture $arch (amd64, arm64 or armhf)" >&2
	exit 2
	;;
esac
umask 022
root=$(cd "$(dirname "$0")/../.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
# A pre-release sorts before its release: 2.0.0-rc.1 is 2.0.0~rc.1.
debversion=$(printf %s "$version" | sed 's/-/~/')-1
maintainer="Alessandro Zarrilli <alessandro@zarrilli.net>"
: "${SOURCE_DATE_EPOCH:=$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pkg=$work/polywan
doc=$pkg/usr/share/doc/polywan
mkdir -m 0755 "$pkg"

install -D -m 0755 "$binary" "$pkg/usr/bin/polywan"
install -D -m 0644 "$root/packaging/polywan.service" "$pkg/usr/lib/systemd/system/polywan.service"
install -D -m 0644 "$root/packaging/sysusers.d/polywan.conf" "$pkg/usr/lib/sysusers.d/polywan.conf"
# The example is the file `generate-config` prints, copied (DIST-1).
install -D -m 0644 "$root/crates/polywan/src/config/example.toml" "$doc/examples/config.toml"
install -D -m 0644 "$root/packaging/deb/copyright" "$doc/copyright"
install -D -m 0644 "$root/packaging/deb/lintian-overrides" "$pkg/usr/share/lintian/overrides/polywan"
date=$(date -u -d "@$SOURCE_DATE_EPOCH" -R)
printf 'polywan (%s) unstable; urgency=medium\n\n  * PolyWAN %s: https://github.com/drsound/polywan/releases\n\n -- %s  %s\n' \
	"$debversion" "$version" "$maintainer" "$date" | gzip -9n >"$doc/changelog.Debian.gz"

(cd "$root" && cargo xtask man "$work/gen" && cargo xtask completions "$work/gen")
install -D -m 0644 "$work/gen/polywan.8" "$pkg/usr/share/man/man8/polywan.8"
gzip -9n "$pkg/usr/share/man/man8/polywan.8"
install -D -m 0644 "$work/gen/polywan" "$pkg/usr/share/bash-completion/completions/polywan"
install -D -m 0644 "$work/gen/_polywan" "$pkg/usr/share/zsh/vendor-completions/_polywan"
install -D -m 0644 "$work/gen/polywan.fish" "$pkg/usr/share/fish/vendor_completions.d/polywan.fish"

mkdir -m 0755 "$pkg/DEBIAN"
for script in postinst prerm postrm; do
	install -m 0755 "$root/packaging/deb/$script" "$pkg/DEBIAN/$script"
done
size=$(du -sk --apparent-size --exclude=DEBIAN "$pkg" | cut -f 1)
cat >"$pkg/DEBIAN/control" <<EOF
Package: polywan
Version: $debversion
Architecture: $arch
Maintainer: $maintainer
Installed-Size: $size
Depends: nftables (>= 1.0.6), systemd | systemd-standalone-sysusers | systemd-sysusers
Suggests: msmtp
Section: net
Priority: optional
Homepage: https://github.com/drsound/polywan
Description: multi-uplink policy routing daemon for Linux routers
 PolyWAN balances new outgoing connections across the healthy internet
 uplinks of a Linux router with hash-based multipath routing, keeps every
 connection on the uplink it started on, and probes every uplink for IPv4
 and IPv6 independently. It manages its own policy routing rules, routing
 tables and nftables table, and offers a status API, a command line
 interface, Prometheus metrics, event hooks and email notifications.
 .
 The service is installed neither enabled nor started; the example
 configuration is /usr/share/doc/polywan/examples/config.toml.
EOF
(cd "$pkg" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | LC_ALL=C sort -z | xargs -0 md5sum) >"$pkg/DEBIAN/md5sums"
chmod 0644 "$pkg/DEBIAN/control" "$pkg/DEBIAN/md5sums"
find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$out/polywan_${debversion}_${arch}.deb"
