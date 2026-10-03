#!/bin/sh
# Builds the Debian 12 root filesystem used to run the namespace suite on the
# minimum supported platform (SPEC.md PLAT-1, PLAT-2): Linux 6.1 and
# nftables 1.0.6, booted with virtme-ng by run-suite.sh.
#
# Usage: sudo tests/vm/build-rootfs.sh DEST
# Needs mmdebstrap (and debian-archive-keyring on non-Debian hosts). DEBIAN_MIRROR overrides http://deb.debian.org/debian.
set -eu

dest=${1:?usage: build-rootfs.sh DEST}
mirror=${DEBIAN_MIRROR:-http://deb.debian.org/debian}
security=${DEBIAN_SECURITY_MIRROR:-http://security.debian.org/debian-security}

# Test tools of the harness, plus "mount" which virtme-ng's guest init needs.
packages="linux-image-amd64,mount,kmod,procps,iproute2,nftables,dnsmasq-base,ppp,pppoe,udhcpc,iputils-ping,conntrack,tcpdump"

# Hosts that are not Debian (for example Ubuntu CI runners) need the Debian
# archive keyring to verify the suite.
keyring=
[ -f /usr/share/keyrings/debian-archive-keyring.gpg ] && keyring=--keyring=/usr/share/keyrings/debian-archive-keyring.gpg

mmdebstrap --variant=apt --include="$packages" $keyring \
  --dpkgopt='path-exclude=/usr/share/doc/*' --dpkgopt='path-exclude=/usr/share/man/*' \
  bookworm "$dest" \
  "deb $mirror bookworm main" \
  "deb $mirror bookworm-updates main" \
  "deb $security bookworm-security main"

kernel=$(ls "$dest"/boot/vmlinuz-* | sort -V | tail -n 1)
echo "kernel: $kernel"
chroot "$dest" nft --version
