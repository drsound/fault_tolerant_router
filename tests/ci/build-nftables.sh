#!/usr/bin/env bash
# Build an upstream nftables release (with the libmnl and libnftnl it needs)
# into PREFIX, so that the namespace suite can run against the newest
# nftables instead of the distribution's (SPEC.md §14.1).
#
# Usage: build-nftables.sh PREFIX
# Requires a C toolchain, pkg-config, curl, xz and the jansson headers
# (Debian/Ubuntu: build-essential pkg-config curl xz-utils libjansson-dev).
# The result is PREFIX/sbin/nft, linked with an rpath to PREFIX/lib.
set -euo pipefail

NFTABLES_VERSION=1.1.7
LIBNFTNL_VERSION=1.3.2
LIBMNL_VERSION=1.0.5
NFTABLES_SHA256=a6fbf060d8d4fff001517a2b94f356bb4366bfbf0ba366366f9d27cc38caa58f
LIBNFTNL_SHA256=c97abc3409f8fa396b4462b2bb7f147a3a47a4ddc97cfa0b2f18890c9cfde8b0
LIBMNL_SHA256=274b9b919ef3152bfb3da3a13c950dd60d6e2bcd54230ffeca298d03b40d0525

prefix=${1:?usage: build-nftables.sh PREFIX}
mkdir -p "$prefix"
prefix=$(cd "$prefix" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

fetch() { # fetch URL SHA256 (checksums published on netfilter.org)
  local file=${1##*/}
  curl -fsSL --retry 3 -o "$file" "$1"
  echo "$2  $file" | sha256sum -c --quiet -
  tar xf "$file"
}
fetch "https://www.netfilter.org/pub/libmnl/libmnl-$LIBMNL_VERSION.tar.bz2" "$LIBMNL_SHA256"
fetch "https://www.netfilter.org/pub/libnftnl/libnftnl-$LIBNFTNL_VERSION.tar.xz" "$LIBNFTNL_SHA256"
fetch "https://www.netfilter.org/pub/nftables/nftables-$NFTABLES_VERSION.tar.xz" "$NFTABLES_SHA256"

export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
export LDFLAGS="-Wl,-rpath,$prefix/lib"
jobs=$(nproc)
build() { # build DIR CONFIGURE-ARGS...
  (cd "$1" && ./configure --prefix="$prefix" --disable-static "${@:2}" >/dev/null && make -s -j"$jobs" && make -s install) >/dev/null
}
build "libmnl-$LIBMNL_VERSION"
build "libnftnl-$LIBNFTNL_VERSION"
build "nftables-$NFTABLES_VERSION" --with-json --with-mini-gmp --without-cli --disable-man-doc
"$prefix/sbin/nft" --version
