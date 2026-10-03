#!/bin/sh
# Builds the namespace test suite as static musl binaries and runs it, either
# on this host (current kernel and nftables) or inside a virtme-ng virtual
# machine booted with the kernel of a root filesystem made by build-rootfs.sh.
#
# Usage:
#   tests/vm/run-suite.sh [--host | --vm ROOTFS] [-- TEST-ARGS...]
#
# The build runs as the invoking user; running the suite needs root, so the
# script uses sudo when it is not already root. Extra arguments after "--"
# go to the test binary (for example a test name filter).
set -eu

mode=host
rootfs=
while [ $# -gt 0 ]; do
  case $1 in
    --host) mode=host; shift ;;
    --vm) mode=vm; rootfs=${2:?--vm needs a root filesystem}; shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
target=x86_64-unknown-linux-musl
target_dir=${CARGO_TARGET_DIR:-$repo/target}
bindir=$target_dir/netns-suite
cd "$repo"

cargo build --target $target -p testbed --bin ftr-testbed
test_bin=$(cargo test --target $target -p testbed --test netns --no-run --message-format=json \
  | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .target.name == "netns") | .executable')
kernel_bin=$(cargo test --target $target -p fault-tolerant-router --test kernel_netlink --no-run --message-format=json \
  | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .target.name == "kernel_netlink") | .executable')
rm -rf "$bindir"
mkdir -p "$bindir"
cp "$target_dir/$target/debug/ftr-testbed" "$bindir/"
cp "$test_bin" "$bindir/netns"
cp "$kernel_bin" "$bindir/kernel_netlink"

sudo=
[ "$(id -u)" -eq 0 ] || sudo=sudo

case $mode in
  host)
    cd /tmp
    # The daemon's kernel tests change rules and routes: they run in a
    # private network namespace.
    $sudo unshare -n "$bindir/kernel_netlink" --ignored --test-threads=1
    exec $sudo env FTR_TESTBED_BIN="$bindir/ftr-testbed" "$bindir/netns" --ignored "$@"
    ;;
  vm)
    rootfs=$(cd "$rootfs" && pwd)
    kernel=$(ls "$rootfs"/boot/vmlinuz-* | sort -V | tail -n 1)
    vng=$(command -v vng)
    # The binaries are shared read-only at /mnt (a directory that exists in
    # the root filesystem); the guest's exit status is the suite's. PATH is
    # passed through sudo because vng runs its helpers (virtme-run) from it,
    # and a pipx installation lives in ~/.local/bin.
    exec $sudo env PATH="$PATH" "$vng" --run "$kernel" --root "$rootfs" --user root \
      --memory "${VM_MEMORY:-2G}" --cpus "${VM_CPUS:-2}" \
      --rodir "/mnt=$bindir" \
      --exec "uname -r && nft --version && cd /tmp && unshare -n /mnt/kernel_netlink --ignored --test-threads=1 && FTR_TESTBED_BIN=/mnt/ftr-testbed /mnt/netns --ignored --test-threads=${VM_TEST_THREADS:-2} $*"
    ;;
esac
