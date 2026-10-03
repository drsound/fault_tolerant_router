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

cargo build --target $target -p testbed --bin ftr-testbed -p fault-tolerant-router --bin fault-tolerant-router
test_bin=$(cargo test --target $target -p testbed --test netns --no-run --message-format=json \
  | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .target.name == "netns") | .executable')
# Acceptance scenarios with the daemon under test.
m1_bin=$(cargo test --target $target -p testbed --test m1 --no-run --message-format=json \
  | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .target.name == "m1") | .executable')
# The daemon's kernel tests (crates/fault-tolerant-router/tests/kernel_*.rs).
kernel_tests="kernel_netlink kernel_probe kernel_handoff"
rm -rf "$bindir"
mkdir -p "$bindir"
cp "$target_dir/$target/debug/ftr-testbed" "$bindir/"
cp "$test_bin" "$bindir/netns"
cp "$m1_bin" "$bindir/m1"
cp "$target_dir/$target/debug/fault-tolerant-router" "$bindir/"
for t in $kernel_tests; do
  bin=$(cargo test --target $target -p fault-tolerant-router --test "$t" --no-run --message-format=json \
    | jq -r --arg t "$t" 'select(.reason == "compiler-artifact" and .profile.test == true and .target.name == $t) | .executable')
  cp "$bin" "$bindir/$t"
done
# The M1 scenarios run once per fwmark_mask (AS-43: offsets 16, 0 and 24);
# FTR_TEST_MASKS narrows the list.
masks=${FTR_TEST_MASKS:-"0x00ff0000 0x000000ff 0xff000000"}
m1_in_vm=
for mask in $masks; do
  m1_in_vm="$m1_in_vm && echo '== M1 scenarios with fwmark_mask $mask' && FTR_TESTBED_BIN=/mnt/ftr-testbed FTR_DAEMON_BIN=/mnt/fault-tolerant-router FTR_TEST_FWMARK_MASK=$mask /mnt/m1 --ignored --test-threads=${VM_TEST_THREADS:-2} $*"
done
# They change rules and routes, so each runs in a private network namespace.
kernel_in_vm=
for t in $kernel_tests; do
  kernel_in_vm="$kernel_in_vm unshare -n /mnt/$t --ignored --test-threads=1 &&"
done

sudo=
[ "$(id -u)" -eq 0 ] || sudo=sudo

case $mode in
  host)
    cd /tmp
    for t in $kernel_tests; do
      $sudo unshare -n "$bindir/$t" --ignored --test-threads=1
    done
    $sudo env FTR_TESTBED_BIN="$bindir/ftr-testbed" "$bindir/netns" --ignored "$@"
    for mask in $masks; do
      echo "== M1 scenarios with fwmark_mask $mask"
      $sudo env FTR_TESTBED_BIN="$bindir/ftr-testbed" FTR_DAEMON_BIN="$bindir/fault-tolerant-router" \
        FTR_TEST_FWMARK_MASK="$mask" "$bindir/m1" --ignored "$@"
    done
    ;;
  vm)
    rootfs=$(cd "$rootfs" && pwd)
    kernel=$(ls "$rootfs"/boot/vmlinuz-* | sort -V | tail -n 1)
    vng=$(command -v vng)
    # The binaries are shared read-only at /mnt (a directory that exists in
    # the root filesystem); the guest's exit status is the suite's. Some
    # virtme-ng versions mount the guest's /run world-writable, which the
    # daemon refuses as a parent of its configuration (FR-CFG-5); the tests
    # keep their configurations there, so the guest's /run is made 0755. PATH is
    # passed through sudo because vng runs its helpers (virtme-run) from it,
    # and a pipx installation lives in ~/.local/bin.
    exec $sudo env PATH="$PATH" "$vng" --run "$kernel" --root "$rootfs" --user root \
      --memory "${VM_MEMORY:-2G}" --cpus "${VM_CPUS:-2}" \
      --rodir "/mnt=$bindir" \
      --exec "uname -r && nft --version && chmod 0755 /run && cd /tmp &&$kernel_in_vm FTR_TESTBED_BIN=/mnt/ftr-testbed /mnt/netns --ignored --test-threads=${VM_TEST_THREADS:-2} $* $m1_in_vm"
    ;;
esac
