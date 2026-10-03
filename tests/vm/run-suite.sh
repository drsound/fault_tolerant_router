#!/bin/sh
# Builds the namespace test suite as static musl binaries and runs it, either
# on this host (current kernel and nftables) or inside a virtme-ng virtual
# machine booted with the kernel of a root filesystem made by build-rootfs.sh.
#
# Usage:
#   tests/vm/run-suite.sh [--host | --vm ROOTFS | --build-only] [--bindir DIR] [-- TEST-ARGS...]
#
# The build runs as the invoking user; running the suite needs root, so the
# script uses sudo when it is not already root. Extra arguments after "--"
# go to the test binary (for example a test name filter). --build-only
# leaves the binaries in the suite directory; --bindir runs binaries built
# earlier (copied to a machine without a Rust toolchain, for example) and
# skips the build.
set -eu

mode=host
rootfs=
prebuilt=
while [ $# -gt 0 ]; do
  case $1 in
    --host) mode=host; shift ;;
    --vm) mode=vm; rootfs=${2:?--vm needs a root filesystem}; shift 2 ;;
    --build-only) mode=build; shift ;;
    --bindir) prebuilt=${2:?--bindir needs a directory}; shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
target=x86_64-unknown-linux-musl
target_dir=${CARGO_TARGET_DIR:-$repo/target}
bindir=$target_dir/netns-suite
# The daemon's kernel tests (crates/fault-tolerant-router/tests/kernel_*.rs).
kernel_tests="kernel_netlink kernel_probe kernel_handoff"
cd "$repo"

if [ -n "$prebuilt" ]; then
  bindir=$(cd "$prebuilt" && pwd)
else
  # The daemon under test has the hooks of the acceptance scenarios
  # (crates/fault-tolerant-router/src/test_hooks.rs).
  cargo build --target $target -p testbed --bin ftr-testbed -p fault-tolerant-router --bin fault-tolerant-router \
    --features fault-tolerant-router/test-hooks
  # Test executables by target name, one cargo call per package.
  test_exes() { # PACKAGE TEST...
    pkg=$1
    shift
    tests=
    for t in "$@"; do tests="$tests --test $t"; done
    cargo test --target $target -p "$pkg" $tests --no-run --message-format=json \
      | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true) | "\(.target.name) \(.executable)"'
  }
  rm -rf "$bindir"
  mkdir -p "$bindir"
  # Copied before the test builds: the daemon's integration tests rebuild
  # its executable without the hooks.
  cp "$target_dir/$target/debug/ftr-testbed" "$target_dir/$target/debug/fault-tolerant-router" "$bindir/"
  # netns: the harness's own checks; m1: the acceptance scenarios.
  { test_exes testbed netns m1; test_exes fault-tolerant-router $kernel_tests; } \
    | while read -r name exe; do cp "$exe" "$bindir/$name"; done
  for t in netns m1 $kernel_tests; do
    [ -x "$bindir/$t" ] || { echo "test executable $t was not built" >&2; exit 1; }
  done
fi
if [ "$mode" = build ]; then
  echo "$bindir"
  exit 0
fi
# The M1 scenarios run once per fwmark_mask (AS-43: offsets 16, 0 and 24);
# FTR_TEST_MASKS narrows the list; on the host, FTR_PARALLEL_MASKS=1 runs
# them at the same time.
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
    m1() { # m1 MASK TEST-ARGS...
      m1_mask=$1
      shift
      $sudo env FTR_TESTBED_BIN="$bindir/ftr-testbed" FTR_DAEMON_BIN="$bindir/fault-tolerant-router" \
        FTR_TEST_FWMARK_MASK="$m1_mask" "$bindir/m1" --ignored "$@"
    }
    if [ "${FTR_PARALLEL_MASKS:-0}" = 1 ]; then
      # The scenarios wait more than they compute: with enough cores, the
      # masks can run at the same time, each in its own process.
      out=$(mktemp -d)
      for mask in $masks; do
        m1 "$mask" "$@" > "$out/$mask" 2>&1 &
        echo $! > "$out/$mask.pid"
      done
      failed=0
      for mask in $masks; do
        wait "$(cat "$out/$mask.pid")" || failed=1
        echo "== M1 scenarios with fwmark_mask $mask"
        cat "$out/$mask"
      done
      rm -rf "$out"
      [ $failed = 0 ]
    else
      for mask in $masks; do
        echo "== M1 scenarios with fwmark_mask $mask"
        m1 "$mask" "$@"
      done
    fi
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
