#!/bin/sh
# Builds the namespace test suite as static musl binaries and runs it, either
# on this host (current kernel and nftables) or inside a virtme-ng virtual
# machine booted with the kernel of a root filesystem made by build-rootfs.sh.
#
# Usage:
#   tests/vm/run-suite.sh [--host | --vm ROOTFS | --build-only] [--bindir DIR] [--unit] [-- TEST-ARGS...]
#
# The build runs as the invoking user; running the suite needs root, so the
# script uses sudo when it is not already root. Extra arguments after "--"
# go to the test binary (for example a test name filter). --build-only
# leaves the binaries in the suite directory; --bindir runs binaries built
# earlier (copied to a machine without a Rust toolchain, for example) and
# skips the build. --unit runs the M1 to M4 scenarios on this host with the
# daemon started as the shipped packaging/polywan.service (AS-34; copied
# next to the binaries), once, with the default fwmark_mask unless
# POLYWAN_TEST_MASKS says otherwise.
set -eu

mode=host
rootfs=
prebuilt=
unit=
while [ $# -gt 0 ]; do
  case $1 in
    --host) mode=host; shift ;;
    --vm) mode=vm; rootfs=${2:?--vm needs a root filesystem}; shift 2 ;;
    --build-only) mode=build; shift ;;
    --bindir) prebuilt=${2:?--bindir needs a directory}; shift 2 ;;
    --unit) unit=1; shift ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
target=x86_64-unknown-linux-musl
target_dir=${CARGO_TARGET_DIR:-$repo/target}
bindir=$target_dir/netns-suite
# The daemon's kernel tests (crates/polywan/tests/kernel_*.rs).
kernel_tests="kernel_netlink kernel_probe kernel_handoff"
cd "$repo"

if [ -n "$prebuilt" ]; then
  bindir=$(cd "$prebuilt" && pwd)
else
  # The daemon under test has the hooks of the acceptance scenarios
  # (crates/polywan/src/test_hooks.rs).
  cargo build --target $target -p testbed --bin polywan-testbed -p polywan --bin polywan \
    --features polywan/test-hooks
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
  cp "$target_dir/$target/debug/polywan-testbed" "$target_dir/$target/debug/polywan" "$bindir/"
  cp packaging/polywan.service "$bindir/"
  # netns: the harness's own checks; m1 to m4: the acceptance scenarios.
  { test_exes testbed netns m1 m2 m3 m4; test_exes polywan $kernel_tests; } \
    | while read -r name exe; do cp "$exe" "$bindir/$name"; done
  for t in netns m1 m2 m3 m4 $kernel_tests; do
    [ -x "$bindir/$t" ] || { echo "test executable $t was not built" >&2; exit 1; }
  done
fi
if [ "$mode" = build ]; then
  echo "$bindir"
  exit 0
fi
if [ -n "$unit" ]; then
  # systemd as PID 1 is needed: not in the virtme-ng guest.
  [ "$mode" = host ] || { echo "--unit runs on the host only" >&2; exit 2; }
  sudo=
  [ "$(id -u)" -eq 0 ] || sudo=sudo
  cd /tmp
  status=0
  for mask in ${POLYWAN_TEST_MASKS:-0x00ff0000}; do
    echo "== M1 to M4 scenarios under the unit with fwmark_mask $mask"
    for s in m1 m2 m3 m4; do
      $sudo env POLYWAN_TESTBED_BIN="$bindir/polywan-testbed" POLYWAN_DAEMON_BIN="$bindir/polywan" \
        POLYWAN_TEST_UNIT="$bindir/polywan.service" POLYWAN_TEST_FWMARK_MASK="$mask" \
        "$bindir/$s" --ignored "$@" || status=1
    done
  done
  exit $status
fi
# The M1 to M4 scenarios run once per fwmark_mask (AS-43: offsets 16, 0
# and 24); POLYWAN_TEST_MASKS narrows the list; on the host,
# POLYWAN_PARALLEL_MASKS=1 runs them at the same time.
masks=${POLYWAN_TEST_MASKS:-"0x00ff0000 0x000000ff 0xff000000"}
scenarios="m1 m2 m3 m4"
m1_in_vm=
for mask in $masks; do
  m1_in_vm="$m1_in_vm && echo '== M1 to M4 scenarios with fwmark_mask $mask'"
  for s in $scenarios; do
    m1_in_vm="$m1_in_vm && POLYWAN_TESTBED_BIN=/mnt/polywan-testbed POLYWAN_DAEMON_BIN=/mnt/polywan POLYWAN_TEST_FWMARK_MASK=$mask /mnt/$s --ignored --test-threads=${VM_TEST_THREADS:-2} $*"
  done
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
    $sudo env POLYWAN_TESTBED_BIN="$bindir/polywan-testbed" "$bindir/netns" --ignored "$@"
    m1() { # m1 MASK TEST-ARGS...: every scenario binary, whatever fails
      m1_mask=$1
      shift
      m1_status=0
      for s in $scenarios; do
        $sudo env POLYWAN_TESTBED_BIN="$bindir/polywan-testbed" POLYWAN_DAEMON_BIN="$bindir/polywan" \
          POLYWAN_TEST_FWMARK_MASK="$m1_mask" "$bindir/$s" --ignored "$@" || m1_status=1
      done
      return $m1_status
    }
    if [ "${POLYWAN_PARALLEL_MASKS:-0}" = 1 ]; then
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
        echo "== M1 to M4 scenarios with fwmark_mask $mask"
        cat "$out/$mask"
      done
      rm -rf "$out"
      [ $failed = 0 ]
    else
      for mask in $masks; do
        echo "== M1 to M4 scenarios with fwmark_mask $mask"
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
    # virtme-ng passes the --exec command on the kernel command line
    # (base64, within its 2048 bytes): the suite's commands go to a script
    # in the shared directory. The guest's shell holds descriptors without
    # close-on-exec (the daemon found 4 to 7 under virtme-ng 1.35), which
    # the daemon refuses with hooks or email configured (FR-HOOK-3): they
    # are listed, then closed (dash keeps the script itself above 9).
    printf '%s\n' "ls -l /proc/\$\$/fd; exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; uname -r && nft --version && chmod 0755 /run && cd /tmp &&$kernel_in_vm POLYWAN_TESTBED_BIN=/mnt/polywan-testbed /mnt/netns --ignored --test-threads=${VM_TEST_THREADS:-2} $* $m1_in_vm" \
      > "$bindir/vm-suite.sh"
    exec $sudo env PATH="$PATH" "$vng" --run "$kernel" --root "$rootfs" --user root \
      --memory "${VM_MEMORY:-2G}" --cpus "${VM_CPUS:-2}" \
      --rodir "/mnt=$bindir" \
      --exec "sh /mnt/vm-suite.sh"
    ;;
esac
