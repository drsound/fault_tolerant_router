#!/bin/sh
# Measures the CPU time and memory of a PolyWAN release build with four
# uplinks and default settings (IMPL-9), in network namespaces: a router
# namespace with a LAN interface and four veth uplinks, each to a provider
# namespace that answers the default probe targets of both families. The
# four uplinks share priority 1, as the example's two do, so that every
# path is active.
#
# Usage (as root): tests/perf/impl9.sh POLYWAN-BINARY [SECONDS]
#                  tests/perf/impl9.sh --unit [SECONDS]
#
# SECONDS defaults to 600; the measurement starts after a 60 s warm-up.
# The report gives the average CPU use of one core and the resident memory
# (current and peak) of the daemon, which runs no hooks and sends no email.
# With --unit the daemon is the installed package's polywan.service, with
# the default configuration path, state and sockets, in the router
# namespace through a runtime drop-in (NetworkNamespacePath=); IMPL9_EXEC
# names another executable for its ExecStart= (a path the sandbox can
# see). The host must have no PolyWAN configuration and the service must
# be stopped. The report then records the unit's effective sandbox, and on
# a Raspberry Pi its temperature, clock and throttling.
set -eu

usage="usage: impl9.sh POLYWAN-BINARY [SECONDS] | impl9.sh --unit [SECONDS]"
unit=
if [ "${1:-}" = --unit ]; then
  unit=polywan.service
  bin=/usr/bin/polywan
  seconds=${2:-600}
  [ -x "$bin" ] || { echo "impl9.sh: the polywan package is not installed" >&2; exit 2; }
  [ ! -e /etc/polywan/config.toml ] || { echo "impl9.sh: /etc/polywan/config.toml exists" >&2; exit 2; }
  ! systemctl -q is-active "$unit" || { echo "impl9.sh: $unit is running" >&2; exit 2; }
else
  bin=$(realpath "${1:?$usage}")
  seconds=${2:-600}
fi
warmup=60
id=i9$$
dir=$(mktemp -d /run/polywan-impl9.XXXXXX)
chmod 0755 "$dir"
router=$id-router
pid=
made_etc=

dropin=/run/systemd/system/polywan.service.d/impl9.conf

cleanup() {
  if [ -n "$unit" ]; then
    systemctl stop "$unit" 2>/dev/null || true
    [ -e /etc/polywan/config.toml ] && ip netns exec "$router" "$bin" cleanup >/dev/null 2>&1
    rm -f /etc/polywan/config.toml "$dropin"
    [ -z "$made_etc" ] || rmdir /etc/polywan
    systemctl daemon-reload
  fi
  [ -n "$pid" ] && [ -z "$unit" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
  for i in 1 2 3 4; do ip netns del "$id-isp$i" 2>/dev/null || true; done
  ip netns del "$router" 2>/dev/null || true
  rm -rf "$dir"
}
trap cleanup EXIT INT TERM

in_router() { ip netns exec "$router" "$@"; }

ip netns add "$router"
in_router ip link set lo up
in_router ip link add lan type dummy
in_router ip addr add 192.168.1.1/24 dev lan
in_router ip addr add fd10::1/64 dev lan nodad
in_router ip link set lan up
for i in 1 2 3 4; do
  isp=$id-isp$i
  ip netns add "$isp"
  ip -n "$isp" link set lo up
  # The default probe targets (SPEC.md §11.2) answer in every provider.
  for a in 1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222; do ip -n "$isp" addr add "$a/32" dev lo; done
  for a in 2606:4700:4700::1111 2001:4860:4860::8888 2620:fe::fe; do ip -n "$isp" addr add "$a/128" dev lo; done
  ip link add "wan$i" netns "$router" type veth peer name core netns "$isp"
  ip -n "$isp" addr add "10.0.$i.1/24" dev core
  ip -n "$isp" addr add "fd00:$i::1/64" dev core nodad
  ip -n "$isp" link set core up
  in_router ip addr add "10.0.$i.2/24" dev "wan$i"
  in_router ip addr add "fd00:$i::2/64" dev "wan$i" nodad
  in_router ip link set "wan$i" up
  in_router ip route add default via "10.0.$i.1" dev "wan$i" metric "$((100 * i))"
  in_router ip -6 route add default via "fd00:$i::1" dev "wan$i" metric "$((100 * i))"
done

uplinks() {
  for i in 1 2 3 4; do
    printf '\n[[uplink]]\nid = %d\nname = "isp%d"\ninterface = "wan%d"\npriority = 1\n[uplink.ipv4]\n[uplink.ipv6]\nnat = "masquerade"\n' "$i" "$i" "$i"
  done
}

if [ -n "$unit" ]; then
  # The packaged defaults: state, sockets and the polywan group.
  config=/etc/polywan/config.toml
  [ -d /etc/polywan ] || { mkdir /etc/polywan; made_etc=1; }
  { printf '[[downlink]]\ninterface = "lan"\n'; uplinks; } > "$config"
  chmod 0644 "$config"
  mkdir -p "$(dirname "$dropin")"
  {
    printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' "$router"
    [ -z "${IMPL9_EXEC:-}" ] || printf 'ExecStart=\nExecStart=%s run\n' "$IMPL9_EXEC"
  } > "$dropin"
  systemctl daemon-reload
  # Returns once the daemon has reported its readiness.
  systemctl start "$unit"
  pid=$(systemctl show -P MainPID "$unit")
  sleep "$warmup"
  [ "$(systemctl show -P MainPID "$unit")" = "$pid" ] || { journalctl -u "$unit" -n 30 --no-pager; exit 1; }
  status_socket=/run/polywan/status.sock
else
  config=$dir/config.toml
  {
    printf 'state_dir = "%s/state"\n\n[[downlink]]\ninterface = "lan"\n' "$dir"
    uplinks
    printf '\n[api]\nsocket = "%s/api.sock"\nstatus_socket = "%s/status.sock"\ngroup = "root"\n' "$dir" "$dir"
  } > "$config"
  chmod 0644 "$config"

  # Not through a shell function: $! is then the daemon (ip execs it).
  ip netns exec "$router" "$bin" --lock "$dir/lock" run --config "$config" > "$dir/daemon.log" 2>&1 &
  pid=$!
  sleep "$warmup"
  kill -0 "$pid" || { cat "$dir/daemon.log"; exit 1; }
  [ "$(readlink "/proc/$pid/exe")" = "$bin" ] || { echo "process $pid is not $bin" >&2; exit 1; }
  status_socket=$dir/status.sock
fi
exe=$(readlink "/proc/$pid/exe")
status=$("$bin" status --socket "$status_socket" | sed -n 1p)

# A Raspberry Pi's operating conditions, before and after. get_throttled's
# history bits last until a reboot; the kernel logs every under-voltage.
pi() {
  command -v vcgencmd >/dev/null || return 0
  echo "$1: $(vcgencmd measure_temp), $(vcgencmd measure_clock arm), $(vcgencmd get_throttled)," \
    "governor $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)," \
    "$(dmesg | grep -c 'Undervoltage detected') under-voltages logged since boot"
}
before=$(pi "Pi before")

ticks() { awk '{print $14 + $15}' "/proc/$pid/stat"; }
hz=$(getconf CLK_TCK)
start=$(ticks)
sleep "$seconds"
end=$(ticks)
paths=$("$bin" status --socket "$status_socket" | grep -c ': up (.*, ready, active')
rss=$(awk '/^VmRSS/ {print $2}' "/proc/$pid/status")
hwm=$(awk '/^VmHWM/ {print $2}' "/proc/$pid/status")
threads=$(awk '/^Threads/ {print $2}' "/proc/$pid/status")

echo "host: $(uname -m), Linux $(uname -r), $(nproc) CPUs ($(awk -F': ' '/^(model name|Model)/ {print $2; exit}' /proc/cpuinfo))"
echo "daemon: $exe, $("$exe" --version), $(stat -c %s "$exe") bytes, sha256 $(sha256sum "$exe" | cut -d ' ' -f 1); $status"
if [ -n "$unit" ]; then
  echo "unit: $(systemctl show -P FragmentPath "$unit") with $dropin; systemd $(systemctl --version | awk 'NR == 1 {print $2}')"
  systemctl show "$unit" -p NoNewPrivileges -p ProtectSystem -p ProtectHome -p PrivateTmp \
    -p CapabilityBoundingSet -p RestrictAddressFamilies -p SystemCallFilter -p NetworkNamespacePath \
    | sed 's/^SystemCallFilter=\(.\{60\}\).*/SystemCallFilter=\1… (@system-service)/; s/^/  /'
  [ "$(systemctl show -P MainPID "$unit")" = "$pid" ] && same="the same" || same="NOT the same"
  echo "  NRestarts=$(systemctl show -P NRestarts "$unit"), $same main process throughout"
fi
[ -z "$before" ] || { echo "$before"; pi "Pi after"; }
echo "measured: $seconds s after a $warmup s warm-up, 4 uplinks, IPv4 and IPv6, default settings; $paths of 8 paths up and active at the end"
awk -v d="$((end - start))" -v hz="$hz" -v s="$seconds" \
  'BEGIN { printf "CPU: %.3f%% of one core (%d ticks at %d Hz)\n", 100 * d / hz / s, d, hz }'
echo "memory: RSS $((rss / 1024)) MB ($rss kB), peak $((hwm / 1024)) MB ($hwm kB); $threads threads"
