#!/bin/sh
# Measures the CPU time and memory of a PolyWAN release build with four
# uplinks and default settings (IMPL-9), in network namespaces: a router
# namespace with a LAN interface and four veth uplinks, each to a provider
# namespace that answers the default probe targets of both families.
#
# Usage (as root): tests/perf/impl9.sh POLYWAN-BINARY [SECONDS]
#
# SECONDS defaults to 600; the measurement starts after a 60 s warm-up.
# The report gives the average CPU use of one core and the resident memory
# (current and peak) of the daemon, which runs no hooks and sends no email.
set -eu

bin=$(realpath "${1:?usage: impl9.sh POLYWAN-BINARY [SECONDS]}")
seconds=${2:-600}
warmup=60
id=i9$$
dir=$(mktemp -d /run/polywan-impl9.XXXXXX)
chmod 0755 "$dir"
router=$id-router
pid=

cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
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

config=$dir/config.toml
{
  printf 'version = 2\nstate_dir = "%s/state"\n\n[[downlink]]\ninterface = "lan"\n' "$dir"
  for i in 1 2 3 4; do
    printf '\n[[uplink]]\nid = %d\nname = "isp%d"\ninterface = "wan%d"\n[uplink.ipv4]\n[uplink.ipv6]\nnat = "masquerade"\n' "$i" "$i" "$i"
  done
  printf '\n[api]\nsocket = "%s/api.sock"\nstatus_socket = "%s/status.sock"\ngroup = "root"\n' "$dir" "$dir"
} > "$config"
chmod 0644 "$config"

# Not through a shell function: $! is then the daemon (ip execs it).
ip netns exec "$router" "$bin" --lock "$dir/lock" run --config "$config" > "$dir/daemon.log" 2>&1 &
pid=$!
sleep "$warmup"
kill -0 "$pid" || { cat "$dir/daemon.log"; exit 1; }
[ "$(readlink "/proc/$pid/exe")" = "$bin" ] || { echo "process $pid is not $bin" >&2; exit 1; }
status=$("$bin" status --socket "$dir/status.sock" | sed -n 1p)

ticks() { awk '{print $14 + $15}' "/proc/$pid/stat"; }
hz=$(getconf CLK_TCK)
start=$(ticks)
sleep "$seconds"
end=$(ticks)
paths=$("$bin" status --socket "$dir/status.sock" | grep -c ': up (')
rss=$(awk '/^VmRSS/ {print $2}' "/proc/$pid/status")
hwm=$(awk '/^VmHWM/ {print $2}' "/proc/$pid/status")
threads=$(awk '/^Threads/ {print $2}' "/proc/$pid/status")

echo "host: $(uname -m), Linux $(uname -r), $(nproc) CPUs ($(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo))"
echo "daemon: $("$bin" --version), $(stat -c %s "$bin") bytes; $status"
echo "measured: $seconds s after a $warmup s warm-up, 4 uplinks, IPv4 and IPv6, default settings; $paths of 8 paths up at the end"
awk -v d="$((end - start))" -v hz="$hz" -v s="$seconds" \
  'BEGIN { printf "CPU: %.3f%% of one core (%d ticks at %d Hz)\n", 100 * d / hz / s, d, hz }'
echo "memory: RSS $((rss / 1024)) MB ($rss kB), peak $((hwm / 1024)) MB ($hwm kB); $threads threads"
