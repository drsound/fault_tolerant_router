# Configuration reference

PolyWAN reads one TOML file, `/etc/polywan/config.toml` by default (`--config PATH` selects another). The packages install a commented example as `/usr/share/doc/polywan/examples/config.toml`, and `polywan generate-config` prints the same text. The [recipes](recipes/) show complete configurations for common setups. 1.x YAML configurations are not read: a 2.0 configuration is written anew from the example.

- The file and every directory above it must be owned by root and not writable by group or others; otherwise the daemon refuses to start. The same applies to `firewall.nft_path` and `notify.email.sendmail`, and to the targets of symbolic links on the way.
- Unknown keys are errors, reported with the file, line and key, as are invalid values: `polywan check-config` reports every problem at once, and `polywan check-config --offline` checks the file alone, without looking at the system.
- Durations are strings of one or more numbers with a unit, `ms`, `s`, `m` or `h`: `"500ms"`, `"5s"`, `"1m30s"`.
- The file has no version key.

## Reloading

`systemctl reload polywan` (or `polywan reload`, or SIGHUP) applies a changed file without a restart. The new configuration is validated completely first; if anything is wrong, the running configuration is kept and a `reload_failed` event is emitted. A valid configuration is applied as a set of differences: uplinks whose settings did not change keep their connections, and their probes keep running.

Every key can change on reload except:

- the **structural settings** `routing.fwmark_mask`, `routing.table_base`, `routing.rule_priority_base`, `routing.route_protocol` and `firewall.mode`: they define the objects PolyWAN owns, and are recorded in the state directory. To change one, stop the daemon, run `polywan cleanup` (which removes everything with the recorded settings), change the file and start again. This interrupts routing through PolyWAN, and established connections break.
- `state_dir`: see [state directory](#state-directory).
- an uplink's `id` and `name` pair, which identifies its connections: see [uplinks](#uplinks).

Changes of the API sockets and of the metrics listener are prepared before the new configuration is accepted (a socket that cannot be created rejects the reload) and close the connections of the endpoints they change. For changes of the control socket, restart instead of reloading (see [API](api.md#reload)).

## A minimal configuration

```toml
[[downlink]]
interface = "lan0"

[[uplink]]
id = 1
name = "fiber"
interface = "wan0"
priority = 1

[uplink.ipv4]

[[uplink]]
id = 2
name = "lte"
interface = "wwan0"
priority = 2

[uplink.ipv4]
```

Two IPv4 uplinks, the second used only when the first fails, with masquerade, discovered addresses and gateways, and default health checks. Everything else has defaults.

## routing

| Key | Default | Values |
|---|---|---|
| `routing.all_down_policy` | `"ready"` | `"ready"`, `"keep"` |
| `routing.discovery_tables` | `["main"]` | table names `"main"`, `"default"` or numbers; not in PolyWAN's range |
| `routing.manage_sysctls` | `true` | |
| `routing.reconcile_interval` | `"60s"` | 10 s to 1 h |
| `routing.on_shutdown` | `"keep"` | `"keep"`, `"cleanup"` |
| `routing.table_base` | `1000` | 1 to 4294967103, the 192 tables from it excluding 253–255; structural |
| `routing.rule_priority_base` | `1000` | 1 to 31066 (the 700 priorities from it end below 32766, the main table's rule); structural |
| `routing.route_protocol` | `249` | 5 to 255; structural |
| `routing.fwmark_mask` | `0x00ff0000` | exactly 8 contiguous bits; structural |

`all_down_policy` decides what happens when no candidate uplink of a family passes its health checks: `"ready"` uses the uplinks of the best priority group that are ready anyway (if every check fails at once, the probes may be the problem), `"keep"` keeps the previous active set, restricted to the uplinks still ready. See [the active set](how-it-works.md#the-active-set).

`discovery_tables` lists the routing tables where PolyWAN looks for each uplink's default route, to discover its gateway: by default the main table, where DHCP clients, Router Advertisements and network managers put them. Add a table if your network manager installs the uplinks' default routes elsewhere; PolyWAN only reads them.

`manage_sysctls` lets PolyWAN set forwarding, the multipath hash policy and the per-interface reverse-path, mark and link-down settings it needs (see [system settings](how-it-works.md#system-settings)). With `false`, PolyWAN changes none of them and warns at startup about every value that differs from what it needs.

`reconcile_interval` is the period of the full comparison of PolyWAN's rules, routes and nftables table with what they should be, which also repairs a removed nftables table and looks for flowtables.

`on_shutdown = "keep"` leaves routing in place when the daemon stops, so that a restart or an upgrade causes no outage; `"cleanup"` removes everything at every stop, which interrupts routing through PolyWAN.

`table_base`, `rule_priority_base`, `route_protocol` and `fwmark_mask` only need changing when another tool already uses the same tables, rule priorities, routing protocol number or mark bits. PolyWAN refuses to start when it finds rules or routes of another tool in its ranges. Rules of other tools with a priority between 1 and `rule_priority_base` come before PolyWAN's, and PolyWAN's guarantees do not cover the traffic they match; startup and `check-config` list them. Nothing else may write the 8 mark bits of `fwmark_mask`, in packet or connection marks.

## firewall

| Key | Default | Values |
|---|---|---|
| `firewall.mode` | `"managed"` | `"managed"`, `"external"`; structural |
| `firewall.nat_priority` | `100` | −149 to 400 |
| `firewall.nft_path` | `"/usr/sbin/nft"` | absolute path, owned by root and not writable by others |

In `managed` mode PolyWAN installs and maintains the nftables table `inet polywan`. In `external` mode it never changes nftables: you load the output of `polywan export-nft` yourself, and again after every change of the configuration that changes it. PolyWAN still runs `nft` in both modes, to read the ruleset for its checks. See [the nftables table](how-it-works.md#the-nftables-table).

`nat_priority` is the priority of PolyWAN's source NAT chain in the postrouting hook; it must come after the marking chain at −150.

## Downlinks

```toml
[[downlink]]
interface = "lan0"

[[downlink]]
interface = "dmz0"
```

| Key | Default | Values |
|---|---|---|
| `downlink.interface` | required | an interface name, not used by an uplink |

At least one downlink is required. Downlinks are the interfaces whose traffic PolyWAN routes through the uplinks and translates (NAT), and where policies apply. Their networks must be routed by the main table, as the operating system does for addresses configured normally; `check-config` warns when a downlink's prefix is not there. Interfaces that are neither uplinks nor downlinks (a VPN, a management network) are left alone: traffic towards them is routed by the main table.

## Uplinks

```toml
[[uplink]]
id = 1
name = "fiber"
description = "Fiber 1 Gbps (provider A)"
interface = "wan0"
priority = 1
weight = 10

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"
```

| Key | Default | Values |
|---|---|---|
| `uplink.id` | required | 1 to 63, unique |
| `uplink.name` | required | 1 to 32 characters among `a-z 0-9 _ -`, unique |
| `uplink.description` | the name | free text, for messages |
| `uplink.interface` | required | an interface name, unique among uplinks and downlinks |
| `uplink.priority` | none | 1 to 1000; lower numbers are preferred; absent: never used for new connections |
| `uplink.weight` | `1` | 1 to 256 |
| `uplink.ipv4`, `uplink.ipv6` | absent | a table per family the uplink carries; at least one |
| `uplink.health` | absent | overrides of the [health](#health) settings for this uplink |

**Identity.** `id` and `name` identify the uplink for good: the id is stored in the marks of its connections, and PolyWAN records the pair in its state directory. A configuration that gives an existing name another id, or an existing id to another name, refuses startup (exit status 78) and reloads. When an uplink is removed from the configuration, its id stays reserved, because connections that still carry it are rejected rather than routed elsewhere; after they are gone, `polywan forget-uplink NAME` releases the id (see [forget-uplink](api.md#forget-uplink)). Renaming an uplink is removing it and adding a new one with another id. Changing its `interface`, `priority`, `weight` or family tables is a normal reload.

**Priority and weight.** New connections use the healthy uplinks of the best priority group, spread by weight: with weights 10 and 3, about 10 of every 13 new connections go to the first. Weights split connections, not traffic: one large download stays on the uplink it started on. An uplink without `priority` is never used for new outgoing connections, but inbound connections, its probes, policies that name it and traffic of the router bound to its address keep working: use it for an uplink reserved to inbound services or to policies.

### uplink.ipv4 and uplink.ipv6

| Key | Default | Values |
|---|---|---|
| `uplink.ipv4.source`, `uplink.ipv6.source` | `"auto"` | `"auto"` or an address of the family |
| `uplink.ipv4.gateway`, `uplink.ipv6.gateway` | `"auto"` | `"auto"` or an address of the family |
| `uplink.ipv4.gateway_onlink`, `uplink.ipv6.gateway_onlink` | `false` | only with a static `gateway` |
| `uplink.ipv4.nat`, `uplink.ipv6.nat` | IPv4: `"masquerade"`; IPv6: required | `"masquerade"`, `"snat"`, `"none"` |

An empty `[uplink.ipv4]` table enables IPv4 with every default; IPv6 always needs `nat`.

`source = "auto"` uses one of the interface's global addresses, preferring permanent over dynamic and primary over secondary addresses. A static `source` must be present on the router; the path is ready only while it is. It may belong to another interface: an IPv6 provider that gives only a delegated prefix, and no address on the uplink, works with a static `source` taken from that prefix on the LAN interface and `nat = "snat"`. Two uplinks cannot share a static source.

`gateway = "auto"` takes the next hop from the uplink's default route in `routing.discovery_tables`; IPv4 point-to-point interfaces (PPP) need none. An IPv6 gateway is normally the link-local address of the provider's router, learnt from Router Advertisements. A static `gateway` must be inside a network connected to the interface, unless `gateway_onlink = true` declares it reachable on the link anyway.

`nat` chooses the translation of traffic from the downlinks leaving through this uplink: `"masquerade"` to the uplink's current address, `"snat"` to the static `source` (required), `"none"` for routed setups. For IPv6 it must be chosen explicitly:

- `"none"` keeps end-to-end addressing, but with several providers it works only if every provider routes your LAN prefix, which is rare: a connection that leaves through one provider with a source address of another provider's prefix is usually dropped by the provider's filtering.
- `"masquerade"` with a unique local (ULA) prefix on the LAN gives transparent failover, like IPv4, at the cost of end-to-end addressing.

If you also translate traffic on the uplink interfaces in your own nftables tables, the first NAT chain that matches decides: set `nat = "none"` on those paths. `check-config` warns when it finds source NAT in other tables.

## health

```toml
[health]
interval = "5s"
timeout = "1s"
attempts = 2
required_reachable = 2
fall = 2
rise = 3

[health.ipv4]
targets = ["icmp:1.1.1.1", "icmp:8.8.8.8", "icmp:9.9.9.9", "icmp:208.67.222.222"]

[health.ipv6]
targets = ["icmp:2606:4700:4700::1111", "icmp:2001:4860:4860::8888", "icmp:2620:fe::fe"]
```

| Key | Default | Values |
|---|---|---|
| `health.interval` | `"5s"` | 1 s to 5 min |
| `health.timeout` | `"1s"` | greater than zero; `timeout × attempts` shorter than `interval` |
| `health.attempts` | `2` | 1 to 5 |
| `health.required_reachable` | `2` | 1 to the number of distinct target addresses |
| `health.fall` | `2` | 1 to 20 |
| `health.rise` | `3` | 1 to 20 |
| `health.ipv4.targets` | four anycast resolvers (above) | `icmp:ADDRESS` or `tcp:ADDRESS:PORT` |
| `health.ipv6.targets` | three anycast resolvers (above) | `icmp:ADDRESS` or `tcp:[ADDRESS]:PORT` |
| `health.quality.max_loss` | none | 0 to 1 |
| `health.quality.max_rtt` | none | a duration |
| `health.quality.max_jitter` | none | a duration |
| `health.quality_window` | `6` | 2 to 100 rounds |
| `health.quality_min_samples` | `10` | 1 to targets × `quality_window` |

Every `interval`, each ready path runs a round: all its targets are probed at once, each with up to `attempts` attempts of `timeout` each. A target is reachable if one attempt got a reply; the round passes if at least `required_reachable` targets were reachable. A path goes down after `fall` failed rounds in a row and up again after `rise` passed rounds in a row. With the defaults, a silent failure is detected within `(fall + 1) × interval + timeout × attempts`, 17 seconds; carrier loss within a second, without probes.

`icmp:` targets are probed with ICMP or ICMPv6 echo; `tcp:` targets with a TCP handshake, for links that filter ICMP: a SYN-ACK or a reset is a reply. Targets must be global unicast addresses of the family, and must be neither addresses of the router nor inside a downlink's network.

**Choosing targets.** Probe hosts that are far away and highly available, operated by different organisations: the defaults are anycast DNS resolvers of Cloudflare, Google, Quad9 and OpenDNS. Do not probe the provider's own router or anything inside its network: a provider can be cut off from the internet while its router still answers, and the uplink would look healthy while it is useless. Do not require every target to answer either: single probes get lost and single targets go down. Several targets with `required_reachable` below their number tolerate both.

**Per uplink.** An `[uplink.health]` table after an `[[uplink]]` overrides any of these keys for that uplink, for example a longer `timeout` for a satellite link or TCP targets for a provider that filters ICMP; keys it does not set come from `[health]`, also inside `quality`.

```toml
[[uplink]]
id = 3
name = "satellite"
interface = "wan2"
priority = 2

[uplink.ipv4]

[uplink.health]
timeout = "2s"

[uplink.health.ipv4]
targets = ["tcp:1.1.1.1:443", "tcp:8.8.8.8:443", "tcp:9.9.9.9:443"]
```

### Quality gates

`max_loss`, `max_rtt` and `max_jitter` make a round fail, as `degraded`, when the link answers but badly. They are evaluated at the end of each round over the samples of the last `quality_window` rounds (every attempt that got a reply or timed out is a sample): the loss ratio over all samples, the median round-trip time of the replies, and the jitter, the median of the differences between consecutive round-trip times of the same target. The loss gate needs at least `quality_min_samples` samples, the round-trip and jitter gates at least 5 replies or 5 differences; until then they do not fail a round.

Because old samples stay in the window, a path taken down by a gate comes back only after `rise` passed rounds **and** once the window no longer violates the gate: recovery takes at least `rise` rounds and can take up to the whole window.

The statistics (loss, round-trip time, jitter) are computed and shown by `polywan status` and the metrics with or without gates. Without gates, a round ends as soon as its outcome is certain, so attempts still running then are not counted: the statistics describe completed attempts only, and favour faster targets. With gates enabled on a path, every attempt runs to its reply or its timeout, so that the samples are not biased.

## Policies

```toml
[[policy]]
name = "smtp-via-fiber"
family = "ipv4"
source = "192.168.1.25/32"
protocol = "tcp"
destination_port = 25
uplink = "fiber"
fallback = "block"
```

| Key | Default | Values |
|---|---|---|
| `policy.name` | required | unique |
| `policy.family` | required | `"ipv4"`, `"ipv6"`; the uplink must carry it |
| `policy.input_interface` | any downlink | a downlink |
| `policy.source` | any | an address or prefix of the family |
| `policy.destination` | any | an address or prefix of the family |
| `policy.protocol` | any | `"tcp"`, `"udp"`, `"sctp"`, `"icmp"` (IPv4), `"icmpv6"` (IPv6) |
| `policy.destination_port` | any | a port 1–65535 or a range `"A-B"`; only with `tcp`, `udp` or `sctp` |
| `policy.uplink` | required | an uplink name |
| `policy.fallback` | `"balance"` | `"balance"`, `"block"` |

A policy sends new forwarded connections that match all of its conditions through `uplink`; policies are evaluated in order, and the first that matches wins. While the uplink is not healthy or is drained, `fallback = "balance"` spreads the matching connections over the active set and `"block"` rejects them. Policies do not apply to traffic of the router itself, nor to destinations routed by the main table (local networks, VPNs). See [policies](how-it-works.md#policies).

## notify

| Key | Default | Values |
|---|---|---|
| `notify.coalesce` | `"30s"` | a duration |
| `notify.hook_user` | `"nobody"` | an existing local user other than UID 0 |
| `notify.email` | absent | see [email](email.md) |
| `notify.email.from` | required | one plain address, `local-part@domain` |
| `notify.email.to` | required | a non-empty list of plain addresses |
| `notify.email.sendmail` | `"/usr/sbin/sendmail"` | absolute path of a sendmail-compatible program, without arguments; owned by root |
| `notify.email.max_per_hour` | `20` | 1 to 10000 |
| `notify.email.events` | see [email](email.md) | a non-empty list of event types |
| `notify.hook` | none | a list of hooks |
| `notify.hook.command` | required | the absolute path of a program, then its arguments |
| `notify.hook.events` | every event type | a non-empty list of event types |
| `notify.hook.timeout` | `"10s"` | greater than zero |

`coalesce` is the time email waits to collect changes into one message. Email, its limits and the supported mail configuration are described in [email](email.md).

### Hooks

```toml
[[notify.hook]]
command = ["/usr/local/bin/polywan-to-ntfy", "--topic", "router"]
events = ["path_state_changed", "active_set_changed"]
timeout = "5s"
```

A hook is a program run for every event of the selected types (the types are listed in [events](api.md#get-v1events)); it cannot delay or veto routing changes. It runs:

- without a shell: `command` is the program and its arguments, as written;
- as `notify.hook_user` with that user's primary group, no supplementary groups and no capabilities; the user must be a local account (see [users and groups](api.md#users-and-groups));
- with the event as JSON on standard input, and in the environment `POLYWAN_EVENT` (the type), `POLYWAN_UPLINK`, `POLYWAN_FAMILY`, `POLYWAN_OLD`, `POLYWAN_NEW` and `POLYWAN_REASON` where they apply, and `PATH=/usr/sbin:/usr/bin:/sbin:/bin`; nothing else;
- in a new process group, killed as a whole when `timeout` expires;
- at most 4 at a time; events that find the queue full are dropped and counted (`polywan_events_dropped_total`).

Its standard output and error, up to 64 KiB each, and its exit status are logged. Under the packaged unit, a hook runs inside the service's sandbox: the file system is read-only except for PolyWAN's own directories, home directories are hidden, `/tmp` is private, and only IPv4, IPv6, Unix and netlink sockets can be opened. `polywan notify-test` runs every hook once with a test event.

## api

| Key | Default | Values |
|---|---|---|
| `api.socket` | `"/run/polywan/api.sock"` | absolute path |
| `api.group` | `"polywan"` | an existing local group |
| `api.status_socket` | `"/run/polywan/status.sock"` | absolute path, distinct from `api.socket`, or `""` to disable it |
| `api.status_group` | absent | an existing local group |

The control socket gives full control of the daemon to the members of `api.group`. The status socket shows the status and the event history, including addresses, gateways and the health of every uplink, **to every local user** unless `status_group` restricts it to a group or `status_socket = ""` disables it. See [who can do what](api.md#who-can-do-what), and, for socket paths outside `/run/polywan`, [installation](installation.md).

## metrics

| Key | Default | Values |
|---|---|---|
| `metrics.listen` | absent (disabled) | an address and port, such as `"127.0.0.1:9750"` or `"[::1]:9750"` |

The endpoint serves Prometheus metrics at `/metrics`, without access control: bind it to a loopback or management address. The metrics are listed in [metrics](api.md#metrics).

## State directory

| Key | Default | Values |
|---|---|---|
| `state_dir` | `"/var/lib/polywan"` | absolute path |

`state_dir` is a top-level key: in TOML it must come before the first table of the file. It holds the manifest of what PolyWAN installed, the drain state and the health checkpoint (see [the state directory](how-it-works.md#the-state-directory)). It cannot change on reload. To move it:

1. Stop the daemon, with `routing.on_shutdown = "keep"` so that routing stays in place.
2. Move the whole directory, keeping its ownership (root), permissions (0700) and contents.
3. Change `state_dir` in the configuration and, under systemd, give the service write access to the new location (the packaged unit only allows `/var/lib/polywan`; see [installation](installation.md)).
4. Start the daemon.

No cleanup is needed: the daemon finds its installation and adopts it, and established connections continue if nothing else changed meanwhile.

## Flow offload

nftables flowtables must not offload traffic between downlinks and uplinks: offloaded packets skip PolyWAN's marking, and PolyWAN's guarantees do not hold for them. Startup, reload and `check-config` refuse a flowtable whose devices name a configured uplink or downlink, whatever its flags, and a running daemon that finds one reports the status `degraded` (`flow_offload`). For VLANs, bridges and bonds, offload attached below a configured interface is just as forbidden, and the check of names alone does not detect it. See [living with your own ruleset](how-it-works.md#living-with-your-own-ruleset).
