# API, command line and access

The running daemon is controlled and observed through an HTTP API on two Unix sockets, which the `polywan` command uses, and through an optional Prometheus endpoint. This page describes who can do what, the commands that talk to the daemon, every endpoint and field of the API, and the accounts PolyWAN looks up. `man 8 polywan` describes every command and option.

## Who can do what

| Endpoint | Default path | Owner and mode | Gives |
|---|---|---|---|
| Control socket (`api.socket`) | `/run/polywan/api.sock` | root, group `api.group` (default `polywan`), 0660 | every endpoint: status and events, drain, undrain, reload, forget an uplink, notification tests |
| Status socket (`api.status_socket`) | `/run/polywan/status.sock` | root:root, 0666; with `api.status_group`, root and that group, 0660 | status and events only |
| Metrics (`metrics.listen`) | disabled | a TCP address, for example `127.0.0.1:9750` | `GET /metrics` only |

**Membership of `api.group` is full control of the daemon.** A member can drain every uplink with `--force` (which leaves the network without new connections), reload the configuration and run the notification commands as root. Grant it only to administrators; the package creates the `polywan` group with no members.

**The status socket is readable by every local user by default.** It discloses current and historical operational information about the network: the uplinks' addresses and gateways, their health and drain state, the reasons of transitions and the messages of the last 1000 events. It discloses no configuration contents, notification addresses, credentials or output of hooks and sendmail. To restrict it to a group, name an existing group:

```toml
[api]
status_group = "monitoring"
```

To disable it, set `status_socket = ""`; `polywan status` and `polywan events` then need `--socket /run/polywan/api.sock` and membership of `api.group`.

Like every listener, the status socket serves at most 16 connections at once (see [limits](#limits-and-overload)), and a client following the events holds one for up to a minute: any local user can therefore occupy it and keep other status clients waiting. The routing and the control socket are not affected. Where untrusted users log in on the router, restrict the status socket with `status_group`.

The metrics endpoint has no access control: bind it to a loopback or management address, and filter it in your firewall if needed.

Which socket answers decides what a request may do: authorisation does not depend on headers or methods, and the status socket answers 404 to every control endpoint, as if it did not exist.

### Socket paths

The default paths are in `/run/polywan`, which the packaged unit creates (`RuntimeDirectory=polywan`, root, 0755) and keeps across restarts. A socket elsewhere needs a parent directory owned by root and not writable by group or others (also through symbolic links), traversable by the clients, and, under the packaged unit's `ProtectSystem=strict`, made writable for the service with a drop-in (see [installation](installation.md)). PolyWAN refuses to start, or to reload, when a socket path is occupied by something it cannot identify as its own: a socket left by an earlier run is replaced when PolyWAN's record of the sockets it published (in `/run/polywan`) identifies it; one it cannot identify is refused and must be removed by hand.

A reload that changes a socket's path, group or mode, or disables it, closes its open connections. A reload that changes the control socket closes the very connection that asked for it, before the answer: `polywan reload` and `systemctl reload` then report an unknown outcome (see [reload](#reload)). For such changes, restart the daemon instead of reloading it. A reload cannot swap the control and status roles of an existing path.

## The command line

Commands that talk to the daemon never read the configuration, so they work for users who cannot read `/etc/polywan/config.toml`:

| Command | Socket | Needs |
|---|---|---|
| `polywan status [--json]` | status socket | access to the status socket |
| `polywan events [--follow] [--json]` | status socket | access to the status socket |
| `polywan drain NAME [--force]`, `polywan undrain NAME` | control socket | membership of `api.group` |
| `polywan reload` | control socket | membership of `api.group` |
| `polywan notify-test` | control socket | membership of `api.group` |
| `polywan forget-uplink NAME` | control socket, or offline | membership of `api.group`, or root offline |

`--socket PATH` selects another socket, for example the control socket when the status socket is disabled, or the sockets of a configuration with non-default paths. Commands exit with status 0 on success, 1 on failure and 2 on a usage error; output meant for scripts goes to standard output and diagnostics to standard error. `polywan run` additionally exits with status 78 when the configuration refuses startup (see [installation](installation.md)).

The other commands (`run`, `check-config`, `generate-config`, `export-nft`, `cleanup`, `notify-test --offline`) work without the daemon; those that read the configuration take `--config PATH` (default `/etc/polywan/config.toml`).

### status

```text
$ polywan status
polywan 2.0.0, up 3h 12m, status ok
generation: desired 14, applied 14
active ipv4: fiber, fwa5g
active ipv6: fiber
uplink fiber (id 1, wan0)
  ipv4: up (probes_recovered) since 2026-10-06T07:02:11.408Z, ready, active, source 203.0.113.10 via 203.0.113.1, rtt 8.1 ms, jitter 0.4 ms, loss 0%
  ipv6: up (startup) since 2026-10-06T06:58:40.017Z, ready, active, source 2001:db8:10::2 via fe80::1, rtt 9.0 ms, jitter 0.3 ms, loss 0%
uplink fwa5g (id 2, wan1)
  ipv4: up (startup) since 2026-10-06T06:58:40.017Z, ready, active, source 100.64.12.7 via 100.64.12.1, rtt 31.6 ms, jitter 2.2 ms, loss 0%
  ipv6: down (probe_failed) since 2026-10-06T09:41:55.230Z, ready, not active, source 2001:db8:20::5 via fe80::1, rtt 35.2 ms, jitter 3.1 ms, loss 58%
```

For every path: its health and the reason of its last transition, since when, whether it is ready and whether it is in the active set, its source and gateway, and the statistics of the last rounds; for every uplink, whether it is drained. `--json` prints the API's answer. The command succeeds whenever it retrieved the status, also while the daemon is degraded: for monitoring, check the `status` field of `--json`, or the metric `polywan_status_degraded`.

### events

```text
$ polywan events
2026-10-06T06:58:40.016Z #1 daemon_started polywan 2.0.0 started
2026-10-06T09:41:55.230Z #2 path_state_changed uplink fwa5g ipv6: up -> down (probe_failed)
2026-10-06T09:41:55.231Z #3 active_set_changed ipv6 active set: [fiber, fwa5g] -> [fiber]
```

`polywan events` prints the history the daemon keeps (the last 1000 events at most) and exits. `--follow` keeps waiting for new events; across a restart of the daemon it waits for the daemon to come back, and then prints the new daemon's history from the start, after a notice. `--json` prints one JSON object per line: each event as the API returns it, and `{"notice": "reset", "instance": ...}` or `{"notice": "truncated", "instance": ...}` where the history restarted or lost events that were not yet read.

### drain and undrain

`polywan drain NAME` takes an uplink out of use for new connections (see [how it works](how-it-works.md#the-active-set)); `polywan undrain NAME` puts it back. Both return when the change is applied to the kernel. Draining the last usable uplink of a family is refused unless `--force` is given.

### reload

`polywan reload` asks the daemon to read and apply its configuration file again, and is what `systemctl reload polywan` runs; sending SIGHUP to the daemon does the same without waiting for the result. It succeeds only when the new configuration was applied. It fails, with exit status 1, when:

- the configuration is invalid: the daemon keeps the running configuration and the command prints the errors;
- a step of the application failed: the command prints the failed steps, and the daemon keeps retrying them;
- the application was not confirmed within 8 seconds: the daemon keeps applying it, and `polywan status` shows when the applied generation reaches the desired one;
- the connection closed before the answer, which happens when the reload changes the control socket itself: the outcome is unknown, and the `config_reloaded` or `reload_failed` event in `polywan events` tells which.

A failed reload never rolls back what was already applied. Structural settings and `state_dir` cannot change on reload.

### forget-uplink

A removed uplink keeps its id reserved, in the state directory, so that no other uplink can take the id while connections that carry it in their conntrack mark may still exist: until they end, their packets are rejected by PolyWAN's rules, never routed through another uplink. `polywan forget-uplink NAME` releases the reservation, once the uplink is no longer in the configuration. Before it, let those connections expire or delete them; with the default `fwmark_mask`, for the id 3:

```sh
conntrack -D --mark 0x00030000/0x00ff0000
```

While the daemon runs, the command goes through the control socket. When the socket is absent or refuses connections, it works offline: as root, with the configuration (`--config`) and the instance lock. A permission error or a broken answer from a running daemon is reported, never retried offline.

### notify-test

`polywan notify-test` asks the daemon to test every configured notification channel (email and each hook) inside its own sandbox, bypassing coalescing, rate limits and event filters, and prints each channel's outcome with its exit status and standard error. It fails if any channel fails or none is configured. Only one test runs at a time. `polywan notify-test --offline` runs the test locally as root, while the daemon is stopped, without the service's sandbox; it says so, because a test outside the sandbox does not prove that notifications work from the service. Email is described in [email](email.md).

## The HTTP API

The API is HTTP/1.1 with JSON bodies, on the Unix sockets above. With curl:

```sh
curl --unix-socket /run/polywan/status.sock http://localhost/v1/status
curl --unix-socket /run/polywan/api.sock -X POST -d '{"force": true}' http://localhost/v1/uplinks/fiber/drain
```

The host name in the URL is ignored. The API is versioned: everything under `/v1` stays backward compatible for all of PolyWAN 2.x. New fields may be added to responses, so clients should ignore fields they do not know.

| Method and path | Sockets | Does |
|---|---|---|
| `GET /v1/status` | both | the current status |
| `GET /v1/events` | both | the event history, optionally waiting for new events |
| `POST /v1/uplinks/NAME/drain` | control | drain an uplink |
| `POST /v1/uplinks/NAME/undrain` | control | undrain an uplink |
| `POST /v1/uplinks/NAME/forget` | control | release the id of a removed uplink |
| `POST /v1/reload` | control | reload the configuration |
| `POST /v1/notify-test` | control | test the notification channels |

Errors have a JSON body with an `error` message, and sometimes more fields described below. An unknown path, or a control path on the status socket, answers 404; a known path with another method, 405.

### Limits and overload

The daemon protects its routing from its clients; a client that exceeds a limit is cut off, never queued:

- Each listener (control socket, status socket, metrics) accepts at most 16 connections at once. Further connections wait in the kernel's listen backlog or are closed at once.
- Each connection carries one request; the daemon closes it after the response.
- A request has 10 seconds for its headers, body, handling and response; `GET /v1/events` may additionally wait up to 60 seconds for an event, and `POST /v1/notify-test` for the test's duration.
- Request headers and trailers are limited to 8 KiB and 64 fields each, bodies to 64 KiB (413 beyond).
- Commands (drain, undrain, forget, reload) run one at a time; when too many wait, the answer is 503 `too many commands in progress`.

Status and event requests are served from snapshots and never wait for the routing; a saturated status socket or metrics listener does not take capacity from the control socket.

### GET /v1/status

```json
{
  "version": "2.0.0",
  "instance": "6f1d0c2b9a8e4f3d2c1b0a9f8e7d6c5b",
  "started": "2026-10-06T06:58:39.871Z",
  "uptime_seconds": 11520,
  "config_digest": "9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab",
  "generation": { "desired": 14, "applied": 14 },
  "status": "ok",
  "reasons": [],
  "uplinks": [
    { "name": "fiber", "id": 1, "interface": "wan0", "drained": false }
  ],
  "paths": [
    {
      "uplink": "fiber",
      "family": "ipv4",
      "state": "up",
      "ready": true,
      "reason": "probes_recovered",
      "since": "2026-10-06T07:02:11.408Z",
      "source": "203.0.113.10",
      "gateway": "203.0.113.1",
      "addresses": ["203.0.113.10"],
      "statistics": { "samples": 48, "loss": 0.0, "rtt_seconds": 0.0081, "jitter_seconds": 0.0004 }
    }
  ],
  "active": { "ipv4": ["fiber"], "ipv6": [] }
}
```

| Field | Meaning |
|---|---|
| `version` | PolyWAN's version |
| `instance` | random identifier of this run of the daemon (32 hexadecimal digits); it changes at every start |
| `started`, `uptime_seconds` | when the daemon started (RFC 3339, UTC) and for how long it has run |
| `config_digest` | SHA-256 of the running configuration file, to tell whether a reload took effect; an identifier, not a secret |
| `generation.desired`, `generation.applied` | the generation of the desired state and the last one fully applied; they differ while changes are being applied or retried |
| `status` | `ok` or `degraded` |
| `reasons` | why the status is `degraded`, see below; empty when `ok` |
| `uplinks[]` | every configured uplink: `name`, `id`, `interface`, `drained` |
| `paths[]` | every configured path, see below |
| `active` | for each managed family (`ipv4`, `ipv6`), the names of the uplinks in its active set |

Degradation reasons:

| Reason | Meaning |
|---|---|
| `apply_failed` | a kernel, sysctl or nftables operation failed and is being retried; the log and the `apply_failed` events say which |
| `ownership_conflict` | another program keeps removing PolyWAN's rules, routes or nftables table; repairs happen only at full reconciliations |
| `flow_offload` | a flowtable covers a configured uplink or downlink (see [how it works](how-it-works.md#living-with-your-own-ruleset)) |
| `external_ruleset_missing` | in external firewall mode, the table exported by `polywan export-nft` is not loaded |

Path fields:

| Field | Meaning |
|---|---|
| `uplink`, `family` | the uplink's name and `ipv4` or `ipv6` |
| `state` | `up` or `down` |
| `ready` | whether the interface, a source address and a next hop are usable and the routes installed |
| `reason` | the reason of the last transition, see below |
| `since` | when the path entered its state (RFC 3339, UTC) |
| `source` | the source address used for probes and NAT; absent when there is none |
| `gateway` | the next hop; absent when there is none, and on IPv4 point-to-point links, which need none |
| `addresses` | the uplink's addresses of the family that have `from` rules |
| `statistics` | over the samples of the last `quality_window` rounds: `samples`, `loss` (0 to 1), `rtt_seconds` (median), `jitter_seconds` (median difference between consecutive round-trip times); `null` when there are too few samples to compute it |

Transition reasons:

| Reason | Meaning |
|---|---|
| `startup` | initial state at a cold start |
| `probe_failed` | `fall` rounds in a row did not reach `required_reachable` targets |
| `degraded` | rounds reached the targets but violated a quality gate |
| `probes_recovered` | `rise` rounds in a row passed |
| `carrier_lost` | the interface lost carrier or went down |
| `interface_removed` | the interface disappeared |
| `address_lost` | the path has no usable source address |
| `address_conflict` | an address belongs to two uplinks of the same family |
| `gateway_lost` | the path has no usable next hop |
| `route_install_failed` | the kernel refused the path's routes or its interface settings; retried |

### GET /v1/events

Query parameters, all optional:

| Parameter | Meaning |
|---|---|
| `instance` | the `instance` of the previous response |
| `after` | the sequence number of the last event already read; only later events are returned |
| `limit` | at most this many events (1 to 1000, default 1000) |
| `wait` | if no event is newer than `after`, wait up to this many seconds (at most 60) for one |

```json
{
  "instance": "6f1d0c2b9a8e4f3d2c1b0a9f8e7d6c5b",
  "reset": false,
  "truncated": false,
  "events": [
    {
      "seq": 2,
      "instance": "6f1d0c2b9a8e4f3d2c1b0a9f8e7d6c5b",
      "timestamp": "2026-10-06T09:41:55.230Z",
      "type": "path_state_changed",
      "uplink": "fwa5g",
      "family": "ipv6",
      "old": "up",
      "new": "down",
      "reason": "probe_failed",
      "message": "uplink fwa5g ipv6: up -> down (probe_failed)"
    }
  ]
}
```

The daemon keeps the last 1000 events, or fewer when they exceed 4 MiB, in memory; they are lost at restart. A response holds at most 1000 events and 4 MiB. To follow the events, repeat the request with the `instance` and the last `seq` received, and `wait=60`:

- `reset` is true when `instance` names another run of the daemon (it restarted) or `after` is beyond the last event: the response then starts from the oldest event kept.
- `truncated` is true when events after `after` were evicted before they could be read.

Event fields: `seq` (increasing within a run), `instance`, `timestamp` (RFC 3339, UTC), `type`, `message` (human-readable), and, where they apply, `uplink`, `family`, `old`, `new` and `reason`:

| Type | Fields | When |
|---|---|---|
| `daemon_started` | | the daemon started |
| `daemon_stopping` | | the daemon is stopping |
| `config_reloaded` | | a new configuration was accepted |
| `reload_failed` | | a reload was rejected; the running configuration is kept, the errors are in the log |
| `path_state_changed` | `uplink`, `family`, `old`, `new` (`up`, `down`), `reason` | a path's health changed |
| `path_address_changed` | `uplink`, `family`, `old`, `new` (addresses or `null`) | a path's source address changed |
| `path_gateway_changed` | `uplink`, `family`, `old`, `new` (addresses or `null`) | a path's next hop changed |
| `active_set_changed` | `family`, `old`, `new` (lists of uplink names) | a family's active set changed |
| `uplink_drained`, `uplink_undrained` | `uplink` | an uplink was drained or undrained |
| `artifact_repaired` | `reason` (`rules`, `routes`, `nftables`) | PolyWAN restored objects that another program removed |
| `apply_failed` | `reason` (`route`, `rule`, `nftables`, `sysctl`) | an operation failed; the message names it, with the errno and the kernel's message |
| `status_degraded` | `old`, `new`, `reason` | the overall status became `degraded`, for the reason given |
| `status_recovered` | `old`, `new`, `reason` | the overall status became `ok` again, the last reason cleared |

Hooks receive the same JSON on standard input. A notification test sends hooks a synthetic event of type `notify_test` with `"test": true`, which does not appear in the history.

### POST endpoints

Only the drain endpoint takes a body, `{"force": true}` to drain the last candidate of a family; the others take none (400 otherwise). Uplink names are the configured `name`s.

| Answer | Body | When |
|---|---|---|
| 200 | drain, undrain: `{"uplink": NAME, "drained": BOOL, "generation": N}`; reload: `{"reloaded": true, "generation": N}`; forget: `{"uplink": NAME, "id": ID}` | done and applied in generation `N` |
| 202 | `{"error": ..., "generation": N}` | accepted but not applied within 8 seconds; PolyWAN keeps applying it |
| 400 | `{"error": ...}` | a malformed body or query |
| 404 | `{"error": ...}` | no configured uplink has that name |
| 409 | `{"error": ...}` | drain of the last candidate without `force`; forget of an uplink still configured, or not known |
| 413 | `{"error": ...}` | the body exceeds 64 KiB |
| 422 | `{"error": ..., "errors": [...]}` | reload: the configuration is invalid; the running one is kept |
| 500 | `{"error": ..., "failed_steps": [{"operation", "kind", "errno"}]}` | a step failed while applying; PolyWAN keeps retrying it |
| 503 | `{"error": ...}` | too many commands waiting, the state directory busy, or the daemon stopping |
| 504 | `{"error": ...}` | no answer in time; the command may still complete |

`POST /v1/notify-test` answers 200 with `{"channels": [...]}`, one report per channel: `channel` (`email` or `hook`), `program` (a hook's executable), `outcome` (`succeeded`, `failed`, `timed_out`, `not_started`), `exit_status` and `signal` where available, `error` (a failure around the process, for example an untrusted executable), `stderr` (at most 64 KiB) and `stderr_truncated`. It answers 429 while another test runs, and 503 when the email notifier cannot admit a test at that moment. A client that disconnects does not cancel the test, and never causes a second one.

## Metrics

With `metrics.listen` set, `GET /metrics` serves, in the Prometheus text format:

| Metric | Labels | Meaning |
|---|---|---|
| `polywan_build_info` | `version` | always 1 |
| `polywan_status_degraded` | | 1 while the status is `degraded` |
| `polywan_path_up` | `uplink`, `family` | 1 while the path is `up` |
| `polywan_path_ready` | `uplink`, `family` | 1 while the path is ready |
| `polywan_path_active` | `uplink`, `family` | 1 while the path is in the active set |
| `polywan_uplink_drained` | `uplink` | 1 while the uplink is drained |
| `polywan_path_rtt_seconds` | `uplink`, `family` | median round-trip time of the window, when available |
| `polywan_path_jitter_seconds` | `uplink`, `family` | jitter of the window, when available |
| `polywan_path_loss_ratio` | `uplink`, `family` | loss ratio of the window, when available |
| `polywan_path_transitions_total` | `uplink`, `family`, `to` | health transitions |
| `polywan_probe_samples_total` | `uplink`, `family`, `target`, `result` (`ok`, `lost`) | probe samples |
| `polywan_artifact_repairs_total` | `kind` | repairs of objects removed by other programs |
| `polywan_apply_failures_total` | `kind` | failed operations |
| `polywan_events_dropped_total` | `notifier` (`email`, `hooks`) | events a full notifier queue had to drop |
| `polywan_notifications_failed_total` | `channel` (`email`, `hook`) | failed notification attempts, each retry included, tests excluded |

## Users and groups

PolyWAN looks up three kinds of accounts by name: `api.group` (default `polywan`), `api.status_group` (when set) and `notify.hook_user` (default `nobody`, the user hooks run as; it must not have UID 0, nor GID 0 as its primary group). They are looked up at startup and at every reload, outside the routing. An account that does not exist refuses startup with exit status 78, or rejects the reload.

Define these accounts **locally**, in `/etc/passwd` and `/etc/group`. The release binaries are statically linked with musl, which does not load NSS modules: accounts of LDAP, SSSD, NIS or systemd-userdb (including `DynamicUser=` users) are not visible to PolyWAN unless the local name service cache daemon (nscd) provides them, and that is not supported. The package creates the `polywan` group with `systemd-sysusers`; to give someone control, add them to it (`usermod -a -G polywan NAME`) and have them log in again.
