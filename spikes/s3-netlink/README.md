# S3 — Rust netlink

Spike S3 of SPEC.md §15: create, dump, replace and delete the rules and inline multipath routes that FTR needs, receive notifications, and find out how errors, interrupted dumps and receive-buffer overruns surface, using the current Rust netlink crates. Result: **the crates are usable for 2.0, with a thin local layer and one socket-usage rule (subscribe-only observer socket); nothing requires `unsafe` or a raw netlink implementation.**

## Environment

| | minimum | latest |
|---|---|---|
| Distribution | Debian 12 | Debian 13 with trixie-backports |
| Kernel | 6.1.0-53 | 7.1.13 |
| iproute2 | 6.1.0 | 6.15.0 |

Crates (crates.io, October 2026): `rtnetlink` 0.23.0, `netlink-packet-route` 0.33.0, `netlink-packet-core` 0.9.0, `netlink-proto` 0.13.0, `netlink-sys` 0.9.0, `tokio` 1.53.2. Rust 1.99.0, edition 2024, `#![forbid(unsafe_code)]`. The binary is built once as a static musl executable (3.2 MB, release) and run unchanged on both kernels.

## How to reproduce

```
cargo build --release --target x86_64-unknown-linux-musl
sudo ./run.sh target/x86_64-unknown-linux-musl/release/s3-netlink all
sudo ./run.sh target/x86_64-unknown-linux-musl/release/s3-netlink install   # leaves the layout in place and prints `ip rule` / `ip route`
```

`run.sh` creates the namespace `s3-a` with two dummy uplinks (`d1`, `d2`, IPv4 and IPv6), an IPv4 point-to-point `ipip` link (`p0`), a GRE point-to-point link with an IPv6 link-local address (`g6`), a veth pair (`v1`/`v1p`) to cause carrier loss, operating-system default routes in main (`proto dhcp`, `proto ra`), and a default route that references a nexthop object in table 3005. Individual groups: `rules`, `routes`, `extack`, `notify`, `inspect`, `implicit`, `dumpintr`, `enobufs`. Full outputs: [`results/linux-6.1.txt`](results/linux-6.1.txt), [`results/linux-7.1.txt`](results/linux-7.1.txt). Both kernels gave the same results in every group (33 PASS; the single FAIL is the deliberate demonstration of the `netlink-proto` sequence-number collision described below).

The program builds every message itself (`RuleMessage`, `RouteMessage` from `netlink-packet-route`) and sends it through `rtnetlink::Handle::request` with explicit flags, which is the approach recommended below; the `rtnetlink` builders are exercised only to document their pitfalls.

## Results

### Rules (FR-ROUTE-3)

The complete FR-ROUTE-3 layout for two uplinks (23 rules per family: probe rules, probe guard, main bypass with `suppress_prefixlength 0`, path rules, the six path-guard rules, policy rules and guard, `from` rules with zero-field selector and source guards, balancing rule, final guard) is created with `NLM_F_CREATE | NLM_F_EXCL`, all tagged with protocol 249, tables above 255 through `FRA_TABLE`, for both families. `ip rule` shows exactly the intended layout:

```
1064:	from all fwmark 0x400000/0xc00000 unreachable proto 249
1100:	from all lookup main suppress_prefixlength 0 proto 249
1264:	from all fwmark 0x10000/0xc10000 unreachable proto 249
...
1264:	from all fwmark 0x200000/0xe00000 unreachable proto 249
1501:	from 192.0.2.2 fwmark 0/0xff0000 lookup 1001 proto 249
1564:	from 192.0.2.2 fwmark 0/0xff0000 unreachable proto 249
1600:	from all lookup 1000 proto 249
1699:	from all unreachable proto 249
```

Observations, identical on both kernels:

- Dumps return all 23 rules per family and `netlink-packet-route` parses every attribute FTR uses (`Priority`, `FwMark`, `FwMask`, `Table`, `Source`, `Protocol`, `SuppressPrefixLen`, action `Unreachable`).
- Normalisation needed when comparing dumps with the desired state: the kernel always dumps `FRA_SUPPRESS_PREFIXLEN` (`0xffffffff` when unset); a zero-field selector (`fwmark 0/0xff0000`) is dumped with `FRA_FWMASK` only, without `FRA_FWMARK`; unreachable rules are dumped with `FRA_TABLE 0`.
- A duplicate add with `NLM_F_EXCL` fails with `EEXIST`. The protocol is part of the rule identity: the same rule with protocol `static` is accepted as a second rule.
- **There is no rule replace**: `NLM_F_CREATE | NLM_F_REPLACE` on an existing rule succeeds and adds a duplicate (23 → 24 rules). This is what `rtnetlink::RuleAddRequest::replace()` sends.
- Delete by a constructed key (not the dumped message) works, including picking one of the six path-guard rules that share priority B + 264 by mark and mask; deleting again gives `ENOENT`. Deleting every rule from its own dump message works.

### Routes (FR-ROUTE-2, FR-ROUTE-3, FR-DISC-3)

All of the following succeed on both kernels with `RTA_TABLE` ≥ 256, metric 100 and protocol 249:

- IPv4 inline multipath with two gateways and a device-only point-to-point member, weights 10/3/1 (`hops = weight − 1`, so 1–256 maps to 0–255); replace multipath → single nexthop (`RTA_GATEWAY` + `RTA_OIF`) → multipath with weights 1/256, each with `NLM_F_CREATE | NLM_F_REPLACE`.
- IPv4 path routes `via GW dev d1 src ADDR` and point-to-point `dev p0 src ADDR`.
- `onlink`: an off-subnet gateway is rejected without it (`ENETUNREACH`, extack "Nexthop has invalid gateway") and accepted with the route flag; an `onlink` member inside a multipath route (nexthop flag) is accepted and dumped with the flag.
- IPv6 multipath with the same gateway `fe80::1` on two interfaces, weights 10/3, dumped as one message with `RTA_MULTIPATH`; replace with three members including the GRE point-to-point link via `fe80::1`; replace three members → single point-to-point member; a single-member `RTA_MULTIPATH` replacing a single route is accepted and stored as a plain single-nexthop route.
- An IPv6 device-only multipath member is rejected: `EINVAL`, extack "Device only routes can not be added for IPv6 using the multipath API." (confirms Q12 on both kernels).
- Delete by exact key (family, table, destination default, metric 100, protocol 249 or unspec, no nexthops) removes the whole multipath route in both families. A different metric, or protocol `static`, gives `ESRCH`.
- A strict-checked dump (`NETLINK_GET_STRICT_CHK`) with `RTA_TABLE` and the protocol in the header returns only the matching route and sets `NLM_F_DUMP_FILTERED`; filtering by protocol alone returns all FTR routes across tables.
- A default route that references a nexthop object is dumped with `RTA_NH_ID` **and** the resolved `RTA_GATEWAY` / `RTA_OIF` (`metric 50 nhid 7 via 192.0.2.1 oif 6`): discovery must test for `NhId` before treating a route as an inline nexthop.
- IPv6 default routes carry `RTA_PREF` (parsed as `RoutePreference`); links expose `IFF_POINTOPOINT`, `IFF_LOWER_UP` and `IFLA_CARRIER`; addresses expose the 32-bit `IFA_FLAGS` (`Permanent`, `Nodad`, `Deprecated`, `Tentative`, `Dadfailed`, …). The crate has no separate name for the IPv6 temporary flag: it is bit 0x01, parsed as `Secondary`.

### Errors and extended acknowledgement (PLAT-1)

The errno is always available (`ErrorMessage::code`). The extended acknowledgement message is sent only when the socket has `NETLINK_EXT_ACK` enabled (`netlink_sys::Socket::set_ext_ack`), on both kernels, with or without `NETLINK_CAP_ACK`. No crate parses it: `ErrorMessage::header` holds the raw payload after the error code (the echoed request, or only its 16-byte header with `CAP_ACK`, followed by the TLVs), and `parse_extack` in `src/main.rs` extracts `NLMSGERR_ATTR_MSG` in 25 lines of safe code.

```
EXT_ACK=false: off-subnet gateway: errno 101 (Network unreachable), no extack
EXT_ACK=true:  off-subnet gateway: errno 101 (Network unreachable), extack "Nexthop has invalid gateway"
               delete missing v6 route: errno 3 (No such process), extack "FIB table does not exist"
               duplicate rule: errno 17 (File exists), no extack
```

Many errors (`EEXIST`, `ENOENT`, most `ESRCH`) carry no message, so reports must show "no extended acknowledgement" rather than an empty string.

### Notifications

A socket subscribed to the link, IPv4/IPv6 address, IPv4/IPv6 route and IPv4/IPv6 rule groups (`rtnetlink::new_multicast_connection`) receives every rule and route change made by another socket, and link and address changes made by `ip`. Each notification carries the sequence number and port id of the request that caused it; changes made by the kernel itself carry port id 0 and sequence 0. IPv6 multipath add and replace produce a single notification with the full `RTA_MULTIPATH` (flags `NLM_F_CREATE` and `NLM_F_REPLACE` respectively) on both kernels.

**`netlink-proto` collision (both kernels).** `netlink-proto` matches incoming messages to pending requests by sequence number and source port only (the source is always the kernel, port 0); it ignores the destination port id in the header. Consequences on a socket that is both subscribed and used for requests:

- the notification of a change made through that same socket is consumed as a reply to the request and never reaches the notification stream;
- a notification caused by *another* socket whose request has the same sequence number (every new `netlink-proto` socket starts at 1) is taken as a reply to a pending request. In the test, an observer dumping 20 000 routes with its first request while other sockets add routes with their first requests: the dump stream ended after 1 message (the foreign notification), and the remaining 20 319 dump replies arrived on the notification stream.

This is reproducible by construction, not a timing accident. Mitigation without upstream changes: the subscribed socket never sends requests; dumps and mutations use separate, unsubscribed sockets (an unsubscribed socket only receives replies to its own requests).

### Overruns and interrupted dumps (§12.2 Observer)

- `ENOBUFS` on the subscribed socket surfaces as one `NetlinkPayload::Overrun` message on the notification stream (2000 route additions into a 4 KiB receive buffer: 9–11 messages delivered, 1 overrun marker), and the stream keeps working afterwards. This is the trigger for the full resynchronisation of §12.2. (`netlink-proto` has an `unimplemented!()` for an overrun matched to a pending request; with a subscribe-only socket there are no pending requests, so it is unreachable.)
- `NLM_F_DUMP_INTR` is visible only through `Handle::request`: the `rtnetlink` `get()` streams return the inner messages without the header. `NLMSG_DONE` is dropped by `netlink-proto` unless `Connection::set_forward_done(true)`.
- Under continuous churn (address, route and link add/delete loops), the flag appeared on data messages of 25–40 of 40 address dumps (4000 addresses, multi-part), never on `NLMSG_DONE`, and never on IPv4 route dumps (20 000 routes), IPv6 route dumps, rule dumps or link dumps. Retrying an address dump until it is not interrupted can therefore take many attempts while something churns addresses; retries need a bound. For routes and rules the flag gives no signal at all, so the observer cannot rely on it: consistency comes from subscribing before dumping, buffering the notifications received meanwhile and applying them in order after the dump, plus the periodic full reconciliation of FR-REC-6.

### Kernel-initiated changes without notifications (FR-COEX-3, FR-DISC-3, FR-DISC-5)

With FTR-like routes installed (IPv4 and IPv6 path route via the veth `v1`, and a two-member multipath over `d1` and `v1`), identical on both kernels:

| Event | Notifications for proto-249 routes | State after the event |
|---|---|---|
| Carrier loss on `v1` | none | routes kept, route flag or member flag `Linkdown` set |
| Carrier back | none | flags cleared |
| Admin down `v1` | IPv6 path route `DelRoute` only | IPv4 path route **deleted silently**; IPv6 path route deleted; multipath members `Dead | Linkdown` in both families |
| Admin up `v1` | none | member flags cleared; deleted path routes not restored |
| IPv4 address of `v1` removed | none | IPv4 route with that `src` **deleted silently**; IPv4 multipath member whose gateway lost its connected route marked `Dead` |
| IPv6 link-local of `v1` removed | none | IPv6 routes kept |

So the observer cannot learn every kernel-initiated removal or nexthop-flag change from route notifications; it has to re-read the affected tables after link and address events of uplink interfaces.

## Documentation cross-check (Context7)

The crate documentation indexed by Context7 (docs.rs for `rtnetlink`, the `netlink-packet-route` repository docs) was checked against the experiments after the fact:

- `RouteMessageBuilder` defaults (table main, protocol `static`, scope universe, type `unicast`, settings ignored by dumps unless `NETLINK_GET_STRICT_CHK` is enabled) are documented and match the observed `ESRCH` and empty filtered dumps.
- `RuleAddRequest` documents `fw_mark` but no mask setter, as found.
- `RuleAddRequest::replace()` is documented as "Replace existing matching rule"; the experiment shows that the kernel has no replace operation for rules and that the request adds a duplicate. The experiment is authoritative; the documentation is misleading and worth an upstream fix.
- `netlink-proto` is not indexed by Context7; the sequence-number collision is established by experiment and by reading the crate source.

## Conclusions

1. `netlink-packet-route` 0.33 covers every message, attribute and flag FTR needs for rules, routes, links and addresses (both families, tables above 255, `RTA_MULTIPATH` with weights and nexthop flags, `RTA_PREF`, `RTA_NH_ID`, `FRA_PROTOCOL`, `FRA_SUPPRESS_PREFIXLEN`, `FRA_FWMASK`, rule action `unreachable`). No upstream contribution is required to implement 2.0.
2. `netlink-proto` 0.13 + `netlink-sys` 0.9 (tokio) are a sound transport, provided the observer's subscribed socket never sends requests. Socket options FTR needs (`set_ext_ack`, `set_cap_ack`, `set_netlink_get_strict_chk`, `set_rx_buf_sz`, group membership) are exposed safely through `Connection::socket_mut()`.
3. The `rtnetlink` 0.23 request builders should not be used for FTR's artifacts: `RuleAddRequest::replace()` creates duplicate rules; `RuleAddRequest` puts table main in the header even for `unreachable` and has no setter for `FRA_FWMASK`; `RouteMessageBuilder` defaults to protocol `static` and type `unicast`, so used as a dump filter on a strict socket it returns nothing for FTR's tables and used as a delete key it fails with `ESRCH`; the `get()` streams hide the header flags (`NLM_F_DUMP_INTR`, `NLM_F_DUMP_FILTERED`). Using `rtnetlink` only for `new_connection` / `new_multicast_connection` and `Handle::request` is fine, and depending on `netlink-proto` directly is equally simple.
4. Bounded local implementation in FTR (safe Rust, estimated 400–600 lines): a request wrapper with explicit flags that returns errno plus parsed extack; construction and normalisation of rule and route messages (including the dump quirks listed above, and treating a single-nexthop route as equal to a one-member multipath route); the observer with a subscribe-only socket, separate dump and mutation sockets, notification buffering during dumps, bounded `NLM_F_DUMP_INTR` retries, resynchronisation on `Overrun`, and re-reads after uplink link/address events.
5. Upstream contributions worth offering, none blocking: in `netlink-proto`, match replies only when the header port id equals the socket's own port id (fixes the collision); parse extended-ack TLVs in `netlink-packet-core::ErrorMessage`; replace the `unimplemented!()` for overruns; in `rtnetlink`, document or remove `RuleAddRequest::replace()` and make the route-builder defaults explicit for dump and delete.

## IMPL-2 recommendation

Keep `tokio`, `netlink-packet-route` (0.33) and `netlink-proto` / `netlink-sys` (0.13 / 0.9, feature `tokio_socket`) as the netlink stack. Make `rtnetlink` optional (connection helpers only) or drop it. Pin exact versions: these crates are pre-1.0 and change APIs between minor versions.

## Proposed SPEC amendments

- **IMPL-2**: replace "`rtnetlink` / `netlink-packet-route`" with "`netlink-packet-route` for message types and `netlink-proto` / `netlink-sys` for transport (`rtnetlink` at most for connection setup); FTR builds its own rule and route messages".
- **§12.2 Observer**: add "the socket subscribed to notifications never sends requests; dumps run on a separate socket while notifications received meanwhile are buffered and applied in order after the dump"; "`NLM_F_DUMP_INTR` is honoured where the kernel sets it (address dumps) with a bounded number of retries, after which the dump is used and a full resynchronisation is scheduled; route and rule dumps do not report interruption"; "because the kernel does not notify every removal (IPv4 routes deleted on administrative down or on removal of their source address) nor nexthop flag changes (`linkdown`, `dead`), the observer re-reads FTR's tables and the discovery tables after every link or address event of an uplink interface".
- **FR-COEX-3**: classify route and rule removals by the notification's port id: 0 is the kernel (expected, not counted), FTR's own mutation socket is FTR, any other port id is a third party (counted by FR-COEX-4). Removals found only by a re-read after a link or address event are kernel-initiated.
- **FR-DISC-3**: state that routes with `RTA_NH_ID` are recognised by that attribute even though the kernel also dumps the resolved gateway and interface; and that `dead` / `linkdown` member flags change without notification, so readiness is re-evaluated from a re-read after link events (FR-DISC-5).
- **FR-REC-6** (or a new IMPL item): rules are created with `NLM_F_CREATE | NLM_F_EXCL` and never with `NLM_F_REPLACE` (which adds a duplicate); comparison of dumped rules normalises `FRA_SUPPRESS_PREFIXLEN = 0xffffffff`, absent `FRA_FWMARK` for zero marks and `FRA_TABLE 0` on `unreachable` rules; rule identity includes the protocol; a single-nexthop route equals a one-member multipath route.
- **PLAT-1**: "netlink sockets enable `NETLINK_EXT_ACK`; when the kernel provides no message, the report says so".
