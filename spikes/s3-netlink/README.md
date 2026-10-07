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

`run.sh` creates the namespace `s3-a` with two dummy uplinks (`d1`, `d2`, IPv4 and IPv6), an IPv4 point-to-point `ipip` link (`p0`), a GRE point-to-point link with an IPv6 link-local address (`g6`), a veth pair (`v1`/`v1p`) to cause carrier loss, operating-system default routes in main (`proto dhcp`, `proto ra`), and a default route that references a nexthop object in table 3005. Individual groups: `rules`, `routes`, `extack`, `notify`, `inspect`, `implicit`, `dumpintr`, `enobufs`, `dumpskip` (about 2 minutes; `S3_DUMPSKIP_CASES=name,...` limits it to some cases). Full outputs: [`results/linux-6.1.txt`](results/linux-6.1.txt), [`results/linux-7.1.txt`](results/linux-7.1.txt). Both kernels gave the same results in every group (33 PASS; the single FAIL is the deliberate demonstration of the `netlink-proto` sequence-number collision described below). The `dumpskip` group, added later to close the interrupted-dump question, prints only `INFO` lines; its output is appended at the end of each results file.

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
- Under continuous churn (address, route and link add/delete loops), the flag appeared on data messages of 25–40 of 40 address dumps (4000 addresses, multi-part), never on `NLMSG_DONE`, and never on IPv4 route dumps (20 000 routes), IPv6 route dumps, rule dumps or link dumps. Retrying an address dump until it is not interrupted can therefore take many attempts while something churns addresses; retries need a bound. For routes and rules the flag gives no signal at all, so the observer cannot rely on it: consistency comes from subscribing before dumping, buffering the notifications received meanwhile and applying them in order after the dump, plus the periodic full reconciliation of FR-REC-6. The `dumpskip` group below shows that this matters: route and rule dumps really do lose and repeat entries without any flag.

### Silent skips and duplicates in interrupted dumps (`dumpskip`)

Follow-up question: can a dump interrupted by concurrent changes omit an entry that existed unchanged during the whole dump (silent skip), or return an entry twice, and does `NLM_F_DUMP_INTR` say so? Answer: **yes for rules, IPv4 routes within one trie leaf (routes with the same prefix, such as default routes with different metrics), IPv6 routes, addresses and, on 6.1 only, links; not for nexthop objects, IPv4 routes in different leaves or links on 7.1. Rule and route dumps never set `NLM_F_DUMP_INTR`; address dumps set it in almost every affected dump but not in all, on both kernels; link and nexthop dumps set it.**

**Method.** Each dump runs on a blocking `netlink_sys::Socket` (safe API), so that every datagram, which is one kernel batch, is visible, and the read size is controlled: the kernel sizes each batch from the largest read seen on the socket, capped at 32 KiB minus overhead, with a first batch of about 3.7 KiB on a fresh socket. Two read sizes: 4 KiB (batches of about 4 KiB, like the first batch of any socket) and 64 KiB (what `netlink-proto` uses: batches of up to about 32 KiB). For each case a set of stable entries is created and a reference dump taken; every reference entry then exists unchanged during each later dump, so it must appear exactly once. Churn entries are placed before the dump's resume point (lower rule priority, lower key, lower metric in the same leaf or node, head of the interface's address list, lower nexthop id). Two experiments per case: one change injected after the first batch is read (the kernel builds batch 2 during that read, so the change acts on the resume of batch 3), and 300–1000 dumps (100 for links, 50 for the IPv6 node case) while another process loops `ip -force -batch` adding and deleting the churn entries. Cases: 1000 rules per family; the FR-ROUTE-3 layout of 3 uplinks plus 5 foreign rules and the kernel's rules (FTR size); 10 000 IPv4 /32 routes in one table; 1500 IPv4 default routes with different metrics in one table (one trie leaf); 200 tables with one default route each plus 3 default routes in main (FTR size, both families); 10 000 IPv6 /128 routes; 600 IPv6 default routes with different metrics (one fib6 node); 2000 IPv4 and 1000 IPv6 addresses on one interface; 200 dummy links; 2000 nexthop objects.

**Injected change** (identical on both kernels; one change after batch 1):

| Case | Delete an entry before the resume point | Add an entry before the resume point | `NLM_F_DUMP_INTR` |
|---|---|---|---|
| Rules, IPv4 and IPv6 | 1 stable rule missing | 1 stable rule twice | not set |
| IPv4 routes, different keys | nothing | nothing | not set |
| IPv4 routes, one leaf (default routes, metrics) | 1 stable route missing | 1 stable route twice | not set |
| IPv6 routes, different prefixes | nothing | 1 stable route twice | not set |
| IPv6 routes, delete before and then add after the resume point | 1 stable route missing | | not set |
| IPv6 routes, one node (default routes, metrics) | nothing | 57 stable routes twice (the node restarts) | not set |
| Addresses, IPv4 and IPv6 | 1 stable address missing | 1 stable address twice | set |
| Nexthop objects | nothing | nothing | set |

**Concurrent churn** (dumps with at least one stable entry missing / with a stable entry returned twice / with either anomaly and no `NLM_F_DUMP_INTR`, for 4 KiB reads; 64 KiB reads):

| Case (dumps) | 6.1, 4 KiB | 6.1, 64 KiB | 7.1, 4 KiB | 7.1, 64 KiB | `NLM_F_DUMP_INTR` |
|---|---|---|---|---|---|
| Rules IPv4, 1000 rules (300) | 286 / 289 / 289 | 73 / 99 / 140 | 87 / 90 / 97 | 33 / 27 / 45 | never |
| Rules IPv6, 1000 rules (300) | 273 / 276 / 278 | 109 / 173 / 217 | 275 / 276 / 281 | 58 / 62 / 100 | never |
| Rules IPv4, FTR size (1000) | 0 / 5 / 5 | 0 / 16 / 16 | 0 / 0 / 0 | 0 / 0 / 0 | never |
| Rules IPv6, FTR size (1000) | 0 / 1 / 1 | 0 / 6 / 6 | 0 / 0 / 0 | 0 / 0 / 0 | never |
| IPv4 routes, 10 000 keys (300) | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | never |
| IPv4 routes, one leaf (300) | 296 / 296 / 296 | 71 / 80 / 131 | 190 / 193 / 196 | 32 / 33 / 45 | never |
| IPv4 routes, FTR size (1000) | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | never |
| IPv6 routes, 10 000 prefixes (300) | 300 / 300 / 300 | 288 / 289 / 289 | 300 / 300 / 300 | 265 / 268 / 270 | never |
| IPv6 routes, one node (50) | 0 / 32 / 32 | 0 / 20 / 20 | 0 / 38 / 38 | 0 / 27 / 27 | never |
| IPv6 routes, FTR size (1000) | 11 / 72 / 83 | 0 / 0 / 0 | 2 / 55 / 57 | 0 / 0 / 0 | never |
| IPv4 addresses (1000) | 955 / 967 / 0 | 711 / 794 / 0 | 984 / 989 / 2 | 699 / 684 / 3 | 986–997 dumps |
| IPv6 addresses (1000) | 594 / 620 / 0 | 536 / 581 / 1 | 636 / 622 / 3 | 182 / 160 / 10 | 892–968 dumps |
| Links, 200 dummies (100) | 0 / 0 / 0 | 1 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 76–99 dumps |
| Nexthop objects (300) | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 86–167 dumps |

In the IPv6 FTR-size case the entries that disappeared were always the two default routes of main with the higher metrics (1025 and 1026), together, while the one with the lowest metric was returned: exactly the routes discovery relies on (FR-DISC-3). Under churn up to 38 stable entries were missing from one dump (IPv6, 4 KiB reads). An IPv6 dump of one large node can restart over and over: with 4 KiB reads the recorded runs averaged 35–46 batches instead of 20, and in an earlier run on 7.1 the average was 983 batches and 7 of 50 dumps had not completed after 5000 batches. Repeated runs of the address cases (three runs of 1000 dumps per read size and kernel) gave anomalous dumps without the flag in every run on 7.1 (0–10 per 1000, both families) and on 6.1 only for IPv6 with 64 KiB reads (2 in 3000), never for IPv4 on 6.1.

**Mechanism** (kernel source of v6.1 and v7.1.13, read from git.kernel.org; the experiment confirms each point that it exercises):

- Batches. `netlink_dump()` (`net/netlink/af_netlink.c`) fills one skb per call: `max(min_dump_alloc, NLMSG_GOODSIZE)` (3.7 KiB with 4 KiB pages) or, when larger, the largest read length seen on the socket, capped at `SKB_WITH_OVERHEAD(32768)` and attempted with `__GFP_NORETRY`, falling back to the small size under memory pressure. The first batch is built by the request itself (before any read, so it is small on a fresh socket); each following batch is built inside `netlink_recvmsg()` after the previous one is read. Between two batches the dump keeps only a few integers in `cb->args`/`cb->ctx`; the dump function resumes from them. In 6.1 every rtnetlink dump runs under RTNL, so a batch is atomic with respect to changes made under RTNL; in 7.1 rule, route and address dumps are `RTNL_FLAG_DUMP_UNLOCKED` (RCU only), link and nexthop dumps still take RTNL.
- `NLM_F_DUMP_INTR` is set only by `nl_dump_check_consistent()` (`include/net/netlink.h`) when `cb->seq` changed between batches. Its callers are the address dumps (`net/ipv4/devinet.c`, `net/ipv6/addrconf.c`), the link dump (`net/core/rtnetlink.c`), the nexthop dump (`net/ipv4/nexthop.c`) and `netlink_dump_done()`. There is no caller in `net/core/fib_rules.c`, `net/ipv4/fib_frontend.c`, `net/ipv4/fib_trie.c`, `net/ipv6/ip6_fib.c` or `net/ipv6/route.c`, in both versions: route and rule dumps cannot report interruption.
- Rules: `dump_rules()` resumes by position in `ops->rules_list` (`if (idx < cb->args[1]) goto skip`), identical in 6.1 and 7.1. Deleting a rule before the resume point skips the next rule; adding one returns the last rule again. In 6.1 `fib_nl_dumprule()` returns `skb->len` for a family-specific dump even when the list is finished, so the kernel calls it once more and sends `NLMSG_DONE` in a second batch; that call resumes by index too, which is why even a one-batch FTR-size rule dump returned the last rule (`32767 lookup default`, `32766 lookup main`) twice when a rule was added in between. In 7.1 it returns `dump_rules()`'s result and the dump ends in one batch.
- IPv4 routes: `inet_dump_fib()` resumes tables by hash bucket and position in the bucket (`cb->args[0..1]`), `fib_table_dump()` by trie key (`cb->args[3]`, robust), and `fn_trie_dump_leaf()` by alias position inside the leaf (`cb->args[4]`). All routes with the same key share a leaf: the default routes of a table (0.0.0.0/0 with different metrics, sorted by metric) are aliases of leaf 0. A skip or duplicate needs a batch boundary inside a leaf and a change of an earlier alias of that leaf. A table created at the head of its hash bucket while the dump is in that bucket shifts the position and causes duplicates (source only; FTR creates tables only when uplinks are added). Identical in both versions.
- IPv6 routes: `fib6_dump_table()` (`net/ipv6/ip6_fib.c`) suspends the tree walker between batches; when the table's root `fn_sernum` changed, it restarts from the root and skips `w->count` nodes (`w->skip = w->count`), where `fib6_walk_continue()` counts completed nodes, not routes. `fib6_add()` updates the serial number up to the root; `fib6_del_route()` only moves suspended walkers and does not change it. So an addition before the resume point re-dumps one node (duplicates); a deletion before it leaves `count` one too high, and the next addition anywhere in the table makes the restart skip one node, including every route of that node. A restart inside a node re-dumps the node from its first route (`skip_in_node = 0`), so a node larger than a batch can restart indefinitely while routes are added. The walk is post-order and the table root, which holds the default routes, comes last: in main this is exactly where the IPv6 FTR-size case lost its default routes. 6.1 resumes tables by bucket position; 7.1 by table id (`cb->args[1] = tb->tb6_id`).
- Addresses: positions in the interface's address list (`in_dev_dump_addr()` / `in_dev_dump_ifaddr()`, `in6_dump_addrs()`), interfaces by hash bucket in 6.1 and by ifindex in 7.1 (`for_each_netdev_dump`). `cb->seq` combines `dev_addr_genid` and `dev_base_seq`. The flag is missed when a batch sees the changed list before the generation counter moves and no later batch follows: the IPv4 counter is incremented by `fib_inetaddr_event()` after `__inet_insert_ifa()` has linked the address (a window only for lockless dumps, 7.1); an IPv6 address added with `nodad` is linked under RTNL but `__ipv6_ifa_notify()` increments the counter later from the DAD work (`addrconf_dad_start()` defers it), a window on 6.1 too.
- Links: 6.1 resumes by hash bucket and position (`dev_index_head`), 7.1 by ifindex; both set `cb->seq = dev_base_seq`. On 6.1 one link went missing, flagged; on 7.1 nothing can be skipped by position.
- Nexthop objects: `rtm_dump_walk_nexthops()` resumes by nexthop id, so nothing is skipped or repeated; `cb->seq = net->nexthop.seq` still flags concurrent changes.

**FTR's sizes.** Rule dumps per family with the FR-ROUTE-3 layout and 5 foreign rules: 2648 bytes for 3 uplinks (37 rules), about 460 bytes per uplink; they fit in the 3.7 KiB first batch up to 5 uplinks and in one 32 KiB batch up to beyond 32 uplinks (15.9 KiB). The IPv4 route dump with 200 FTR tables and 3 default routes in main is 13 100 bytes; the IPv6 one is 27 628 bytes, close to the 32 KiB limit. On a fresh socket or with small batches they take 3 to 8 batches; on a long-lived socket read with 64 KiB buffers they fit in one data batch, and 1000 such dumps per family and kernel under churn were clean. So at FTR's sizes the risk exists whenever a dump spans batches: always for the first dump on a new socket (route dumps of 200 tables), when the kernel falls back to small batches, when third parties add many rules or routes (a full routing table in main), and on 6.1 for rules through the trailing call even in one batch (duplicates only). It is small (2–11 lost IPv6 default routes per 1000 dumps under continuous churn in main with 4 KiB batches) but it hits the entries that matter most.

**Documentation cross-check (Context7).** The kernel documentation (`userspace-api/netlink/intro`, "Dump consistency") says that dumps are not atomic snapshots and that `NLM_F_DUMP_INTR` on any message means the dump may be inconsistent and should be retried; the kernel developer guidance (`core-api/netlink`) asks dump implementations to report with `NLM_F_DUMP_INTR` any iteration that "might lead to skips or repetitions", through a generation counter in `cb->seq`. Rule and route dumps do not follow that guidance (source and experiment agree), so the absence of the flag must not be read as consistency. The same documentation recommends a 32 KiB receive buffer for dumps, which matches the batch cap observed. The `rtnetlink` crate documentation says nothing about `NLM_F_DUMP_INTR` or interrupted dumps; `netlink-proto` is not indexed. Everything about which dump kinds skip, how often and why is from source and experiment only.

**Consequences for the observer.**

1. A rule or route dump is a possibly incomplete, possibly repeating view, on both kernels, with no signal. Dump results are merged by identity (a repeated entry is not an error and carries the same content).
2. The absence of an entry from one dump is not evidence of its removal. A removal is learnt from a deletion notification, or confirmed by another dump that cannot be affected in the same way: a strict-checked dump filtered to the entry's table (`RTA_TABLE`, small enough for one batch), or a second full dump that also lacks it. This covers FTR's own artifacts (no repair counted as a third-party removal), discovered default routes (no path made not ready) and foreign rules.
3. `NLM_F_DUMP_INTR` keeps its role for addresses, links and nexthop objects (bounded retries), but it is not complete for addresses either (a few per thousand affected dumps unflagged on 7.1), so the confirmation rule applies to address removals too.
4. Dump sockets stay open and are read with buffers of at least 32 KiB, so that after the first dump FTR-sized dumps normally fit in one batch. This lowers the probability; it is not a guarantee (first batch, allocation fallback, third-party growth).
5. Every dump has a deadline, after which it is abandoned on a fresh socket and retried; an IPv6 table dump can restart many times while routes are added.
6. "Re-dump until two consecutive dumps agree" is not needed as a general rule: under continuous churn it may not converge, and duplicates are harmless after merging. Confirmation is needed only where an absence would lead to an action.

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
- Interrupted dumps: see the cross-check in the `dumpskip` section (kernel documentation on dump consistency; nothing in the crate documentation).

## Conclusions

1. `netlink-packet-route` 0.33 covers every message, attribute and flag FTR needs for rules, routes, links and addresses (both families, tables above 255, `RTA_MULTIPATH` with weights and nexthop flags, `RTA_PREF`, `RTA_NH_ID`, `FRA_PROTOCOL`, `FRA_SUPPRESS_PREFIXLEN`, `FRA_FWMASK`, rule action `unreachable`). No upstream contribution is required to implement 2.0.
2. `netlink-proto` 0.13 + `netlink-sys` 0.9 (tokio) are a sound transport, provided the observer's subscribed socket never sends requests. Socket options FTR needs (`set_ext_ack`, `set_cap_ack`, `set_netlink_get_strict_chk`, `set_rx_buf_sz`, group membership) are exposed safely through `Connection::socket_mut()`.
3. The `rtnetlink` 0.23 request builders should not be used for FTR's artifacts: `RuleAddRequest::replace()` creates duplicate rules; `RuleAddRequest` puts table main in the header even for `unreachable` and has no setter for `FRA_FWMASK`; `RouteMessageBuilder` defaults to protocol `static` and type `unicast`, so used as a dump filter on a strict socket it returns nothing for FTR's tables and used as a delete key it fails with `ESRCH`; the `get()` streams hide the header flags (`NLM_F_DUMP_INTR`, `NLM_F_DUMP_FILTERED`). Using `rtnetlink` only for `new_connection` / `new_multicast_connection` and `Handle::request` is fine, and depending on `netlink-proto` directly is equally simple.
4. Bounded local implementation in FTR (safe Rust, estimated 400–600 lines): a request wrapper with explicit flags that returns errno plus parsed extack; construction and normalisation of rule and route messages (including the dump quirks listed above, and treating a single-nexthop route as equal to a one-member multipath route); the observer with a subscribe-only socket, separate dump and mutation sockets, notification buffering during dumps, bounded `NLM_F_DUMP_INTR` retries, resynchronisation on `Overrun`, and re-reads after uplink link/address events.
5. Upstream contributions worth offering, none blocking: in `netlink-proto`, match replies only when the header port id equals the socket's own port id (fixes the collision); parse extended-ack TLVs in `netlink-packet-core::ErrorMessage`; replace the `unimplemented!()` for overruns; in `rtnetlink`, document or remove `RuleAddRequest::replace()` and make the route-builder defaults explicit for dump and delete.
6. Interrupted dumps (`dumpskip`): rule and route dumps can silently omit or repeat entries under concurrent changes on both kernels, IPv6 route dumps most easily (node-count restart) and IPv4 route dumps only inside one leaf (several routes with the same prefix, such as default routes with different metrics); address dumps are flagged in nearly all such cases; link and nexthop dumps are flagged and, on 7.1 for links and on both for nexthops, cannot skip. At FTR's sizes a long-lived dump socket read with 64 KiB buffers usually gets each dump in one batch, but not the first dump of a socket, not under allocation fallback and not when third parties grow the tables. The observer must merge by identity and confirm any absence before acting on it.

## IMPL-2 recommendation

Keep `tokio`, `netlink-packet-route` (0.33) and `netlink-proto` / `netlink-sys` (0.13 / 0.9, feature `tokio_socket`) as the netlink stack. Make `rtnetlink` optional (connection helpers only) or drop it. Pin exact versions: these crates are pre-1.0 and change APIs between minor versions.

## Proposed SPEC amendments

- **IMPL-2**: replace "`rtnetlink` / `netlink-packet-route`" with "`netlink-packet-route` for message types and `netlink-proto` / `netlink-sys` for transport (`rtnetlink` at most for connection setup); FTR builds its own rule and route messages".
- **§12.2 Observer**: add "the socket subscribed to notifications never sends requests; dumps run on a separate socket while notifications received meanwhile are buffered and applied in order after the dump"; "`NLM_F_DUMP_INTR` is honoured where the kernel sets it (address dumps) with a bounded number of retries, after which the dump is used and a full resynchronisation is scheduled; route and rule dumps do not report interruption"; "because the kernel does not notify every removal (IPv4 routes deleted on administrative down or on removal of their source address) nor nexthop flag changes (`linkdown`, `dead`), the observer re-reads FTR's tables and the discovery tables after every link or address event of an uplink interface".
- **FR-COEX-3**: classify route and rule removals by the notification's port id: 0 is the kernel (expected, not counted), FTR's own mutation socket is FTR, any other port id is a third party (counted by FR-COEX-4). Removals found only by a re-read after a link or address event are kernel-initiated.
- **FR-DISC-3**: state that routes with `RTA_NH_ID` are recognised by that attribute even though the kernel also dumps the resolved gateway and interface; and that `dead` / `linkdown` member flags change without notification, so readiness is re-evaluated from a re-read after link events (FR-DISC-5).
- **FR-REC-6** (or a new IMPL item): rules are created with `NLM_F_CREATE | NLM_F_EXCL` and never with `NLM_F_REPLACE` (which adds a duplicate); comparison of dumped rules normalises `FRA_SUPPRESS_PREFIXLEN = 0xffffffff`, absent `FRA_FWMARK` for zero marks and `FRA_TABLE 0` on `unreachable` rules; rule identity includes the protocol; a single-nexthop route equals a one-member multipath route.
- **PLAT-1**: "netlink sockets enable `NETLINK_EXT_ACK`; when the kernel provides no message, the report says so".

### From `dumpskip`

- **§12.2 Observer**: replace "honours `NLM_F_DUMP_INTR` wherever it is received (S3 observed it only on address dumps under churn, which does not prove it absent elsewhere) by retrying the dump a bounded number of times, then schedules a full resynchronisation" with: "merges dump results by identity, because dumps can return an entry twice; treats every rule and route dump as possibly incomplete, because the kernel resumes them by position and never sets `NLM_F_DUMP_INTR` (S3: silent omissions and repetitions on 6.1 and 7.1); retries a dump that carries `NLM_F_DUMP_INTR` (addresses, links, nexthop objects) a bounded number of times, then uses it and schedules a full resynchronisation; abandons a dump that exceeds a deadline and retries it on a new socket; keeps its dump socket open and reads it with buffers of at least 32 KiB. An entry that the observer's view contains, that no deletion notification removed and that a dump lacks is considered removed only when a confirming read also lacks it: a strict-checked dump filtered to its table for routes, a second dump otherwise. Absence confirmation applies to address removals too (`NLM_F_DUMP_INTR` missed a few affected address dumps per thousand)."
- **FR-REC-6**: add "an FTR artifact that a full reconciliation finds missing is re-created only after the absence is confirmed as in §12.2; `EEXIST` when re-creating a rule with `NLM_F_EXCL` means the rule is present (the dump missed it) and is neither an error nor a repair". Keep the existing comparison rules; add "duplicate entries in a dump are ignored".
- **FR-COEX-3 / FR-COEX-4**: add "an absence found by a dump counts as a third-party removal only when confirmed and not explained by an observed kernel event; a single dump's absence is never counted (S3: the kernel's dump resumption produces unconfirmed absences)".
- **FR-DISC-3 / FR-DISC-5**: add "a discovered route (default routes of main or of another discovery table) that a dump lacks without a deletion notification keeps the path's state until the absence is confirmed (S3: the higher-metric IPv6 default routes of main disappeared from 2–11 of 1000 FTR-sized dumps with small batches while main changed)". The confirming read takes milliseconds, within the one-second bound.
- No "re-dump until two consecutive dumps agree" rule: it may not converge under continuous churn and repeated entries are harmless after merging; confirmation is needed only where an absence leads to an action.
- **Observer tests**: reuse the `dumpskip` technique, a test hook in the dump reader that forces small batches (4 KiB reads on a fresh socket) and injects a change after the first batch, so that the cases are deterministic rather than timing-dependent:
  - rule dump spanning batches, a foreign rule deleted before FTR's rules during the dump: no FTR rule reported missing, no repair, no third-party removal counted, no duplicate rule created;
  - a rule added during the dump (on 6.1 also with a one-batch dump, through the trailing call): no duplicate in the view, no error;
  - main with three IPv6 default routes, a prefix route deleted and a route added in main during the dump: discovery never marks the path not ready;
  - main with several IPv4 default routes, a lower-metric one deleted during the dump while the batch boundary is inside the leaf: the others stay discovered;
  - address dump with `NLM_F_DUMP_INTR`: bounded retries, then use and resynchronisation; an address absence is confirmed before an uplink loses its address;
  - an IPv6 table with one node larger than a batch while routes are added continuously: the dump deadline fires, the dump is retried, the observer does not stall;
  - dumps with repeated entries: the view is unchanged.
