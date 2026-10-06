# Troubleshooting

This page is organised by symptom. Most problems show up in one of four places:

- `polywan status`: the overall status and its reasons, the active set of each family, and for every path its health, the reason of its last transition, whether it is ready and active, its source, gateway and probe statistics.
- `polywan events`: what changed and when, for the last 1000 events (`--follow` to watch).
- The daemon's log: `journalctl -u polywan` under systemd, standard error otherwise. Errors carry the failed operation, the errno and the kernel's own message.
- `polywan check-config`, as root: validates the configuration and the system (kernel, nftables, sysctls, systemd-networkd, rules and routes of other tools, flowtables, your nftables ruleset), without changing anything. `--offline` checks only the file.

What PolyWAN installed can be read with `ip rule show`, `ip -6 rule show`, `ip route show table 1000` (and the other tables of [how it works](how-it-works.md#routing-tables-and-rules)), `nft list table inet polywan`, and `conntrack -L` for the connection marks.

## The daemon does not start

`systemctl status polywan` shows how it exited, and `journalctl -u polywan -b` why.

**Exit status 78** (`status=78/CONFIG`): the configuration refuses startup, and systemd does not restart the daemon until you start it again. Fix the cause, check with `polywan check-config`, then `systemctl start polywan`. The causes:

- The file cannot be read, parsed or validated: the message gives the file, line and key. Unknown keys are errors, often a misspelling or a key in the wrong table.
- The file, a directory above it, `state_dir`, `firewall.nft_path` or `notify.email.sendmail` is not owned by root or is writable by group or others: fix ownership and mode (`chown root:root`, `chmod go-w`), also of the targets of symbolic links.
- A group (`api.group`, `api.status_group`) or the hook user does not exist, or `notify.hook_user` has UID 0. The `polywan` group comes with the package; from the static binary it must be created (see [installation](installation.md)). Accounts must be local (see [users and groups](api.md#users-and-groups)).
- The configuration changes a structural setting (`fwmark_mask`, `table_base`, `rule_priority_base`, `route_protocol`, `firewall.mode`) against what is installed: run `polywan cleanup`, which removes the installed objects with the recorded settings, then start.
- The configuration reuses the id of an uplink for another name, or changes an uplink's id: give the uplink its old id back, or, if the old uplink is gone for good, run `polywan forget-uplink OLDNAME` (see [forget-uplink](api.md#forget-uplink)).

**Exit status 1**: other failures that end startup. The common ones:

- Linux older than 6.1, or nftables older than 1.0.6 in managed firewall mode.
- systemd-networkd runs with `ManageForeignRoutingPolicyRules` or `ManageForeignRoutes` enabled (the default): it would delete PolyWAN's rules and routes. The message gives the fix, a drop-in `/etc/systemd/networkd.conf.d/polywan.conf` with both set to `no` in `[Network]`, followed by a restart of systemd-networkd.
- A collision: a rule in PolyWAN's priority range, or a route in its table range, that another tool installed. Move PolyWAN's range (`rule_priority_base`, `table_base`) or the other tool's.
- A flowtable that covers a configured uplink or downlink.
- A probe target that is an address of the router, or inside the network of a downlink.
- PolyWAN rules that do not match the configuration, left by an earlier installation whose manifest is gone: run `polywan cleanup` with the current configuration, as the message says, then start.
- The instance lock is held: another `polywan run`, or a `cleanup`, `forget-uplink` or `notify-test --offline`, is running.
- A state file in `/var/lib/polywan` is corrupt or of an unknown version, for example after a downgrade. `polywan run --reset-state` discards the drain state and the health checkpoints, and a corrupt manifest; see [upgrades and downgrades](installation.md#upgrades-and-downgrades).
- A socket path is occupied by something PolyWAN cannot identify as its own: remove it by hand.

## No internet for the LAN

Start with `polywan status`.

**The active set is empty** (`active ipv4: none`): new connections are rejected with ICMP unreachable (clients usually report "network unreachable"). With the default `all_down_policy = "ready"`, an empty active set means that no uplink with a `priority` is both ready and not drained. Look at the paths:

- `carrier_lost`, `interface_removed`: the interface is down or missing.
- `address_lost`: no usable global address; for a DHCP or PPP uplink, the client has no lease yet, or lost it (see [DHCP](#dhcp-leases-not-renewed-or-not-acquired)).
- `gateway_lost`: no default route was found for the interface in the `discovery_tables` (default `main`); see [IPv6 paths that never become ready](#an-ipv6-path-never-becomes-ready) for IPv6. For a static gateway, the gateway must be inside a connected network of the interface, or `gateway_onlink = true` set.
- `route_install_failed`: the kernel refused the path's routes or an interface setting; the log has `apply_failed` lines with the kernel's message.
- `address_conflict`: the same address is on two uplinks of one family.
- Every uplink drained: `polywan undrain NAME`.

**The active set is not empty, but connections fail**:

- Your firewall drops the traffic: PolyWAN never accepts anything on your behalf. With a `forward` chain whose policy is `drop`, the traffic between the downlinks and the uplinks must be accepted there.
- `nat = "none"` on a path whose provider does not route your LAN prefix, or a second source NAT in your own tables (see [NAT](how-it-works.md#nat)).
- The destination is covered by a route of the main table, for example a VPN or a static route, and does not use PolyWAN at all (the [main bypass](how-it-works.md#the-main-bypass)).
- A foreign rule with a priority below `rule_priority_base` matches the traffic: `check-config` lists them.
- A path is `up` and active but its uplink does not carry traffic beyond what the probes reach: see [an uplink is up although it does not work](#an-uplink-is-up-although-it-does-not-work).

## Services of the router stop working when every uplink is down

DNS resolution, time synchronisation, package downloads and VPN clients of the router open connections that are not bound to an uplink. Like the LAN's, they use the active set, and they are rejected while it is empty. This is intended: no default route of the operating system is ever used behind PolyWAN's back. They work again as soon as a path is usable. A program that must reach a host through a given uplink whatever its health can bind to that uplink's address (for example `ping -I 203.0.113.10`): such traffic follows that uplink while it is ready, also when drained.

Traffic bound to an interface instead of an address (`ping -I wan0`, `SO_BINDTODEVICE`) behaves differently: PolyWAN only guarantees that it does not leave through another interface. When the uplink's table has no usable route, the kernel sends IPv4 traffic bound to the interface on-link, as if the destination were on the local network (so ARP requests for an internet address appear on the uplink and the packets are lost), and IPv6 traffic fails with "network unreachable" or picks a source address of another interface; see [traffic of the router itself](how-it-works.md#traffic-of-the-router-itself).

## An uplink goes down although it works

The path is `down` with reason `probe_failed` (fewer than `required_reachable` targets answered in `fall` rounds in a row) or `degraded` (a quality gate was violated). Look at its statistics in `polywan status`, and at `polywan_probe_samples_total` by target if metrics are enabled.

- The provider filters ICMP, or the targets drop it from your addresses: use TCP targets, such as `tcp:1.1.1.1:443`.
- One target is unreachable through this provider: replace it, or keep more targets than `required_reachable`.
- High-latency links (satellite, some 5G and LTE): raise `timeout`, keeping `timeout × attempts` below `interval`.
- `max_loss`, `max_rtt` or `max_jitter` are too strict for the link.
- After a gate took a path down, it comes back only after `rise` passed rounds **and** once the window of the last `quality_window` rounds no longer violates the gate, which with the defaults can take up to 30 seconds after the link recovered.

## An uplink is up although it does not work

- The targets are too close: the provider's own router, its DNS servers, or anything inside its network answer while the provider is cut off from the internet. Use distant anycast services of several operators, as the defaults do.
- `required_reachable = 1` lets a link that loses most packets pass whenever one probe of one target gets through; keep it at 2 or more, with more targets than that.
- A partly broken link: quality gates (`max_loss`, `max_rtt`) turn a high loss or latency into a failure.
- The statistics shown without gates may look better than the link: rounds end as soon as their outcome is certain, so late answers and slower targets are under-represented. The configuration reference explains this.

## An uplink flaps up and down

Look at the transitions in `polywan events`. Raise `fall` and `rise`, or `required_reachable` with more targets; if `degraded` alternates with `probes_recovered`, the gate is close to the link's normal behaviour. Carrier flaps (`carrier_lost`) come from the link itself, its cable or the modem.

## An IPv6 path never becomes ready

The path is `down` and not ready with reason `gateway_lost` or `address_lost`. PolyWAN reads the IPv6 default route and addresses that the kernel or the network manager installed from the provider's Router Advertisements; it does not configure them.

- `check-config` and the daemon warn when an uplink has `accept_ra = 1`: once forwarding is enabled (PolyWAN enables it), the kernel ignores Router Advertisements on such interfaces. Set `net.ipv6.conf.IFACE.accept_ra = 2`, or let systemd-networkd or NetworkManager handle Router Advertisements (they use `accept_ra = 0` and install the routes themselves).
- When no IPv6 default route appears within 30 seconds of startup or of the link coming up, the log says `no IPv6 default route discovered on IFACE ...` with the likely cause: `accept_ra = 1` with forwarding; `accept_ra = 0` with no user-space client installing the route; or no Router Advertisement with a non-zero router lifetime arrived at all. A static `gateway` (usually the provider router's link-local address, for example `fe80::1`) avoids depending on Router Advertisements.
- The log says `the only default routes on IFACE use a nexthop group`: something installed the default route through a nexthop group, which PolyWAN does not use. Configure a static `gateway`, or install the route differently. Routes through a single nexthop object, which systemd-networkd installs for Router Advertisements, work.
- The provider gives only a delegated prefix and no address on the uplink: the uplink has no source of its own. This works only with a static `source` assigned to another interface (typically the router's LAN address from the delegated prefix) and `nat = "snat"`.

## The status is degraded

`polywan status` shows the reasons in parentheses:

- `apply_failed`: a route, rule, sysctl or nftables operation failed and is retried with backoff (1 s to 60 s). The log's `apply_failed` lines and the events name the operation, the errno and the kernel's message. The status returns to `ok` when the desired generation is fully applied. A special case: if the kernel fails while replacing the IPv6 multipath route after its first member, it removes the whole route, and new IPv6 connections are rejected until the retry succeeds; pinned connections are not affected.
- `ownership_conflict`: another program removed PolyWAN's rules, routes or nftables table more than 3 times in 5 minutes, so PolyWAN repairs them only every `reconcile_interval`. Find the program: systemd-networkd with foreign rule management (which also prevents startup, but may have been changed afterwards), NetworkManager using PolyWAN's tables as `route-table` values, a firewall manager or script that flushes the whole nftables ruleset (`flush ruleset`: Debian's default `/etc/nftables.conf` does it on every start and reload of `nftables.service`, and stopping the service flushes everything), or another script. `ip monitor rule route` shows the removals as they happen. The reason clears after two full reconciliations in a row without a removal.
- `flow_offload`: a flowtable covers a configured uplink or downlink; the log names the flowtable, the selector and the interface. Remove the interfaces from the flowtable, or the flowtable; PolyWAN never touches it.
- `external_ruleset_missing`: in external firewall mode, the table printed by `polywan export-nft` is not loaded. Load it, and reload it whenever the configuration changes.

## Connections break

- **At failover**: connections pinned to an uplink that stops being ready are rejected, not moved, and break; clients reconnect through another uplink. Connections pinned to an uplink that is only `down` (probes failing, link still ready) keep using it.
- **On a reload that removes an uplink**: its connections are rejected until they expire.
- **When the uplink's address changes** (a new DHCP lease, a PPP reconnection): with masquerade, the connections' translated source address is gone, and they break.
- **Conntrack**: a flushed or expired conntrack entry forgets the connection's uplink, and its next packet may be balanced to another uplink, which breaks it. A full conntrack table (the kernel logs `nf_conntrack: table full, dropping packet`) makes the kernel drop packets; raise `net.netfilter.nf_conntrack_max`. Packets conntrack considers invalid are not marked. `notrack` rules in your ruleset for data traffic disable pinning for it, and `check-config` warns about them.
- **The nftables table was flushed**: a `flush ruleset` deletes PolyWAN's table too: Debian's default `/etc/nftables.conf` starts with one, so reloading `nftables.service` with it, or stopping the service, removes PolyWAN's marking. PolyWAN replaces it at the next full reconciliation (every `reconcile_interval`, default 60 s); meanwhile new connections are not assigned an uplink id and established ones are not restored. Delete only your own tables in your ruleset file instead of flushing everything.
- **Flow offload**: offloaded traffic bypasses the marking (see [the status is degraded](#the-status-is-degraded)).

## Port forwarding or inbound connections do not work

- Inbound connections work on every ready uplink, also one without `priority` or drained: if they fail, check your DNAT rules and your `forward` and `input` chains first.
- DNAT must run after PolyWAN's prerouting chain (priority −150): the usual `dstnat` priority −100 does.
- `src_valid_mark` must be 1 on the uplink (PolyWAN sets it with `manage_sysctls = true`); otherwise the reverse-path check drops inbound forwarded packets.
- `check-config` warns when a downlink's prefix is not in the main table: replies towards that network would then follow an uplink instead.
- An nftables `fib`-based reverse-path filter must include the mark and run after PolyWAN's prerouting chain.

## DHCP leases not renewed or not acquired

PolyWAN does not need any exception for DHCP, DHCPv6, Router Advertisements, neighbour discovery or PPP: discovery, requests and rebinding of DHCPv4 use packet sockets, link-local and on-link traffic is routed by the main bypass, IPv6 multicast by the local table, and PPP control traffic is not routed. This was tested with systemd-networkd, NetworkManager, ISC dhclient, dhcpcd, the kernel's SLAAC, pppd and Kea, with an empty active set. Two cases of unicast traffic to a server that is not on the link are exceptions.

**DHCPv4 renewal through a provider relay.** When the DHCP server is not on the link (the provider uses a relay), the renewal at T1 is a unicast message to it. ISC dhclient and dhcpcd send it without binding it to the leased address, so for PolyWAN it is a new connection of the router: it is rejected while the active set is empty, and balanced over the active set otherwise, possibly through another uplink, where the server does not answer. The client then falls back to the broadcast rebind at T2, which succeeds if the provider answers rebinds. With very short leases a client may let the lease expire before rebinding; this was observed with ISC dhclient and 2-minute leases, also without PolyWAN. systemd-networkd and NetworkManager bind the renewal to the leased address: it then follows the uplink's `from` rule and is not affected.

**DHCPv6 with the Server Unicast option.** A DHCPv6 server can tell clients to send later messages by unicast to its address (the Server Unicast option, obsoleted by RFC 9915). Those messages follow ordinary routing, and PolyWAN does not guarantee their delivery independently of the active set. This can prevent the **initial acquisition** of an address or a delegated prefix, not only its renewal:

- dhcpcd 10.1.0 and 10.3.0 in manager mode (one dhcpcd for every interface) send Request and Renew by unicast, specifying neither a source address nor an interface. They are rejected while the active set is empty, and balanced otherwise. If the Request is hashed to another uplink, through which the server is unreachable, acquisition fails, and retransmissions keep the same addresses and ports, so they keep choosing that uplink. Acquisition has no rebind to fall back to; an empty active set can also block it until a suitable uplink becomes active.
- ISC dhclient 4.4.3-P1 sends Request by multicast, so acquisition works, but Renew by unicast, bound to the interface and with a link-local source. It goes through the interface's member of the balancing route while that uplink is active, and is rejected otherwise; it never leaves through another interface. Binding to the interface therefore does not by itself guarantee delivery outside the active set.
- After a failed renewal, the tested clients send a multicast Rebind at T2; addresses and prefixes are then kept only if the server answers before they expire.
- NetworkManager 1.52.1's internal client ignored the option in our tests. systemd-networkd's handling of it was not tested.

Remedies: configure the DHCPv6 server without the Server Unicast option, if it is yours or your provider can change it; or use a client or mode that ignores the option, as NetworkManager 1.52.1's internal client and dhcpcd outside manager mode (one dhcpcd per interface, for example `dhcpcd wan0`) were observed to do. ISC dhclient avoids the acquisition problem, but keeps the renewal limitation described above.

Symptoms: the client's log shows repeated Renew or Request messages without answers, then Rebind, or an interface that never gets its DHCPv6 address or prefix while another uplink is active.

## systemctl reload fails

`systemctl reload polywan` runs `polywan reload`, which succeeds only when the new configuration is applied. `journalctl -u polywan` shows its message:

- The configuration is invalid: the errors are listed, and the running configuration is kept. `polywan check-config` shows the same errors before you reload.
- A step failed while applying: PolyWAN keeps retrying it, and the status is `degraded` (`apply_failed`) meanwhile. Nothing is rolled back.
- Not applied within 8 seconds: PolyWAN keeps applying it; `polywan status` shows when the applied generation catches up with the desired one.
- The outcome is unknown: the reload changed the control socket's path or access, which closes the connection that asked for it. `polywan events` shows `config_reloaded` or `reload_failed`. Restart the daemon for such changes instead.
- A structural setting or `state_dir` changed: they cannot change on reload (see [the daemon does not start](#the-daemon-does-not-start) for structural settings, and the configuration reference for moving the state directory).

With a non-default `api.socket`, the unit's `ExecReload=` needs a drop-in with `--socket`, as described in [installation](installation.md).

## Stopping or removing left routing behind

With the default `on_shutdown = "keep"`, stopping the daemon leaves its routing in place on purpose: routing keeps working, without health checks. To remove it, run `polywan cleanup` while the daemon is stopped.

If a cleanup was interrupted (the unit's stop timeout of 30 s expired, the system lost power, a kernel operation failed), the manifest in `/var/lib/polywan` is kept: run `polywan cleanup` again; it removes what is left, with the same configuration or the recorded settings, and deletes the manifest only when everything is gone. If the package was removed while the cleanup was skipped (the daemon was still running, or the configuration was missing or not at the default path), the removal printed instructions; with the binary gone, install it again (package or static binary) and run `polywan cleanup --config PATH`.

## polywan status cannot connect

- `No such file or directory` or `Connection refused`: the daemon is not running, or the status socket is disabled (`api.status_socket = ""`) or at another path (`--socket`).
- `Permission denied`: the status socket is restricted to `api.status_group`, or, for commands of the control socket, you are not in `api.group` (log in again after being added to it).
- `404 Not Found` from `drain`, `reload` and the other commands: they were sent to the status socket with `--socket`; use the control socket.

## Email does not arrive

See [email](email.md): run `polywan notify-test`, which tests through the daemon, inside its sandbox, and prints the mail program's exit status and error output.

## Warnings at startup

`check-config` and the daemon print warnings for conditions that do not prevent operation but that you should know about:

- `the rule at priority N precedes PolyWAN's rules`: a rule of another tool comes before PolyWAN's; PolyWAN's guarantees do not cover the traffic it matches. The kernel's VRF rule is listed too, and matches only traffic of VRF devices.
- `downlink IFACE: the prefix ... is not in the main table`: replies towards that network would follow an uplink; add the prefix route to the main table.
- `chain ... contains notrack statements`: untracked traffic is not pinned.
- `chain ... performs source NAT`: if it translates traffic on the uplinks, set `nat = "none"` on those paths.
- `uplink NAME: the IPv6 path with gateway = "auto" would get no default route`: see [IPv6 paths](#an-ipv6-path-never-becomes-ready).
- With `manage_sysctls = false`, every system setting that differs from what PolyWAN needs.
