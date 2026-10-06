# Larger setups

The packaged example has two uplinks and one LAN. This page shows a fuller configuration: an office with three uplinks, a LAN and a DMZ, policies, email and a hook, and metrics. Every part is described in the [configuration reference](../configuration.md).

```toml
[routing]
all_down_policy = "ready"

[[downlink]]
interface = "lan0"

[[downlink]]
interface = "dmz0"

# Two fixed lines share the traffic, roughly 2 to 1.
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

[[uplink]]
id = 2
name = "cable"
description = "Cable 500 Mbps (provider B)"
interface = "wan1"
priority = 1
weight = 5

[uplink.ipv4]
nat = "masquerade"

[uplink.ipv6]
nat = "masquerade"

# A metered 5G line, used only when both fixed lines fail; slower to
# declare down, since short interruptions are normal on it.
[[uplink]]
id = 3
name = "fwa5g"
description = "5G, metered (provider C)"
interface = "wan2"
priority = 2

[uplink.ipv4]
nat = "masquerade"

[uplink.health]
timeout = "2s"
fall = 3

# A static address for the mail server, reserved to policies and inbound
# traffic: no priority, so ordinary connections never use it.
[[uplink]]
id = 4
name = "business"
description = "Business line with static addresses (provider D)"
interface = "wan3"

[uplink.ipv4]
source = "203.0.113.25"
gateway = "203.0.113.1"
nat = "snat"

[health]
interval = "5s"
timeout = "1s"
attempts = 2
required_reachable = 2

[health.quality]
max_loss = 0.2

# The mail server in the DMZ sends through the business line, whose address
# has the right reverse DNS; nothing else is acceptable for it.
[[policy]]
name = "smtp-out"
family = "ipv4"
input_interface = "dmz0"
source = "192.168.10.25/32"
protocol = "tcp"
destination_port = 25
uplink = "business"
fallback = "block"

# Video calls prefer the fibre, and fall back to the others when it fails.
[[policy]]
name = "calls"
family = "ipv4"
input_interface = "lan0"
protocol = "udp"
destination_port = "3478-3481"
uplink = "fiber"

[notify]
coalesce = "30s"

[notify.email]
from = "router@example.com"
to = ["noc@example.com"]
sendmail = "/usr/bin/msmtp"

[[notify.hook]]
command = ["/usr/local/bin/polywan-to-chat", "--channel", "network"]
events = ["path_state_changed", "active_set_changed", "status_degraded", "status_recovered"]
timeout = "5s"

[api]
status_group = "monitoring"

[metrics]
listen = "127.0.0.1:9750"
```

Notes:

- The 5G line carries only IPv4 here: IPv6 uses only the two fixed lines. When both lose their link, new IPv6 connections are rejected while IPv4 ones use the 5G line, and hosts with both families fall back to IPv4. When both are only failing their checks, IPv4 uses the healthy 5G line, while IPv6, which has no healthy uplink left, keeps using the fixed lines under `all_down_policy = "ready"`.
- The business line has no `priority`: inbound connections to its addresses (port forwarding to the DMZ, see [port forwarding](port-forwarding.md)), its probes and the `smtp-out` policy use it; nothing else does. With `fallback = "block"`, mail waits in the server's queue while the line is down instead of leaving from an address with the wrong reverse DNS.
- `max_loss = 0.2` takes a line out of use when more than a fifth of its probes are lost over the last six rounds, even if enough targets still answer.
- Members of `monitoring` can read the status and events; members of `polywan` control the daemon (see [API](../api.md)).
