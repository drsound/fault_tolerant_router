# fault_tolerant_router

This is a Ruby daemon, to be run in the backgound on a Linux router or firewall. It monitors the state of multiple uplinks/providers by pinging some externel IP addresses through the outgoing interfaces. When an uplink goes down it changes the multipath routing removing such uplink and sends an email to the administrator. When an uplink goes up it changes the multipath routing adding such uplink and sends an email to the administrator.

Fault_tolerant_router is well tested and already used in production by several years, in several customers sites. I've just released it to GitHub, I will write some documentation in the next days.
