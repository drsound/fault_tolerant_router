# Fault Tolerant Router

This is a Ruby daemon, to be run in the backgound on a Linux router or firewall. It monitors the state of multiple uplinks/providers by pinging some externel IP addresses through the outgoing interfaces. When an uplink goes down it changes the multipath routing removing such uplink and sends an email to the administrator. When an uplink goes up it changes the multipath routing adding such uplink and sends an email to the administrator.

Fault Tolerant Router is well tested and already used in production by several years, in several customers sites. I've just released it to GitHub, I will write some documentation in the next days.

## Installation

    $ gem install fault_tolerant_router

And then execute:

    $ fault_tolerant_router

## Usage

## To do
- [ ] improve documentation
- [ ] i18n

## License
GNU General Public License v2.0, see LICENSE file

## Author
Alessandro Zarrilli - <alessandro@zarrilli.net>
