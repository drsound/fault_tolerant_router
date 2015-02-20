#!/usr/bin/env ruby
#encoding: UTF-8

LAN_INTERFACE = "eth0"

#set to "nil" if you don't have a DMZ
#DMZ_INTERFACE = "eth1"
DMZ_INTERFACE = nil

UPLINKS = [
    {
        :interface => 'eth1',
        :ip => '1.1.1.1',
        :gateway => '1.1.1.254',
        :description => 'Provider 1',
        #optional
        :weight => 1,
        #optional
        :default_route => false
    },
    {
        :interface => 'eth2',
        :ip => '2.2.2.2',
        :gateway => '2.2.2.254',
        :description => 'Provider 2',
        #optional
        :weight => 2,
        #optional
        #:default_route => false
    },
    {
        :interface => 'eth3',
        :ip => '3.3.3.3',
        :gateway => '3.3.3.254',
        :description => 'Provider 3'
        #optional
        #:weight => 3,
        #optional
        #:default_route => false
    }
]

puts <<END
*mangle
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:INPUT ACCEPT [0:0]

#new outbound connections: force the connection to use a specific uplink instead of letting the multipath routing decide (ex. for a SMTP server)
#[0:0] -A PREROUTING -i #{LAN_INTERFACE} -m state --state NEW -p tcp --syn --dport XXX -j CONNMARK --set-mark YYY
END
puts "#[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -m state --state NEW -p tcp --syn --dport XXX -j CONNMARK --set-mark YYY" if DMZ_INTERFACE
puts <<END

#mark packets with the outgoing interface:
#- active outbound connections: non-first packets
#- active inbound connections: returning packets
#- active outbound connections: only working if has been done a previous marking (ex. for a SMTP server)
[0:0] -A PREROUTING -i #{LAN_INTERFACE} -j CONNMARK --restore-mark
END
puts "[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -j CONNMARK --restore-mark" if DMZ_INTERFACE
puts <<END

#new inbound connections: mark with the incoming interface (decided by the connecting host)
END
UPLINKS.each_with_index do |connection, i|
  puts "[0:0] -A PREROUTING -i #{connection[:interface]} -m state --state NEW -j CONNMARK --set-mark #{i + 1}"
end
puts <<END

#new outbound connections: mark with the outgoing interface (decided by the multipath routing)
END
UPLINKS.each_with_index do |connection, i|
  puts "[0:0] -A POSTROUTING -o #{connection[:interface]} -m state --state NEW -j CONNMARK --set-mark #{i + 1}"
end
puts <<END

COMMIT






*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

#DNAT: WAN --> DMZ
END
UPLINKS.each do |connection|
  puts "#[0:0] -A PREROUTING -i #{connection[:interface]} -d #{connection[:ip]} -j DNAT --to-destination XXX.XXX.XXX.XXX"
end
puts <<END

#SNAT: LAN/DMZ --> WAN: force the source address to be a specific one (for example for an SMTP server)
END
UPLINKS.each do |connection|
  puts "#[0:0] -A POSTROUTING -s XXX.XXX.XXX.XXX -o #{connection[:interface]} -j SNAT --to-source YYY.YYY.YYY.YYY"
end
puts <<END

#SNAT: LAN --> WAN
END
UPLINKS.each do |connection|
  puts "[0:0] -A POSTROUTING -o #{connection[:interface]} -j SNAT --to-source #{connection[:ip]}"
end
puts <<END

COMMIT






*filter

[...]

:LAN_WAN - [0:0]
:WAN_LAN - [0:0]
END

if DMZ_INTERFACE
  puts ":DMZ_WAN - [0:0]"
  puts ":WAN_DMZ - [0:0]"
end

puts <<END

[...]

END
UPLINKS.each do |connection|
  puts "[0:0] -A FORWARD -i #{LAN_INTERFACE} -o #{connection[:interface]} -j LAN_WAN"
end
UPLINKS.each do |connection|
  puts "[0:0] -A FORWARD -i #{connection[:interface]} -o #{LAN_INTERFACE} -j WAN_LAN"
end
if DMZ_INTERFACE
  UPLINKS.each do |connection|
    puts "[0:0] -A FORWARD -i #{DMZ_INTERFACE} -o #{connection[:interface]} -j DMZ_WAN"
  end
  UPLINKS.each do |connection|
    puts "[0:0] -A FORWARD -i #{connection[:interface]} -o #{DMZ_INTERFACE} -j WAN_DMZ"
  end
end
puts <<END

[...]

COMMIT
END
