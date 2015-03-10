def generate_iptables
  puts <<END
#Integrate with your existing "iptables-save" configuration, or adapt to work
#with any other iptables configuration system

*mangle
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:INPUT ACCEPT [0:0]

#New outbound connections: force a connection to use a specific uplink instead
#of participating in the multipath routing. This can be useful if you have an
#SMTP server that should always send emails originating from a specific IP
#address (because of PTR DNS records), or if you have some service that you want
#always to use a particular slow/fast uplink.
#
#Uncomment if needed.
#
#NB: these are just examples, you can add as many options as needed: -s, -d,
#    --sport, etc.

END
  UPLINKS.each_with_index do |uplink, i|
    puts "##{uplink[:description]}"
    puts "#[0:0] -A PREROUTING -i #{LAN_INTERFACE} -m conntrack --ctstate NEW -p tcp --dport XXX -j CONNMARK --set-mark #{BASE_FWMARK + i}"
    puts "#[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -m conntrack --ctstate NEW -p tcp --dport XXX -j CONNMARK --set-mark #{BASE_FWMARK + i}" if DMZ_INTERFACE
  end
  puts <<END

#Mark packets with the outgoing interface:
#
#- Established outbound connections: mark non-first packets (first packet will
#  be marked as 0, as a standard unmerked packet, because the connection has not
#  yet been marked with CONNMARK --set-mark)
#
#- New outbound connections: mark first packet, only effective if marking has
#  been done in the section above
#
#- Inbound connections: mark returning packets (from LAN/DMZ to WAN)

[0:0] -A PREROUTING -i #{LAN_INTERFACE} -j CONNMARK --restore-mark
END
  puts "[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -j CONNMARK --restore-mark" if DMZ_INTERFACE
  puts <<END

#New inbound connections: mark the connection with the incoming interface.

END
  UPLINKS.each_with_index do |uplink, i|
    puts "##{uplink[:description]}"
    puts "[0:0] -A PREROUTING -i #{uplink[:interface]} -m conntrack --ctstate NEW -j CONNMARK --set-mark #{BASE_FWMARK + i}"
  end
  puts <<END

#New outbound connections: mark the connection with the outgoing interface
#(chosen by the multipath routing).

END
  UPLINKS.each_with_index do |uplink, i|
    puts "##{uplink[:description]}"
    puts "[0:0] -A POSTROUTING -o #{uplink[:interface]} -m conntrack --ctstate NEW -j CONNMARK --set-mark #{BASE_FWMARK + i}"
  end
  puts <<END

COMMIT


*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

#DNAT: WAN --> LAN/DMZ. The original destination IP (-d) can be any of the IP
#addresses assigned to the uplink interface. XXX.XXX.XXX.XXX can be any of your
#LAN/DMZ IPs.
#
#Uncomment if needed.
#
#NB: these are just examples, you can add as many options as you wish: -s,
#    --sport, --dport, etc.

END
  UPLINKS.each do |uplink|
    puts "##{uplink[:description]}"
    puts "#[0:0] -A PREROUTING -i #{uplink[:interface]} -d #{uplink[:ip]} -j DNAT --to-destination XXX.XXX.XXX.XXX"
  end
  puts <<END

#SNAT: LAN/DMZ --> WAN. Force an outgoing connection to use a specific source
#address instead of the default one of the outgoing interface. Of course this
#only makes sense if more than one IP address is assigned to the uplink
#interface.
#
#Uncomment if needed.
#
#NB: these are just examples, you can add as many options as needed: -d,
#    --sport, --dport, etc.

END
  UPLINKS.each do |uplink|
    puts "##{uplink[:description]}"
    puts "#[0:0] -A POSTROUTING -s XXX.XXX.XXX.XXX -o #{uplink[:interface]} -j SNAT --to-source YYY.YYY.YYY.YYY"
  end
  puts <<END

#SNAT: LAN --> WAN

END
  UPLINKS.each do |uplink|
    puts "##{uplink[:description]}"
    puts "[0:0] -A POSTROUTING -o #{uplink[:interface]} -j SNAT --to-source #{uplink[:ip]}"
  end
  puts <<END

COMMIT


*filter

:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LAN_WAN - [0:0]
:WAN_LAN - [0:0]
END

  if DMZ_INTERFACE
    puts ':DMZ_WAN - [0:0]'
    puts ':WAN_DMZ - [0:0]'
  end

  puts <<END

#This is just a very basic example, add your own rules for the INPUT chain.

[0:0] -A INPUT -i lo -j ACCEPT
[0:0] -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

[0:0] -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

END
  UPLINKS.each do |uplink|
    puts "[0:0] -A FORWARD -i #{LAN_INTERFACE} -o #{uplink[:interface]} -j LAN_WAN"
  end
  UPLINKS.each do |uplink|
    puts "[0:0] -A FORWARD -i #{uplink[:interface]} -o #{LAN_INTERFACE} -j WAN_LAN"
  end
  if DMZ_INTERFACE
    UPLINKS.each do |uplink|
      puts "[0:0] -A FORWARD -i #{DMZ_INTERFACE} -o #{uplink[:interface]} -j DMZ_WAN"
    end
    UPLINKS.each do |uplink|
      puts "[0:0] -A FORWARD -i #{uplink[:interface]} -o #{DMZ_INTERFACE} -j WAN_DMZ"
    end
  end
  puts <<END

#This is just a very basic example, add your own rules for the FORWARD chain.

[0:0] -A LAN_WAN -j ACCEPT
[0:0] -A WAN_LAN -j REJECT
END
  if DMZ_INTERFACE
    puts '[0:0] -A DMZ_WAN -j ACCEPT'
    puts '[0:0] -A WAN_DMZ -j ACCEPT'
  end
  puts <<END

COMMIT
END
end
