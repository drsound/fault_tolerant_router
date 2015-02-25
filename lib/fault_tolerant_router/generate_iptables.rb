def generate_iptables
  puts <<END
#integrate with your existing "iptables-save" configuration, or adapt to work with any other iptables configuration system

*mangle
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:INPUT ACCEPT [0:0]

#new outbound connections: force connection to use a specific uplink instead of letting multipath routing decide (for
#example for an SMTP server). Uncomment if needed.
END
  UPLINKS.each_with_index do |uplink, i|
    puts "##{uplink[:description]}"
    puts "#[0:0] -A PREROUTING -i #{LAN_INTERFACE} -m state --state NEW -p tcp --dport XXX -j CONNMARK --set-mark #{BASE_FWMARK + i}"
    puts "#[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -m state --state NEW -p tcp --dport XXX -j CONNMARK --set-mark #{BASE_FWMARK + i}" if DMZ_INTERFACE
  end
  puts <<END

#mark packets with the outgoing interface:
#- active outbound connections: non-first packets
#- active inbound connections: returning packets
#- active outbound connections: only effective if a previous marking has been done (for example for an SMTP server)
[0:0] -A PREROUTING -i #{LAN_INTERFACE} -j CONNMARK --restore-mark
END
  puts "[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -j CONNMARK --restore-mark" if DMZ_INTERFACE
  puts <<END

#new inbound connections: mark with the incoming interface (decided by the connecting host)
END
  UPLINKS.each_with_index do |uplink, i|
    puts "##{uplink[:description]}"
    puts "[0:0] -A PREROUTING -i #{uplink[:interface]} -m state --state NEW -j CONNMARK --set-mark #{BASE_FWMARK + i}"
  end
  puts <<END

#new outbound connections: mark with the outgoing interface (decided by the multipath routing)
END
  UPLINKS.each_with_index do |uplink, i|
    puts "##{uplink[:description]}"
    puts "[0:0] -A POSTROUTING -o #{uplink[:interface]} -m state --state NEW -j CONNMARK --set-mark #{BASE_FWMARK + i}"
  end
  puts <<END

COMMIT


*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

#DNAT: WAN --> DMZ. Uncomment if needed.
END
  UPLINKS.each do |uplink|
    puts "##{uplink[:description]}"
    puts "#[0:0] -A PREROUTING -i #{uplink[:interface]} -d #{uplink[:ip]} -j DNAT --to-destination XXX.XXX.XXX.XXX"
  end
  puts <<END

#SNAT: LAN/DMZ --> WAN: force the usage of a specific source address (for example for an SMTP server). Uncomment if needed.
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

#[...] (merge existing rules)

:LAN_WAN - [0:0]
:WAN_LAN - [0:0]
END

  if DMZ_INTERFACE
    puts ':DMZ_WAN - [0:0]'
    puts ':WAN_DMZ - [0:0]'
  end

  puts <<END

#[...] (merge existing rules)

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

#[...] (merge existing rules)

COMMIT
END
end
