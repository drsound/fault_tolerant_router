#!/usr/bin/env ruby
#encoding: UTF-8

LAN_INTERFACE = "eth0"

#impostare a "nil" se non si ha una DMZ
#DMZ_INTERFACE = "eth1"
DMZ_INTERFACE = nil

CONNECTIONS = [
    {
        :interface => 'eth1',
        :ip => '1.1.1.1',
        :gateway => '1.1.1.254',
        :description => 'Provider 1',
        #opzionale
        :weight => 1,
        #opzionale
        :default_route => false
    },
    {
        :interface => 'eth2',
        :ip => '2.2.2.2',
        :gateway => '2.2.2.254',
        :description => 'Provider 2',
        #opzionale
        :weight => 2,
        #opzionale
        #:default_route => false
    },
    {
        :interface => 'eth3',
        :ip => '3.3.3.3',
        :gateway => '3.3.3.254',
        :description => 'Provider 3'
        #opzionale
        #:weight => 3,
        #opzionale
        #:default_route => false
    }
]

puts <<END
*mangle
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:INPUT ACCEPT [0:0]

#marcatura pacchetto proveniente da localhost con interfaccia di uscita:
#- connessioni già attive iniziate dall'interno: pacchetti successivi al primo
#- connessioni già attive iniziate dall'esterno: pacchetti di risposta
#- connessioni già attive iniziate dall'interno: efficace solo se è stata fatta una preventiva marcatura (es. mail server)
#RIMOSSO: inutile, perché la decisione di routing viene presa ancora prima che il paccheto arrivi nella catena OUTPUT
#[0:0] -A OUTPUT -j CONNMARK --restore-mark

#nuove connessioni iniziate dall'interno: forza la marcatura della connessione con una particolare interfaccia di uscita,
#anziché lasciar decidere al multipath routing (es. mail server)
#[0:0] -A PREROUTING -i #{LAN_INTERFACE} -m state --state NEW -p tcp --syn --dport XXX -j CONNMARK --set-mark YYY
END
puts "#[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -m state --state NEW -p tcp --syn --dport XXX -j CONNMARK --set-mark YYY" if DMZ_INTERFACE
puts <<END

#marcatura pacchetto con interfaccia di uscita:
#- connessioni già attive iniziate dall'interno: pacchetti successivi al primo
#- connessioni già attive iniziate dall'esterno: pacchetti di risposta
#- connessioni già attive iniziate dall'interno: efficace solo se è stata fatta una preventiva marcatura (es. mail server)
[0:0] -A PREROUTING -i #{LAN_INTERFACE} -j CONNMARK --restore-mark
END
puts "[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -j CONNMARK --restore-mark" if DMZ_INTERFACE
puts <<END

#nuove connessioni iniziate dall'esterno: marcatura connessione con interfaccia di provenienza (decisa dall'host che si connette)
END
CONNECTIONS.each_with_index do |connection, i|
  puts "[0:0] -A PREROUTING -i #{connection[:interface]} -m state --state NEW -j CONNMARK --set-mark #{i + 1}"
end
puts <<END

#nuove connessioni iniziate dall'interno: marcatura connessione con interfaccia di uscita (decisa dal multipath routing)
END
CONNECTIONS.each_with_index do |connection, i|
  puts "[0:0] -A POSTROUTING -o #{connection[:interface]} -m state --state NEW -j CONNMARK --set-mark #{i + 1}"
end
puts <<END

COMMIT






*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

#DNAT: Internet --> DMZ.XXX
END
CONNECTIONS.each do |connection|
  puts "#[0:0] -A PREROUTING -i #{connection[:interface]} -d #{connection[:ip]} -j DNAT --to-destination XXX.XXX.XXX.XXX"
end
puts <<END

#SNAT: LAN/DMZ.XXX --> Internet: forza l'uscita da un particolare indirizzo IP (es. per mail server)
END
CONNECTIONS.each do |connection|
  puts "#[0:0] -A POSTROUTING -s XXX.XXX.XXX.XXX -o #{connection[:interface]} -j SNAT --to-source YYY.YYY.YYY.YYY"
end
puts <<END

#SNAT: LAN --> Internet
END
CONNECTIONS.each do |connection|
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
CONNECTIONS.each do |connection|
  puts "[0:0] -A FORWARD -i #{LAN_INTERFACE} -o #{connection[:interface]} -j LAN_WAN"
end
CONNECTIONS.each do |connection|
  puts "[0:0] -A FORWARD -i #{connection[:interface]} -o #{LAN_INTERFACE} -j WAN_LAN"
end
if DMZ_INTERFACE
  CONNECTIONS.each do |connection|
    puts "[0:0] -A FORWARD -i #{DMZ_INTERFACE} -o #{connection[:interface]} -j DMZ_WAN"
  end
  CONNECTIONS.each do |connection|
    puts "[0:0] -A FORWARD -i #{connection[:interface]} -o #{DMZ_INTERFACE} -j WAN_DMZ"
  end
end
puts <<END

[...]

COMMIT
END
