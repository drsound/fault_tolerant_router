#!/usr/bin/env ruby

LAN_INTERFACE = 'eth0'

#set to "nil" if you don't have a DMZ
#DMZ_INTERFACE = 'eth1'
DMZ_INTERFACE = nil

#ping retries in case of ping error
PING_RETRIES = 1

#number of successful pinged addresses to consider an uplink to be functional
REQUIRED_SUCCESSFUL_TESTS = 4

#seconds between a check of the uplinks and the next one
PROBES_INTERVAL = 60

SEND_EMAIL = false
EMAIL_SENDER = "root@#{`hostname -f`.strip}"
EMAIL_RECIPIENTS = %w(user@domain.com)
SMTP_PARAMETERS = {
    address: 'mail.domain.com',
    #port: 25,
    #domain: 'domain.com',
    #authentication: :plain,
    #enable_starttls_auto: false,
    user_name: 'user@domain.com',
    password: 'my-secret-password'
}

#LOG_FILE = '/var/log/fault_tolerant_router.log'
LOG_FILE = '/tmp/fault_tolerant_router.log'

DEBUG = true
DEMO = true

UPLINKS = [
    {
        interface: 'eth1',
        ip: '1.1.1.1',
        gateway: '1.1.1.254',
        description: 'Example Provider 1',
        #optional
        weight: 1,
        #optional
        default_route: false
    },
    {
        interface: 'eth2',
        ip: '2.2.2.2',
        gateway: '2.2.2.254',
        description: 'Example Provider 2',
        #optional
        weight: 2,
        #optional
        #default_route: false
    },
    {
        interface: 'eth3',
        ip: '3.3.3.3',
        gateway: '3.3.3.254',
        description: 'Example Provider 3',
        #optional
        # weight: 3,
        #optional
        # default_route: false
    }
]

TESTS = %w(
  208.67.222.222
  208.67.220.220
  8.8.8.8
  8.8.4.4
  4.2.2.2
  4.2.2.3
)

require 'optparse'
require 'net/smtp'
require 'mail'
require 'logger'

def shuffle
  sort_by { rand }
end

def command(c)
  `#{c}` unless DEMO
  puts "Command: #{c}" if DEBUG
end

def set_default_route
  #find the enabled uplinks
  enabled_connections = UPLINKS.find_all { |connection| connection[:enabled] }
  #do not use balancing if there is just one enabled uplink
  if enabled_connections.size == 1
    nexthops = "via #{enabled_connections.first[:gateway]}"
  else
    nexthops = enabled_connections.collect do |connection|
      #the "weight" parameter is optional
      weight = connection[:weight] ? " weight #{connection[:weight]}" : ''
      "nexthop via #{connection[:gateway]}#{weight}"
    end
    nexthops = nexthops.join(' ')
  end
  #set the route for first packet of outbound connections
  command "ip route replace table 100 default #{nexthops}"
  #apply the routeing changes
  command 'ip route flush cache'
end

def ping(ip, source)
  if DEMO
    sleep 0.1
    rand(2) == 0
  else
    `ping -n -c 1 -W 2 -I #{source} #{ip}`
    $?.to_i == 0
  end
end


parser = OptionParser.new do |opts|
  opts.banner = "Use: #{File.basename($0)} [options] generate_iptables|monitor"
  opts.on('--debug', 'Print debug output') do |debug|
    options[:debug] = debug
  end
  opts.on('--demo', 'Demo routing changes by faking random uplink failures') do |demo|
    options[:demo] = demo
  end
end
begin
  parser.parse!
rescue OptionParser::ParseError
  puts parser.help
  exit 1
end

if ARGV.size != 1 || !%w(generate_iptables monitor).include?(ARGV[0])
  puts parser.help
  exit 1
end

if ARGV[0] == 'generate_iptables'
  puts <<END
*mangle
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:INPUT ACCEPT [0:0]

#new outbound connections: force connection to use a specific uplink instead of letting multipath routing decide (for
#example for an SMTP server). Uncomment if needed.
#[0:0] -A PREROUTING -i #{LAN_INTERFACE} -m state --state NEW -p tcp --dport XXX -j CONNMARK --set-mark YYY
END
  puts "#[0:0] -A PREROUTING -i #{DMZ_INTERFACE} -m state --state NEW -p tcp --dport XXX -j CONNMARK --set-mark YYY" if DMZ_INTERFACE
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

#DNAT: WAN --> DMZ. Uncomment if needed.
END
  UPLINKS.each do |connection|
    puts "#[0:0] -A PREROUTING -i #{connection[:interface]} -d #{connection[:ip]} -j DNAT --to-destination XXX.XXX.XXX.XXX"
  end
  puts <<END

#SNAT: LAN/DMZ --> WAN: force the usage of a specific source address (for example for an SMTP server). Uncomment if needed.
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

#[...] (integrate with existing rules)

:LAN_WAN - [0:0]
:WAN_LAN - [0:0]
END

  if DMZ_INTERFACE
    puts ":DMZ_WAN - [0:0]"
    puts ":WAN_DMZ - [0:0]"
  end

  puts <<END

#[...] (integrate with existing rules)

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

#[...] (integrate with existing rules)

COMMIT
END
else
  logger = Logger.new(LOG_FILE, 10, 1024000)

  #enable all the uplinks
  UPLINKS.each do |connection|
    connection[:working] = true
    connection[:default_route] ||= connection[:default_route].nil?
    connection[:enabled] = connection[:default_route]
  end

#clean all previous configurations, try to clean more than needed to avoid problems in case of changes in the
#number of uplinks between different executions
  10.times do |i|
    command "ip rule del priority #{39001 + i} &> /dev/null"
    command "ip rule del priority #{40001 + i} &> /dev/null"
    command "ip route del table #{1 + i} &> /dev/null"
  end
  command 'ip rule del priority 40100 &> /dev/null'
  command 'ip route del table 100 &> /dev/null'

#disable "reverse path filtering" on the uplink interfaces
  command 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter'
  UPLINKS.each do |connection|
    command "echo 2 > /proc/sys/net/ipv4/conf/#{connection[:interface]}/rp_filter"
  end

#- locally generated packets having as source ip the ethX ip
#- returning packets of inbound connections coming from ethX
#- non-first packets of outbound connections for which the first packet has been sent to ethX via multipath routing
  UPLINKS.each_with_index do |connection, i|
    command "ip route add table #{1 + i} default via #{connection[:gateway]} src #{connection[:ip]}"
    command "ip rule add priority #{39001 + i} from #{connection[:ip]} lookup #{1 + i}"
    command "ip rule add priority #{40001 + i} fwmark #{1 + i} lookup #{1 + i}"
  end
#first packet of outbound connections
  command 'ip rule add priority 40100 from all lookup 100'
  set_default_route

  loop do
    #for each uplink...
    UPLINKS.each do |connection|
      #set current "working" state as the previous one
      connection[:previously_working] = connection[:working]
      #set current "enabled" state as the previous one
      connection[:previously_enabled] = connection[:enabled]
      connection[:successful_tests] = 0
      connection[:unsuccessful_tests] = 0
      #for each test (in random order)...
      TESTS.shuffle.each_with_index do |test, i|
        successful_test = false
        #retry for several times...
        PING_RETRIES.times do
          if DEBUG
            print "Uplink #{connection[:description]}: ping #{test}... "
            STDOUT.flush
          end
          if ping(test, connection[:ip])
            successful_test = true
            puts 'ok' if DEBUG
            #avoid more pings to the same ip after a successful one
            break
          else
            puts 'error' if DEBUG
          end
        end
        if successful_test
          connection[:successful_tests] += 1
        else
          connection[:unsuccessful_tests] += 1
        end
        #if not currently doing the last test...
        if i + 1 < TESTS.size
          if connection[:successful_tests] >= REQUIRED_SUCCESSFUL_TESTS
            puts "Uplink #{connection[:description]}: avoiding more tests because there are enough positive ones" if DEBUG
            break
          elsif TESTS.size - connection[:unsuccessful_tests] < REQUIRED_SUCCESSFUL_TESTS
            puts "Uplink #{connection[:description]}: avoiding more tests because too few are remaining" if DEBUG
            break
          end
        end
      end
      connection[:working] = connection[:successful_tests] >= REQUIRED_SUCCESSFUL_TESTS
      connection[:enabled] = connection[:working] && connection[:default_route]
    end

    #only consider uplinks flagged as default route
    if UPLINKS.find_all { |connection| connection[:default_route] }.all? { |connection| !connection[:working] }
      UPLINKS.find_all { |connection| connection[:default_route] }.each { |connection| connection[:enabled] = true }
      puts 'No uplink seems to be working, enabling them all' if DEBUG
    end

    UPLINKS.each do |connection|
      description = case
                      when connection[:enabled] && !connection[:previously_enabled] then
                        ', enabled'
                      when !connection[:enabled] && connection[:previously_enabled] then
                        ', disabled'
                    end
      puts "Uplink #{connection[:description]}: #{connection[:successful_tests]} successful tests, #{connection[:unsuccessful_tests]} unsuccessful tests#{description}"
    end if DEBUG

    #set a new default route if there are changes between the previous and the current uplinks situation
    set_default_route if UPLINKS.any? { |connection| connection[:enabled] != connection[:previously_enabled] }

    if UPLINKS.any? { |connection| connection[:working] != connection[:previously_working] }
      body = ''
      UPLINKS.each do |connection|
        body += "Uplink #{connection[:description]}: #{connection[:previously_working] ? 'up' : 'down'}"
        if connection[:previously_working] == connection[:working]
          body += "\n"
        else
          body += " --> #{connection[:working] ? 'up' : 'down'}\n"
        end
      end

      logger.warn(body.gsub("\n", ';'))

      if SEND_EMAIL
        mail = Mail.new
        mail.from = EMAIL_SENDER
        mail.to = EMAIL_RECIPIENTS
        mail.subject = 'Uplinks status change'
        mail.body = body
        mail.delivery_method :smtp, SMTP_PARAMETERS
        begin
          mail.deliver
        rescue Exception => ex
          puts "Problem sending email: #{ex}" if DEBUG
          logger.error("Problem sending email: #{ex}")
        end
      end
    end

    puts "Waiting #{PROBES_INTERVAL} seconds..." if DEBUG
    sleep PROBES_INTERVAL
  end
end
