#!/usr/bin/env ruby

require 'optparse'
require 'net/smtp'
require 'mail'
require 'logger'
require 'yaml'

def command(c)
  `#{c}` unless DEMO
  puts "Command: #{c}" if DEBUG
end

def set_default_route
  #find the enabled uplinks
  enabled_uplinks = UPLINKS.find_all { |uplink| uplink[:enabled] }
  #do not use balancing if there is just one enabled uplink
  if enabled_uplinks.size == 1
    nexthops = "via #{enabled_uplinks.first[:gateway]}"
  else
    nexthops = enabled_uplinks.collect do |uplink|
      #the "weight" parameter is optional
      weight = uplink[:weight] ? " weight #{uplink[:weight]}" : ''
      "nexthop via #{uplink[:gateway]}#{weight}"
    end
    nexthops = nexthops.join(' ')
  end
  #set the route for first packet of outbound connections
  command "ip route replace table #{BASE_TABLE + UPLINKS.size} default #{nexthops}"
  #apply the routing changes
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

options = {
    config: '/etc/fault_tolerant_router.conf',
    debug: false,
    demo: false
}
parser = OptionParser.new do |opts|
  opts.banner = "Use: #{File.basename($0)} [options] generate_iptables|monitor"
  opts.on('--config=FILE', 'Configuration file (default /etc/fault_tolerant_router.conf)') do |configuration_file|
    options[:config] = configuration_file
  end
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

unless File.exists?(options[:config])
  puts "Configuration file #{options[:config]} does not exists!"
  exit 1
end

DEMO = options[:demo]
#activate debug if we are in demo mode
DEBUG = options[:debug] || DEMO

config = YAML.load_file(options[:config])
UPLINKS = config[:uplinks]
LAN_INTERFACE = config[:downlinks][:lan]
DMZ_INTERFACE = config[:downlinks][:dmz]
TEST_IPS = config[:tests][:ips]
REQUIRED_SUCCESSFUL_TESTS = config[:tests][:required_successful]
PING_RETRIES = config[:tests][:ping_retries]
TEST_INTERVAL = config[:tests][:interval]
LOG_FILE = config[:log_file]
SEND_EMAIL = config[:email][:send]
EMAIL_SENDER = config[:email][:sender]
EMAIL_RECIPIENTS = config[:email][:recipients]
SMTP_PARAMETERS = config[:email][:smtp_parameters]
BASE_TABLE = config[:base_table]
BASE_PRIORITY = config[:base_priority]
BASE_FWMARK = config[:base_fwmark]

if ARGV[0] == 'generate_iptables'
  puts <<END
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
else
  logger = Logger.new(LOG_FILE, 10, 1024000)

  #enable all the uplinks
  UPLINKS.each do |uplink|
    uplink[:working] = true
    uplink[:default_route] ||= uplink[:default_route].nil?
    uplink[:enabled] = uplink[:default_route]
  end

  #clean all previous configurations, try to clean more than needed (double) to avoid problems in case of changes in the
  #number of uplinks between different executions
  ((UPLINKS.size * 2 + 1) * 2).times do |i|
    command "ip rule del priority #{BASE_PRIORITY + i} &> /dev/null"
  end
  ((UPLINKS.size + 1) * 2).times do |i|
    command "ip route del table #{BASE_TABLE + i} &> /dev/null"
  end

  #disable "reverse path filtering" on the uplink interfaces
  command 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter'
  UPLINKS.each do |uplink|
    command "echo 2 > /proc/sys/net/ipv4/conf/#{uplink[:interface]}/rp_filter"
  end

  #- locally generated packets having as source ip the ethX ip
  #- returning packets of inbound connections coming from ethX
  #- non-first packets of outbound connections for which the first packet has been sent to ethX via multipath routing
  UPLINKS.each_with_index do |uplink, i|
    command "ip route add table #{BASE_TABLE + i} default via #{uplink[:gateway]} src #{uplink[:ip]}"
    command "ip rule add priority #{BASE_PRIORITY + i} from #{uplink[:ip]} lookup #{BASE_TABLE + i}"
    command "ip rule add priority #{BASE_PRIORITY + UPLINKS.size + i} fwmark #{BASE_FWMARK + i} lookup #{BASE_TABLE + i}"
  end
  #first packet of outbound connections
  command "ip rule add priority #{BASE_PRIORITY + UPLINKS.size * 2} from all lookup #{BASE_TABLE + UPLINKS.size}"
  set_default_route

  loop do
    #for each uplink...
    UPLINKS.each do |uplink|
      #set current "working" state as the previous one
      uplink[:previously_working] = uplink[:working]
      #set current "enabled" state as the previous one
      uplink[:previously_enabled] = uplink[:enabled]
      uplink[:successful_tests] = 0
      uplink[:unsuccessful_tests] = 0
      #for each test (in random order)...
      TEST_IPS.shuffle.each_with_index do |test, i|
        successful_test = false
        #retry for several times...
        PING_RETRIES.times do
          if DEBUG
            print "Uplink #{uplink[:description]}: ping #{test}... "
            STDOUT.flush
          end
          if ping(test, uplink[:ip])
            successful_test = true
            puts 'ok' if DEBUG
            #avoid more pings to the same ip after a successful one
            break
          else
            puts 'error' if DEBUG
          end
        end
        if successful_test
          uplink[:successful_tests] += 1
        else
          uplink[:unsuccessful_tests] += 1
        end
        #if not currently doing the last test...
        if i + 1 < TEST_IPS.size
          if uplink[:successful_tests] >= REQUIRED_SUCCESSFUL_TESTS
            puts "Uplink #{uplink[:description]}: avoiding more tests because there are enough positive ones" if DEBUG
            break
          elsif TEST_IPS.size - uplink[:unsuccessful_tests] < REQUIRED_SUCCESSFUL_TESTS
            puts "Uplink #{uplink[:description]}: avoiding more tests because too many have been failed" if DEBUG
            break
          end
        end
      end
      uplink[:working] = uplink[:successful_tests] >= REQUIRED_SUCCESSFUL_TESTS
      uplink[:enabled] = uplink[:working] && uplink[:default_route]
    end

    #only consider uplinks flagged as default route
    if UPLINKS.find_all { |uplink| uplink[:default_route] }.all? { |uplink| !uplink[:working] }
      UPLINKS.find_all { |uplink| uplink[:default_route] }.each { |uplink| uplink[:enabled] = true }
      puts 'No uplink seems to be working, enabling all of them' if DEBUG
    end

    UPLINKS.each do |uplink|
      description = case
                      when uplink[:enabled] && !uplink[:previously_enabled] then
                        ', enabled'
                      when !uplink[:enabled] && uplink[:previously_enabled] then
                        ', disabled'
                      else
                        ''
                    end
      puts "Uplink #{uplink[:description]}: #{uplink[:successful_tests]} successful tests, #{uplink[:unsuccessful_tests]} unsuccessful tests#{description}"
    end if DEBUG

    #set a new default route if there are changes between the previous and the current uplinks situation
    set_default_route if UPLINKS.any? { |uplink| uplink[:enabled] != uplink[:previously_enabled] }

    if UPLINKS.any? { |uplink| uplink[:working] != uplink[:previously_working] }
      body = ''
      UPLINKS.each do |uplink|
        body += "Uplink #{uplink[:description]}: #{uplink[:previously_working] ? 'up' : 'down'}"
        if uplink[:previously_working] == uplink[:working]
          body += "\n"
        else
          body += " --> #{uplink[:working] ? 'up' : 'down'}\n"
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
        rescue Exception => e
          puts "Problem sending email: #{e}" if DEBUG
          logger.error("Problem sending email: #{e}")
        end
      end
    end

    puts "Waiting #{TEST_INTERVAL} seconds..." if DEBUG
    sleep TEST_INTERVAL
  end
end
