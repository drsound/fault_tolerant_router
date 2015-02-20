#!/usr/bin/env ruby
#encoding: UTF-8

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
    :address => 'mail.domain.com',
    #:port => 25,
    #:domain => 'domain.com',
    #:authentication => :plain,
    #:enable_starttls_auto => false,
    :user_name => 'user@domain.com',
    :password => 'my-secret-password'
}

#LOG_FILE = '/var/log/route_monitor.log'
LOG_FILE = './route_monitor.log'

DEBUG = true
DRY_RUN = true

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

TESTS = %w(
  208.67.222.222
  208.67.220.220
  8.8.8.8
  8.8.4.4
  4.2.2.2
  4.2.2.3
)

require 'rubygems'
require 'net/smtp'
require 'mail'
require 'logger'
logger = Logger.new(LOG_FILE, 10, 1024000)

def shuffle
  sort_by { rand }
end

def command(c)
  `#{c}` unless DRY_RUN
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
  if DRY_RUN
    sleep 0.1
    rand(2) == 0
  else
    `ping -n -c 1 -W 2 -I #{source} #{ip}`
    $?.to_i == 0
  end
end


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
          puts "Uplink #{connection[:description]}: avoiding more tests because there are too few remaining" if DEBUG
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
    puts 'No uplink seems to be working: enabling all of them' if DEBUG
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
