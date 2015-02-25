def command(c)
  `#{c}` unless DEMO
  puts "Command: #{c}" if DEBUG
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

def monitor
  logger = Logger.new(LOG_FILE, LOG_OLD_FILES, LOG_MAX_SIZE)

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