class Uplink
  attr_reader :description, :fwmark, :gateway, :id, :interface, :ip, :previous_gateway, :previous_ip, :previously_up, :priority_group, :rule_priority_1, :table, :type, :up, :weight
  attr_accessor :default_route, :previously_default_route, :rule_priority_2

  def initialize(config, id)
    @id = id
    @rule_priority_1 = BASE_PRIORITY + @id
    @table = BASE_TABLE + @id
    @fwmark = BASE_FWMARK + @id
    @interface = config['interface']
    raise "Uplink interface not specified: #{config}" unless @interface
    @type = case config['type']
              when 'static'
                :static
              when 'ppp'
                :ppp
              else
                raise "Uplink type not valid: #{config}"
            end
    @description = config['description']
    raise "Uplink description not specified: #{config}" unless @description
    @weight = config['weight']
    @priority_group = config['priority_group']
    @default_route = false

    if @type == :static
      @ip = config['ip']
      raise "Uplink IP address not specified: #{config}" unless @ip
      @gateway = config['gateway']
      raise "Uplink gateway not specified: #{config}" unless @gateway
    else
      detect_ppp_ips!
    end

    @previous_ip = @ip
    @previous_gateway = @gateway
    #a new uplink is supposed to be up
    @up = true
    @previously_up = true
  end

  def detect_ppp_ips!
    @previous_ip = @ip
    @previous_gateway = @gateway
    if DEMO
      @ip = ['3.0.0.101', '3.0.0.102', nil].sample
      @gateway = ['3.0.0.1', '3.0.0.2', nil].sample
    else
      ifaddr = Socket.getifaddrs.find { |i| i.name == @interface && i.addr && i.addr.ipv4? }
      if ifaddr
        @ip = ifaddr.addr.ip_address
        @gateway = ifaddr.dstaddr.ip_address
      else
        @ip = nil
        @gateway = nil
      end
    end
    puts "Uplink #{@description}: detected ip #{@ip || 'none'}, gateway #{@gateway || 'none'}" if DEBUG
  end

  def ping(ip_address)
    if DEMO
      sleep 0.1
      rand(3) > 0
    else
      `ping -n -c 1 -W 2 -I #{@ip} #{ip_address}`
      $?.to_i == 0
    end
  end

  def test!
    #save current state
    @previously_up = @up

    successful_tests = 0
    unsuccessful_tests = 0
    commands = []

    if @type == :ppp
      detect_ppp_ips!
      if (@previous_ip != @ip) || (@previous_gateway != @gateway)
        #only apply routing commands if there are an ip and gateway, else they will be applied on next checks, whenever new ip and gateway will be available
        if @ip && @gateway
          commands << "ip rule del priority #{@rule_priority_1}"
          commands << "ip rule del priority #{@rule_priority_2}"
          commands += route_add_commands
        end
      end
    end

    #do not ping if there is no ip or gateway (for example in case of a PPP interface down)
    if @ip && @gateway
      #for each test (in random order)...
      TEST_IPS.shuffle.each_with_index do |test, i|
        successful_test = false

        #retry for several times...
        PING_RETRIES.times do
          if DEBUG
            print "Uplink #{@description}: ping #{test}... "
            STDOUT.flush
          end
          if ping(test)
            successful_test = true
            puts 'ok' if DEBUG
            #avoid more pings to the same ip after a successful one
            break
          else
            puts 'error' if DEBUG
          end
        end

        if successful_test
          successful_tests += 1
        else
          unsuccessful_tests += 1
        end

        #if not currently doing the last test...
        if i + 1 < TEST_IPS.size
          if successful_tests >= REQUIRED_SUCCESSFUL_TESTS
            puts "Uplink #{@description}: avoiding more tests because there are enough positive ones" if DEBUG
            break
          elsif TEST_IPS.size - unsuccessful_tests < REQUIRED_SUCCESSFUL_TESTS
            puts "Uplink #{@description}: avoiding more tests because too many have been failed" if DEBUG
            break
          end
        end
      end
    end

    @up = successful_tests >= REQUIRED_SUCCESSFUL_TESTS

    if DEBUG
      state = @previously_up ? 'up' : 'down'
      state += " --> #{@up ? 'up' : 'down'}" if @up != @previously_up
      puts "Uplink #{@description}: #{successful_tests} successful tests, #{unsuccessful_tests} unsuccessful tests, state #{state}"
    end

    commands
  end

  def route_add_commands
    #- locally generated packets having as source ip the ethX ip
    #- returning packets of inbound connections coming from ethX
    #- non-first packets of outbound connections for which the first packet has been sent to ethX via multipath routing
    [
        "ip route replace table #{@table} default via #{@gateway} src #{@ip}",
        "ip rule add priority #{@rule_priority_1} from #{@ip} lookup #{@table}",
        "ip rule add priority #{@rule_priority_2} fwmark #{@fwmark} lookup #{@table}"
    ]
  end

end
