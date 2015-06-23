class Uplink
  attr_reader :interface, :weight, :gateway, :default_route, :up, :description, :type, :ip
  attr_accessor :active
  #todo: get rid of class variable
  @@count = 0

  def initialize(config)
    @id = @@count
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
    @default_route = config['default_route'].nil? ? true : config['default_route']

    #a new uplink is supposed to be up
    @up = true
    #a new uplink starts as active if it's marked as a default route
    @active = @default_route

    if @type == :static
      @ip = config['ip']
      raise "Uplink IP address not specified: #{config}" unless @ip
      @gateway = config['gateway']
      raise "Uplink gateway not specified: #{config}" unless @gateway
    else
      detect_ppp_ips!
      puts "Uplink #{@description}: initialized with [ip: #{@ip}, gateway: #{@gateway}]" if DEBUG
    end

    @@count += 1
  end

  def priorities
    [BASE_PRIORITY + @id, BASE_PRIORITY + @@count + @id]
  end

  def table
    BASE_TABLE + @id
  end

  def fwmark
    BASE_FWMARK + @id
  end

  def up_state_changed?
    @up != @previously_up
  end

  def active_state_changed?
    @active != @previously_active
  end

  def detect_ppp_ips!
    @previous_ip = @ip
    @previous_gateway = @gateway
    if DEMO
      @ip = %w(3.0.0.101 3.0.0.102).sample
      @gateway = %w(3.0.0.1 3.0.0.2).sample
    else
      ifaddr = Socket.getifaddrs.find { |i| i.name == @interface && i.addr && i.addr.ipv4? }
      if ifaddr
        @ip = ifaddr.addr.ip_address
        @gateway = ifaddr.dstaddr.ip_address
      else
        #todo: what to do if it happens?
        raise 'PPP IP address not found'
      end
    end
  end

  def detect_ip_changes!
    commands = []
    if @type == :ppp
      detect_ppp_ips!
      if @previous_ip != @ip || @previous_gateway != @gateway
        puts "Uplink #{@description}: IP change [ip: #{@previous_ip}, gateway: #{@previous_gateway}] --> [ip: #{@ip}, gateway: #{@gateway}]" if DEBUG
        commands = [route_del_commands, route_add_commands].flatten
      end
    end
    {commands: commands, active: @active, gateway_changed: @previous_gateway != @gateway}
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

  def test_routing!
    #save current state
    @previously_up = @up
    @previously_active = @active

    @successful_tests = 0
    @unsuccessful_tests = 0

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
        @successful_tests += 1
      else
        @unsuccessful_tests += 1
      end

      #if not currently doing the last test...
      if i + 1 < TEST_IPS.size
        if @successful_tests >= REQUIRED_SUCCESSFUL_TESTS
          puts "Uplink #{@description}: avoiding more tests because there are enough positive ones" if DEBUG
          break
        elsif TEST_IPS.size - @unsuccessful_tests < REQUIRED_SUCCESSFUL_TESTS
          puts "Uplink #{@description}: avoiding more tests because too many have been failed" if DEBUG
          break
        end
      end

    end

    @up = @successful_tests >= REQUIRED_SUCCESSFUL_TESTS
    @active = @up && @default_route
  end

  def debug_description
    tail = case
             when @active && !@previously_active
               'disabled --> enabled'
             when !@active && @previously_active
               'enabled --> disabled'
             when @active && @previously_active
               'enabled'
             else
               'disabled'
           end
    "Uplink #{@description}: #{@successful_tests} successful tests, #{@unsuccessful_tests} unsuccessful tests, routing #{tail}"
  end

  def log_description
    description = "Uplink #{@description}: #{@previously_up ? 'up' : 'down'}"
    if up_state_changed?
      description += " --> #{@up ? 'up' : 'down'}"
    end
    description
  end

  def route_del_commands
    [
        "ip rule del priority #{priorities.min}",
        "ip rule del priority #{priorities.max}"
    ]
  end

  def route_add_commands
    #- locally generated packets having as source ip the ethX ip
    #- returning packets of inbound connections coming from ethX
    #- non-first packets of outbound connections for which the first packet has been sent to ethX via multipath routing
    [
        "ip route replace table #{table} default via #{@gateway} src #{@ip}",
        "ip rule add priority #{priorities.min} from #{@ip} lookup #{table}",
        "ip rule add priority #{priorities.max} fwmark #{fwmark} lookup #{table}"
    ]
  end

end
