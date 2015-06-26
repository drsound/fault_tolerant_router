class Uplinks

  def initialize(config)
    @uplinks = config.each_with_index.map { |uplink, i| Uplink.new(uplink, i) }
    @uplinks.each { |uplink| uplink.priority2 = BASE_PRIORITY + @uplinks.size + uplink.id }
  end

  def each
    @uplinks.each { |uplink| yield uplink }
  end

  def initialize_routing_commands
    commands = []
    priorities = @uplinks.map { |uplink| [uplink.priority1, uplink.priority2] }.flatten.minmax
    tables = @uplinks.map { |uplink| uplink.table }.minmax

    #enable IP forwarding
    commands += ['echo 1 > /proc/sys/net/ipv4/ip_forward']

    #clean all previous configurations, try to clean more than needed (double) to avoid problems in case of changes in the
    #number of uplinks between different executions
    ((priorities.max - priorities.min + 2) * 2).times { |i| commands += ["ip rule del priority #{priorities.min + i} &> /dev/null"] }
    ((tables.max - tables.min + 2) * 2).times { |i| commands += ["ip route del table #{tables.min + i} &> /dev/null"] }

    #disable "reverse path filtering" on the uplink interfaces
    commands += ['echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter']
    commands += @uplinks.map { |uplink| "echo 2 > /proc/sys/net/ipv4/conf/#{uplink.interface}/rp_filter" }

    #set uplinks routes
    commands += @uplinks.map { |uplink| uplink.route_add_commands }

    #rule for first packet of outbound connections
    commands += ["ip rule add priority #{priorities.max + 1} from all lookup #{tables.max + 1}"]

    #set default route
    commands += set_default_route_commands

    #apply the routing changes
    commands += ['ip route flush cache']

    commands.flatten
  end

  def set_default_route_commands
    routing_uplinks = @uplinks.find_all { |uplink| uplink.routing }

    #do not use balancing if there is just one routing uplink
    if routing_uplinks.size == 1
      nexthops = "via #{routing_uplinks.first.gateway}"
    else
      nexthops = routing_uplinks.map do |uplink|
        #the "weight" parameter is optional
        tail = uplink.weight ? " weight #{uplink.weight}" : ''
        "nexthop via #{uplink.gateway}#{tail}"
      end
      nexthops = nexthops.join(' ')
    end
    #set the route for first packet of outbound connections
    ["ip route replace table #{@uplinks.map { |uplink| uplink.table }.max + 1} default #{nexthops}"]
  end

  def detect_ip_changes!
    commands = []
    need_default_route_update = false
    @uplinks.each do |uplink|
      c, n = uplink.detect_ip_changes!
      commands += c
      need_default_route_update ||= n
    end
    if need_default_route_update
      puts 'Will update default route because some of its gateways changed' if DEBUG
      commands += set_default_route_commands
    else
      puts 'Will not update default route because none of its gateways changed' if DEBUG
    end
    #apply the routing changes, in any
    commands += ['ip route flush cache'] if commands.any?
    commands
  end

  def test_routing!
    any_routing_state_changed = false
    log_messages = []
    debug_messages = []
    @uplinks.each do |uplink|
      routing_state_changed, log_message, debug_message = uplink.test_routing!
      any_routing_state_changed ||= routing_state_changed
      log_messages << log_message
      debug_messages << debug_message
    end

    debug_messages.each { |message| puts message } if DEBUG

    default_route_uplinks = @uplinks.find_all { |uplink| uplink.default_route }
    if default_route_uplinks.all? { |uplink| !uplink.up }
      default_route_uplinks.each { |uplink| uplink.routing = true }
      puts 'No default route uplink seems to be up: enabling them all!' if DEBUG
      all_default_route_uplinks_down = true
    else
      all_default_route_uplinks_down = false
    end

    #change default route if any uplink changed its routing state
    if any_routing_state_changed
      commands = set_default_route_commands
      #apply the routing changes
      commands += ['ip route flush cache']
    else
      commands = []
    end

    [commands, log_messages, all_default_route_uplinks_down]
  end

end
