class Uplinks
  include Enumerable

  def initialize(config)
    @uplinks = config.each_with_index.map { |uplink, i| Uplink.new(uplink, i) }
    @uplinks.each { |uplink| uplink.rule_priority_2 = BASE_PRIORITY + @uplinks.size + uplink.id }
    @default_route_table = @uplinks.map { |uplink| uplink.table }.max + 1
  end

  def each
    @uplinks.each { |uplink| yield uplink }
  end

  def initialize_routing!
    commands = []
    rule_priorities = @uplinks.map { |uplink| [uplink.rule_priority_1, uplink.rule_priority_2] }.flatten.minmax
    tables = @uplinks.map { |uplink| uplink.table }.minmax

    #enable IP forwarding
    commands << 'echo 1 > /proc/sys/net/ipv4/ip_forward'

    #clean all previous configurations, try to clean more than needed (double) to avoid problems in case of changes in the
    #number of uplinks between different executions
    ((rule_priorities.max - rule_priorities.min + 2) * 2).times { |i| commands << "ip rule del priority #{rule_priorities.min + i} &> /dev/null" }
    ((tables.max - tables.min + 2) * 2).times { |i| commands << "ip route del table #{tables.min + i} &> /dev/null" }

    #disable "reverse path filtering" on the uplink interfaces
    commands << 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter'
    commands += @uplinks.map { |uplink| "echo 2 > /proc/sys/net/ipv4/conf/#{uplink.interface}/rp_filter" }

    #set uplinks routes
    commands += @uplinks.map { |uplink| uplink.route_add_commands }

    #rule for first packet of outbound connections
    commands << "ip rule add priority #{rule_priorities.max + 1} from all lookup #{tables.max + 1}"

    #set default route
    commands += update_default_route!

    #apply the routing changes
    commands << 'ip route flush cache'

    commands.flatten
  end

  def update_default_route!
    #select uplinks that are up and with a specified priority group value
    selected = @uplinks.find_all { |uplink| uplink.up && uplink.priority_group }
    puts "Choosing default route: available uplinks: #{selected.map { |uplink| uplink.description }.join(', ')}" if DEBUG

    #restrict the selection to the members of highest priority group
    highest_available_priority = selected.map { |uplink| uplink.priority_group }.min
    selected = selected.find_all { |uplink| uplink.priority_group == highest_available_priority }
    puts "Choosing default route: highest priority group uplinks: #{selected.map { |uplink| uplink.description }.join(', ')}" if DEBUG

    changes = false
    #assign default route status to the uplinks and detect changes from previous configuration
    @uplinks.each do |uplink|
      uplink.previously_default_route = uplink.default_route
      uplink.default_route = selected.include?(uplink)
      changes ||= uplink.default_route != uplink.previously_default_route
    end

    #check if any default route uplink changed its gateway (for example due to a ppp update)
    if @uplinks.any? { |uplink| uplink.default_route && uplink.gateway != uplink.previous_gateway }
      changes ||= true
      puts "Choosing default route: detected gateway change in a default route uplink" if DEBUG
    end

    commands = []
    if selected.size == 0
      puts 'Choosing default route: no available uplinks, no need for an update' if DEBUG
    elsif !changes
      puts 'Choosing default route: no changes, no need for an update' if DEBUG
    else
      puts 'Choosing default route: changes detected, update needed' if DEBUG
      #do not use balancing if there is just one routing uplink
      if selected.size == 1
        nexthops = "via #{selected.first.gateway}"
      else
        nexthops = selected.map do |uplink|
          #the "weight" parameter is optional
          tail = uplink.weight ? " weight #{uplink.weight}" : ''
          "nexthop via #{uplink.gateway}#{tail}"
        end
        nexthops = nexthops.join(' ')
      end

      #set the route for first packet of outbound connections
      commands << "ip route replace table #{@default_route_table} default #{nexthops}"
    end

    commands
  end

  def test!
    commands = []
    messages = []
    @uplinks.each do |uplink|
      c = uplink.test!
      commands += c
    end

    commands += update_default_route!

    #apply the routing changes, in any
    commands << 'ip route flush cache' if commands.any?

    changes = false
    @uplinks.each do |uplink|
      current = uplink.ip || 'none'
      previous = uplink.previous_ip || 'none'
      changes ||= current != previous
      ip = current == previous ? current : "#{previous} --> #{current}"

      current = uplink.gateway || 'none'
      previous = uplink.previous_gateway || 'none'
      changes ||= current != previous
      gateway = current == previous ? current : "#{previous} --> #{current}"

      current = uplink.up ? 'up' : 'down'
      previous = uplink.previously_up ? 'up' : 'down'
      changes ||= current != previous
      up = current == previous ? current : "#{previous} --> #{current}"

      current = uplink.default_route ? 'routing' : 'standby'
      previous = uplink.previously_default_route ? 'routing' : 'standby'
      changes ||= current != previous
      default_route = current == previous ? current : "#{previous} --> #{current}"

      messages << "Uplink #{uplink.description}: ip #{ip}, gateway #{gateway}, #{up}, #{default_route}"
    end
    messages = [] unless changes

    [commands, messages]
  end

  def all_priority_group_members_down?
    @uplinks.all? { |uplink| !uplink.priority_group || !uplink.up }
  end

end
