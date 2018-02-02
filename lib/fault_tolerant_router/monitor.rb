def command(input)
  input = [input] if input.is_a?(String)
  input.each do |c|
    puts "Command: #{c}" if DEBUG
    if c
      `#{c}` unless DEMO
    end
  end
end

def log(logger, messages)
  logger.warn(messages.join('; ')) if messages.any?
end

def send_email(body)
  mail = Mail.new
  mail.from = EMAIL_SENDER
  mail.to = EMAIL_RECIPIENTS
  mail.subject = 'Uplinks status change'
  mail.body = body
  mail.delivery_method :smtp, SMTP_PARAMETERS
  mail.deliver
end

def monitor
  logger = Logger.new(LOG_FILE, LOG_OLD_FILES, LOG_MAX_SIZE)
  command(UPLINKS.initialize_routing!)

  list = UPLINKS.select { |uplink| uplink.default_route }.map { |uplink| uplink.description }.join(', ')
  log(logger, ["Monitor started, initial default route uplinks: #{list}"])

  loop do
    commands, messages = UPLINKS.test!
    command(commands)
    log(logger, messages)

    if SEND_EMAIL && messages.any?
      begin
        send_email(messages.join("\n"))
      rescue Exception => e
        puts "Problem sending email: #{e}" if DEBUG
        logger.error("Problem sending email: #{e}")
      end
    end

    if UPLINKS.all_priority_group_members_down?
      puts 'No waiting, because all of the priority group members are down' if DEBUG
    elsif DEMO
      puts "Waiting just 5 seconds because in demo mode, otherwise would be #{TEST_INTERVAL} seconds..." if DEBUG
      sleep 5
    else
      puts "Waiting #{TEST_INTERVAL} seconds..." if DEBUG
      sleep TEST_INTERVAL
    end
  end
end
