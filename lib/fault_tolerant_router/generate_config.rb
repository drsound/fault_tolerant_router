def generate_config(file_path)
  if File.exists?(file_path)
    puts "Configuration file #{file_path} already exists, will not overwrite!"
    exit 1
  end
  begin
    open(file_path, 'w') do |file|
      file.puts <<END
#see https://github.com/drsound/fault_tolerant_router for a complete parameter
#description

#add as many uplinks as needed
uplinks:
- interface: eth1
  type: static
  ip: 1.0.0.2
  gateway: 1.0.0.1
  description: Example Provider 1
  #optional parameter
  weight: 1
  #optional parameter, default is true
  default_route: true
- interface: eth2
  type: static
  ip: 2.0.0.2
  gateway: 2.0.0.1
  description: Example Provider 2
  #optional parameter
  weight: 2
  #optional parameter, default is true
  default_route: true
- interface: ppp0
  type: ppp
  description: Example Provider 3
  #optional parameter
  weight: 1
  #optional parameter, default is true
  default_route: true

downlinks:
  lan: eth0
  #leave blank if you have no DMZ
  dmz:

tests:
  #an array of IP addresses to ping to verify the uplinks state. You can add as
  #many as you wish. Predefined ones are Google DNS, OpenDNS DNS, other public
  #DNS. Every time an uplink is tested the IP addresses are shuffled, so listing
  #order is not important.
  ips:
  - 8.8.8.8
  - 8.8.4.4
  - 208.67.222.222
  - 208.67.220.220
  - 4.2.2.2
  - 4.2.2.3
  #number of successfully pinged IP addresses to consider an uplink to be
  #functional
  required_successful: 4
  #number of ping retries before giving up on an IP
  ping_retries: 1
  #seconds between a check of the uplinks and the next one
  interval: 60

log:
  #file: "/var/log/fault_tolerant_router.log"
  file: "/tmp/fault_tolerant_router.log"
  #maximum log file size (in bytes). Once reached this size, the log file will
  #be rotated.
  max_size: 1024000
  #number of old rotated files to keep
  old_files: 10

email:
  send: false
  sender: router@domain.com
  recipients:
  - user1@domain.com
  - user2@domain.com
  - user3@domain.com
  #see http://ruby-doc.org/stdlib-2.2.0/libdoc/net/smtp/rdoc/Net/SMTP.html
  smtp_parameters:
    address: smtp.gmail.com
    port: 587
    #domain: domain.com
    authentication: :login
    enable_starttls_auto: true
    user_name: user@gmail.com
    password: secret-password

#base IP route table number, just need to change if you are already using
#multiple routing tables
base_table: 1

#just need to change if you are already using ip policy routing, to avoid
#overlapping, must be higher than 32767 (default priority, see output of
#"ip rule" command)
base_priority: 40000

#just need to change if you are already using packet marking, to avoid
#overlapping
base_fwmark: 1
END
    end
    puts "Example configuration saved to #{file_path}"
  rescue
    puts "Error while saving configuration file #{file_path}!"
    exit 1
  end
end