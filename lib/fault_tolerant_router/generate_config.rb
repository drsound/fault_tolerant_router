def generate_config(file_path)
  if File.exists?(file_path)
    puts "Configuration file #{file_path} already exists, will not overwrite!"
    exit 1
  end
  begin
    open(file_path, 'w') do |file|
      file.puts <<END
#add as many uplinks as needed
uplinks:
- interface: eth1
  ip: 1.0.0.2
  gateway: 1.0.0.1
  description: Example Provider 1
  #optional parameter
  weight: 1
  #optional parameter, default is true
  default_route: true
- interface: eth2
  ip: 2.0.0.2
  gateway: 2.0.0.1
  description: Example Provider 2
  #optional parameter
  weight: 2
  #optional parameter, default is true
  default_route: true
- interface: eth3
  ip: 3.0.0.2
  gateway: 3.0.0.1
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
  #add as many ips as needed, make sure they are reliable ones, these are Google DNS, OpenDNS DNS, public DNS server
  ips:
  - 8.8.8.8
  - 8.8.4.4
  - 208.67.222.222
  - 208.67.220.220
  - 4.2.2.2
  - 4.2.2.3
  #number of successful pinged addresses to consider an uplink to be functional
  required_successful: 4
  #ping retries in case of ping error
  ping_retries: 1
  #seconds between a check of the uplinks and the next one
  interval: 60

log:
  #file: "/var/log/fault_tolerant_router.log"
  file: "/tmp/fault_tolerant_router.log"
  #max log file size (in bytes)
  max_size: 1024000
  #number of old log files to keep
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

#base ip route table
base_table: 1

#base ip rule priority, must be higher than 32767 (default priority, see "ip rule")
base_priority: 40000

#base fwmark
base_fwmark: 1
END
    end
    puts "Example configuration saved to #{file_path}"
  rescue
    puts "Error while saving configuration file #{file_path}!"
    exit 1
  end
end