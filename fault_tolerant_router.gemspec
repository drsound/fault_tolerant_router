# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'fault_tolerant_router/version'

Gem::Specification.new do |spec|
  spec.name = 'fault_tolerant_router'
  spec.version = FaultTolerantRouter::VERSION
  spec.authors = ['Alessandro Zarrilli']
  spec.email = ['alessandro@zarrilli.net']
  spec.summary = %q{Multiple uplinks Linux routing supervising daemon}
  spec.description = %q{A daemon, running in background on a Linux router or firewall, monitoring the state of multiple internet uplinks and changing the routing accordingly. LAN/DMZ internet traffic (outgoing connections) is load balanced between the uplinks using Linux multipath routing. The daemon monitors the state of the uplinks by routinely pinging well known IP addresses (Google public DNS servers, etc.) through each outgoing interface: once an uplink goes down, it is excluded from the multipath routing, when it comes back up, it is included again. An uplink may be assigned to a priority group: lower priority uplinks will only be used if all higher priority ones are down. That's useful to only use pay-per-traffic uplinks if no regular uplink is working. All of the routing changes are notified to the administrator by email. Fault Tolerant Router is well tested and has been used in production for several years, in several sites. See https://github.com/drsound/fault_tolerant_router for full documentation.}
  spec.homepage = 'https://github.com/drsound/fault_tolerant_router'
  spec.license = 'GPL-2'

  spec.files = `git ls-files -z`.split("\x0")
  spec.executables = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_runtime_dependency 'mail', '~> 2.6'
end
