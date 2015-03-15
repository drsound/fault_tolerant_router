# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'fault_tolerant_router/version'

Gem::Specification.new do |spec|
  spec.name          = 'fault_tolerant_router'
  spec.version       = FaultTolerantRouter::VERSION
  spec.authors       = ['Alessandro Zarrilli']
  spec.email         = ['alessandro@zarrilli.net']
  #todo: fix descriptions
  spec.summary       = %q{My description}
  spec.description   = %q{My longer description}
  spec.homepage      = 'https://github.com/drsound/fault_tolerant_router'
  spec.license       = 'GPL-2'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'mail', '~> 2.6'
end
