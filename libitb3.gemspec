# frozen_string_literal: true

require_relative "lib/libitb3/version"

Gem::Specification.new do |spec|
  spec.name = "libitb3"
  spec.version = ITB::VERSION
  spec.authors = ["Andrey Kuvshinov"]
  spec.email = ["andrew@encloud.blue"]

  spec.summary = "ITB Symmetric Cipher Construction with Ambiguity-Based Security - Ruby"
  spec.description = <<~DESC.strip
    Thin proxy over the libitb3 shared library's ITB_Triple_* surface.
    Runtime FFI via the ffi gem -- no C compiler at install time, no
    compile-time link. The shared library is resolved at load time via
    ITB_LIBITB3_PATH, the in-repo dist/ directory, or the OS loader path.
  DESC
  spec.homepage = "https://github.com/everanium/itb"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 2.7"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/everanium/itb"
  spec.metadata["bug_tracker_uri"] = "https://github.com/everanium/itb/issues"

  spec.files = Dir["lib/**/*.rb", "README.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi", "~> 1.17"
end
