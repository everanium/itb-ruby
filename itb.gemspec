# frozen_string_literal: true

require_relative "lib/itb/version"

Gem::Specification.new do |spec|
  spec.name = "itb"
  spec.version = ITB::VERSION
  spec.authors = ["Andrey Kuvshinov"]
  spec.email = ["a@encloud.asia"]

  spec.summary = "Ruby binding for the ITB cipher's Triple Pipeline via the libitb shared library (ffi)"
  spec.description = <<~DESC.strip
    Thin proxy over the libitb shared library's ITB_Triple_* surface.
    Runtime FFI via the ffi gem -- no C compiler at install time, no
    compile-time link. The shared library is resolved at load time via
    ITB_LIBITB_PATH, the in-repo dist/ directory, or the OS loader path.
  DESC
  spec.homepage = "https://github.com/everanium/itb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/everanium/itb"

  spec.files = Dir["lib/**/*.rb", "README.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi", "~> 1.17"
end
