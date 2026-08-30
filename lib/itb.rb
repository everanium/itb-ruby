# frozen_string_literal: true

require "itb/version"
require "itb/ffi_bridge"
require "itb/pipeline"
require "itb/stream"
require "itb/errors"

# Thin Ruby proxy over the libitb shared library's Triple Pipeline
# surface.
#
# The gem wraps the ITB_Triple_* C ABI exported by cmd/cshared
# (libitb.so / .dylib / .dll) through the ffi gem -- runtime FFI, no
# compile-time link, no C compiler at install time. Every hash-name /
# MAC-name / cipher-name / profile-name is an opaque string passed
# through to Go for validation; the binding carries no ITB
# construction logic of its own.
#
# Example:
#
#   require "itb"
#
#   sender = ITB.create("singlemsg-triple-mac-v1")
#   receiver = ITB.open("singlemsg-triple-mac-v1", sender.blob)
#   wire = sender.encrypt_message("hello")
#   raise unless receiver.decrypt_message(wire) == "hello"
module ITB
  # One shipped hash primitive: name + native width in bits.
  HashInfo = Struct.new(:name, :width)

  # Shipped Triple profile names accepted by ITB.create / ITB.open.
  # The authoritative registry lives in Go; this roster mirrors it for
  # discovery from the shell and tests.
  PROFILES = %w[
    streaming-aead-triple-mac-v1
    streaming-noaead-triple-v1
    singlemsg-triple-mac-v1
    singlemsg-triple-nomac-v1
    blob-triple-mac-v1
    streaming-aead-triple-mac-mixed-v1
    streaming-noaead-triple-mixed-v1
    singlemsg-triple-mac-mixed-v1
    singlemsg-triple-nomac-mixed-v1
  ].freeze

  class << self
    # Constructs a fresh Pipeline against the named profile.
    def create(profile, opts = nil)
      Pipeline.new(profile, nil, opts)
    end

    # Reconstructs a Pipeline from a blob produced by ITB.create (via
    # Pipeline#blob) or Pipeline#rekey. +masters+ is nil to use the
    # blob-embedded masters, or a +[perm, wrap]+ pair to override
    # them.
    def open(profile, blob, opts = nil, masters: nil)
      Pipeline.new(profile, blob, opts, masters: masters)
    end

    # The shipped hash primitive roster in registry order, as
    # HashInfo structs.
    def hashes
      Array.new(FFIBridge.ITB_HashCount) do |i|
        need = FFI::MemoryPointer.new(:size_t)
        buf = FFI::MemoryPointer.new(128)
        FFIBridge.check(FFIBridge.ITB_HashName(i, buf, 128, need))
        name = buf.read_bytes([need.read(:size_t) - 1, 0].max)
                  .force_encoding(Encoding::UTF_8)
        HashInfo.new(name, FFIBridge.ITB_HashWidth(i))
      end
    end

    # The shipped Triple profile names.
    def profiles
      PROFILES
    end

    # Returns the libitb library version string.
    def version
      need = FFI::MemoryPointer.new(:size_t)
      rc = FFIBridge.ITB_Version(nil, 0, need)
      unless [Status::OK, Status::BUFFER_TOO_SMALL].include?(rc)
        raise Error.new(FFIBridge.last_error, rc)
      end
      n = need.read(:size_t)
      return "" if n <= 1

      buf = FFI::MemoryPointer.new(n)
      FFIBridge.check(FFIBridge.ITB_Version(buf, n, need))
      buf.read_bytes([need.read(:size_t) - 1, 0].max).force_encoding(Encoding::UTF_8)
    end

    # Sets the Go runtime's soft heap limit in bytes and returns the
    # previous limit. A negative value queries without changing.
    def set_memory_limit(limit_bytes)
      FFIBridge.ITB_SetMemoryLimit(limit_bytes)
    end

    # Sets the Go GC trigger percentage and returns the previous
    # value. A negative value queries without changing.
    def set_gc_percent(pct)
      FFIBridge.ITB_SetGCPercent(pct)
    end

    # Registers a user-defined Triple profile under +name+ so
    # subsequent ITB.create / ITB.open calls resolve it. +opts+
    # follows the register-profile grammar validated by Go. A
    # duplicate name fails with Status::PROFILE_EXISTS.
    def register_profile(name, opts)
      FFIBridge.check(
        FFIBridge.ITB_Triple_RegisterProfile(name, Pipeline.render_opts(opts))
      )
      nil
    end
  end
end
