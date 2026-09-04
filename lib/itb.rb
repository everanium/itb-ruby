# frozen_string_literal: true

require "json"

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
#   receiver = ITB.load(sender.save)
#   wire = sender.encrypt_message("hello")
#   raise unless receiver.decrypt_message(wire) == "hello"
module ITB
  # Floor capacity for profile-JSON output buffers (Inspect / Lookup /
  # Profiles).
  JSON_CAP = 4 * 1024

  class << self
    # Constructs a fresh Pipeline against the named profile. The
    # session blob is available through Pipeline#save.
    def create(profile, opts = nil)
      Pipeline.init(profile, opts)
    end
    alias init create

    # Reconstructs a Pipeline from a blob produced by Pipeline#save or
    # Pipeline#rekey. The blob's embedded profile record is the sole
    # structural source -- no profile name, no opts. +masters+ is nil
    # to use the blob-embedded masters, or a +[perm, wrap]+ pair to
    # override them.
    def load(blob, masters: nil)
      Pipeline.load(blob, masters: masters)
    end

    # ITB.load for a blob stored in a file; the file is read inside
    # the library.
    def load_f(path, masters: nil)
      Pipeline.load_f(path, masters: masters)
    end

    # Decodes the blob's embedded profile record without opening a
    # Pipeline and returns it as a Hash (the JSON object libitb
    # emits: keys "name", "mode", "width", "hash", "hashes",
    # "keybits", "mac", "tagstub", "chunk", "wrapper", "outer",
    # "parallax", "palette", "segment"). No registry read, no
    # primitive probe -- a primitive name the local build lacks is
    # returned unchanged.
    def inspect_blob(blob)
      blob_b = FFIBridge.as_bytes(blob)
      json_out do |buf, cap, need|
        FFIBridge.ITB_Triple_Inspect(blob_b, blob_b.bytesize, buf, cap, need)
      end
    end

    # Registers a profile record under +name+ so subsequent ITB.create
    # / ITB.lookup calls resolve it. +profile+ is the record as a Hash
    # (the shape ITB.inspect_blob / ITB.lookup return) or an
    # already-encoded JSON String; a "name" key inside it, if present,
    # must be empty or equal to +name+. Validation (name pattern,
    # reserved prefixes, field rules) is performed by libitb; a
    # duplicate name fails with Status::PROFILE_EXISTS.
    def register(name, profile)
      text = profile.is_a?(String) ? profile : JSON.generate(profile)
      FFIBridge.check(FFIBridge.ITB_Triple_Register(name, text))
      nil
    end

    # Returns the profile record registered under +name+ (a shipped
    # catalogue entry or a prior ITB.register) as a Hash. An unknown
    # name raises ITB::Error with Status::UNKNOWN_PROFILE.
    def lookup(name)
      json_out do |buf, cap, need|
        FFIBridge.ITB_Triple_Lookup(name, buf, cap, need)
      end
    end

    # The sorted list of every registered profile name.
    def profiles
      json_out do |buf, cap, need|
        FFIBridge.ITB_Triple_Profiles(buf, cap, need)
      end
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

    private

    # Shared body for the JSON-returning catalogue entries: retry-once
    # buffer, then a standard-library JSON decode of the bytes libitb
    # wrote.
    def json_out(&call)
      JSON.parse(FFIBridge.retry_once(JSON_CAP, &call).force_encoding(Encoding::UTF_8))
    end
  end
end
