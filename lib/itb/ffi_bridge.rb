# frozen_string_literal: true

require "ffi"

module ITB
  # Runtime symbol loading over the libitb shared library (ffi gem).
  #
  # The library is loaded once per process and never unloaded. Search
  # order:
  #
  # 1. +ITB_LIBITB_PATH+ environment variable (path to the shared
  #    library file).
  # 2. +<repo>/dist/<os>-<arch>/libitb.<ext>+ resolved by walking up
  #    from this file (in-repo builds).
  # 3. The OS default loader path (+LD_LIBRARY_PATH+, +ld.so.cache+,
  #    +DYLD_LIBRARY_PATH+, +PATH+).
  #
  # Every prototype mirrors cmd/cshared/libitb.h. uintptr_t handles
  # cross as +:size_t+ (same width on every supported platform);
  # input buffers cross as +:buffer_in+ so Ruby Strings are borrowed
  # without an explicit MemoryPointer; output buffers cross as
  # +:buffer_out+ (FFI::MemoryPointer). Calls that can do nontrivial
  # Go-side work are attached with +blocking: true+ so the GVL is
  # released for their duration.
  module FFIBridge
    extend FFI::Library

    def self.lib_filename
      case RbConfig::CONFIG["host_os"]
      when /mswin|mingw|cygwin/ then "libitb.dll"
      when /darwin/ then "libitb.dylib"
      else "libitb.so"
      end
    end

    def self.dist_subdir
      os =
        case RbConfig::CONFIG["host_os"]
        when /mswin|mingw|cygwin/ then "windows"
        when /darwin/ then "darwin"
        else "linux"
        end
      arch =
        case RbConfig::CONFIG["host_cpu"].downcase
        when "x86_64", "amd64" then "amd64"
        when "aarch64", "arm64" then "arm64"
        else RbConfig::CONFIG["host_cpu"].downcase
        end
      "#{os}-#{arch}"
    end

    def self.library_candidates
      cands = []
      env = ENV["ITB_LIBITB_PATH"].to_s
      cands << env unless env.empty?
      # lib/itb/ffi_bridge.rb -> repo root is four levels up.
      repo = File.expand_path("../../../..", __dir__)
      in_repo = File.join(repo, "dist", dist_subdir, lib_filename)
      cands << in_repo if File.file?(in_repo)
      cands << lib_filename
      cands
    end

    begin
      ffi_lib library_candidates
    rescue LoadError => e
      raise LoadError,
            "itb: failed to load libitb (tried #{library_candidates.join(', ')}): #{e.message}"
    end

    # -- Library / runtime surface --------------------------------------
    attach_function :ITB_Version, [:buffer_out, :size_t, :pointer], :int
    attach_function :ITB_LastError, [:buffer_out, :size_t, :pointer], :int
    attach_function :ITB_SetMemoryLimit, [:int64], :int64
    attach_function :ITB_SetGCPercent, [:int], :int
    attach_function :ITB_HashCount, [], :int
    attach_function :ITB_HashName, [:int, :buffer_out, :size_t, :pointer], :int
    attach_function :ITB_HashWidth, [:int], :int

    # -- Triple Pipeline surface ----------------------------------------
    attach_function :ITB_Triple_Init,
                    [:string, :string, :buffer_out, :size_t, :pointer, :pointer],
                    :int, blocking: true
    attach_function :ITB_Triple_Open,
                    [:string, :buffer_in, :size_t, :string,
                     :buffer_in, :size_t, :buffer_in, :size_t, :size_t, :pointer],
                    :int, blocking: true
    attach_function :ITB_Triple_Rekey,
                    [:size_t, :buffer_in, :size_t, :buffer_in, :size_t,
                     :buffer_out, :size_t, :pointer],
                    :int, blocking: true
    attach_function :ITB_Triple_Close, [:size_t], :int
    attach_function :ITB_Triple_Free, [:size_t], :int
    attach_function :ITB_Triple_EncryptStream,
                    [:size_t, :buffer_in, :size_t, :buffer_out, :size_t, :pointer],
                    :int, blocking: true
    attach_function :ITB_Triple_DecryptStream,
                    [:size_t, :buffer_in, :size_t, :buffer_out, :size_t, :pointer],
                    :int, blocking: true
    attach_function :ITB_Triple_EncryptMessage,
                    [:size_t, :buffer_in, :size_t, :buffer_out, :size_t, :pointer],
                    :int, blocking: true
    attach_function :ITB_Triple_DecryptMessage,
                    [:size_t, :buffer_in, :size_t, :buffer_out, :size_t, :pointer],
                    :int, blocking: true
    attach_function :ITB_Triple_RegisterProfile, [:string, :string], :int
    attach_function :ITB_Triple_EncryptStreamBegin, [:size_t, :pointer], :int
    attach_function :ITB_Triple_DecryptStreamBegin, [:size_t, :pointer], :int
    attach_function :ITB_Triple_StreamWrite,
                    [:size_t, :buffer_in, :size_t], :int, blocking: true
    attach_function :ITB_Triple_StreamEnd, [:size_t], :int, blocking: true
    attach_function :ITB_Triple_StreamRead,
                    [:size_t, :buffer_out, :size_t, :pointer, :pointer],
                    :int, blocking: true
    attach_function :ITB_Triple_StreamFree, [:size_t], :int

    # Reads the ITB_LastError diagnostic (NUL-stripped). Returns the
    # empty string when no diagnostic is recorded.
    def self.last_error
      need = FFI::MemoryPointer.new(:size_t)
      rc = ITB_LastError(nil, 0, need)
      n = need.read(:size_t)
      return "" unless [Status::OK, Status::BUFFER_TOO_SMALL].include?(rc) && n > 1

      buf = FFI::MemoryPointer.new(n)
      rc = ITB_LastError(buf, n, need)
      return "" unless rc == Status::OK

      buf.read_bytes([need.read(:size_t) - 1, 0].max).force_encoding(Encoding::UTF_8)
    end

    # Maps a raw FFI return code onto nil / ITB::Error.
    def self.check(rc)
      return if rc == Status::OK

      raise Error.new(last_error, rc)
    end

    # Single retry-once dispatch site for every variable-size output
    # buffer: pre-allocate +cap+ bytes, call the block with
    # (buffer, capacity, length-out-pointer), and on BUFFER_TOO_SMALL
    # retry once with the exact size the FFI reported through the
    # length out-param. The retry is gated on the reported length
    # strictly exceeding the current capacity (pattern P1).
    def self.retry_once(cap)
      buf = FFI::MemoryPointer.new(cap)
      need = FFI::MemoryPointer.new(:size_t)
      rc = yield(buf, cap, need)
      n = need.read(:size_t)
      if rc == Status::BUFFER_TOO_SMALL && n > cap
        buf = FFI::MemoryPointer.new(n)
        rc = yield(buf, n, need)
        n = need.read(:size_t)
      end
      check(rc)
      buf.read_bytes(n)
    end

    # Normalises the accepted input types to a binary String borrowed
    # by a :buffer_in parameter.
    def self.as_bytes(data)
      s = data.to_s
      s.encoding == Encoding::BINARY ? s : s.b
    end
  end
end
