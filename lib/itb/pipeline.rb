# frozen_string_literal: true

require "uri"

module ITB
  # A Triple Pipeline session.
  #
  # #save returns the serialised session blob the receiver feeds to
  # ITB.load; #rekey refreshes it. #close zeroes key material inside
  # libitb; #free releases the Go-side handle (a GC finalizer covers
  # the non-explicit path).
  #
  # Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  # chunk, so plaintext of verified chunks is released before a later
  # chunk can fail authentication.
  class Pipeline
    # Floor capacity for blob output buffers (Init / Save / Rekey).
    BLOB_CAP = 64 * 1024

    # Not part of the public API -- use Pipeline.init / Pipeline.load /
    # Pipeline.load_f (or the ITB module shortcuts).
    def initialize(handle)
      # The one-element box is shared with the finalizer proc so the
      # proc does not capture self (which would defeat GC).
      @handle_box = [handle]
      # Serialises access to the pooled Message scratch buffer; the
      # blocking FFI calls release the GVL, so concurrent
      # encrypt_message / decrypt_message on one Pipeline would
      # otherwise share the buffer mid-flight.
      @cipher_lock = Mutex.new
      ObjectSpace.define_finalizer(self, self.class.finalizer(@handle_box))
    end

    # Constructs a fresh session against the named profile
    # (ITB_Triple_Init). +opts+ is an opts string or Hash rendered to
    # the URL-query grammar libitb validates. The session blob is
    # available through #save. On a blob-buffer retry the Init re-runs
    # and yields a fresh session (the undersized attempt is closed by
    # libitb before returning).
    def self.init(profile, opts = nil)
      opts_s = render_opts(opts)
      handle_ptr = FFI::MemoryPointer.new(:size_t)
      FFIBridge.retry_once(BLOB_CAP) do |buf, cap, need|
        FFIBridge.ITB_Triple_Init(profile, opts_s, buf, cap, need, handle_ptr)
      end
      new(handle_ptr.read(:size_t))
    end

    # Reconstructs a session from a blob produced by #save or #rekey
    # (ITB_Triple_Load). The blob's embedded profile record is the
    # sole structural source -- no profile name, no opts. +masters+ is
    # nil to use the blob-embedded masters or a +[perm, wrap]+ pair to
    # override them.
    def self.load(blob, masters: nil)
      blob_b = FFIBridge.as_bytes(blob)
      pm, wm, count = masters_triple(masters)
      handle_ptr = FFI::MemoryPointer.new(:size_t)
      FFIBridge.check(
        FFIBridge.ITB_Triple_Load(
          blob_b, blob_b.bytesize, pm, pm.bytesize, wm, wm.bytesize, count, handle_ptr
        )
      )
      new(handle_ptr.read(:size_t))
    end

    # Pipeline.load for a blob stored in a file (ITB_Triple_LoadF);
    # the file is read inside the library.
    def self.load_f(path, masters: nil)
      pm, wm, count = masters_triple(masters)
      handle_ptr = FFI::MemoryPointer.new(:size_t)
      FFIBridge.check(
        FFIBridge.ITB_Triple_LoadF(
          path.to_s, pm, pm.bytesize, wm, wm.bytesize, count, handle_ptr
        )
      )
      new(handle_ptr.read(:size_t))
    end

    # Folds the optional +[perm, wrap]+ pair into the
    # (perm_master, wrap_master, masters_count) triple the Load entries
    # take: count 0 selects the blob-embedded masters, count 2
    # overrides them.
    def self.masters_triple(masters)
      return ["", "", 0] if masters.nil?

      [FFIBridge.as_bytes(masters[0]), FFIBridge.as_bytes(masters[1]), 2]
    end
    private_class_method :masters_triple

    # The current serialised session blob (binary String) -- the bytes
    # init produced, the bytes load re-marshalled, or the bytes of the
    # latest #rekey.
    def save
      h = handle
      FFIBridge.retry_once(BLOB_CAP) do |buf, cap, need|
        FFIBridge.ITB_Triple_Save(h, buf, cap, need)
      end
    end

    # Writes the current session blob to +path+ inside the library
    # (mode 0600; the containing directory must exist).
    def save_f(path)
      FFIBridge.check(FFIBridge.ITB_Triple_SaveF(handle, path.to_s))
      nil
    end

    # Rotates the parallax + wrapper masters and returns the refreshed
    # session blob (also observable through #save). Must not run
    # concurrently with cipher calls or open stream sessions on the
    # same Pipeline.
    def rekey(perm, wrap)
      pm = FFIBridge.as_bytes(perm)
      wm = FFIBridge.as_bytes(wrap)
      h = handle
      FFIBridge.retry_once(BLOB_CAP) do |buf, cap, need|
        FFIBridge.ITB_Triple_Rekey(h, pm, pm.bytesize, wm, wm.bytesize, buf, cap, need)
      end
    end

    # Sets the worker cap for every subsequent cipher call. +n+ is
    # clamped, never rejected: n <= 0 selects auto (runtime.NumCPU),
    # 1..256 pins the cap, larger values are treated as 256. The cap
    # is per-machine tuning and is never written to the blob.
    def max_workers(n)
      FFIBridge.check(FFIBridge.ITB_Triple_MaxWorkers(handle, n))
      nil
    end

    # Zeroes the Pipeline's key material and marks it closed.
    # Idempotent; subsequent cipher calls raise ITB::Error with
    # Status::TRIPLE_CLOSED.
    def close
      FFIBridge.check(FFIBridge.ITB_Triple_Close(handle))
      nil
    end

    # Single Message encrypt: one call, one self-contained wire.
    def encrypt_message(plaintext)
      cipher(:ITB_Triple_EncryptMessage, plaintext)
    end

    # Receive-side counterpart of #encrypt_message.
    def decrypt_message(wire)
      cipher(:ITB_Triple_DecryptMessage, wire)
    end

    # Allocation-free sibling of #encrypt_message: writes the wire
    # into the caller-supplied FFI::MemoryPointer +dst+ (reusable
    # across calls) and returns the wire byte count. Raises
    # ITB::Error with Status::BUFFER_TOO_SMALL when +cap+ is
    # insufficient; the pre-allocation formula
    # payload * 5/4 + 65536 typically suffices for large payloads,
    # but small payloads may still expand past it -- on
    # BUFFER_TOO_SMALL the caller re-issues with a larger +dst+ or
    # falls back to #encrypt_message (the String-returning variant,
    # whose retry path absorbs the expansion). Raises ArgumentError
    # when +cap+ exceeds the real size of +dst+. Bytes past the
    # returned count are unspecified.
    def encrypt_message_into(plaintext, dst, cap = dst.size)
      cipher_into(:ITB_Triple_EncryptMessage, plaintext, dst, cap)
    end

    # Receive-side counterpart of #encrypt_message_into: fills +dst+
    # with plaintext and returns the byte count.
    def decrypt_message_into(wire, dst, cap = dst.size)
      cipher_into(:ITB_Triple_DecryptMessage, wire, dst, cap)
    end

    # Opens an incremental encrypt session (plaintext in, wire out).
    # With a block, yields the session and frees it on return.
    def encrypt_stream
      session = StreamEncryptor.new(self, handle)
      return session unless block_given?

      begin
        yield session
      ensure
        session.free
      end
    end

    # Opens an incremental decrypt session (wire in, plaintext out).
    # With a block, yields the session and frees it on return.
    def decrypt_stream
      session = StreamDecryptor.new(self, handle)
      return session unless block_given?

      begin
        yield session
      ensure
        session.free
      end
    end

    # One-shot stream encrypt for callers holding the whole plaintext
    # in memory: routes the payload through the Pipeline's stream
    # chain in a single FFI round trip and returns the wire. Prefer
    # #encrypt_stream for bounded-memory streaming.
    def encrypt_stream_one_shot(plaintext)
      cipher(:ITB_Triple_EncryptStream, plaintext)
    end

    # Receive-side counterpart of #encrypt_stream_one_shot.
    def decrypt_stream_one_shot(wire)
      cipher(:ITB_Triple_DecryptStream, wire)
    end

    # Releases the Pipeline handle (libitb closes and zeroes key
    # material first). Safe to call more than once.
    def free
      h = @handle_box[0]
      return if h.zero?

      @handle_box[0] = 0
      @cipher_lock.synchronize do
        @scratch&.free
        @scratch = nil
      end
      FFIBridge.ITB_Triple_Free(h)
      nil
    end

    def inspect
      "#<ITB::Pipeline #{handle.zero? ? 'freed' : 'open'}>"
    end
    alias to_s inspect

    # Finalizer proc for GC-driven release; captures only the shared
    # handle box, never the Pipeline itself.
    def self.finalizer(handle_box)
      proc do
        h = handle_box[0]
        handle_box[0] = 0
        FFIBridge.ITB_Triple_Free(h) unless h.zero?
      end
    end

    # Renders nil / String / Hash opts to the URL-query pass-through
    # string. The binding performs no validation -- libitb rejects
    # unknown keys or bad values with a diagnostic surfaced via
    # ITB::Error.
    def self.render_opts(opts)
      case opts
      when nil then ""
      when String then opts
      when Hash
        URI.encode_www_form(opts.map { |k, v| [k.to_s, v.to_s] })
      else
        raise Error, "opts must be nil, a String, or a Hash"
      end
    end

    private

    def handle
      @handle_box[0]
    end

    # Pre-allocation formula for Message output buffers:
    # max(65536, payload * 5/4 + 65536).
    def out_cap(payload)
      payload + (payload / 4) + 65_536
    end

    # Grow-only pooled native scratch for Message output buffers,
    # reused across calls under @cipher_lock. Uncleared on purpose:
    # libitb writes the first +need+ bytes and only those are read
    # back. A fresh zero-filled MemoryPointer per call costs an
    # mmap + memset of ~1.25x the payload every Message, which
    # dominates large-payload throughput.
    def scratch(cap)
      cur = @scratch
      return cur if cur && cur.size >= cap

      cur&.free
      @scratch = FFI::MemoryPointer.new(:char, cap, false)
    end

    # Shared body for the buffer-in / buffer-out cipher entries.
    # Retry-once discipline matches FFIBridge.retry_once: on
    # BUFFER_TOO_SMALL with a reported length strictly above the
    # current capacity, the scratch grows to the exact size and the
    # call re-runs once.
    def cipher(sym, src)
      src_b = FFIBridge.as_bytes(src)
      h = handle
      @cipher_lock.synchronize do
        buf = scratch(out_cap(src_b.bytesize))
        need = (@need ||= FFI::MemoryPointer.new(:size_t))
        rc = FFIBridge.public_send(sym, h, src_b, src_b.bytesize, buf, buf.size, need)
        n = need.read(:size_t)
        if rc == Status::BUFFER_TOO_SMALL && n > buf.size
          buf = scratch(n)
          rc = FFIBridge.public_send(sym, h, src_b, src_b.bytesize, buf, buf.size, need)
          n = need.read(:size_t)
        end
        FFIBridge.check(rc)
        buf.read_bytes(n)
      end
    end

    # Shared body for the caller-buffer Message entries: one FFI call
    # into +dst+, no retry (the caller owns capacity policy), byte
    # count out. +cap+ is the write ceiling libitb honours, so it
    # must never exceed the real size of +dst+.
    def cipher_into(sym, src, dst, cap)
      raise ArgumentError, "cap #{cap} exceeds buffer size #{dst.size}" if cap > dst.size

      src_b = FFIBridge.as_bytes(src)
      h = handle
      @cipher_lock.synchronize do
        need = (@need ||= FFI::MemoryPointer.new(:size_t))
        FFIBridge.check(FFIBridge.public_send(sym, h, src_b, src_b.bytesize, dst, cap, need))
        need.read(:size_t)
      end
    end
  end
end
