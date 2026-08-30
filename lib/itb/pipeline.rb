# frozen_string_literal: true

require "uri"

module ITB
  # A Triple Pipeline session plus its exported blob bytes.
  #
  # The blob carries the session bundle the receiver feeds to
  # ITB.open; #rekey refreshes it. #close zeroes key material inside
  # libitb; #free releases the Go-side handle (a GC finalizer covers
  # the non-explicit path).
  #
  # Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  # chunk, so plaintext of verified chunks is released before a later
  # chunk can fail authentication.
  class Pipeline
    # Floor capacity for blob output buffers (Init / Rekey).
    BLOB_CAP = 64 * 1024

    # Constructs a session against the named profile. With +blob+ nil
    # a fresh session is initialised (ITB_Triple_Init); with +blob+
    # given the session is reconstructed from a bundle produced by a
    # prior init or #rekey (ITB_Triple_Open). +opts+ is an opts string
    # or Hash rendered to the URL-query grammar libitb validates;
    # +masters+ is nil to use the blob-embedded masters or a
    # +[perm, wrap]+ pair to override them (open path only).
    def initialize(profile, blob = nil, opts = nil, masters: nil)
      opts_s = self.class.render_opts(opts)
      handle_ptr = FFI::MemoryPointer.new(:size_t)
      if blob.nil?
        # On a blob-buffer retry the Init re-runs and yields a fresh
        # session (the undersized attempt is closed by libitb before
        # returning).
        @blob = FFIBridge.retry_once(BLOB_CAP) do |buf, cap, need|
          FFIBridge.ITB_Triple_Init(profile, opts_s, buf, cap, need, handle_ptr)
        end
      else
        blob_b = FFIBridge.as_bytes(blob)
        if masters.nil?
          pm, wm, count = "", "", 0
        else
          pm = FFIBridge.as_bytes(masters[0])
          wm = FFIBridge.as_bytes(masters[1])
          raise Error, "master override buffers must be non-empty" if pm.empty? || wm.empty?

          count = 2
        end
        FFIBridge.check(
          FFIBridge.ITB_Triple_Open(
            profile, blob_b, blob_b.bytesize, opts_s,
            pm, pm.bytesize, wm, wm.bytesize, count, handle_ptr
          )
        )
        @blob = blob_b
      end
      # The one-element box is shared with the finalizer proc so the
      # proc does not capture self (which would defeat GC).
      @handle_box = [handle_ptr.read(:size_t)]
      # Serialises access to the pooled Message scratch buffer; the
      # blocking FFI calls release the GVL, so concurrent
      # encrypt_message / decrypt_message on one Pipeline would
      # otherwise share the buffer mid-flight.
      @cipher_lock = Mutex.new
      ObjectSpace.define_finalizer(self, self.class.finalizer(@handle_box))
    end

    # The exported session bundle bytes for the receiver side.
    attr_reader :blob

    # Rotates the parallax + wrapper masters and refreshes #blob. Must
    # not run concurrently with cipher calls or open stream sessions
    # on the same Pipeline.
    def rekey(perm, wrap)
      pm = FFIBridge.as_bytes(perm)
      wm = FFIBridge.as_bytes(wrap)
      @blob = FFIBridge.retry_once([BLOB_CAP, @blob.bytesize].max) do |buf, cap, need|
        FFIBridge.ITB_Triple_Rekey(handle, pm, pm.bytesize, wm, wm.bytesize, buf, cap, need)
      end
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

    # The blob bytes are elided -- session-bundle material does not
    # belong in debug logs.
    def inspect
      "#<ITB::Pipeline blob_len=#{@blob.bytesize}>"
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
    # Retry-once discipline matches FFIBridge.retry_once (pattern P1):
    # on BUFFER_TOO_SMALL with a reported length strictly above the
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
