# frozen_string_literal: true

module ITB
  # Incremental stream session over an open Pipeline.
  #
  # A session is a dumb byte pump: StreamEncryptor takes plaintext in
  # through #write and yields wire through #read / #drain_all;
  # StreamDecryptor is the mirror (wire in, plaintext out). All
  # chunking, MAC, envelope, and wire-format decisions stay inside
  # libitb. #free (or garbage collection) cancels the session and
  # frees the Go-side state.
  class StreamSession
    # Feed / drain slice size used by the pump loops.
    PUMP_BUF = 1 << 20

    # Not part of the public API -- obtain sessions via
    # Pipeline#encrypt_stream / Pipeline#decrypt_stream.
    def initialize(parent, pipe_handle)
      # Pin the parent Pipeline via a Ruby reference so it cannot be
      # garbage-collected (and its Go-side handle freed) while this
      # session is still live. The Go handle registry would degrade a
      # stale-pipe StreamWrite/Read to a bad-handle status, but the
      # nondeterminism is a correctness trap for a caller that lets
      # the parent go out of scope.
      @parent = parent
      @ended = false
      handle_ptr = FFI::MemoryPointer.new(:size_t)
      FFIBridge.check(FFIBridge.public_send(self.class::BEGIN_SYM, pipe_handle, handle_ptr))
      @handle_box = [handle_ptr.read(:size_t)]
      # Persistent drain-side scratch: one uncleared native buffer
      # plus the two out-params, reused across every #read /
      # #read_into call. A fresh zero-filled MemoryPointer per drain
      # call dominates large pump loops.
      @out_ptr = FFI::MemoryPointer.new(:char, PUMP_BUF, false)
      @need = FFI::MemoryPointer.new(:size_t)
      @fin = FFI::MemoryPointer.new(:int)
      ObjectSpace.define_finalizer(self, self.class.finalizer(@handle_box))
    end

    # The Pipeline this session runs over (kept alive for the
    # session's lifetime).
    attr_reader :parent

    # Feeds +src+ into the session. Blocks until the cipher chain
    # accepts the bytes; errors are sticky.
    def write(src)
      src_b = FFIBridge.as_bytes(src)
      FFIBridge.check(FFIBridge.ITB_Triple_StreamWrite(handle, src_b, src_b.bytesize))
      nil
    end

    # Signals end-of-input. Idempotent; #write after #end_stream fails
    # with Status::BAD_INPUT.
    def end_stream
      FFIBridge.check(FFIBridge.ITB_Triple_StreamEnd(handle))
      @ended = true
      nil
    end

    # Drains up to +max_bytes+ produced bytes; returns
    # +[chunk, finished]+. Partial drains are normal. After
    # #end_stream, an empty-spool read blocks until the terminal bytes
    # arrive or the session errors.
    def read(max_bytes = PUMP_BUF)
      buf = max_bytes <= @out_ptr.size ? @out_ptr : FFI::MemoryPointer.new(:char, max_bytes, false)
      n, finished = read_into(buf, max_bytes)
      [buf.read_bytes(n), finished]
    end

    # Allocation-free drain primitive: fills up to +cap+ bytes of the
    # caller-supplied FFI::MemoryPointer +buf+ in place and returns
    # +[n, finished]+. +buf+ is reusable across calls, which keeps a
    # high-throughput drain loop free of per-slice buffer churn
    # (#read copies each slice into a fresh String). Bytes past +n+
    # are unspecified. Raises ArgumentError when +cap+ exceeds the
    # real size of +buf+ -- libitb honours +cap+ as the write
    # ceiling, so an oversized +cap+ would license an out-of-bounds
    # native write.
    def read_into(buf, cap = buf.size)
      raise ArgumentError, "cap #{cap} exceeds buffer size #{buf.size}" if cap > buf.size

      FFIBridge.check(FFIBridge.ITB_Triple_StreamRead(handle, buf, cap, @need, @fin))
      [@need.read(:size_t), @fin.read(:int) != 0]
    end

    # Calls #end_stream (if not yet called) and returns every
    # remaining output byte.
    def drain_all
      end_stream unless @ended
      out = +""
      loop do
        n, finished = read_into(@out_ptr)
        out << @out_ptr.read_bytes(n) if n.positive?
        return out if finished
      end
    end

    # Moves +src+ (any object responding to +read(len)+) through the
    # session into +dst+ (any object responding to +write+) with
    # bounded memory: feed a slice, drain available output, repeat;
    # end + final drain on source EOF.
    def pump(src, dst)
      while (piece = src.read(PUMP_BUF))
        break if piece.empty?

        write(piece)
        # Drain whatever the chain has produced so far; a read before
        # end_stream never blocks.
        loop do
          n, = read_into(@out_ptr)
          break if n.zero?

          dst.write(@out_ptr.read_bytes(n))
        end
      end
      end_stream
      loop do
        n, finished = read_into(@out_ptr)
        dst.write(@out_ptr.read_bytes(n)) if n.positive?
        break if finished
      end
      dst.flush if dst.respond_to?(:flush)
      nil
    end

    # Cancels (if still running) and releases the session. Safe to
    # call from any state and more than once.
    def free
      h = @handle_box[0]
      return if h.zero?

      @handle_box[0] = 0
      FFIBridge.ITB_Triple_StreamFree(h)
      nil
    end

    # Finalizer proc for GC-driven release; captures only the shared
    # handle box, never the session itself.
    def self.finalizer(handle_box)
      proc do
        h = handle_box[0]
        handle_box[0] = 0
        FFIBridge.ITB_Triple_StreamFree(h) unless h.zero?
      end
    end

    private

    def handle
      @handle_box[0]
    end
  end

  # Incremental encrypt session: plaintext in, wire out.
  #
  # Stream sessions are single-threaded: the drain out-params and the
  # pooled drain buffer are per-session state shared across calls, so
  # concurrent access to one session from multiple Ruby threads is
  # undefined behaviour. Use one session per thread, or serialise
  # access externally.
  class StreamEncryptor < StreamSession
    BEGIN_SYM = :ITB_Triple_EncryptStreamBegin
  end

  # Incremental decrypt session: wire in, plaintext out.
  #
  # Stream sessions are single-threaded: the drain out-params and the
  # pooled drain buffer are per-session state shared across calls, so
  # concurrent access to one session from multiple Ruby threads is
  # undefined behaviour. Use one session per thread, or serialise
  # access externally.
  class StreamDecryptor < StreamSession
    BEGIN_SYM = :ITB_Triple_DecryptStreamBegin
  end
end
