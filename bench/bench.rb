# frozen_string_literal: true

# Micro-benchmarks for the Ruby binding: encrypt_message (Single
# Message profile) and stream-session encrypt (Streaming Non-AEAD
# profile) throughput at 1 MiB / 16 MiB / 64 MiB. Wall-clock via
# Process.clock_gettime(MONOTONIC); output is a fixed-width table:
#
#   bench             size     mb_per_sec
#   message           1 MiB    <n>
#   ...
#
# Configuration is driven by environment variables so a side-by-side
# comparison with the root Go bench harness is straightforward:
#
#   ITB_NONCE_BITS      512         shipped secure default
#   ITB_KEY_BITS        1024        matches root Go BENCH3.md table
#   ITB_WITH_PARALLAX   false       root Go bench runs without parallax
#   ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
#   ITB_INNER_HASH      (profile)   opaque hash name
#   ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
#   ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
#   ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)

require "securerandom"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "itb"

# Per-case iteration floor alongside the wall-clock budget.
BENCH_MIN_ITERS = 3
SIZES = [1 << 20, 16 << 20, 64 << 20].freeze

def bench_min_seconds
  v = ENV["ITB_BENCH_MIN_SEC"].to_f
  v.positive? ? v : 5.0
end

# Reads the bench-shape env vars and builds the opts Hash. Defaults
# match root Go BENCH3.md so numbers are directly comparable.
def build_opts
  opts = {
    "nonceBits" => (ENV["ITB_NONCE_BITS"] || "512"),
    "keyBits" => (ENV["ITB_KEY_BITS"] || "1024"),
    "withParallax" => %w[true 1].include?(ENV["ITB_WITH_PARALLAX"]) ? "true" : "false",
    "withWrapper" => %w[true 1].include?(ENV["ITB_WITH_WRAPPER"]) ? "true" : "false"
  }
  inner = ENV["ITB_INNER_HASH"].to_s
  opts["innerHash"] = inner unless inner.empty?
  mac = ENV["ITB_MAC_NAME"].to_s
  opts["macName"] = mac unless mac.empty?
  opts
end

def profile_name(shape_env, fallback)
  p = ENV[shape_env].to_s
  return p unless p.empty?
  p = ENV["ITB_PROFILE"].to_s
  p.empty? ? fallback : p
end

def size_label(size)
  size >= (1 << 20) ? "#{size >> 20} MiB" : "#{size >> 10} KiB"
end

def mono
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

# Runs the block until the wall-clock budget is spent (with an
# iteration floor + one untimed warm-up), then prints one table row.
def bench_case(name, size)
  yield # warm-up
  budget = bench_min_seconds
  start = mono
  elapsed = 0.0
  iters = 0
  while elapsed < budget || iters < BENCH_MIN_ITERS
    yield
    iters += 1
    elapsed = mono - start
  end
  mb = size * iters / (1024.0 * 1024.0)
  printf("%-17s %-8s %.1f\n", name, size_label(size), mb / elapsed)
end

def bench_message
  pipe = ITB.create(profile_name("ITB_MSG_PROFILE", "singlemsg-triple-nomac-v1"), build_opts)
  SIZES.each do |size|
    # CSPRNG-fill so plaintext content matches the root Go bench
    # (crypto/rand). Not in the timing loop.
    plain = SecureRandom.random_bytes(size)
    # The allocating public entry point is measured (one result
    # String per call) so the row stays shape-comparable with the
    # Julia and R message rows, which measure the same allocating
    # path. The caller-buffer #encrypt_message_into variant trades
    # that per-call copy for a reusable buffer; its throughput is
    # not part of the canonical table.
    bench_case("message", size) { pipe.encrypt_message(plain) }
    # Pre-encrypt one wire outside the decrypt timing loop.
    dec_wire = pipe.encrypt_message(plain)
    bench_case("message-dec", size) { pipe.decrypt_message(dec_wire) }
  end
  pipe.free
end

def bench_stream_one_shot
  pipe = ITB.create(profile_name("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"), build_opts)
  SIZES.each do |size|
    plain = SecureRandom.random_bytes(size)
    bench_case("stream_one_shot", size) { pipe.encrypt_stream_one_shot(plain) }
    # Pre-encrypt one wire outside the decrypt timing loop.
    dec_wire = pipe.encrypt_stream_one_shot(plain)
    bench_case("stream_one_shot-dec", size) { pipe.decrypt_stream_one_shot(dec_wire) }
  end
  pipe.free
end

def bench_stream
  pipe = ITB.create(profile_name("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"), build_opts)
  slice = ITB::StreamSession::PUMP_BUF
  # One reusable drain buffer for the whole run: models a realistic
  # consumer that owns its buffer instead of allocating a fresh slice
  # per drain call.
  scratch = FFI::MemoryPointer.new(:char, slice, false)
  SIZES.each do |size|
    plain = SecureRandom.random_bytes(size)
    bench_case("stream", size) do
      pipe.encrypt_stream do |enc|
        off = 0
        while off < plain.bytesize
          enc.write(plain.byteslice(off, slice))
          off += slice
          # Drain available output so the spool stays bounded.
          loop do
            n, = enc.read_into(scratch)
            break if n.zero?
          end
        end
        enc.end_stream
        loop do
          _n, finished = enc.read_into(scratch)
          break if finished
        end
      end
    end
    # Pre-encrypt one wire outside the decrypt timing loop.
    dec_wire_parts = []
    pipe.encrypt_stream do |enc|
      off = 0
      while off < plain.bytesize
        enc.write(plain.byteslice(off, slice))
        off += slice
        loop do
          n, = enc.read_into(scratch)
          break if n.zero?
          dec_wire_parts << scratch.read_bytes(n)
        end
      end
      enc.end_stream
      loop do
        n, finished = enc.read_into(scratch)
        dec_wire_parts << scratch.read_bytes(n) if n.positive?
        break if finished
      end
    end
    dec_wire = dec_wire_parts.join
    bench_case("stream-dec", size) do
      pipe.decrypt_stream do |dec|
        off = 0
        while off < dec_wire.bytesize
          dec.write(dec_wire.byteslice(off, slice))
          off += slice
          loop do
            n, = dec.read_into(scratch)
            break if n.zero?
          end
        end
        dec.end_stream
        loop do
          _n, finished = dec.read_into(scratch)
          break if finished
        end
      end
    end
  end
  pipe.free
end

# Bench-scale allocation churn leaks Go scratch heap unboundedly
# without a soft memory cap + aggressive GC; the return values report
# the previous settings, not an error.
ITB.set_memory_limit(512 << 20)
ITB.set_gc_percent(20)

printf("%-17s %-8s %s\n", "bench", "size", "mb_per_sec")
bench_message
bench_stream
bench_stream_one_shot
