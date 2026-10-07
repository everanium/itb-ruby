# frozen_string_literal: true

require "json"

require_relative "size"
require_relative "payload"

# The final summary in both renderings, the two measurements it folds
# in that are not per-worker counters (the process resident set and the
# shared library's pool counters), and the single-write line emitter
# every unit logs through.
module Loop
  # Serialises the line emitter below. Workers log concurrently during
  # maintenance, so the text and its newline have to reach the stream as
  # one write.
  LOG_LOCK = Mutex.new

  module_function

  # Prints one prefixed status line to stdout.
  #
  # The line is assembled with its newline and handed over in a single
  # write, so a worker logging a maintenance line from another thread
  # cannot land between a text and the newline that terminates it.
  def log_line(text)
    LOG_LOCK.synchronize { $stdout.write("[loop] #{text}\n") }
  end

  def on_off(flag)
    flag ? "on" : "off"
  end

  # Renders an encoder policy env value for the summary: the raw string
  # when set, "default" when the shipped ladder applies.
  def policy_label(env)
    return "default" if env.nil?

    stripped = env.sub(/\A[ \t]+/, "")
    stripped.empty? ? "default" : stripped
  end

  # The failure detail a log line carries: the numeric status the
  # binding's own surface exposes and the finished sentence the library
  # left behind. Nothing is composed here -- the wording arrives whole
  # from the failing call.
  def status_detail(err)
    return err.message unless err.respond_to?(:status_code) && err.status_code

    "status #{err.status_code}: #{err.last_error}"
  end

  module Summary
    module_function

    # ---------------------------------------------------------------- #
    # Resident set                                                      #
    # ---------------------------------------------------------------- #

    # The process's current resident set and its high-water mark in
    # bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
    # Both are zero on a platform without that file; the figures are
    # informational and never enter the verdict.
    def read_rss
      current = 0
      peak = 0
      File.foreach("/proc/self/status") do |line|
        current = status_kb(line) if line.start_with?("VmRSS:")
        peak = status_kb(line) if line.start_with?("VmHWM:")
      end
      [current, peak]
    rescue SystemCallError
      [0, 0]
    end

    # Parses one "Vm...:   1234 kB" line of /proc/self/status into
    # bytes; zero on any parse failure.
    def status_kb(line)
      field = line.split[1]
      return 0 unless field&.match?(/\A[0-9]+\z/)

      field.to_i * 1024
    end

    # ---------------------------------------------------------------- #
    # Pool counters                                                     #
    # ---------------------------------------------------------------- #

    # Pool counters. The shared library keeps process-wide monotonic
    # totals at every pool checkout of its cipher core: per hash-array
    # tier the starter width, checkouts, constructor misses, regrow
    # replacements and bytes allocated; for the scratch byte pool and
    # the parallax chunk pool the checkouts, constructor misses, regrows
    # and regrow bytes. Two snapshots bracketing the main loop are
    # differenced into per-run hit / miss figures that tell whether a
    # pool keeps its items warm between calls or evicts them across GC
    # cycles. The slot layout is read from the library: slot 0 carries
    # the tier count T, tier i occupies the five slots at 1 + 5*i, and
    # the two byte pools occupy the eight slots at 1 + 5*T; the vector
    # is sized from the binding's length query, never from a constant.
    def pool_snapshot
      ITB.pool_stats
    rescue ITB::Error
      []
    end

    # The differenced pool figures of one run.
    class PoolDelta
      attr_reader :tiers, :starter, :get, :new_, :regrow, :new_bytes, :buf, :chunk

      def initialize(warmup, steady)
        @tiers = 0
        @starter = []
        @get = []
        @new_ = []
        @regrow = []
        @new_bytes = []
        @buf = [0, 0, 0, 0]
        @chunk = [0, 0, 0, 0]
        return if warmup.empty? || steady.empty? || steady.size < 9 || warmup.size != steady.size

        tiers = steady[0]
        return if tiers.negative? || (1 + (5 * tiers) + 8) > steady.size

        @tiers = tiers
        tiers.times do |i|
          base = 1 + (5 * i)
          @starter << steady[base]
          @get << (steady[base + 1] - warmup[base + 1])
          @new_ << (steady[base + 2] - warmup[base + 2])
          @regrow << (steady[base + 3] - warmup[base + 3])
          @new_bytes << (steady[base + 4] - warmup[base + 4])
        end
        tail = 1 + (5 * tiers)
        @buf = (0..3).map { |i| steady[tail + i] - warmup[tail + i] }
        @chunk = (0..3).map { |i| steady[tail + 4 + i] - warmup[tail + 4 + i] }
      end
    end

    # Misses over checkouts as a percentage; zero when nothing was
    # checked out.
    def miss_percent(miss, get)
      return 0.0 if get <= 0

      100.0 * miss / get
    end

    # The effective GC percentage as the runtime reports it: the query
    # form of the setter (a set-and-restore round trip inside the
    # library) so the field is the same whether the value came from the
    # flag, the environment, or the runtime default.
    def effective_gogc(flag)
      flag.positive? ? flag : ITB.set_gc_percent(-1)
    end

    # Output contract. Both renderings are shared with the Go harness
    # and every other binding's loop utility field for field: the same
    # lines in the same order, the same keys in the same order, floats
    # with a fixed number of decimals so the JSON is byte-identical
    # across implementations. The Go harness alone adds its
    # runtime-internal lines after rss: and its runtime-internal keys
    # after parallax_chunk_pool; nothing here reproduces them because
    # nothing they read is reachable through the C ABI.
    def final_summary(run, elapsed_ns)
      cfg = run.cfg
      workers = run.workers[0, cfg.workers]
      total_iters = workers.sum(&:iters)
      total_enc = workers.sum(&:bytes_enc)
      total_dec = workers.sum(&:bytes_dec)
      nanos_enc = workers.sum(&:nanos_enc)
      nanos_dec = workers.sum(&:nanos_dec)
      errors = workers.select(&:failed).map(&:error)

      # Throughput. Per-direction throughput divides the sum of every
      # worker's wall time in that direction by the worker count -- the
      # equivalent single-stream wall time under N-way concurrency -- so
      # each direction reports the aggregate rate it sustained rather
      # than collapsing to combined/2 (every iteration moves equal
      # encrypt and decrypt bytes, so a total-elapsed denominator would
      # give both directions the same figure). The combined rate keeps
      # total elapsed as the one-glance overall figure.
      avg_enc = nanos_enc.positive? ? nanos_enc / cfg.workers : 0
      avg_dec = nanos_dec.positive? ? nanos_dec / cfg.workers : 0

      rss_delta = run.rss_final - run.rss_warmup
      rss_growth = run.rss_warmup.positive? ? 100.0 * rss_delta / run.rss_warmup : 0.0
      delta = PoolDelta.new(run.pool_warmup, run.pool_steady)
      passed = errors.empty?

      if cfg.json_output
        emit_json(run, elapsed_ns, workers, total_iters, total_enc, total_dec,
                  avg_enc, avg_dec, errors, passed, delta, rss_growth)
        return passed ? 0 : 1
      end

      emit_human(run, elapsed_ns, workers, total_iters, total_enc, total_dec,
                 avg_enc, avg_dec, errors, passed, delta, rss_growth, rss_delta)
    end

    # rubocop:disable Metrics/ParameterLists
    def emit_human(run, elapsed_ns, workers, total_iters, total_enc, total_dec,
                   avg_enc, avg_dec, errors, passed, delta, rss_growth, rss_delta)
      cfg = run.cfg
      s = Loop::Size
      Loop.log_line("=== FINAL ===")
      Loop.log_line("  duration: #{s.human_duration((elapsed_ns + 500_000) / 1_000_000 * 1_000_000)}")
      Loop.log_line("  iterations: #{workers.map(&:iters).join(' + ')} = #{total_iters} total")
      Loop.log_line("  throughput: encrypt #{s.human_rate(total_enc, avg_enc)}, " \
                    "decrypt #{s.human_rate(total_dec, avg_dec)}, " \
                    "combined #{s.human_rate(total_enc + total_dec, elapsed_ns)}")
      Loop.log_line("  bytes: #{s.human_bytes(total_enc)} encrypted, " \
                    "#{s.human_bytes(total_dec)} decrypted")
      Loop.log_line("  data integrity: #{total_iters}/#{total_iters} PASS")
      Loop.log_line("  concurrency: #{Loop::CONCURRENCY}, workers #{cfg.workers} " \
                    "(requested #{cfg.workers_requested})")
      Loop.log_line("  rss: warmup #{s.human_bytes(run.rss_warmup)}, " \
                    "peak #{s.human_bytes(run.rss_peak)}, " \
                    "final #{s.human_bytes(run.rss_final)} " \
                    "(delta #{s.human_bytes_signed(rss_delta)}, " \
                    "#{format('%.1f', rss_growth)}% growth)")
      delta.tiers.times do |i|
        next if delta.starter[i].zero?

        miss = delta.new_[i] + delta.regrow[i]
        Loop.log_line("  hash pool tier #{i} (starter #{delta.starter[i]}): " \
                      "get #{delta.get[i]}, miss #{miss} " \
                      "(new #{delta.new_[i]} + regrow #{delta.regrow[i]}), " \
                      "miss #{format('%.2f', miss_percent(miss, delta.get[i]))}%, " \
                      "#{s.human_bytes(delta.new_bytes[i])} allocated")
      end
      Loop.log_line("  buf pool: get #{delta.buf[0]}, regrow #{delta.buf[2]} " \
                    "(of which fresh #{delta.buf[1]}), " \
                    "miss #{format('%.2f', miss_percent(delta.buf[2], delta.buf[0]))}%, " \
                    "#{s.human_bytes(delta.buf[3])} regrown")
      Loop.log_line("  parallax chunk pool: get #{delta.chunk[0]}, regrow #{delta.chunk[2]} " \
                    "(of which fresh #{delta.chunk[1]}), " \
                    "miss #{format('%.2f', miss_percent(delta.chunk[2], delta.chunk[0]))}%, " \
                    "#{s.human_bytes(delta.chunk[3])} regrown")
      Loop.log_line("  rekeys: #{run.rekeys}") if run.rekeys.positive?
      Loop.log_line("  blob cycles: #{run.blob_cycles}") if run.blob_cycles.positive?
      errors.each { |text| Loop.log_line("  ERROR: #{text}") }
      if passed
        Loop.log_line("  verdict: PASS")
        return 0
      end
      Loop.log_line("  verdict: FAIL (errors=#{errors.size})")
      1
    end

    # One compact object on one line, keys in the contract's order,
    # floats with the contract's decimal counts and never in exponent
    # form.
    def emit_json(run, elapsed_ns, workers, total_iters, total_enc, total_dec,
                  avg_enc, avg_dec, errors, passed, delta, rss_growth)
      cfg = run.cfg
      s = Loop::Size
      tiers = delta.tiers.times.reject { |i| delta.starter[i].zero? }.map do |i|
        format('{"tier":%d,"starter":%d,"get":%d,"new":%d,"regrow":%d,"new_bytes":%d,' \
               '"miss_percent":%.2f}',
               i, delta.starter[i], delta.get[i], delta.new_[i], delta.regrow[i],
               delta.new_bytes[i],
               miss_percent(delta.new_[i] + delta.regrow[i], delta.get[i]))
      end
      out = +""
      out << format('{"duration_seconds":%.3f', elapsed_ns / 1e9)
      out << format(',"iterations":%d', total_iters)
      out << format(',"per_worker_iterations":[%s]', workers.map(&:iters).join(","))
      out << format(',"bytes_encrypted":%d', total_enc)
      out << format(',"bytes_decrypted":%d', total_dec)
      out << format(',"encrypt_mb_per_sec":%.1f', s.mb_per_sec(total_enc, avg_enc))
      out << format(',"decrypt_mb_per_sec":%.1f', s.mb_per_sec(total_dec, avg_dec))
      out << format(',"combined_mb_per_sec":%.1f', s.mb_per_sec(total_enc + total_dec, elapsed_ns))
      out << format(',"rekeys":%d', run.rekeys)
      out << format(',"blob_cycles":%d', run.blob_cycles)
      out << format(',"worker_errors":[%s]', errors.map { |e| JSON.generate(e) }.join(","))
      out << format(',"verdict":"%s"', passed ? "PASS" : "FAIL")
      out << format(',"shape":"%s"', Loop::SHAPE_NAMES[cfg.shape])
      out << format(',"stream_profile":%s', JSON.generate(run.stream_pipe ? run.stream_profile : ""))
      out << format(',"message_profile":%s', JSON.generate(run.msg_pipe ? run.msg_profile : ""))
      out << format(',"hash":%s', JSON.generate(cfg.hash))
      out << format(',"mac":%s', JSON.generate(cfg.mac))
      out << format(',"payload_bytes":%d', cfg.payload)
      out << format(',"payload_mode":"%s"', Loop::Payload.mode_name(cfg.payload_mode))
      out << format(',"seed":%d', cfg.seed)
      out << format(',"key_bits":%d', cfg.key_bits)
      out << format(',"nonce_bits":%d', cfg.nonce_bits)
      out << format(',"blob_mode":%d', cfg.blob_mode)
      out << format(',"drbg":%s', JSON.generate(cfg.drbg))
      out << format(',"drbg_auto_tier":%s', JSON.generate(ITB.drbg_auto_tier))
      out << format(',"chunk_size_bytes":%d', cfg.chunk_size)
      out << format(',"barrier_fill":%d', cfg.barrier_fill)
      out << format(',"parallax":"%s"', Loop.on_off(cfg.parallax))
      out << format(',"wrapper":"%s"', Loop.on_off(cfg.wrapper))
      out << format(',"goroutines_requested":%d', cfg.workers_requested)
      out << format(',"goroutines":%d', cfg.workers)
      out << format(',"concurrency":"%s"', Loop::CONCURRENCY)
      out << format(',"gogc":"%d"', effective_gogc(cfg.gogc))
      out << format(',"memlimit_bytes":%d', cfg.memlimit)
      out << format(',"gomaxprocs":%d', ITB.set_gomaxprocs(0))
      out << format(',"microbatch_tiers":%s',
                    JSON.generate(Loop.policy_label(ENV.fetch("ITB_MICROBATCH_TIERS", nil))))
      out << format(',"hashpool_starters":%s',
                    JSON.generate(Loop.policy_label(ENV.fetch("ITB_HASHPOOL_STARTERS", nil))))
      out << format(',"rss_warmup_bytes":%d', run.rss_warmup)
      out << format(',"rss_peak_bytes":%d', run.rss_peak)
      out << format(',"rss_final_bytes":%d', run.rss_final)
      out << format(',"rss_growth_percent":%.2f', rss_growth)
      out << format(',"hash_pool_tiers":[%s]', tiers.join(","))
      out << format(',"buf_pool":{"get":%d,"new":%d,"regrow":%d,"regrow_bytes":%d,' \
                    '"miss_percent":%.2f}',
                    delta.buf[0], delta.buf[1], delta.buf[2], delta.buf[3],
                    miss_percent(delta.buf[2], delta.buf[0]))
      out << format(',"parallax_chunk_pool":{"get":%d,"new":%d,"regrow":%d,' \
                    '"regrow_bytes":%d,"miss_percent":%.2f}',
                    delta.chunk[0], delta.chunk[1], delta.chunk[2], delta.chunk[3],
                    miss_percent(delta.chunk[2], delta.chunk[0]))
      out << "}\n"
      $stdout.write(out)
    end
    # rubocop:enable Metrics/ParameterLists
  end
end
