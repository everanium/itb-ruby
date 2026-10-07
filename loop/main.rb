# frozen_string_literal: true

# Long-run stress harness. The loop utility holds one Pipeline handle
# per exercised cipher surface for minutes, hammers it with concurrent
# encrypt -> decrypt -> compare round-trips from N worker threads,
# rotates the outer masters and reopens the handle from its session blob
# on a schedule, and reports whether the process survived with every
# byte intact. It is the Ruby binding's counterpart of the Go harness
# under tools/loop: the same flags, the same round structure, the same
# summary in both renderings.
#
# The default shape is full production: the Streaming AEAD profile with
# parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
# 1024-bit keys, and the compile-in 512-bit nonce width, driven through
# a stream session by three workers for five minutes on 16 MiB
# plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
# held for the whole run, so any cross-call state leakage inside the
# Pipeline surfaces as a data mismatch between workers rather than
# cancelling out.
#
# A failure is one of two things. A cipher, rekey or load call that
# returns a non-OK status is a worker error: the run stops, the summary
# lists it, the verdict is FAIL and the exit code 1. A round-trip that
# returns without error but with different bytes is a data mismatch: the
# process terminates on the spot with exit code 3, printing the worker,
# the iteration and the first differing offset, and no summary -- the
# state that produced the wrong bytes is the evidence. A crash inside
# the shared library or the host runtime has no exit code of its own
# here; surfacing it is what the utility is for.
#
# Usage:
#
#   ruby loop/main.rb --duration 5m --goroutines 3 --shape stream \
#       --hash areion512 --mac hmac-blake3 --payload-size 16MB \
#       --memlimit auto --parallax on --wrapper on
#
# Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
# then the partial summary prints.

# Ruby-specific. Running a script does not put the binding's lib/ on the
# load path, so the gem this utility consumes is placed there explicitly
# rather than through an environment variable the launcher would have to
# set -- everything the launcher contributes has to be part of what a
# reader runs by hand.
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "libitb3"

require_relative "size"
require_relative "payload"
require_relative "summary"
require_relative "ops"
require_relative "worker"

module Loop
  # Profiles the shape-based pair is built against when --profile is
  # empty.
  DEFAULT_STREAM_PROFILE = "streaming-aead-triple-mac-v1"
  DEFAULT_MESSAGE_PROFILE = "singlemsg-triple-mac-v1"

  # The primitive supplied for the parallax palette and the outer cipher
  # when a profile leaves them unnamed. AES-CMAC is PRF-grade, so it is
  # sound outside the Interlocked Barrier, and it is the closest
  # relative of the AES-based inner primitive whose profiles need this
  # fill.
  KEYSTREAM_FILL_CIPHER = "aescmac"

  INT = 0
  INT64 = 1
  UINT64 = 2
  STRING = 3
  BOOL = 4

  INT32_MAX = 2_147_483_647
  UINT64_MAX = (1 << 64) - 1

  # One command-line flag: its name, the type label the usage prints,
  # its kind, its default, and its help text. Values are validated after
  # the whole line is parsed. The table is in alphabetical order, which
  # is the order the usage prints.
  FLAGS = [
    ["barrier-fill", "int", INT, 0,
     "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"],
    ["blob-cycle-every", "int", INT64, 0,
     "reopen each pipeline from its session blob every N iterations per worker; 0 = never"],
    ["blob-mode", "int", INT, 1,
     "container floor sizing mode: 1 (per-region, default) | 2 (per-container)"],
    ["chunk-size", "string", STRING, "0",
     "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape"],
    ["drbg", "string", STRING, "",
     "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)"],
    ["duration", "duration", STRING, "5m",
     "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"],
    ["gogc", "int", INT, 0,
     "GC trigger percentage; 0 = leave the runtime default"],
    ["gomaxprocs", "int", INT, 0,
     "Go runtime GOMAXPROCS override; 0 = inherit from the environment"],
    ["goroutines", "int", INT, 3,
     "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1"],
    ["hash", "string", STRING, "areion512",
     "inner ITB hash primitive name"],
    ["iterations", "int", INT64, 0,
     "fixed per-worker iteration count; 0 = duration-based"],
    ["json-output", "", BOOL, false,
     "print the final summary as one compact JSON object instead of log lines"],
    ["key-bits", "int", INT, 0,
     "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"],
    ["mac", "string", STRING, "hmac-blake3",
     "MAC primitive name"],
    ["memlimit", "string", STRING, "auto",
     "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when " \
     "the runtime has no limit) or a size (e.g. 512MB)"],
    ["memprofile", "string", STRING, "",
     "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none"],
    ["nonce-bits", "int", INT, 0,
     "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"],
    ["parallax", "string", STRING, "on",
     "parallax layer: on | off"],
    ["payload-mode", "string", STRING, "fixed",
     "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"],
    ["payload-size", "string", STRING, "16MB",
     "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"],
    ["profile", "string", STRING, "",
     "exercise this single registered triple profile (overrides --shape with the profile's " \
     "surface); empty = shape-based profile pair"],
    ["rekey-every", "int", INT64, 0,
     "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never"],
    ["seed", "uint", UINT64, 0,
     "deterministic plaintext RNG seed for bug reproduction, NOT for security testing " \
     "(pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts"],
    ["shape", "string", STRING, "stream",
     "cipher surface to exercise: stream | message | stream_one_shot | both"],
    ["wrapper", "string", STRING, "on",
     "wrapper layer: on | off"]
  ].freeze

  # The resolved command line.
  Config = Struct.new(
    :duration_ns, :iterations, :workers_requested, :workers, :shape, :hash, :mac,
    :payload, :memlimit, :memlimit_auto, :gogc, :parallax, :wrapper,
    :profile, :key_bits, :nonce_bits, :chunk_size, :barrier_fill, :gomaxprocs,
    :rekey_every, :blob_cycle_every, :payload_mode, :seed, :json_output, :memprofile,
    :blob_mode, :drbg
  )

  module Main
    module_function

    def err(text)
      $stderr.write("loop: #{text}\n")
    end

    def usage
      out = +"Usage of loop:\n"
      FLAGS.each do |name, label, kind, default, help|
        out << "  -#{name}#{label.empty? ? '' : ' '}#{label}\n"
        line = +"    \t#{help}"
        # The default-value suffix follows the shape a Go flag set
        # prints: an integer default only when it is non-zero, a string
        # default only when it is non-empty.
        line << " (default #{default})" if kind == INT && default != 0
        line << " (default \"#{default}\")" if kind == STRING && default != ""
        out << line << "\n"
      end
      $stderr.write(out)
    end

    # Parses one value into its flag slot; nil on a malformed value.
    def assign(kind, value)
      case kind
      when INT, INT64
        body = value.start_with?("+", "-") ? value[1..] : value
        return nil unless body.match?(/\A[0-9]+\z/)

        n = value.to_i
        return nil if kind == INT && (n > INT32_MAX || n < -INT32_MAX)

        n
      when UINT64
        body = value.start_with?("+") ? value[1..] : value
        return nil unless body.match?(/\A[0-9]+\z/)

        n = body.to_i
        n <= UINT64_MAX ? n : nil
      when STRING
        value
      else
        return true if value == "true"
        return false if value == "false"

        nil
      end
    end

    # Parses argv into the raw flag values. Accepts -name value,
    # --name value, -name=value and --name=value; a boolean flag takes
    # no value unless given as -name=true / -name=false. Returns
    # [0, values], [1, nil] for -h / --help (usage printed), or
    # [-1, nil] after printing the error.
    def parse_argv(argv)
      raw = {}
      by_name = {}
      FLAGS.each do |name, _label, kind, default, _help|
        raw[name] = default
        by_name[name] = kind
      end
      i = 0
      while i < argv.length
        arg = argv[i]
        unless arg.start_with?("-") && arg != "-"
          err("unexpected positional arguments: [#{arg}]")
          return [-1, nil]
        end
        name = arg.start_with?("--") ? arg[2..] : arg[1..]
        if %w[h help].include?(name)
          usage
          return [1, nil]
        end
        eq = name.index("=")
        value = nil
        if eq
          value = name[(eq + 1)..]
          name = name[0, eq]
        end
        kind = by_name[name]
        if kind.nil?
          err("flag provided but not defined: -#{name}")
          usage
          return [-1, nil]
        end
        if value.nil?
          if kind == BOOL
            value = "true"
          elsif i + 1 < argv.length
            i += 1
            value = argv[i]
          else
            err("flag needs an argument: -#{name}")
            return [-1, nil]
          end
        end
        parsed = assign(kind, value)
        if parsed.nil?
          err("invalid value \"#{value}\" for flag -#{name}")
          return [-1, nil]
        end
        raw[name] = parsed
        i += 1
      end
      [0, raw]
    end

    def parse_on_off(value)
      return true if value == "on"
      return false if value == "off"

      nil
    end

    # Whether name is in the shipped hash registry the binding
    # enumerates.
    def hash_registered?(name)
      ITB.hash_names.include?(name)
    rescue ITB::Error
      false
    end

    # Resolves a registered profile to the shape family its record's
    # mode exposes by reading the record through the binding's lookup: a
    # mode beginning with "streaming" exposes the stream surfaces, one
    # beginning with "singlemsg" the message surface, "blob-only" none.
    # Prints the validation message and returns nil on rejection.
    def profile_surface(name)
      begin
        record = ITB.lookup(name)
      rescue ITB::Error
        err("--profile \"#{name}\" is not a registered triple profile")
        return nil
      end
      mode = record["mode"].to_s
      return SHAPE_STREAM if mode.start_with?("streaming")
      return SHAPE_MESSAGE if mode.start_with?("singlemsg")

      err("--profile \"#{name}\" carries no cipher surface (blob-only mode)")
      nil
    end

    # Applies a --profile's surface to the requested shape: a
    # message-surface profile forces message; a stream-surface profile
    # keeps stream or stream_one_shot as requested and turns message or
    # both into stream.
    def narrow_shape(requested, surface)
      return SHAPE_MESSAGE if surface == SHAPE_MESSAGE

      requested == SHAPE_STREAM_ONE_SHOT ? SHAPE_STREAM_ONE_SHOT : SHAPE_STREAM
    end

    # Builds the resolved config from argv. Returns [0, cfg], [1, nil]
    # for help, or [-1, nil] after printing "loop: <message>" for the
    # first failing rule.
    def parse_flags(argv) # rubocop:disable Metrics/AbcSize
      rc, raw = parse_argv(argv)
      return [rc, nil] unless rc.zero?

      cfg = Config.new
      s = Loop::Size
      cfg.duration_ns = s.parse_duration(raw["duration"])
      if cfg.duration_ns.nil? || cfg.duration_ns <= 0
        err("--duration must be positive, got #{raw['duration']}")
        return [-1, nil]
      end
      cfg.iterations = raw["iterations"]
      if cfg.iterations.negative?
        err("--iterations must be >= 0, got #{cfg.iterations}")
        return [-1, nil]
      end
      goroutines = raw["goroutines"]
      if goroutines < 1 || goroutines > MAX_WORKERS
        err("--goroutines must be in 1..#{MAX_WORKERS}, got #{goroutines}")
        return [-1, nil]
      end
      # Concurrency mode. This binding runs shared-handle: the ffi gem
      # attaches every call that does non-trivial Go-side work with
      # blocking: true, which releases the global VM lock for its
      # duration, so Ruby threads call into one Pipeline handle
      # concurrently. --goroutines is the thread count verbatim, never
      # clamped.
      cfg.workers_requested = goroutines
      cfg.workers = goroutines
      cfg.shape = Loop.parse_shape(raw["shape"])
      if cfg.shape.nil?
        err("--shape must be stream | message | stream_one_shot | both, got \"#{raw['shape']}\"")
        return [-1, nil]
      end
      unless hash_registered?(raw["hash"])
        err("--hash \"#{raw['hash']}\" is not a registered hash primitive")
        return [-1, nil]
      end
      cfg.hash = raw["hash"]
      # Validated by Init: the C ABI enumerates no MAC names.
      cfg.mac = raw["mac"]
      cfg.payload = s.parse_size(raw["payload-size"])
      if cfg.payload.nil?
        err("--payload-size: invalid size \"#{raw['payload-size']}\"")
        return [-1, nil]
      end
      if cfg.payload < 1
        err("--payload-size must be at least 1 byte")
        return [-1, nil]
      end
      if raw["memlimit"] == "auto"
        cfg.memlimit_auto = true
        cfg.memlimit = cfg.workers <= 3 ? (1 << 30) : (256 << 20)
      else
        cfg.memlimit_auto = false
        cfg.memlimit = s.parse_size(raw["memlimit"])
        if cfg.memlimit.nil?
          err("--memlimit: invalid size \"#{raw['memlimit']}\"")
          return [-1, nil]
        end
      end
      cfg.gogc = raw["gogc"]
      if cfg.gogc.negative?
        err("--gogc must be >= 0, got #{cfg.gogc}")
        return [-1, nil]
      end
      cfg.parallax = parse_on_off(raw["parallax"])
      if cfg.parallax.nil?
        err("--parallax must be on | off, got \"#{raw['parallax']}\"")
        return [-1, nil]
      end
      cfg.wrapper = parse_on_off(raw["wrapper"])
      if cfg.wrapper.nil?
        err("--wrapper must be on | off, got \"#{raw['wrapper']}\"")
        return [-1, nil]
      end
      cfg.profile = raw["profile"]
      unless cfg.profile.empty?
        surface = profile_surface(cfg.profile)
        return [-1, nil] if surface.nil?

        cfg.shape = narrow_shape(cfg.shape, surface)
      end
      cfg.key_bits = raw["key-bits"]
      unless [0, 512, 1024, 2048].include?(cfg.key_bits)
        err("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got #{cfg.key_bits}")
        return [-1, nil]
      end
      cfg.nonce_bits = raw["nonce-bits"]
      unless [0, 128, 256, 512].include?(cfg.nonce_bits)
        err("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got #{cfg.nonce_bits}")
        return [-1, nil]
      end
      cfg.blob_mode = raw["blob-mode"]
      unless [1, 2].include?(cfg.blob_mode)
        err("--blob-mode must be 1 (per-region) | 2 (per-container), got #{cfg.blob_mode}")
        return [-1, nil]
      end
      cfg.barrier_fill = raw["barrier-fill"]
      unless [0, 1, 2, 4, 8, 16, 32].include?(cfg.barrier_fill)
        err("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), " \
            "got #{cfg.barrier_fill}")
        return [-1, nil]
      end
      # Validated by Init: the C ABI enumerates no DRBG names.
      cfg.drbg = raw["drbg"]
      cfg.chunk_size = s.parse_size(raw["chunk-size"])
      if cfg.chunk_size.nil?
        err("--chunk-size: invalid size \"#{raw['chunk-size']}\"")
        return [-1, nil]
      end
      cfg.gomaxprocs = raw["gomaxprocs"]
      if cfg.gomaxprocs.negative?
        err("--gomaxprocs must be > 0 when specified, got #{cfg.gomaxprocs}")
        return [-1, nil]
      end
      cfg.rekey_every = raw["rekey-every"]
      if cfg.rekey_every.negative?
        err("--rekey-every must be >= 0, got #{cfg.rekey_every}")
        return [-1, nil]
      end
      cfg.blob_cycle_every = raw["blob-cycle-every"]
      if cfg.blob_cycle_every.negative?
        err("--blob-cycle-every must be >= 0, got #{cfg.blob_cycle_every}")
        return [-1, nil]
      end
      cfg.payload_mode = Payload.parse_mode(raw["payload-mode"])
      if cfg.payload_mode.nil?
        err("--payload-mode must be #{Payload::NAMES.join(' | ')}, " \
            "got \"#{raw['payload-mode']}\"")
        return [-1, nil]
      end
      cfg.seed = raw["seed"]
      cfg.json_output = raw["json-output"]
      cfg.memprofile = raw["memprofile"]
      [0, cfg]
    end

    # ---------------------------------------------------------------- #
    # Signals                                                           #
    # ---------------------------------------------------------------- #

    @signal_seen = false

    class << self
      attr_accessor :signal_seen
    end

    # A consumer that stops reading ends the run. The default
    # disposition for SIGPIPE is restored so the process dies from the
    # signal with status 141 and prints nothing -- the reference
    # behaviour, and what anyone piping into head or less expects. Ruby
    # installs a disposition of its own at interpreter startup that
    # turns the failed write into an Errno::EPIPE and a backtrace, so
    # restoring the operating system's default is an explicit step here
    # rather than something inherited.
    #
    # It runs before the first line is printed, because the first line
    # is already a write that can fail.
    def restore_sigpipe
      Signal.trap("PIPE", "SYSTEM_DEFAULT")
    end

    # Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
    # while it waits for the workers; it turns the flag into the stop
    # request every worker checks before starting an iteration, so a
    # signal interrupts nothing mid-call -- the in-flight encrypt /
    # decrypt / compare completes, the worker returns, and the partial
    # summary prints with the verdict the completed iterations earned.
    def install_signals
      Signal.trap("INT") { Main.signal_seen = true }
      Signal.trap("TERM") { Main.signal_seen = true }
    end

    # ---------------------------------------------------------------- #
    # Pipelines                                                         #
    # ---------------------------------------------------------------- #

    # String value of key in a profile record, or "-" when absent or
    # empty.
    def record_str(record, key)
      value = record[key]
      value.is_a?(String) && !value.empty? ? value : "-"
    end

    # Prints the construction line with the recipe read back from the
    # blob the Pipeline handed out, not echoed from the flags: every
    # construction override is proven to have reached the library by the
    # value the receiver would see. Record values that are empty (a No
    # MAC profile's MAC, a mixed profile's single hash) print as "-".
    def log_pipeline_initialised(profile, blob)
      begin
        record = ITB.inspect_blob(blob)
      rescue ITB::Error => e
        Loop.log_line("pipeline initialised: profile=#{profile} blob=#{blob.bytesize} " \
                      "bytes (inspect: #{e.last_error})")
        return
      end
      Loop.log_line(
        "pipeline initialised: profile=#{profile} blob=#{blob.bytesize} bytes " \
        "hash=#{record_str(record, 'hash')} " \
        "key-bits=#{record.fetch('keybits', 0).to_i} " \
        "nonce-bits=#{record.fetch('nonce_bits', 0).to_i} " \
        "barrier-fill=#{record.fetch('barrier_fill', 0).to_i} " \
        "chunk-size=#{record.fetch('chunk', 0).to_i} " \
        "mac=#{record_str(record, 'mac')} " \
        "parallax=#{Loop.on_off(record.fetch('parallax', false) == true)} " \
        "wrapper=#{Loop.on_off(record.fetch('wrapper', false) == true)}" \
        "#{record['container_mode'] == 2 ? ' container-mode=2' : ''}" \
        "#{record_str(record, 'drbg') == '-' ? '' : " drbg=#{record['drbg']}"}"
      )
    end

    # Returns a copy of a wrap-layer session blob whose inner blob's
    # "mode" field is set to target_mode (1 = per-region, 2 =
    # per-container). The wrap layer's profile record carries its own
    # "mode" (a string); the target is the inner blob's ("ib") integer
    # field. Raises ArgumentError when the blob carries no inner blob
    # mode field, JSON::ParserError when it is not JSON.
    def edit_inner_blob_mode(blob, target_mode)
      doc = JSON.parse(blob.dup.force_encoding(Encoding::UTF_8))
      inner = doc.is_a?(Hash) ? doc["ib"] : nil
      raise ArgumentError, "inner blob mode field not found" unless inner.is_a?(Hash) && inner.key?("mode")

      inner["mode"] = target_mode
      JSON.generate(doc)
    end

    # Folds a keystream primitive into opts for any layer the named
    # profile leaves unfilled but the operator asked for.
    #
    # A profile built around a primitive that is safe only inside the
    # Interlocked Barrier ships with no parallax palette and no outer
    # cipher: both layers run outside the barrier, where that primitive
    # would stand bare, so the recipe leaves them unnamed rather than
    # naming a primitive that must not key them. Engaging either layer
    # therefore needs a keystream-capable primitive supplied from
    # outside the recipe; without it construction fails on a palette
    # below its minimum or an unnamed outer cipher, and the primitive
    # that most deserves stressing becomes the one that cannot be
    # stressed with those layers engaged.
    #
    # Overrides fold into the resolved record the blob carries, so the
    # receiver rebuilds the same shape from the blob alone.
    #
    # Returns 1 when a layer was filled, 0 when none needed it, -1 on a
    # lookup failure (message already printed).
    def fill_keystream_layers(name, opts, want_parallax, want_wrapper)
      begin
        record = ITB.lookup(name)
      rescue ITB::Error
        err("--profile \"#{name}\" is not a registered triple profile")
        return -1
      end
      filled = 0
      if want_parallax && !record.key?("palette")
        opts["parallaxPalette"] = ([KEYSTREAM_FILL_CIPHER] * 3).join(",")
        # A recipe that never carried a palette never carried a segment
        # size either, and the schedule rejects zero.
        opts["parallaxSegmentSize"] = "4093" unless record.key?("segment")
        filled = 1
      end
      if want_wrapper && !record.key?("outer")
        opts["outerCipher"] = KEYSTREAM_FILL_CIPHER
        filled = 1
      end
      filled
    end

    # Constructs one Pipeline against profile with every flag-carried
    # override in the opts string (zero values included -- the shared
    # library treats zero as "profile default"), then obtains the Init
    # blob once through save: the binding's init entry does not hand the
    # blob back, and the bytes are the ones Init produced. Later blob
    # reopens use the retained blob; save is never called again.
    def build_pipeline(cfg, profile)
      opts = {
        "innerHash" => cfg.hash,
        "macName" => cfg.mac,
        "withParallax" => cfg.parallax ? "true" : "false",
        "withWrapper" => cfg.wrapper ? "true" : "false",
        "keyBits" => cfg.key_bits.to_s,
        "nonceBits" => cfg.nonce_bits.to_s,
        "barrierFill" => cfg.barrier_fill.to_s,
        "drbg" => cfg.drbg,
        "chunkSize" => cfg.chunk_size.to_s
      }
      unless cfg.profile.empty?
        filled = fill_keystream_layers(cfg.profile, opts, cfg.parallax, cfg.wrapper)
        return nil if filled.negative?

        if filled.positive?
          err("#{cfg.profile} leaves the requested keystream layers unnamed; " \
              "#{KEYSTREAM_FILL_CIPHER} supplied for them")
        end
      end
      begin
        pipe = ITB.create(profile, opts)
      rescue ITB::Error => e
        err("Init(#{profile}): #{Loop.status_detail(e)}")
        return nil
      end
      begin
        blob = pipe.save
      rescue ITB::Error => e
        err("Save(#{profile}): #{Loop.status_detail(e)}")
        pipe.free
        return nil
      end
      if cfg.blob_mode == 2
        # The sizing mode is not an Opts knob: the Init blob is edited
        # and the pipeline reopened from it, so the retained blob (the
        # one blob-cycle reopens from) carries the edited mode.
        begin
          edited = edit_inner_blob_mode(blob, 2)
        rescue ArgumentError, JSON::ParserError => e
          err("rewrite blob mode: #{e.message}")
          pipe.free
          return nil
        end
        pipe.free
        begin
          pipe = ITB.load(edited)
        rescue ITB::Error => e
          err("reload Mode 2 blob: #{Loop.status_detail(e)}")
          return nil
        end
        blob = edited
      end
      log_pipeline_initialised(profile, blob)
      [pipe, blob]
    end

    # ---------------------------------------------------------------- #
    # Run                                                               #
    # ---------------------------------------------------------------- #

    def run(argv) # rubocop:disable Metrics/AbcSize
      rc, cfg = parse_flags(argv)
      return 0 if rc == 1
      return 2 unless rc.zero?

      state = RunState.new(cfg)
      s = Loop::Size

      # Runtime shaping. A long run under allocation churn grows the Go
      # heap inside the shared library without bound unless a soft limit
      # paces the collector, so a limit is always in force: an explicit
      # --memlimit is set as given, and auto caps the heap only when the
      # runtime reports no limit at all (a limit already installed from
      # the environment is left standing). The GC percentage and
      # GOMAXPROCS are set only when their flag is non-zero -- a zero
      # flag skips the setter rather than calling it with zero, because
      # zero is a real value to the GC-percent setter, and a call would
      # clobber whatever the environment installed. All of it lands
      # before any Pipeline exists so the baselines are taken under the
      # shaped runtime.
      if cfg.memlimit_auto
        ITB.set_memory_limit(cfg.memlimit) if ITB.set_memory_limit(-1) == (1 << 63) - 1
      else
        ITB.set_memory_limit(cfg.memlimit)
      end
      cfg.memlimit = ITB.set_memory_limit(-1)
      ITB.set_gc_percent(cfg.gogc) if cfg.gogc.positive?
      ITB.set_gomaxprocs(cfg.gomaxprocs) if cfg.gomaxprocs.positive?

      Loop.log_line(
        "start: duration=#{s.human_duration(cfg.duration_ns)} " \
        "iterations=#{cfg.iterations} goroutines=#{cfg.workers_requested} " \
        "workers=#{cfg.workers} concurrency=#{CONCURRENCY} " \
        "shape=#{Loop.shape_name(cfg.shape)} hash=#{cfg.hash} mac=#{cfg.mac} " \
        "payload=#{s.human_bytes(cfg.payload)} memlimit=#{s.human_bytes(cfg.memlimit)} " \
        "parallax=#{Loop.on_off(cfg.parallax)} wrapper=#{Loop.on_off(cfg.wrapper)}"
      )
      Loop.log_line(
        "overrides: profile=\"#{cfg.profile}\" key-bits=#{cfg.key_bits} " \
        "nonce-bits=#{cfg.nonce_bits} chunk-size=#{s.human_bytes(cfg.chunk_size)} " \
        "barrier-fill=#{cfg.barrier_fill} gomaxprocs=#{cfg.gomaxprocs} " \
        "rekey-every=#{cfg.rekey_every} blob-cycle-every=#{cfg.blob_cycle_every} " \
        "payload-mode=#{Payload.mode_name(cfg.payload_mode)} seed=#{cfg.seed} " \
        "json-output=#{cfg.json_output ? 'true' : 'false'}" \
        "#{cfg.blob_mode == 1 ? '' : " blob-mode=#{cfg.blob_mode}"}" \
        "#{cfg.drbg.empty? ? '' : " drbg=#{cfg.drbg}"}"
      )
      Loop.log_line(
        "policy: microbatch-tiers=#{Loop.policy_label(ENV.fetch('ITB_MICROBATCH_TIERS', nil))} " \
        "hashpool-starters=#{Loop.policy_label(ENV.fetch('ITB_HASHPOOL_STARTERS', nil))}"
      )

      # Pipeline construction -- one shared handle per exercised shape.
      # stream and stream_one_shot share the streaming handle.
      state.stream_profile = cfg.profile.empty? ? DEFAULT_STREAM_PROFILE : cfg.profile
      state.msg_profile = cfg.profile.empty? ? DEFAULT_MESSAGE_PROFILE : cfg.profile
      if [SHAPE_STREAM, SHAPE_STREAM_ONE_SHOT, SHAPE_BOTH].include?(cfg.shape)
        built = build_pipeline(cfg, state.stream_profile)
        return 1 if built.nil?

        state.stream_pipe, state.stream_blob = built
      end
      if [SHAPE_MESSAGE, SHAPE_BOTH].include?(cfg.shape)
        built = build_pipeline(cfg, state.msg_profile)
        return 1 if built.nil?

        state.msg_pipe, state.msg_blob = built
      end

      # Allocation posture. Per-worker plaintexts are built once and
      # held for the whole run (rotating mode replaces them per
      # iteration); the wire and round-trip buffers are the Strings the
      # binding returns per call and the collector reclaims them when
      # the iteration drops them, and the pump loop accumulates its
      # slices into one joined buffer per direction. Under the default
      # fixed CSPRNG mode every worker's buffer is distinct, so
      # cross-worker data crossover is detectable; pattern modes trade
      # that property for content edge-case coverage.
      cfg.workers.times do |i|
        worker = WorkerState.new(i, state)
        worker.payload_mode = cfg.payload_mode
        worker.seeded = !cfg.seed.zero?
        worker.rng = Payload.seed_worker(cfg.seed, i)
        worker.plaintext, worker.rng =
          Payload.fill(cfg.payload_mode, worker.seeded, worker.rng, cfg.payload)
        state.workers << worker
      end

      state.pool_warmup = Summary.pool_snapshot
      state.pool_steady = state.pool_warmup.dup
      if state.pool_warmup.empty?
        err("pool snapshot alloc failed")
        return 1
      end

      install_signals
      state.warmup_done = Barrier.new(cfg.workers + 1)
      state.release = Barrier.new(cfg.workers + 1)
      state.stop = false
      state.active = cfg.workers

      # Warmup barrier. Every worker runs one iteration and waits; the
      # clock starts only once all of them have paid their first-call
      # costs (pool warm-up, lazy kernel dispatch, page faults on the
      # payload buffers), and the RSS and pool baselines taken here
      # describe a process that has already run the whole cipher path
      # once per worker.
      warmup_start = s.now_ns
      state.workers.each do |worker|
        worker.thread = Thread.new { Worker.main(worker) }
      end
      state.warmup_done.wait
      state.rss_warmup, state.rss_peak = Summary.read_rss
      state.pool_warmup = Summary.pool_snapshot
      warmup_ns = s.now_ns - warmup_start
      Loop.log_line(
        "warmup: #{cfg.workers} workers x 1 iter completed in " \
        "#{s.human_duration((warmup_ns + 50_000_000) / 100_000_000 * 100_000_000)} " \
        "(baseline rss=#{s.human_bytes(state.rss_warmup)})"
      )

      # Open the gate; the duration deadline is enforced by the waiter
      # below in duration mode.
      state.start_ns = s.now_ns
      state.finish_ns = state.start_ns
      state.release.wait

      # Wait for every worker, polling every 100 ms so the deadline and
      # a signal are both noticed promptly.
      state.done_mutex.synchronize do
        while state.active.positive?
          state.stop = true if signal_seen
          state.stop = true if cfg.iterations.zero? && s.now_ns - state.start_ns >= cfg.duration_ns
          state.done_cond.wait(state.done_mutex, 0.1)
        end
      end
      state.workers.each { |worker| worker.thread.join }
      elapsed_ns = state.finish_ns - state.start_ns
      state.rss_final, peak = Summary.read_rss
      state.rss_peak = [state.rss_peak, peak].max
      state.pool_steady = Summary.pool_snapshot

      unless cfg.memprofile.empty?
        begin
          ITB.write_heap_profile(cfg.memprofile)
          Loop.log_line("memprofile: heap profile written to #{cfg.memprofile}")
        rescue ITB::Error => e
          err("memprofile: #{e.last_error}")
        end
      end

      rc = Summary.final_summary(state, elapsed_ns)
      state.stream_pipe&.free
      state.msg_pipe&.free
      rc
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  $stdout.sync = true
  $stderr.sync = true
  Loop::Main.restore_sigpipe
  exit(Loop::Main.run(ARGV))
end
