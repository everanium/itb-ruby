# frozen_string_literal: true

require_relative "size"
require_relative "payload"
require_relative "summary"
require_relative "ops"

# The worker: the vocabulary the run shares, the per-worker and run
# state, its thread body (one warmup iteration, the warmup barrier, the
# main loop), one iteration, the session pump loop the stream shape
# drives, and the round-trip comparison that decides between a worker
# error and a data mismatch.
module Loop
  # Cipher surfaces the --shape flag selects.
  SHAPE_STREAM = 0          # session pump: begin / write / read / end
  SHAPE_MESSAGE = 1         # Single Message: one whole-buffer call
  SHAPE_STREAM_ONE_SHOT = 2 # stream surface, one whole-buffer call
  SHAPE_BOTH = 3            # all three, rotating by iteration number

  SHAPE_NAMES = %w[stream message stream_one_shot both].freeze

  # --goroutines ceiling; the harness targets modest hosts and each
  # worker pins payload-sized buffers for the whole run.
  MAX_WORKERS = 10

  # The concurrency mode this binding implements, as the summary
  # reports it (shared-handle / independent-handles / single).
  CONCURRENCY = "shared-handle"

  # Largest slice fed to a stream session per write; the drain after
  # every write uses the same bound.
  PUMP_SLICE = 1 << 20

  module_function

  def shape_name(shape)
    SHAPE_NAMES[shape]
  end

  def parse_shape(str)
    SHAPE_NAMES.index(str)
  end

  # A reader-preferring read-write lock.
  #
  # Ruby-specific. The standard library ships a mutex and a condition
  # variable but no read-write lock, so the one the contract calls for
  # is built from them: readers admit each other while no writer holds
  # the lock, a writer waits for every reader to leave, and the whole
  # waiting set is woken on release.
  class RWLock
    def initialize
      @mutex = Mutex.new
      @cond = ConditionVariable.new
      @readers = 0
      @writer = false
    end

    def acquire_read
      @mutex.synchronize do
        @cond.wait(@mutex) while @writer
        @readers += 1
      end
    end

    def release_read
      @mutex.synchronize do
        @readers -= 1
        @cond.broadcast if @readers.zero?
      end
    end

    def acquire_write
      @mutex.synchronize do
        @cond.wait(@mutex) while @writer || @readers.positive?
        @writer = true
      end
    end

    def release_write
      @mutex.synchronize do
        @writer = false
        @cond.broadcast
      end
    end

    def with_read
      acquire_read
      begin
        yield
      ensure
        release_read
      end
    end

    def with_write
      acquire_write
      begin
        yield
      ensure
        release_write
      end
    end
  end

  # A rendezvous every participant reaches before any of them proceeds.
  #
  # Ruby-specific. The standard library has no barrier primitive, so the
  # warmup rendezvous is built from a mutex and a condition variable.
  class Barrier
    def initialize(parties)
      @parties = parties
      @count = 0
      @generation = 0
      @mutex = Mutex.new
      @cond = ConditionVariable.new
    end

    def wait
      @mutex.synchronize do
        generation = @generation
        @count += 1
        if @count == @parties
          @count = 0
          @generation += 1
          @cond.broadcast
        else
          @cond.wait(@mutex) while generation == @generation
        end
      end
    end
  end

  # One worker's private state: its plaintext, its generator, its
  # counters, and the error it stopped on.
  class WorkerState
    attr_accessor :id, :run, :thread, :plaintext, :payload_mode, :seeded, :rng,
                  :iters, :bytes_enc, :bytes_dec, :nanos_enc, :nanos_dec,
                  :failed, :error

    def initialize(id, run)
      @id = id
      @run = run
      @plaintext = "".b
      @payload_mode = Payload::FIXED
      @seeded = false
      @rng = 0
      # Counters written by this worker only, so the summary's read
      # after the join needs no further synchronisation.
      @iters = 0
      @bytes_enc = 0
      @bytes_dec = 0
      @nanos_enc = 0
      @nanos_dec = 0
      @failed = false
      @error = ""
    end

    # Records the worker's error text (first error wins) and requests a
    # stop of the whole run.
    def fail!(text)
      unless @failed
        @error = text
        @failed = true
      end
      @run.stop = true
    end
  end

  # The state every worker shares: the Pipeline handles, the retained
  # blobs, the lock that keeps iterations clear of handle mutation, the
  # stop request, the barriers, and the baselines the summary reads.
  class RunState
    attr_accessor :cfg, :stream_pipe, :msg_pipe, :stream_profile, :msg_profile,
                  :stream_blob, :msg_blob, :rekeys, :blob_cycles, :workers,
                  :warmup_done, :release, :stop, :active, :start_ns, :finish_ns,
                  :rss_warmup, :rss_peak, :rss_final, :pool_warmup, :pool_steady
    attr_reader :pipe_lock, :done_mutex, :done_cond

    def initialize(cfg)
      @cfg = cfg
      @stream_pipe = nil
      @msg_pipe = nil
      @stream_profile = ""
      @msg_profile = ""
      # Handle mutation. Iterations hold the read side for their whole
      # encrypt -> decrypt -> compare; rekey and blob reopen take the
      # write side, so no cipher call is in flight while a handle's
      # keying changes or the handle itself is swapped, and no encrypt
      # is separated from its decrypt by either.
      @pipe_lock = RWLock.new
      # The blob Init handed out, replaced by every rekey; the input of
      # the next blob reopen. Guarded by pipe_lock.
      @stream_blob = "".b
      @msg_blob = "".b
      @rekeys = 0
      @blob_cycles = 0
      @workers = []
      @warmup_done = nil
      @release = nil
      @stop = false
      # Main waits for active to reach zero; the last returning worker
      # stamps finish_ns so elapsed excludes the waiter's wake-up
      # latency.
      @done_mutex = Mutex.new
      @done_cond = ConditionVariable.new
      @active = 0
      @start_ns = 0
      @finish_ns = 0
      @rss_warmup = 0
      @rss_peak = 0
      @rss_final = 0
      @pool_warmup = []
      @pool_steady = []
    end
  end

  module Worker
    module_function

    # Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
    # and ITB drives the chunk loop internally; the C ABI has no reader
    # / writer entry, so the caller drives it: open a session, feed
    # slices of at most 1 MiB, drain whatever the session has produced
    # after every write (a read before end never blocks), end, then
    # drain until the session reports finished (after end, a read on an
    # empty spool blocks until the terminal bytes arrive). The loop is
    # written here rather than delegated to the binding's pump
    # convenience so it stands in the utility, at the same place, in
    # every language.
    def pump(pipe, encrypt, src)
      session = encrypt ? pipe.encrypt_stream : pipe.decrypt_stream
      begin
        parts = []
        off = 0
        total = src.bytesize
        while off < total
          take = [PUMP_SLICE, total - off].min
          session.write(src.byteslice(off, take))
          off += take
          loop do
            chunk, = session.read(PUMP_SLICE)
            break if chunk.empty?

            parts << chunk
          end
        end
        session.end_stream
        loop do
          chunk, finished = session.read(PUMP_SLICE)
          parts << chunk unless chunk.empty?
          break if finished
        end
        parts.join.b
      ensure
        session.free
      end
    end

    # First offset at which a and b differ; the shorter length when one
    # is a prefix of the other.
    def first_difference(a, b)
      n = [a.bytesize, b.bytesize].min
      n.times { |i| return i if a.getbyte(i) != b.getbyte(i) }
      n
    end

    # Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
    # has no bytes there.
    def hex_window(buf, off)
      return "-" if off >= buf.bytesize

      buf.byteslice(off, 16).unpack1("H*")
    end

    # Records a worker error for a failed cipher call.
    def cipher_fail(worker, iter, shape, direction, err)
      worker.fail!("g#{worker.id} iter #{iter} shape=#{Loop.shape_name(shape)}: " \
                   "#{direction}: #{Loop.status_detail(err)}")
    end

    # One iteration. In order: refill the plaintext under rotating mode;
    # take the read lock; pick the surface; encrypt (timed); decrypt
    # (timed); compare the round-trip with the plaintext; bump the
    # counters; release the lock. The whole round-trip runs under the
    # read lock so handle-mutating maintenance (rekey, blob reopen)
    # never lands between an encrypt and its matching decrypt --
    # maintenance runs after this returns, from the worker loop. Returns
    # false after recording the worker error.
    def iterate(worker, iter)
      run = worker.run
      if worker.payload_mode == Payload::ROTATING
        worker.plaintext, worker.rng =
          Payload.fill(Payload::ROTATING, worker.seeded, worker.rng, worker.plaintext.bytesize)
      end

      run.pipe_lock.with_read do
        # Shape dispatch. message is one whole-buffer call on the Single
        # Message Pipeline; stream_one_shot is one whole-buffer call on
        # the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
        # which routes to the same one-shot stream entry the Go
        # harness calls by name); stream opens a session on the same
        # streaming Pipeline and drives the chunk loop from here. Under
        # both the three rotate by iteration number so the session path
        # and the whole-buffer path alternate on one handle inside every
        # worker -- the cross-path state-reuse hazard this harness
        # exists to catch.
        shape = run.cfg.shape
        shape = [SHAPE_STREAM, SHAPE_MESSAGE, SHAPE_STREAM_ONE_SHOT][iter % 3] if shape == SHAPE_BOTH

        want = worker.plaintext
        s = Loop::Size
        if shape == SHAPE_STREAM
          t0 = s.now_ns
          begin
            wire = pump(run.stream_pipe, true, want)
          rescue ITB::Error => e
            cipher_fail(worker, iter, shape, "encrypt", e)
            return false
          end
          worker.nanos_enc += s.now_ns - t0
          t0 = s.now_ns
          begin
            got = pump(run.stream_pipe, false, wire)
          rescue ITB::Error => e
            cipher_fail(worker, iter, shape, "decrypt", e)
            return false
          end
          worker.nanos_dec += s.now_ns - t0
        else
          pipe = shape == SHAPE_MESSAGE ? run.msg_pipe : run.stream_pipe
          enc = shape == SHAPE_MESSAGE ? :encrypt_message : :encrypt_stream_one_shot
          dec = shape == SHAPE_MESSAGE ? :decrypt_message : :decrypt_stream_one_shot
          t0 = s.now_ns
          begin
            wire = pipe.public_send(enc, want)
          rescue ITB::Error => e
            cipher_fail(worker, iter, shape, "encrypt", e)
            return false
          end
          worker.nanos_enc += s.now_ns - t0
          t0 = s.now_ns
          begin
            got = pipe.public_send(dec, wire)
          rescue ITB::Error => e
            cipher_fail(worker, iter, shape, "decrypt", e)
            return false
          end
          worker.nanos_dec += s.now_ns - t0
        end

        # Failure model. A cipher call that returns a non-OK status is a
        # worker error: it is recorded, the run is asked to stop, the
        # other workers finish their in-flight iteration, and the error
        # is listed in the summary with the FAIL verdict. A round-trip
        # that returns OK with different bytes is a data mismatch: the
        # process terminates here, without summary or cleanup, because
        # the Pipeline state that produced the wrong bytes is the
        # evidence and nothing that runs afterwards may touch it.
        unless got == want
          off = first_difference(want, got)
          $stderr.write(
            "loop: DATA MISMATCH g#{worker.id} iter #{iter} " \
            "shape=#{Loop.shape_name(shape)}: want #{want.bytesize} bytes, " \
            "got #{got.bytesize} bytes, first difference at offset #{off}: " \
            "want #{hex_window(want, off)} got #{hex_window(got, off)}\n"
          )
          # Ruby-specific. Process.exit! leaves the process on the spot
          # without unwinding, running an at_exit hook or flushing
          # another thread's buffered output, which is what "no summary,
          # no cleanup" asks for; Process.exit only raises SystemExit in
          # this thread and the run would carry on around it.
          Process.exit!(3)
        end

        worker.iters += 1
        worker.bytes_enc += want.bytesize
        worker.bytes_dec += got.bytesize
        true
      end
    end

    # The worker thread body: one warmup iteration, the warmup barrier,
    # then the main loop until a stop is requested or the fixed
    # per-worker iteration budget (warmup included) is spent. A failing
    # warmup still passes both barriers so the launcher never waits on a
    # worker that has already given up.
    def main(worker)
      run = worker.run
      begin
        # Warmup iteration -- counted in the totals; its completion feeds
        # the post-warmup baselines. Anything that escapes an iteration
        # other than a library status becomes a worker error rather than
        # a lost thread: the barriers below have a fixed party count, so
        # a worker that unwound past them would leave the launcher
        # waiting for a rendezvous that can no longer happen, and a
        # thread that dies of an exception is silent by default.
        begin
          ok = iterate(worker, 0)
        rescue Exception => e # rubocop:disable Lint/RescueException
          worker.fail!("g#{worker.id} iter 0: #{e.class}: #{e.message}")
          ok = false
        end
        run.warmup_done.wait
        run.release.wait
        return unless ok

        iter = 1
        loop do
          break if run.cfg.iterations.positive? && iter >= run.cfg.iterations
          break if run.stop

          begin
            break unless iterate(worker, iter)
            break unless Ops.worker_maintenance(worker, iter)
          rescue Exception => e # rubocop:disable Lint/RescueException — see above
            worker.fail!("g#{worker.id} iter #{iter}: #{e.class}: #{e.message}")
            break
          end
          iter += 1
        end
      ensure
        done(run)
      end
    end

    # Marks this worker returned; the last one to return stamps the
    # finish instant and wakes main.
    def done(run)
      run.done_mutex.synchronize do
        run.active -= 1
        if run.active.zero?
          run.finish_ns = Loop::Size.now_ns
          run.done_cond.broadcast
        end
      end
    end
  end
end
