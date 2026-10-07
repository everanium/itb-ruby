# frozen_string_literal: true

require "securerandom"

require_relative "summary"

# The maintenance operations that mutate a live Pipeline handle between
# iterations: master rotation (--rekey-every) and blob reopen
# (--blob-cycle-every).
module Loop
  module Ops
    # Byte length of each fresh master drawn for a rotation. Matches the
    # size Init auto-generates for both the parallax and the wrapper
    # master.
    REKEY_MASTER_SIZE = 32

    module_function

    # Master rotation. Rotates the parallax + wrapper masters on every
    # active Pipeline under the write lock and retains the refreshed
    # blob for subsequent blob reopens. Masters are drawn fresh from the
    # OS CSPRNG on every rotation regardless of --seed (master rotation
    # is pipeline keying, not plaintext content); a disabled layer
    # passes no bytes, which Rekey ignores. The eight inner seeds and
    # the MAC key are untouched by design -- Rekey targets only the two
    # outer-layer master secrets.
    def rekey_pipes(worker, iter)
      run = worker.run
      perm = run.cfg.parallax ? SecureRandom.bytes(REKEY_MASTER_SIZE) : "".b
      wrap = run.cfg.wrapper ? SecureRandom.bytes(REKEY_MASTER_SIZE) : "".b

      count = nil
      run.pipe_lock.acquire_write
      begin
        if run.stream_pipe
          begin
            run.stream_blob = run.stream_pipe.rekey(perm, wrap)
          rescue ITB::Error => e
            worker.fail!("g#{worker.id} iter #{iter}: Rekey(#{run.stream_profile}): " \
                         "#{Loop.status_detail(e)}")
            return false
          end
        end
        if run.msg_pipe
          begin
            run.msg_blob = run.msg_pipe.rekey(perm, wrap)
          rescue ITB::Error => e
            worker.fail!("g#{worker.id} iter #{iter}: Rekey(#{run.msg_profile}): " \
                         "#{Loop.status_detail(e)}")
            return false
          end
        end
        run.rekeys += 1
        count = run.rekeys
      ensure
        run.pipe_lock.release_write
      end
      Loop.log_line("rekey: g#{worker.id} iter #{iter} rotated parallax + wrapper " \
                    "masters (rekey ##{count})")
      true
    end

    # Blob reopen. Reopens every active Pipeline from its retained blob
    # under the write lock: a fresh handle is loaded from the blob, the
    # running handle is freed, and the fresh one is swapped in, so every
    # later iteration round-trips through seeds and masters that
    # survived a blob crossing. The input is the blob Init or the latest
    # Rekey handed out, not a fresh Save: that is what a receiver holds,
    # and reopening from it proves the handed-out bytes rather than the
    # live state. The blob carries the Pipeline's full shape, so no
    # override reaches the reopen. On a Load failure the running handle
    # stays and the failure aborts the run.
    def blob_cycle_pipes(worker, iter)
      run = worker.run
      count = nil
      run.pipe_lock.acquire_write
      begin
        if run.stream_pipe
          begin
            fresh = ITB.load(run.stream_blob)
          rescue ITB::Error => e
            worker.fail!("g#{worker.id} iter #{iter}: Load(#{run.stream_profile}): " \
                         "#{Loop.status_detail(e)}")
            return false
          end
          run.stream_pipe.free
          run.stream_pipe = fresh
        end
        if run.msg_pipe
          begin
            fresh = ITB.load(run.msg_blob)
          rescue ITB::Error => e
            worker.fail!("g#{worker.id} iter #{iter}: Load(#{run.msg_profile}): " \
                         "#{Loop.status_detail(e)}")
            return false
          end
          run.msg_pipe.free
          run.msg_pipe = fresh
        end
        run.blob_cycles += 1
        count = run.blob_cycles
      ensure
        run.pipe_lock.release_write
      end
      Loop.log_line("blob-cycle: g#{worker.id} iter #{iter} reopened from session " \
                    "blob (cycle ##{count})")
      true
    end

    # Handle mutation. Runs the periodic Pipeline-mutating operations
    # after a completed iteration: master rotation (--rekey-every) and
    # blob reopen (--blob-cycle-every). Both intervals count per-worker
    # iterations; the warmup iteration (iter 0) never triggers because
    # the worker loop calls this for iter >= 1 only. Rekey rewrites the
    # outer-layer keying of a live handle and a blob reopen replaces the
    # handle outright; each takes the write lock, so in-flight cipher
    # calls on other workers drain before anything changes and no
    # encrypt is separated from its decrypt by either. Returns false
    # after recording the worker error.
    def worker_maintenance(worker, iter)
      cfg = worker.run.cfg
      if cfg.rekey_every.positive? && (iter % cfg.rekey_every).zero?
        return false unless rekey_pipes(worker, iter)
      end
      if cfg.blob_cycle_every.positive? && (iter % cfg.blob_cycle_every).zero?
        return false unless blob_cycle_pipes(worker, iter)
      end
      true
    end
  end
end
