# frozen_string_literal: true

require "securerandom"

# Plaintext content: the payload modes, the seeded per-worker
# generator, and the buffer fill from the operating-system CSPRNG.
module Loop
  module Payload
    # Payload mode selector values for the --payload-mode flag.
    #
    #   - fixed: one CSPRNG-generated buffer per worker, held unchanged
    #     for the whole run (the default).
    #   - rotating: the buffer is regenerated before every iteration, so
    #     no two encrypt calls see the same plaintext.
    #   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00
    #     / all 0xFF) probing minimum-entropy plaintext handling.
    #   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
    #     structured text.
    FIXED = 0
    ROTATING = 1
    PATTERN_ZERO = 2
    PATTERN_FF = 3
    PATTERN_ASCII = 4

    NAMES = %w[fixed rotating pattern-zero pattern-ff pattern-ascii].freeze

    MASK64 = (1 << 64) - 1
    ASCII_RAMP = ("A".."Z").to_a.join.b.freeze

    module_function

    def mode_name(mode)
      NAMES[mode]
    end

    def parse_mode(str)
      NAMES.index(str)
    end

    # Seeded plaintext. The seed makes plaintext content reproducible so
    # a failing iteration can be replayed with the same bytes; it
    # governs nothing else -- pipeline keys, nonces and masters stay
    # CSPRNG-drawn, so a seeded run is a reproduction aid and never a
    # security test. Each worker's stream is domain-separated by its id
    # so seeded workers still hold pairwise-distinct buffers under the
    # fixed and rotating modes. The generator is splitmix64: a few lines
    # in any language, which is why it is the one every binding uses.
    def seed_worker(seed, worker_id)
      (seed + worker_id + 1) & MASK64
    end

    # One splitmix64 draw; returns the advanced state and the output.
    #
    # Ruby-specific. Integers are arbitrary precision, so every step
    # that would wrap in a 64-bit register is masked explicitly; without
    # the masks the generator still produces bytes and still reproduces
    # itself, but it is not splitmix64.
    def splitmix64(state)
      state = (state + 0x9E37_79B9_7F4A_7C15) & MASK64
      z = state
      z = ((z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9) & MASK64
      z = ((z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB) & MASK64
      [state, z ^ (z >> 31)]
    end

    # Draws n bytes from the operating-system CSPRNG.
    def fill_random(n)
      SecureRandom.bytes(n)
    end

    # Builds one plaintext buffer according to the payload mode and
    # returns it with the advanced generator state. The fixed and
    # rotating modes draw from the seeded generator when the run is
    # seeded and from the OS CSPRNG otherwise; the pattern modes are
    # deterministic regardless of the seed.
    def fill(mode, seeded, rng, n)
      case mode
      when FIXED, ROTATING
        return [fill_random(n), rng] unless seeded

        words = Array.new((n + 7) / 8) do
          rng, value = splitmix64(rng)
          value
        end
        [words.pack("Q<*").byteslice(0, n), rng]
      when PATTERN_ZERO
        ["\x00".b * n, rng]
      when PATTERN_FF
        ["\xFF".b * n, rng]
      else
        [(ASCII_RAMP * ((n / 26) + 1)).byteslice(0, n), rng]
      end
    end
  end
end
