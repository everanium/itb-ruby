# frozen_string_literal: true

# Size and duration parsing, the monotonic clock, and the human
# renderings of sizes, rates and durations. Every rendering here is part
# of the output contract shared with the Go harness and the other
# bindings' loop utilities, so the formats are fixed to the character,
# not to taste.
module Loop
  module Size
    # Byte-size suffixes, longest first so "KIB" is matched before "K"
    # and "B" never swallows the tail of another suffix. Every multiple
    # is binary.
    SUFFIXES = [
      ["KIB", 1 << 10], ["KB", 1 << 10], ["K", 1 << 10],
      ["MIB", 1 << 20], ["MB", 1 << 20], ["M", 1 << 20],
      ["GIB", 1 << 30], ["GB", 1 << 30], ["G", 1 << 30],
      ["B", 1]
    ].freeze

    # Duration units in the order the grammar probes them, so "ms" is
    # taken before "m" and "s".
    UNITS = [
      ["ns", 1.0], ["us", 1e3], ["ms", 1e6],
      ["s", 1e9], ["m", 60e9], ["h", 3600e9]
    ].freeze

    INT64_MAX = (1 << 63) - 1

    module_function

    # Parses a human byte-size string ("16MB", "1MiB", "512K",
    # "1073741824") into a byte count. Every suffix is a binary
    # multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3,
    # B or none = bytes; matching is case-insensitive and surrounding
    # whitespace is trimmed. Returns nil on a malformed or negative
    # value.
    def parse_size(str)
      upper = str.strip.upcase
      return nil if upper.empty?

      mult = 1
      digits = upper
      SUFFIXES.each do |suffix, m|
        next unless upper.end_with?(suffix)

        mult = m
        digits = upper[0, upper.length - suffix.length]
        break
      end
      digits = digits.rstrip
      return nil if digits.empty? || !digits.match?(/\A[0-9]+\z/)

      n = digits.to_i
      return nil if mult > 1 && n > INT64_MAX / mult

      n * mult
    end

    # Parses the Go duration grammar -- a sequence of decimal numbers
    # each followed by a unit (h, m, s, ms, us, ns), such as "30s",
    # "5m", "1h30m", "1.5s" -- into nanoseconds. Returns nil on a
    # malformed string.
    def parse_duration(str)
      return nil if str.empty?

      total = 0.0
      pos = 0
      while pos < str.length
        m = /\G[0-9.]+/.match(str, pos)
        return nil if m.nil?

        text = m[0]
        return nil unless text.match?(/\A[0-9]*\.?[0-9]*\z/) && text.match?(/[0-9]/)

        value = text.to_f
        pos = m.end(0)
        mult = 0.0
        UNITS.each do |unit, ns|
          next unless str[pos, unit.length] == unit && !(str[pos + unit.length, 1] || "").match?(/[A-Za-z]/)

          mult = ns
          pos += unit.length
          break
        end
        return nil if mult.zero?

        total += value * mult
      end
      return nil if total > 9.2e18

      total.to_i
    end

    # Monotonic wall clock in nanoseconds.
    def now_ns
      Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
    end

    # Renders a byte count with a binary-unit suffix: "1.0GiB",
    # "16.0MiB", "4.0KiB", "512B".
    def human_bytes(n)
      return format("%.1fGiB", n.to_f / (1 << 30)) if n >= (1 << 30)
      return format("%.1fMiB", n.to_f / (1 << 20)) if n >= (1 << 20)
      return format("%.1fKiB", n.to_f / (1 << 10)) if n >= (1 << 10)

      "#{n}B"
    end

    # Renders a possibly-negative byte delta with an explicit sign.
    def human_bytes_signed(n)
      n.negative? ? "-#{human_bytes(-n)}" : "+#{human_bytes(n)}"
    end

    # Binary MiB per second over a nanosecond window; 0 when the window
    # is unmeasured.
    def mb_per_sec(byte_count, ns)
      return 0.0 if ns <= 0

      byte_count.to_f / (1 << 20) / (ns.to_f / 1e9)
    end

    # Renders a throughput as "123.4MB/s" (binary MiB per second) or
    # "n/a" for an unmeasured window.
    def human_rate(byte_count, ns)
      return "n/a" if ns <= 0

      format("%.1fMB/s", mb_per_sec(byte_count, ns))
    end

    # The fractional part of a nanosecond remainder (0 .. 1e9) as
    # ".ddd" with trailing zeros removed; empty for zero.
    def fraction(frac_ns)
      return "" if frac_ns.zero?

      ".#{format('%09d', frac_ns).sub(/0+\z/, '')}"
    end

    # Renders a duration the way Go's time.Duration prints: below one
    # second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
    # where the hour part appears when non-zero, the minute part when
    # the hour part appears or the minutes are non-zero, and the
    # seconds carry their fraction with trailing zeros removed ("5s",
    # "5.003s", "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
    def human_duration(ns)
      ns = ns.abs
      return "0s" if ns.zero?

      if ns < 1_000_000_000
        # Scale the sub-millisecond remainder to nine digits so the
        # fraction renderer sees the same shape it does for seconds.
        return "#{ns / 1_000_000}#{fraction((ns % 1_000_000) * 1000)}ms"
      end

      hours, rem = ns.divmod(3_600_000_000_000)
      minutes, rem = rem.divmod(60_000_000_000)
      seconds, frac = rem.divmod(1_000_000_000)
      out = hours.positive? ? "#{hours}h" : ""
      out += "#{minutes}m" if hours.positive? || minutes.positive?
      "#{out}#{seconds}#{fraction(frac)}s"
    end
  end
end
