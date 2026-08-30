# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/itb"

# Surface parity checks for the Ruby binding; the deep suite lives in
# Go under the shipped tree.
class ItbTest < Minitest::Test
  CANONICAL_HASHES = %w[
    areion256 areion512 blake2b256 blake2b512 blake2s
    blake3 aescmac siphash24 chacha20
  ].freeze

  # Deterministic non-trivial payload (xorshift fill).
  def payload(n, seed)
    x = seed | 1
    mask = 0xFFFFFFFFFFFFFFFF
    out = String.new(capacity: n)
    n.times do
      x ^= (x << 13) & mask
      x ^= x >> 7
      x ^= (x << 17) & mask
      out << (x & 0xFF).chr
    end
    out.b
  end

  def test_version_is_nonempty
    v = ITB.version
    refute_empty v
    assert_match(/\A\d+\.\d+/, v)
  end

  def test_hashes_canonical_order
    hashes = ITB.hashes
    assert_equal CANONICAL_HASHES, hashes.map(&:name)
    hashes.each { |h| assert_operator h.width, :>=, 128 }
  end

  def test_profiles_list
    profiles = ITB.profiles
    assert_includes profiles, "singlemsg-triple-mac-v1"
    assert_includes profiles, "streaming-noaead-triple-v1"
    # Every listed profile initialises on the Go side.
    profiles.each do |p|
      pipe = ITB.create(p)
      refute_empty pipe.blob
      pipe.free
    end
  end

  def test_message_round_trip
    sender = ITB.create("singlemsg-triple-mac-v1")
    receiver = ITB.open("singlemsg-triple-mac-v1", sender.blob)
    [4 * 1024, 256 * 1024].each do |size|
      plain = payload(size, size)
      wire = sender.encrypt_message(plain)
      refute plain == wire, "wire must differ from plaintext"
      back = receiver.decrypt_message(wire)
      assert plain == back, "message round trip mismatch @#{size}"
    end
  ensure
    sender&.free
    receiver&.free
  end

  def test_stream_round_trip
    sender = ITB.create("streaming-noaead-triple-v1")
    receiver = ITB.open("streaming-noaead-triple-v1", sender.blob)
    plain = payload(3 * 1024 * 1024 + 17, 42)

    wire = +""
    sender.encrypt_stream do |enc|
      # Feed in uneven slices to exercise incremental writes.
      off = 0
      [1_000_000, 1_700_001, plain.bytesize].each do |upto|
        enc.write(plain.byteslice(off, upto - off))
        off = upto
      end
      wire << enc.drain_all
    end
    refute_empty wire

    back = +""
    receiver.decrypt_stream do |dec|
      dec.write(wire)
      back << dec.drain_all
    end
    # Boolean compare -- assert_equal would dump multi-MiB binary
    # diffs on failure.
    assert plain == back, "stream round trip mismatch (#{plain.bytesize} vs #{back.bytesize} bytes)"
  ensure
    sender&.free
    receiver&.free
  end

  def test_stream_pump_round_trip
    require "stringio"
    sender = ITB.create("streaming-aead-triple-mac-v1")
    receiver = ITB.open("streaming-aead-triple-mac-v1", sender.blob)
    plain = payload(2 * 1024 * 1024 + 3, 7)

    wire_io = StringIO.new(+"", "wb")
    sender.encrypt_stream { |enc| enc.pump(StringIO.new(plain), wire_io) }
    back_io = StringIO.new(+"", "wb")
    receiver.decrypt_stream { |dec| dec.pump(StringIO.new(wire_io.string), back_io) }
    assert plain == back_io.string,
           "pump round trip mismatch (#{plain.bytesize} vs #{back_io.string.bytesize} bytes)"
  ensure
    sender&.free
    receiver&.free
  end

  def test_bad_profile_maps_to_bad_input
    err = assert_raises(ITB::Error) { ITB.create("no-such-profile") }
    assert_equal ITB::Status::BAD_INPUT, err.status_code
    refute_empty err.message
  end

  def test_tampered_wire_fails_decrypt
    sender = ITB.create("singlemsg-triple-mac-v1")
    receiver = ITB.open("singlemsg-triple-mac-v1", sender.blob)
    wire = sender.encrypt_message(payload(8 * 1024, 3)).dup
    # XOR a 64-byte span so the corruption is guaranteed to hit data
    # bits (a single flipped bit can land in a noise-bit position the
    # decode path ignores).
    mid = wire.bytesize / 2
    64.times { |i| wire.setbyte(mid + i, wire.getbyte(mid + i) ^ 0xFF) }
    err = assert_raises(ITB::Error) { receiver.decrypt_message(wire) }
    assert_equal ITB::Status::MAC_FAILURE, err.status_code
  ensure
    sender&.free
    receiver&.free
  end

  def test_closed_pipeline_reports_triple_closed
    pipe = ITB.create("singlemsg-triple-mac-v1")
    pipe.close
    pipe.close # idempotent
    err = assert_raises(ITB::Error) { pipe.encrypt_message("payload") }
    assert_equal ITB::Status::TRIPLE_CLOSED, err.status_code
  ensure
    pipe&.free
  end

  def test_large_plaintext_round_trip
    # Pattern P1: the pre-allocated output buffer plus a single
    # retry gated on strict len > cap must cover a > 1 MiB payload.
    sender = ITB.create("singlemsg-triple-nomac-v1")
    receiver = ITB.open("singlemsg-triple-nomac-v1", sender.blob)
    plain = payload((1 << 20) + 4321, 9)
    wire = sender.encrypt_message(plain)
    back = receiver.decrypt_message(wire)
    assert plain == back,
           "large round trip mismatch (#{plain.bytesize} vs #{back.bytesize} bytes)"
  ensure
    sender&.free
    receiver&.free
  end

  def test_rekey_refreshes_blob
    sender = ITB.create("singlemsg-triple-mac-v1")
    old_blob = sender.blob
    sender.rekey("\x01".b * 32, "\x02".b * 32)
    refute_equal old_blob, sender.blob
    receiver = ITB.open("singlemsg-triple-mac-v1", sender.blob)
    wire = sender.encrypt_message("after rekey")
    assert_equal "after rekey", receiver.decrypt_message(wire)
  ensure
    sender&.free
    receiver&.free
  end

  def test_register_profile_and_duplicate
    name = "ruby-binding-test-#{Process.pid}"
    opts = {
      "mode" => "singlemsg-nomac",
      "width" => "256",
      "innerHashes" => "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256",
      "keyBits" => "1024",
      "parallaxOn" => "false",
      "wrapperOn" => "false"
    }
    ITB.register_profile(name, opts)
    sender = ITB.create(name)
    receiver = ITB.open(name, sender.blob)
    wire = sender.encrypt_message("custom profile")
    assert_equal "custom profile", receiver.decrypt_message(wire)

    err = assert_raises(ITB::Error) { ITB.register_profile(name, opts) }
    assert_equal ITB::Status::PROFILE_EXISTS, err.status_code
  ensure
    sender&.free
    receiver&.free
  end

  def test_runtime_knobs_report_previous_values
    prev = ITB.set_memory_limit(-1)
    assert_kind_of Integer, prev
    prev_gc = ITB.set_gc_percent(-1)
    assert_kind_of Integer, prev_gc
  end

  def test_into_cap_guard_raises_argument_error
    # cap is the write ceiling libitb honours; a cap above the real
    # buffer size must be rejected before the FFI call, never
    # forwarded (silent heap corruption otherwise).
    msg_pipe = ITB.create("singlemsg-triple-nomac-v1")
    stream_pipe = ITB.create("streaming-noaead-triple-v1")
    buf = FFI::MemoryPointer.new(:char, 1024, false)
    assert_raises(ArgumentError) do
      msg_pipe.encrypt_message_into("payload", buf, buf.size + 1)
    end
    assert_raises(ArgumentError) do
      msg_pipe.decrypt_message_into("wire", buf, buf.size + 1)
    end
    stream_pipe.encrypt_stream do |enc|
      assert_raises(ArgumentError) { enc.read_into(buf, buf.size + 1) }
    end
  ensure
    buf&.free
    msg_pipe&.free
    stream_pipe&.free
  end

  def test_message_into_round_trip
    sender = ITB.create("singlemsg-triple-nomac-v1")
    receiver = ITB.open("singlemsg-triple-nomac-v1", sender.blob)
    plain = payload(64 * 1024, 5)
    cap = plain.bytesize + (plain.bytesize / 4) + 65_536
    wire_buf = FFI::MemoryPointer.new(:char, cap, false)
    back_buf = FFI::MemoryPointer.new(:char, cap, false)
    n = sender.encrypt_message_into(plain, wire_buf)
    assert_operator n, :>, 0
    wire = wire_buf.read_bytes(n)
    refute plain == wire, "wire must differ from plaintext"
    m = receiver.decrypt_message_into(wire, back_buf)
    assert plain == back_buf.read_bytes(m),
           "message _into round trip mismatch (#{plain.bytesize} vs #{m} bytes)"
  ensure
    wire_buf&.free
    back_buf&.free
    sender&.free
    receiver&.free
  end

  def test_message_into_undersized_dst_reports_buffer_too_small
    # The _into entries do not retry -- the caller owns capacity
    # policy; an undersized dst surfaces as BUFFER_TOO_SMALL, never
    # as corruption.
    sender = ITB.create("singlemsg-triple-nomac-v1")
    plain = payload(4 * 1024, 11)
    tiny = FFI::MemoryPointer.new(:char, 16, false)
    err = assert_raises(ITB::Error) { sender.encrypt_message_into(plain, tiny) }
    assert_equal ITB::Status::BUFFER_TOO_SMALL, err.status_code
  ensure
    tiny&.free
    sender&.free
  end

  def test_read_into_partial_drains
    sender = ITB.create("streaming-noaead-triple-v1")
    receiver = ITB.open("streaming-noaead-triple-v1", sender.blob)
    plain = payload(1024 * 1024 + 13, 21)
    small = FFI::MemoryPointer.new(:char, 4096, false)

    wire = +""
    sender.encrypt_stream do |enc|
      enc.write(plain)
      enc.end_stream
      loop do
        n, finished = enc.read_into(small)
        assert_operator n, :<=, small.size
        wire << small.read_bytes(n) if n.positive?
        break if finished
      end
      # A drain after the finished flag stays clean: [0, true].
      n, finished = enc.read_into(small)
      assert_equal 0, n
      assert finished
    end
    refute_empty wire

    back = +""
    receiver.decrypt_stream do |dec|
      dec.write(wire)
      dec.end_stream
      loop do
        n, finished = dec.read_into(small)
        back << small.read_bytes(n) if n.positive?
        break if finished
      end
    end
    assert plain == back,
           "partial-drain round trip mismatch (#{plain.bytesize} vs #{back.bytesize} bytes)"
  ensure
    small&.free
    sender&.free
    receiver&.free
  end
end
