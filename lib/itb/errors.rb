# frozen_string_literal: true

module ITB
  # Status codes mirrored from the libitb C ABI
  # (cmd/cshared/internal/capi/errors.go). Numeric values are stable
  # across releases.
  module Status
    OK = 0
    BAD_HASH = 1
    BAD_KEY_BITS = 2
    BAD_HANDLE = 3
    BAD_INPUT = 4
    BUFFER_TOO_SMALL = 5
    ENCRYPT_FAILED = 6
    DECRYPT_FAILED = 7
    SEED_WIDTH_MIX = 8
    BAD_MAC = 9
    MAC_FAILURE = 10
    BLOB_MALFORMED_RECIPE = 11
    RECIPE_PRIMITIVE_UNKNOWN = 12
    UNKNOWN_PROFILE = 13
    BLOB_MODE_MISMATCH = 19
    BLOB_MALFORMED = 20
    BLOB_VERSION_TOO_NEW = 21
    BLOB_TOO_MANY_OPTS = 22
    STREAM_TRUNCATED = 23
    STREAM_AFTER_FINAL = 24
    TRIPLE_CLOSED = 25
    PROFILE_EXISTS = 26
    INTERNAL = 99

    LABELS = {
      OK => "ok",
      BAD_HASH => "unknown hash name",
      BAD_KEY_BITS => "invalid key bits",
      BAD_HANDLE => "invalid handle",
      BAD_INPUT => "invalid input",
      BUFFER_TOO_SMALL => "output buffer too small",
      ENCRYPT_FAILED => "encrypt failed",
      DECRYPT_FAILED => "decrypt failed",
      SEED_WIDTH_MIX => "seed width mismatch",
      BAD_MAC => "unknown MAC name or invalid MAC handle",
      MAC_FAILURE => "MAC verification failed",
      BLOB_MALFORMED_RECIPE => "blob profile record invalid",
      RECIPE_PRIMITIVE_UNKNOWN =>
        "blob profile record names a primitive absent from the local registries",
      UNKNOWN_PROFILE => "unknown profile name",
      BLOB_MODE_MISMATCH => "blob mode mismatch",
      BLOB_MALFORMED => "malformed state blob",
      BLOB_VERSION_TOO_NEW => "blob version too new",
      BLOB_TOO_MANY_OPTS => "too many blob export opts",
      STREAM_TRUNCATED => "stream truncated before terminator",
      STREAM_AFTER_FINAL => "stream chunk after terminator",
      TRIPLE_CLOSED => "Triple Pipeline is closed",
      PROFILE_EXISTS => "profile name already registered",
      INTERNAL => "internal error"
    }.freeze

    # Short human-readable label for a status code; unknown codes
    # collapse to "unknown status".
    def self.label(code)
      LABELS.fetch(code, "unknown status")
    end
  end

  # Raised on every failed libitb call.
  #
  # +status_code+ carries the libitb status integer when the failure
  # came from the shared library (+nil+ for binding-side failures such
  # as a library-load error). +last_error+ carries the ITB_LastError
  # diagnostic captured immediately after the failing call
  # (process-global last-write-wins -- the message may belong to a
  # different call under concurrent FFI use; the status code is always
  # attributable).
  class Error < StandardError
    attr_reader :status_code, :last_error

    def initialize(message, status_code = nil)
      @status_code = status_code
      @last_error = message.to_s
      text =
        if status_code.nil?
          "itb: #{@last_error}"
        elsif @last_error.empty?
          "itb: status=#{status_code} (#{Status.label(status_code)})"
        else
          "itb: status=#{status_code} (#{Status.label(status_code)}): #{@last_error}"
        end
      super(text)
    end
  end
end
