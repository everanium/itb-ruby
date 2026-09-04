# frozen_string_literal: true

# eitb -- command-line demonstrator for the ITB Ruby binding.
#
# Subcommands:
#
#   itb.rb version                                   library + binding versions
#   itb.rb profiles                                  registered profile catalogue
#   itb.rb inspect <blob-hex>                        profile record of a blob
#   itb.rb encrypt <profile> <in-file> <out-file>    Single Message encrypt
#   itb.rb decrypt <profile> <blob-hex> <in-file> <out-file>
#
# encrypt prints the session blob (Pipeline#save) to stderr as hex;
# feed that hex back to decrypt on the receiving side, which reopens
# the session with ITB.load (the profile argument only routes Single
# Message versus streaming). profiles lists the registered profile
# catalogue one name per line; the profiles that carry a cipher
# surface are the ones encrypt / decrypt accept.

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "fileutils"
require "json"
require "itb"

USAGE = <<~TEXT
  usage: itb.rb version
         itb.rb profiles
         itb.rb inspect <blob-hex>
         itb.rb encrypt <profile> <in-file> <out-file>
         itb.rb decrypt <profile> <blob-hex> <in-file> <out-file>
TEXT

def cmd_version
  puts "libitb #{ITB.version}"
  puts "itb-ruby #{ITB::VERSION}"
end

def cmd_profiles
  ITB.profiles.each { |name| puts name }
end

def blob_from_hex(blob_hex)
  raise ITB::Error, "blob hex: odd length or non-hex characters" unless blob_hex.match?(/\A(?:[0-9a-fA-F]{2})+\z/)

  [blob_hex].pack("H*")
end

def cmd_inspect(blob_hex)
  puts JSON.pretty_generate(ITB.inspect_blob(blob_from_hex(blob_hex)))
end

# Profiles whose canonical name begins with "streaming-" route
# through the streaming session pair instead of the Single Message
# pair.
def streaming_profile?(profile)
  profile.start_with?("streaming-")
end

# Recursively create the parent directory of +path+ (mkdir -p).
def ensure_parent_dir(path)
  FileUtils.mkdir_p(File.dirname(path))
end

# One-shot streaming: open a session, feed the whole payload, drain
# until finished.
def stream_one_shot(pipe, direction, payload)
  session = direction == :encrypt ? pipe.encrypt_stream : pipe.decrypt_stream
  begin
    session.write(payload)
    session.drain_all
  ensure
    session.free
  end
end

def cmd_encrypt(profile, infile, outfile)
  plain = File.binread(infile)
  pipe = ITB.create(profile)
  begin
    wire = if streaming_profile?(profile)
      stream_one_shot(pipe, :encrypt, plain)
    else
      pipe.encrypt_message(plain)
    end
    ensure_parent_dir(outfile)
    File.binwrite(outfile, wire)
    warn pipe.save.unpack1("H*")
  ensure
    pipe.free
  end
  puts "encrypted #{infile} -> #{outfile} (#{plain.bytesize} -> #{wire.bytesize} bytes)"
end

def cmd_decrypt(profile, blob_hex, infile, outfile)
  blob = blob_from_hex(blob_hex)
  wire = File.binread(infile)
  pipe = ITB.load(blob)
  begin
    plain = if streaming_profile?(profile)
      stream_one_shot(pipe, :decrypt, wire)
    else
      pipe.decrypt_message(wire)
    end
  ensure
    pipe.free
  end
  ensure_parent_dir(outfile)
  File.binwrite(outfile, plain)
  puts "decrypted #{infile} -> #{outfile} (#{wire.bytesize} -> #{plain.bytesize} bytes)"
end

argv = ARGV
known_shape =
  (argv.length == 1 && %w[version profiles].include?(argv[0])) ||
  (argv.length == 2 && argv[0] == "inspect") ||
  (argv.length == 4 && argv[0] == "encrypt") ||
  (argv.length == 5 && argv[0] == "decrypt")
unless known_shape
  warn USAGE
  exit 2
end

begin
  # Go-runtime pacing caps applied before any cipher work.
  ITB.set_memory_limit(512 << 20)
  ITB.set_gc_percent(20)
  case argv[0]
  when "version" then cmd_version
  when "profiles" then cmd_profiles
  when "inspect" then cmd_inspect(argv[1])
  when "encrypt" then cmd_encrypt(argv[1], argv[2], argv[3])
  else cmd_decrypt(argv[1], argv[2], argv[3], argv[4])
  end
rescue ITB::Error, SystemCallError, IOError => e
  warn "eitb: #{e.message}"
  exit 1
end
