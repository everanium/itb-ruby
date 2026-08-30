# ITB Ruby Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via the `ffi` gem — no C compiler at
install time, no compile-time link; the `.so` / `.dylib` / `.dll` is
resolved at load time. Every hash-name / MAC-name / cipher-name /
profile-name is an opaque string passed through to Go for validation;
the binding carries no ITB construction logic. The public surface is
the `ITB` module (`create` / `open` / `hashes` / `profiles` /
`version` / `register_profile` and the Go runtime knobs), the
`Pipeline` class (Single Message encrypt / decrypt, rekey, close,
incremental stream sessions), and the `StreamEncryptor` /
`StreamDecryptor` session classes.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go ruby
gem install --user-install ffi
```

Generic Linux / macOS: a Go toolchain, Ruby 2.7+, and the `ffi` gem
(`~> 1.17`). Windows: the same; libitb builds as `libitb.dll`. The
`ffi` gem is portable across MRI, JRuby, and TruffleRuby.

## Build the shared library

The convenience driver builds `libitb.so` and syntax-checks the Ruby
sources in one step:

```bash
./bindings/ruby/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The gem is loadable directly from `bindings/ruby/lib` (no build step —
the `ffi` gem loads the shared library at load time); a local gem
build is `gem build itb.gemspec`.

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved from the gem
   directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```ruby
require "itb"

sender = ITB.create("singlemsg-triple-mac-v1")
receiver = ITB.open("singlemsg-triple-mac-v1", sender.blob)

wire = sender.encrypt_message("any text or binary data")
plain = receiver.decrypt_message(wire)
raise unless plain == "any text or binary data"

sender.free
receiver.free
```

Opts override the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette) as a
hash passed to `ITB.create` / `ITB.open`:

```ruby
opts = { "chunkSize" => 65536, "withWrapper" => false }
sender = ITB.create("singlemsg-triple-mac-v1", opts)
receiver = ITB.open("singlemsg-triple-mac-v1", sender.blob, opts)
```

`Pipeline#rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```ruby
sender.rekey("\x11".b * 32, "\x22".b * 32)
receiver = ITB.open("singlemsg-triple-mac-v1", sender.blob)
```

`encrypt_stream` / `decrypt_stream` open incremental sessions
exposing `write` / `end_stream` / `read` / `drain_all` for
caller-driven loops, plus a `pump(src, dst)` helper that moves any
readable IO into any writable one with bounded memory. With a block,
the session is freed on return:

```ruby
pipe = ITB.create("streaming-noaead-triple-v1")
wire = pipe.encrypt_stream do |enc|
  enc.write(chunk_a)
  enc.write(chunk_b)
  enc.drain_all
end
```

`Pipeline` and the stream sessions register GC finalizers, so
un-freed handles are reclaimed eventually; explicit `free` (or the
block form) releases the Go-side state deterministically. Stream
sessions hold a reference to their parent `Pipeline`, so the parent
cannot be garbage-collected while a session is live.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string raises `ITB::Error` carrying the
status code (`status_code`, values in `ITB::Status`) plus the
`ITB_LastError` diagnostic (`last_error`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```ruby
ITB.set_memory_limit(512 << 20)
ITB.set_gc_percent(20)
```

## Testing

```bash
./bindings/ruby/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and runs
the Minitest suite. The suite covers the library version, the hash
roster order, the shipped profile list, Single Message and stream
round trips, pump round trips, tampered-wire rejection, closed-handle
mapping, large-payload buffer sizing, rekey, profile registration,
and error mapping — surface parity checks; the deep suite lives in Go
under the shipped tree.

## Benchmarking

```bash
./bindings/ruby/run_bench.sh
```

Micro-benches: `encrypt_message` and stream-session encrypt
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven by
env vars (`ITB_PROFILE`, `ITB_INNER_HASH`, `ITB_KEY_BITS`,
`ITB_NONCE_BITS`, `ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`,
`ITB_BENCH_MIN_SEC`); the script pins the same defaults as the root
Go BENCH3.md table.

## eitb utility

A small CLI under `bindings/ruby/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
./bindings/ruby/eitb/eitb version
./bindings/ruby/eitb/eitb hashes
./bindings/ruby/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/ruby/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ITB::Error` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- Input strings are borrowed at the FFI boundary for the duration of
  the call (non-binary encodings are copied to a binary string
  first); outputs are freshly-allocated binary strings.
- Potentially-blocking FFI calls are attached with `blocking: true`,
  so the GVL is released while Go-side cipher work runs.
- libitb must be reachable at load time through the lookup order
  above; a resolve failure raises `LoadError` at `require "itb"`.
