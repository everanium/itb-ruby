#!/usr/bin/env bash
#
# build.sh -- one-step build for the Ruby binding's libitb.so
# dependency. Prerequisites (Go, Ruby 2.7+, the ffi gem) must be
# installed separately; see README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#                          # (use on hosts without AVX-512+VL)

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

cd "$REPO_ROOT/bindings/ruby"
echo "==> syntax-checking the itb gem sources"
for f in lib/itb.rb lib/itb/*.rb test/*.rb bench/*.rb eitb/itb.rb; do
    ruby -c "$f" > /dev/null
done

echo "==> Ruby binding loads libitb.so at runtime via the ffi gem; no further build step."
echo "==> ready: ./run_tests.sh"
