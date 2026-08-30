#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Ruby binding. Builds
# libitb.so via build.sh, points ITB_LIBITB_PATH at the freshly-built
# shared library, then runs the Minitest suite. Positional arguments
# are forwarded to Minitest (e.g. a single test via
# `./run_tests.sh -n test_message_round_trip`).
#
# Usage:
#   ./run_tests.sh                             # full suite
#   ./run_tests.sh -n test_stream_round_trip   # one test

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

exec ruby -I lib test/itb_test.rb "$@"
