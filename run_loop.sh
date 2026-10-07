#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Ruby binding:
# runs the utility with every argument passed through. The binding is
# pure Ruby over the ffi gem, so there is nothing to compile here;
# build.sh owns libitb3.so and the syntax check over the sources.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

exec ruby loop/main.rb "$@"
