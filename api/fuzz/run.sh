#!/usr/bin/env bash
# Run every fuzz target for a while. Used by the `fuzz-smoke` PR check (60 s a
# target) and by the weekly long run (four hours a target).
#
#   api/fuzz/run.sh [seconds] [target ...]
#
# Needs a nightly toolchain and cargo-fuzz:
#   rustup toolchain install nightly
#   cargo install cargo-fuzz --locked
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/.."   # `cargo fuzz` expects the crate whose `fuzz/` directory this is

seconds="${1:-60}"
shift || true
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  mapfile -t targets < <(cargo +nightly fuzz list)
fi

# `cargo fuzz` defaults the target triple to the one it was itself built for,
# and a binstalled cargo-fuzz is a musl build — which then asks for a musl std
# nobody installed. Always build for the toolchain's own host.
host="$(rustc +nightly -vV | sed -n 's/^host: //p')"

# Build first, and outside the per-target timeout: `cargo fuzz run` would
# otherwise build inside it, and a cold sanitizer build of the whole dependency
# tree takes far longer than any sane grace on a fuzzing run.
echo "::group::build (sanitizer)"
cargo +nightly fuzz build --target "$host"
echo "::endgroup::"

# What a run may take beyond its budget — libFuzzer's own shutdown, writing the
# corpus back — before the target is called hung. The build is already done.
grace=120
status=0
for target in "${targets[@]}"; do
  echo "::group::fuzz $target (${seconds}s)"
  mkdir -p "fuzz/corpus/$target"
  if [ -d "fuzz/seeds/$target" ]; then
    cp -n "fuzz/seeds/$target"/* "fuzz/corpus/$target/" 2>/dev/null || true
  fi
  rc=0
  timeout $((seconds + grace)) cargo +nightly fuzz run --target "$host" "$target" -- \
    -max_total_time="$seconds" -timeout=25 -rss_limit_mb=4096 -print_final_stats=1 || rc=$?
  case $rc in
    0) ;;
    124) echo "fuzz target $target ran past ${seconds}s + ${grace}s and was stopped"; status=1 ;;
    *) echo "fuzz target $target failed (exit $rc)"; status=1 ;;
  esac
  echo "::endgroup::"
done

if [ $status -ne 0 ]; then
  echo "Crashing inputs are under api/fuzz/artifacts/; reproduce one with:"
  echo "  cargo +nightly fuzz run <target> api/fuzz/artifacts/<target>/<input>"
fi
exit $status
