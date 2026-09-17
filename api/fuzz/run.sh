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

# Time a run may take beyond its budget before the job gives up on it.
grace=300
status=0
for target in "${targets[@]}"; do
  echo "::group::fuzz $target (${seconds}s)"
  mkdir -p "fuzz/corpus/$target"
  if [ -d "fuzz/seeds/$target" ]; then
    cp -n "fuzz/seeds/$target"/* "fuzz/corpus/$target/" 2>/dev/null || true
  fi
  if ! timeout $((seconds + grace)) cargo +nightly fuzz run "$target" -- \
    -max_total_time="$seconds" -timeout=25 -rss_limit_mb=4096 -print_final_stats=1; then
    echo "fuzz target $target failed"
    status=1
  fi
  echo "::endgroup::"
done

if [ $status -ne 0 ]; then
  echo "Crashing inputs are under api/fuzz/artifacts/; reproduce one with:"
  echo "  cargo +nightly fuzz run <target> api/fuzz/artifacts/<target>/<input>"
fi
exit $status
