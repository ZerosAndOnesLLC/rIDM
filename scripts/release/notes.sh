#!/usr/bin/env bash
# notes.sh X.Y.Z: the CHANGELOG.md section for that version, without its
# heading, as the body of the GitHub release. Fails when the section is
# missing or empty, so a release never goes out without notes.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
version="${1:?usage: notes.sh X.Y.Z}"
notes="$(awk -v v="$version" '
  index($0, "## [" v "]") == 1 { on = 1; next }
  on && /^## \[/ { exit }
  on && /^\[[^]]+\]: / { next }
  on { print }
' "$root/CHANGELOG.md" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"
if [ -z "$(tr -d '[:space:]' <<<"$notes")" ]; then
  echo "CHANGELOG.md has no notes for $version" >&2
  exit 1
fi
printf '%s\n' "$notes"
