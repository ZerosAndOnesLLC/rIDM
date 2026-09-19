#!/usr/bin/env bash
# check-version.sh vX.Y.Z[-pre]: the tag must name the version every release
# artifact is stamped with. The version lives in five places and a release
# ships all of them, so they are compared rather than rewritten here; bumping
# them is part of cutting the release (a commit before the tag).
#
#   Cargo.toml                  [workspace.package] version (every crate)
#   ui/package.json             version
#   deploy/helm/ridm/Chart.yaml version and appVersion
#   examples/*/Cargo.toml       the version on the ridm-auth path dependency
#   CHANGELOG.md                a "## [X.Y.Z]" section
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
tag="${1:?usage: check-version.sh vX.Y.Z}"
[[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$ ]] ||
  { echo "tag $tag is not v<semver>" >&2; exit 1; }
want="${BASH_REMATCH[1]}"

status=0
check() {
  local what="$1" got="$2"
  if [ "$got" = "$want" ]; then
    echo "ok   $what = $got"
  else
    echo "FAIL $what = ${got:-<missing>}, tag says $want" >&2
    status=1
  fi
}

check "Cargo.toml workspace version" \
  "$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' "$root/Cargo.toml")"
check "ui/package.json version" \
  "$(sed -n 's/^  "version": "\(.*\)",$/\1/p' "$root/ui/package.json" | head -n 1)"
check "Chart.yaml version" "$(sed -n 's/^version: *//p' "$root/deploy/helm/ridm/Chart.yaml")"
check "Chart.yaml appVersion" "$(sed -n 's/^appVersion: *//p' "$root/deploy/helm/ridm/Chart.yaml")"
for manifest in "$root"/examples/*/Cargo.toml; do
  line="$(grep '^ridm-auth' "$manifest" || true)"
  [ -n "$line" ] || continue
  check "${manifest#"$root"/} ridm-auth" "$(sed -n 's/.*version *= *"\([^"]*\)".*/\1/p' <<<"$line")"
done
if grep -q "^## \[$want\]" "$root/CHANGELOG.md"; then
  echo "ok   CHANGELOG.md has a [$want] section"
else
  echo "FAIL CHANGELOG.md has no \"## [$want]\" section" >&2
  status=1
fi
exit "$status"
