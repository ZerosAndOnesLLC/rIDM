#!/usr/bin/env bash
# Assembles the GitHub Pages site into _site/: the website (site/) at the root
# and the documentation (docs/, mdBook) under docs/. The guide used to be the
# root of the site, so every one of its old page URLs gets a stub that
# redirects to the same page under docs/.
set -euo pipefail
cd "$(dirname "$0")/../.."

docs/build.sh

rm -rf _site
mkdir -p _site
cp -R site/. _site/
cp -R docs/book _site/docs

(cd docs/book && find . -name '*.html' ! -name index.html ! -name 404.html ! -name toc.html) |
  while read -r page; do
    page=${page#./}
    stub=_site/$page
    [ -e "$stub" ] && continue
    mkdir -p "$(dirname "$stub")"
    target=/rIDM/docs/$page
    cat > "$stub" <<HTML
<!doctype html>
<meta charset="utf-8">
<title>Moved</title>
<link rel="canonical" href="$target">
<meta http-equiv="refresh" content="0; url=$target">
<p>This page moved to <a href="$target">$target</a>.</p>
HTML
  done
