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

# sitemap.xml for search engines: the website and every documentation page,
# each dated by the last commit to its source. Redirect stubs, the 404 pages,
# the print-everything page and the table-of-contents frame are left out, and
# the guide's introduction appears once, as docs/.
base=https://zerosandonesllc.github.io/rIDM/
lastmod() { git log -1 --format=%cs -- "$@"; }
{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
  printf '  <url><loc>%s</loc><lastmod>%s</lastmod></url>\n' "$base" "$(lastmod site)"
  printf '  <url><loc>%s</loc><lastmod>%s</lastmod></url>\n' "${base}docs/" "$(lastmod docs/src/introduction.md)"
  printf '  <url><loc>%s</loc><lastmod>%s</lastmod></url>\n' \
    "${base}docs/reference/admin-api/" "$(lastmod api/openapi.json)"
  (cd docs/book && find . -name '*.html' ! -name index.html ! -name 404.html \
    ! -name toc.html ! -name print.html ! -name introduction.html | sort) |
    while read -r page; do
      page=${page#./}
      printf '  <url><loc>%s</loc><lastmod>%s</lastmod></url>\n' \
        "${base}docs/$page" "$(lastmod "docs/src/${page%.html}.md")"
    done
  echo '</urlset>'
} > _site/sitemap.xml
