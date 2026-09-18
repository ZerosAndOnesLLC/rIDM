#!/usr/bin/env bash
# Builds the docs site into docs/book. The admin API reference is rendered in
# the browser from the committed OpenAPI document, so it is copied in rather
# than duplicated under docs/src.
set -euo pipefail
cd "$(dirname "$0")"
mdbook build
cp ../api/openapi.json book/reference/admin-api/openapi.json
