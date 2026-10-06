#!/usr/bin/env bash
# check-binary.sh <ridm-api>: a FIPS build links only validated cryptography.
# Run on the unstripped binary (the release build before `strip`).
#
#   - AWS-LC comes from the FIPS module (`aws_lc_fips_*` symbols) and from
#     nothing else. rustls' `fips` feature still compiles aws-lc-sys, so
#     `cargo tree` lists it, but its `aws_lc_<version>_*` symbols must not be
#     linked.
#   - No `ring` (`ring_core_*`).
#   - OpenSSL is the system's, linked dynamically (libcrypto.so.3), not a
#     vendored static copy.
set -euo pipefail

bin="${1:?usage: check-binary.sh <ridm-api>}"
fail=0
# A stripped binary has no symbols, and every check below would pass on
# nothing. The release profile strips, so build with
# CARGO_PROFILE_RELEASE_STRIP=false for this check.
symbols="$(nm "$bin" 2>/dev/null || true)"
if [ "$(wc -l <<<"$symbols")" -lt 1000 ]; then
  echo "FAIL: $bin has no symbol table (stripped?); check the unstripped build"
  exit 1
fi

fips_syms="$(grep -c ' aws_lc_fips_[0-9]' <<<"$symbols" || true)"
if [ "$fips_syms" -eq 0 ]; then
  echo "FAIL: no AWS-LC FIPS module symbols (aws_lc_fips_*)"; fail=1
else
  echo "ok: AWS-LC FIPS module linked ($fips_syms symbols)"
fi

if grep -qE ' aws_lc_[0-9]+_[0-9]+_[0-9]+_' <<<"$symbols"; then
  echo "FAIL: the non-FIPS AWS-LC (aws-lc-sys) is linked"; fail=1
else
  echo "ok: no non-FIPS AWS-LC"
fi

if grep -q ' ring_core_' <<<"$symbols"; then
  echo "FAIL: ring is linked"; fail=1
else
  echo "ok: no ring"
fi

# A vendored copy defines OpenSSL 3's functions inside the binary (as local
# symbols); OSSL_PROVIDER_load exists only in OpenSSL 3, never in AWS-LC.
if grep -qE ' [Tt] OSSL_PROVIDER_load$' <<<"$symbols"; then
  echo "FAIL: OpenSSL is statically linked (vendored)"; fail=1
elif readelf -d "$bin" | grep -q 'NEEDED.*libcrypto\.so\.3'; then
  echo "ok: system OpenSSL linked dynamically (libcrypto.so.3)"
else
  echo "FAIL: libcrypto.so.3 is not a dynamic dependency"; fail=1
fi

exit "$fail"
