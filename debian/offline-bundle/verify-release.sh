#!/usr/bin/env bash
# Verify the artifact before extracting it or introducing any secret material.
set -euo pipefail

[ "$#" -eq 4 ] || { echo "usage: verify-release.sh BUNDLE.tar.gz RELEASE.json RELEASE.sig.der TRUSTED-P256-PUBLIC.pem" >&2; exit 2; }
bundle="$1"; release="$2"; signature="$3"; public_key="$4"
for file in "$bundle" "$release" "$signature" "$public_key"; do
  [ -f "$file" ] || { echo "missing verification input: $file" >&2; exit 2; }
done
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 2; }

release_line="$(cat "$release")"
pattern='^\{"artifact":"([A-Za-z0-9._-]+)","artifact_sha256":"([0-9a-f]{64})","debian_snapshot":"([0-9]{8}T[0-9]{6}Z)","schema":"regalia.offline-release/v1","source_commit":"([0-9a-f]{40})","source_date_epoch":([0-9]+)\}$'
[[ "$release_line" =~ $pattern ]] || { echo "invalid or non-canonical release manifest" >&2; exit 1; }
[ "${BASH_REMATCH[1]}" = "$(basename "$bundle")" ] || { echo "release manifest artifact mismatch" >&2; exit 1; }
expected="${BASH_REMATCH[2]}"
actual="$(sha256sum "$bundle" | awk '{print $1}')"
[ "$actual" = "$expected" ] || { echo "bundle SHA-256 mismatch" >&2; exit 1; }
openssl dgst -sha256 -verify "$public_key" -signature "$signature" "$release" >/dev/null
echo "VERIFIED: SHA-256 and centralized-KMS P-256 signature for $(basename "$bundle")"
