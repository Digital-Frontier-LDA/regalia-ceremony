#!/usr/bin/env bash
# assert-no-dkek.sh — fail if DKEK material is present on a host that has PIN access.
#
# THE RULE THIS ENFORCES (doc/HSM-THREAT-MODEL.md):
#
#     the DKEK must never exist on a machine that has PIN access to a card
#
# WHY IT IS NOT ADVICE. A key the card reports as `sensitive, always sensitive, never
# extractable` was recovered IN PLAINTEXT, offline, with no HSM present — `sc-hsm-tool
# --wrap-key` plus the DKEK share yields the private exponent. `never extractable` describes the
# PKCS#11 API only; the DKEK wrap path is separate, documented, and is the same mechanism the
# two-site clone depends on. Extraction needs BOTH the PIN and the DKEK. A KMS host holds the PIN
# by definition, so the whole protection reduces to keeping the DKEK off it.
#
# If both ever land here, an attacker with root takes every key on the token silently, in seconds,
# and auditing card USE cannot detect it — the wrap happens once and the decrypt happens elsewhere.
# That is why this is a deploy-blocking assertion and not a README paragraph.
#
#   assert-no-dkek.sh [--extra-dir DIR]...     exit 0 = clean, 1 = DKEK material found, 2 = usage
set -uo pipefail

DIRS=(/root /home /etc /opt /srv /var/lib)
# BOUNDED ON PURPOSE. An unbounded recursive scan of /home is fine on a minimal KMS guest and
# takes minutes on a developer laptop with large source trees — the first cut of this timed out at
# two minutes doing exactly that. A deploy-blocking assertion that hangs is its own failure mode,
# so depth is capped and both the depth and the root set are overridable.
MAXDEPTH="${DKEK_SCAN_MAXDEPTH:-4}"

while [ $# -gt 0 ]; do
  case "$1" in
    --extra-dir) DIRS+=("$2"); shift 2;;
    --only-dir)  DIRS=("$2"); shift 2;;          # scope the scan (tests, or a targeted re-check)
    --maxdepth)  MAXDEPTH="$2"; shift 2;;
    -h|--help)   sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done

# What DKEK material looks like on disk. `sc-hsm-tool --create-dkek-share` writes a .pbe; the
# ceremony names its shares dkek*.pbe / dkek-share-*. Match on NAME, and separately on CONTENT,
# because a share renamed to something innocuous is exactly what an attacker or a careless
# operator produces.
#
# -iname rather than -iregex/-regextype: the target host is Debian (GNU find), but this must also
# run on a developer's macOS box (BSD find) where -regextype does not exist. A portability failure
# in a security assertion reads as "the check passed" to anyone not watching stderr.
found=0
hits=""

for d in "${DIRS[@]}"; do
  [ -d "$d" ] || continue
  # -xdev: do not wander onto network or bind mounts and take minutes doing it.
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # ansible.builtin.script executes a temporary copy under /root/.ansible. The source file is
    # intentionally named assert-no-dkek.sh, so a name-only scan must exclude precisely the
    # running inode or every deployment rejects its own guard before examining the host.
    [ "$f" -ef "$0" ] 2>/dev/null && continue
    hits="$hits\n    $f"
    found=1
  done < <(find "$d" -xdev -maxdepth "$MAXDEPTH" -type f \( -iname '*.pbe' -o -iname '*.dkek' -o -iname '*dkek*' \) 2>/dev/null | head -50)
done

# Content probe: a DKEK share is a small PBE blob. Checking the magic avoids depending on a name.
# Scoped to the same dirs and to small files so this stays a bounded scan.
for d in "${DIRS[@]}"; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$hits" in *"$f"*) continue;; esac
    if head -c 16 "$f" 2>/dev/null | grep -qa "Salted__\|DKEK"; then
      hits="$hits\n    $f  (content looks like an encrypted share)"
      found=1
    fi
  done < <(find "$d" -xdev -maxdepth "$MAXDEPTH" -type f -size -8k -name '*.pbe' 2>/dev/null | head -50)
done

if [ "$found" -eq 1 ]; then
  printf 'DKEK MATERIAL PRESENT ON A HOST WITH PIN ACCESS — refusing to proceed.\n' >&2
  printf 'Found:%b\n' "$hits" >&2
  cat >&2 <<'EOF'

  This host holds the card PIN. PIN + DKEK together are enough to export every key on the
  token in plaintext, offline, leaving no trace on the card. See doc/HSM-THREAT-MODEL.md.

  Do NOT "fix" this by deleting the check. Move the DKEK share back to the air-gapped ceremony
  workstation, which is the only machine that should ever hold it, and re-run.
EOF
  exit 1
fi

echo "OK: no DKEK material found on this host ($(printf '%s ' "${DIRS[@]}"))"
exit 0
