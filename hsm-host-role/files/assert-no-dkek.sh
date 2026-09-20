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

# A SCAN THAT COULD NOT READ A DIRECTORY IS NOT A CLEAN SCAN. `find … 2>/dev/null` discarded
# traversal errors, so a run without access to /root — or to anything under the configured roots —
# printed OK having inspected nothing, which is the opposite of what a deploy-blocking, fail-closed
# assertion must do. Traversal errors are captured and become a refusal (exit 2, "cannot evaluate"),
# distinct from exit 1 ("material found").
#
# Callers must use `out="$(scan_dir …)" || exit $?` and never `< <(scan_dir …)`: inside a process
# substitution this exit ends only the subshell, the loop reads no lines, and the script goes on to
# print OK — the exact failure this guard exists to prevent.
scan_dir() {
  local dir="$1"; shift
  local errs out rc
  errs="$(mktemp)"
  # NO PIPE INTO head HERE. Under pipefail, `find … | head -50` on a directory holding more than
  # 50 matches SIGPIPEs find, the pipeline status becomes 141, and this refuses with an EMPTY error
  # file — a "could not be scanned" that names no path and no reason, on a host that scanned fine.
  # find runs to completion into a variable; the cap is applied afterwards, where the producer is
  # bash itself and nothing can be signalled.
  out="$(find "$dir" -xdev -maxdepth "$MAXDEPTH" "$@" 2>"$errs")"; rc=$?
  out="$(head -50 <<< "$out")"
  if [ "$rc" -ne 0 ] || [ -s "$errs" ]; then
    printf 'REFUSING: %s could not be scanned completely, so this host cannot be reported clean:\n' "$dir" >&2
    sed 's/^/    /' "$errs" >&2
    printf '  Re-run with enough privilege to read these paths (the guard runs as root on a KMS\n  host), or scope the scan with --only-dir if they are genuinely out of scope.\n' >&2
    rm -f "$errs"
    exit 2
  fi
  rm -f "$errs"
  printf '%s\n' "$out"
}

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
  names="$(scan_dir "$d" -type f \( -iname '*.pbe' -o -iname '*.dkek' -o -iname '*dkek*' \))" || exit $?
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # ansible.builtin.script executes a temporary copy under /root/.ansible. The source file is
    # intentionally named assert-no-dkek.sh, so a name-only scan must exclude precisely the
    # running inode or every deployment rejects its own guard before examining the host.
    [ "$f" -ef "$0" ] 2>/dev/null && continue
    hits="$hits\n    $f"
    found=1
  done <<< "$names"
done

# Content probe: a DKEK share is a small PBE blob. Checking the magic avoids depending on a name.
# Scoped to the same dirs and to small files so this stays a bounded scan.
for d in "${DIRS[@]}"; do
  [ -d "$d" ] || continue
  blobs="$(scan_dir "$d" -type f -size -8k -name '*.pbe')" || exit $?
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$hits" in *"$f"*) continue;; esac
    # NO PIPE INTO grep -q UNDER pipefail. grep -q exits the moment it matches, head takes SIGPIPE,
    # and pipefail makes the pipeline status 141 — so the branch is NOT taken and a renamed DKEK
    # share goes UNDETECTED, with the guard printing OK. The race is timing-dependent, which is
    # worse than a reliable failure. (tools/hsm-lint-predicates.sh flags exactly this shape.)
    magic="$(head -c 16 "$f" 2>/dev/null)"
    if grep -qa "Salted__\|DKEK" <<< "$magic"; then
      hits="$hits\n    $f  (content looks like an encrypted share)"
      found=1
    fi
  done <<< "$blobs"
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
