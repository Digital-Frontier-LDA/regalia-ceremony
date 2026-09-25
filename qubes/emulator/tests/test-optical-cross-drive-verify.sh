#!/usr/bin/env bash
# test-optical-cross-drive-verify.sh — the M-DISC cross-drive verify is the ONE check that
# catches a silent bad burn of the only ciphertext+recovery archive. step_archive (option 4)
# prints the verify command the operator copy-pastes. That command MUST checksum the files
# read back from the SECOND drive (the mounted disc), NOT the in-RAM source tree the manifest
# was generated against — otherwise it reports OK even when drive B holds a blank or corrupt
# disc.
#
# The manifest is generated in $WORK with paths RELATIVE to $WORK (line 313:
#   ( cd "$WORK" && find . -type f ... > manifest.sha256 )
# so a `sha256sum -c manifest.sha256` run from $WORK re-checksums the source files and always
# passes. The verify must therefore change into the mounted disc before checksumming.
#
# This test extracts the verify command step_archive actually shows the operator, points its
# mount at a BLANK disc and at a CORRUPT disc, runs it from the source dir, and asserts it
# FAILS in both cases (a sound verify rejects a bad burn). Runs natively (bash + coreutils).
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
ask(){ return 0; }; pause(){ :; }
PRINTER=""
init_work
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP" "${WORK:-}"' EXIT

# ---- capture the verify command step_archive shows the operator ----------------------
out="$(step_archive 2>&1)"
# strip ANSI, take the displayed line that is BOTH the mount+verify (not the manifest-gen line)
verify_line="$(printf '%s\n' "$out" \
  | sed $'s/\033\\[[0-9;]*m//g' \
  | grep -F 'sha256sum -c manifest.sha256' | grep -F 'mount' | head -1)"
if [ -z "$verify_line" ]; then
  F "could not find the cross-drive verify command in step_archive output"
  printf '  %d passed, %d failed\n' "$pass" "$fail"; exit 1
fi
cmd="${verify_line#*\$ }"   # drop the leading "   $ " prompt the show() helper prints
cmd="${cmd%%#*}"            # drop the trailing "# verify on drive B" comment
hdr "verify command as shown to the operator"
info "$cmd"

# ---- build a source tree + manifest exactly like the wizard does (line 313) -----------
SRC="$TMP/work"; mkdir -p "$SRC/recovery-kit"
printf 'CIPHERTEXT-AGE-PAYLOAD-v1' > "$SRC/vault.sops.yaml.age"
printf 'RECOVERY START HERE' > "$SRC/recovery-kit/RECOVERY-START-HERE.txt"
( cd "$SRC" && find . -type f ! -name manifest.sha256 -print0 | xargs -0 sha256sum > manifest.sha256 )

# Helper: run the operator's verify command with the mount pointed at $1 (the "drive B" disc),
# executed from the SOURCE dir (where the operator sits after generating the manifest). We
# replace the real `mount -o ro /dev/srN /mnt` with `true` (mount always succeeds) and retarget
# every /mnt at the disc dir, so the ONLY thing under test is whether the verify checksums the
# disc or the source tree.
run_verify_against() {
  local disc="$1" c="$cmd"
  # whichever drive the wizard chose (a second drive, or the burning drive: ADR-0002 D9)
  c="$(printf '%s' "$c" | sed -E 's#mount -o ro /dev/[A-Za-z0-9]+ /mnt#true#')"
  c="${c//\/mnt/$disc}"
  ( cd "$SRC" && eval "$c" ) >/dev/null 2>&1
}

# ---- scenario 1: BLANK disc (drive B never received the burn) --------------------------
hdr "a BLANK disc on drive B must be REJECTED"
BLANK="$TMP/blank"; mkdir -p "$BLANK"
if run_verify_against "$BLANK"; then
  F "verify reported OK against a BLANK disc — it checksummed the in-RAM source, not drive B"
else
  P "blank disc rejected (verify read back from the disc, found nothing to match)"
fi

# ---- scenario 2: CORRUPT disc (marginal burn flipped a byte) ---------------------------
hdr "a CORRUPT disc on drive B must be REJECTED"
CORRUPT="$TMP/corrupt"; mkdir -p "$CORRUPT/recovery-kit"
cp "$SRC/manifest.sha256" "$CORRUPT/"
cp "$SRC/recovery-kit/RECOVERY-START-HERE.txt" "$CORRUPT/recovery-kit/"
printf 'CIPHERTEXT-AGE-PAYLOAD-v1-CORRUPTED' > "$CORRUPT/vault.sops.yaml.age"   # one byte+ off
if run_verify_against "$CORRUPT"; then
  F "verify reported OK against a CORRUPT disc — it never checksummed drive B"
else
  P "corrupt disc rejected (verify caught the read-back mismatch on drive B)"
fi

# ---- sanity: a GOOD disc (byte-identical burn) must still PASS --------------------------
hdr "a GOOD disc (faithful burn) must PASS"
GOOD="$TMP/good"; mkdir -p "$GOOD/recovery-kit"
cp "$SRC/manifest.sha256" "$GOOD/"
cp "$SRC/vault.sops.yaml.age" "$GOOD/"
cp "$SRC/recovery-kit/RECOVERY-START-HERE.txt" "$GOOD/recovery-kit/"
if run_verify_against "$GOOD"; then
  P "good disc passes (no false rejection of a faithful burn)"
else
  F "good disc was rejected — the verify is broken the other way"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
