#!/usr/bin/env bash
# test-archive-no-plaintext-shares.sh — the M-DISC archive (option 4) must NOT burn the
# plaintext Shamir-share material that step 3 leaves in the tmpfs workdir. The disc model
# is: it carries only the ENCRYPTED artifacts (dkek.pbe / funding-wrapped.bin), the public
# funding pubkey, the self-contained recovery-kit (runbooks + toolkit) and a checksum
# manifest. The paper/metal shares (and their printout text + QR PNGs) live ONLY on
# paper/metal — putting them on archival media permanently commits the secret to a disc.
#
# step_archive (ceremony.sh) shows the operator a `growisofs ... <dir>` burn command and
# then generates a `manifest.sha256` of <dir>. This test reproduces a realistic post-step-3
# workdir (plaintext shares + printouts + QRs alongside the encrypted artifacts), runs
# step_archive, resolves the directory it actually tells the operator to burn, and asserts:
#   1) NO plaintext-share file (and no secret marker) is anywhere under the burned tree
#   2) the manifest does not checksum any share file
#   3) the encrypted artifacts + recovery-kit ARE present (we still burn the real backup)
# Runs natively (bash + coreutils); no hardware, printer, or python needed.
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
ask(){ return 0; }; pause(){ :; }   # auto-confirm the manifest-gen `run`, no interactive stalls
PRINTER=""
init_work
trap 'rm -rf "${WORK:-}"' EXIT

MARK="PLAINTEXT-SHARE-LEAK-MARKER-$$"

# ---- reproduce what step 3 (Shamir split) leaves behind in the RAM workdir ----------------
# plaintext share material (option b/c writes w1..w6 + slip39.txt; option a writes shares.txt
# + sh*; the source secret is secret.in) and the print_share() artifacts (*.txt printout +
# *.png QR, both carrying the share string).
printf '%s share-one secret words\n' "$MARK" > "$WORK/w1"
printf '%s share-two secret words\n' "$MARK" > "$WORK/w2"
printf '%s share-three secret words\n' "$MARK" > "$WORK/w3"
printf '%s\nfull slip39 share set\n' "$MARK" > "$WORK/slip39.txt"
printf '%s' "$MARK" > "$WORK/secret.in"
printf '%s' "$MARK" > "$WORK/shares.txt"
printf '%s' "$MARK" > "$WORK/sh1"
printf 'SLIP-0039 share 1 of 6\n%s\n' "$MARK" > "$WORK/SLIP-0039_share_1_of_6.txt"  # print_share txt
printf 'fake-png-bytes-encoding-%s' "$MARK" > "$WORK/SLIP-0039_share_1_of_6.png"     # print_share QR
chmod 600 "$WORK"/w1 "$WORK"/w2 "$WORK"/w3 "$WORK"/slip39.txt "$WORK"/secret.in \
          "$WORK"/shares.txt "$WORK"/sh1 "$WORK"/*.txt "$WORK"/*.png

# ---- and the ENCRYPTED / public artifacts that SHOULD be archived -------------------------
printf 'DKEK-password-protected-blob' > "$WORK/dkek.pbe"
printf 'DKEK-wrapped-private-key-blob' > "$WORK/funding-wrapped.bin"
printf 'PUBLIC-funding-key-der'        > "$WORK/funding-pub.der"

# ---- run the archive step and capture what it tells the operator to burn ------------------
out="$(step_archive 2>&1)"
clean="$(printf '%s\n' "$out" | sed $'s/\033\\[[0-9;]*m//g')"

# the growisofs burn line; pull the single-quoted directory argument it burns
burn_line="$(printf '%s\n' "$clean" | grep -F 'growisofs' | head -1)"
if [ -z "$burn_line" ]; then
  F "could not find the growisofs burn command in step_archive output"
  printf '  %d passed, %d failed\n' "$pass" "$fail"; exit 1
fi
burn_dir="$(printf '%s\n' "$burn_line" | sed -n "s/.*'\([^']*\)'.*/\1/p" | head -1)"
hdr "directory step_archive tells the operator to burn"
info "$burn_dir"
if [ -z "$burn_dir" ] || [ ! -d "$burn_dir" ]; then
  F "burn target '$burn_dir' is not a directory"
  printf '  %d passed, %d failed\n' "$pass" "$fail"; exit 1
fi

# =====================================================================================
hdr "the burned tree must contain NO plaintext share secret"
if grep -rqF "$MARK" "$burn_dir" 2>/dev/null; then
  F "a plaintext share secret ($MARK) is inside the directory being burned to the M-DISC"
else
  P "no plaintext share secret anywhere under the burned tree"
fi

hdr "the burned tree must contain NO share files"
leaked=""
for f in w1 w2 w3 slip39.txt secret.in shares.txt sh1 \
         SLIP-0039_share_1_of_6.txt SLIP-0039_share_1_of_6.png; do
  if [ -n "$(find "$burn_dir" -name "$f" -print -quit 2>/dev/null)" ]; then leaked="$leaked $f"; fi
done
[ -z "$leaked" ] && P "no Shamir-share / printout / QR files staged for the burn" \
                  || F "share files staged for the burn:$leaked"

# =====================================================================================
hdr "the manifest must not checksum any share file"
manifest="$(find "$burn_dir" -name manifest.sha256 -print -quit 2>/dev/null)"
if [ -n "$manifest" ]; then
  if grep -qE '(^| )(w[0-9]|sh[0-9]|slip39\.txt|secret\.in|shares\.txt)|SLIP-0039_share' "$manifest"; then
    F "manifest.sha256 checksums a plaintext share file"
  else
    P "manifest.sha256 lists only non-secret artifacts"
  fi
else
  P "no manifest generated (nothing to leak via the manifest)"
fi

# =====================================================================================
hdr "we still archive the real backup (encrypted artifacts + recovery kit)"
have_enc=0
for f in dkek.pbe funding-wrapped.bin; do
  [ -n "$(find "$burn_dir" -name "$f" -print -quit 2>/dev/null)" ] && have_enc=$((have_enc+1))
done
[ "$have_enc" -ge 1 ] && P "encrypted artifact(s) present in the burn ($have_enc of 2)" \
                      || F "no encrypted artifact made it into the burn — disc would be useless"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
