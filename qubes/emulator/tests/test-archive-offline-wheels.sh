#!/usr/bin/env bash
# test-archive-offline-wheels.sh — the M-DISC must be self-contained for the CLEAN-MACHINE
# (Tails / spare offline PC) recovery path that RECOVERY-TECHNICAL.md explicitly endorses.
#
# The SLIP-39 recovery tools import third-party packages:
#     bip39-slip39-backup.py  ->  from mnemonic import Mnemonic
#                                  from shamir_mnemonic import combine_mnemonics
#     metal-stamp-worksheet.py ->  import shamir_mnemonic
# whose only documented install is `pip install --require-hashes -r requirements.txt`
# (needs PyPI). On a disconnected clean machine that has no network, recovery is impossible
# unless the hash-pinned WHEELS travel on the disc so the recoverer can:
#     pip install --no-index --find-links wheels/ -r requirements.txt
#
# This test reproduces a post-step-3 workdir, points step_archive at a baked wheels dir
# (as the vault-tools image provides at /opt/vault-ceremony/wheels), runs step_archive,
# resolves the recovery kit it stages onto the disc, and asserts the wheels are present so
# the offline path actually works. Runs natively (bash + coreutils); no hardware/python.
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
ask(){ return 0; }; pause(){ :; }   # auto-confirm the manifest-gen `run`
PRINTER=""
init_work

# ---- a baked wheels dir, as the vault-tools image provides ---------------------------------
WHEELS="$(mktemp -d)"
printf 'fake-wheel-bytes' > "$WHEELS/shamir_mnemonic-0.3.0-py3-none-any.whl"
printf 'fake-wheel-bytes' > "$WHEELS/mnemonic-0.21-py3-none-any.whl"
printf 'fake-wheel-bytes' > "$WHEELS/click-8.4.2-py3-none-any.whl"
export CEREMONY_WHEELS_DIR="$WHEELS"
trap 'rm -rf "${WORK:-}" "$WHEELS"' EXIT

# ---- the encrypted / public artifacts that step_archive stages -----------------------------
printf 'DKEK-password-protected-blob' > "$WORK/dkek.pbe"
printf 'DKEK-wrapped-private-key-blob' > "$WORK/funding-wrapped.bin"
printf 'PUBLIC-funding-key-der'        > "$WORK/funding-pub.der"

# ---- run the archive step and resolve what it burns ----------------------------------------
out="$(step_archive 2>&1)"
clean="$(printf '%s\n' "$out" | sed $'s/\033\\[[0-9;]*m//g')"
burn_line="$(printf '%s\n' "$clean" | grep -F 'growisofs' | head -1)"
burn_dir="$(printf '%s\n' "$burn_line" | sed -n "s/.*'\([^']*\)'.*/\1/p" | head -1)"
hdr "directory step_archive tells the operator to burn"
info "$burn_dir"
if [ -z "$burn_dir" ] || [ ! -d "$burn_dir" ]; then
  F "burn target '$burn_dir' is not a directory"
  printf '  %d passed, %d failed\n' "$pass" "$fail"; exit 1
fi

# =====================================================================================
hdr "the offline-recovery WHEELS travel on the disc (clean-machine path works with NO network)"
if [ -n "$(find "$burn_dir" -name '*.whl' -print -quit 2>/dev/null)" ]; then
  P "wheel files are staged into the burn tree"
else
  F "no *.whl staged — the clean-machine (Tails) recovery path needs network it won't have"
fi

hdr "the two import-critical packages (shamir_mnemonic + mnemonic) are present"
have=0
for w in shamir_mnemonic mnemonic; do
  [ -n "$(find "$burn_dir" -name "${w}-*.whl" -print -quit 2>/dev/null)" ] && have=$((have+1))
done
[ "$have" -eq 2 ] && P "both shamir_mnemonic and mnemonic wheels staged" \
                  || F "missing import-critical wheel(s) — only $have of 2 present"

hdr "requirements.txt rides alongside the wheels (so --find-links + --require-hashes works)"
[ -n "$(find "$burn_dir" -name 'requirements.txt' -print -quit 2>/dev/null)" ] \
  && P "requirements.txt present for an offline --require-hashes install" \
  || F "requirements.txt missing from the kit"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
