#!/usr/bin/env bash
# test-archive-recovery-doc-paths.sh — the burned M-DISC must be SELF-CONSISTENT with the
# recovery runbook it carries. An air-gapped, possibly non-expert recoverer follows
# RECOVERY-TECHNICAL.md literally with no repo, no network, no second chance: every path the
# runbook says is "on this disc" MUST actually be on the disc, or the recovery dead-ends.
#
# QUORUM-CONFIRMED DEFECT (ceremony.sh step_archive vs recovery/RECOVERY-TECHNICAL.md):
#   step_archive stages the toolkit FLAT under recovery-kit/ (there is NO scripts/ dir on the
#   disc) and never stages SECRETS.md — yet RECOVERY-TECHNICAL.md told the recoverer to copy
#   the disc's `scripts/` and to read `SECRETS.md` "also on disc". Following the runbook
#   literally hits missing paths.
#
# This test reproduces a post-step-3 workdir, runs step_archive, resolves the burn tree, and
# asserts the runbook the disc carries only references artifacts that are actually staged:
#   1) if it names a `scripts/` toolkit dir, that dir must exist in the burn tree
#   2) if it claims `SECRETS.md` is on the disc, that file must be in the burn tree
#   3) the toolkit dir the recoverer cd's into (the one holding bip39-slip39-backup.py) must
#      co-locate wheels/ + requirements.txt so the runbook's RELATIVE pip command resolves.
# Runs natively (bash + coreutils); no hardware/printer/python needed.
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

# ---- a baked wheels dir + the encrypted / public artifacts step_archive stages -------------
WHEELS="$(mktemp -d)"
printf 'fake-wheel-bytes' > "$WHEELS/shamir_mnemonic-0.3.0-py3-none-any.whl"
printf 'fake-wheel-bytes' > "$WHEELS/mnemonic-0.21-py3-none-any.whl"
export CEREMONY_WHEELS_DIR="$WHEELS"
trap 'rm -rf "${WORK:-}" "$WHEELS"' EXIT
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

# ---- locate the runbook the disc actually carries ------------------------------------------
runbook="$(find "$burn_dir" -name RECOVERY-TECHNICAL.md -print -quit 2>/dev/null)"
hdr "the disc carries the technical recovery runbook"
if [ -n "$runbook" ]; then
  P "RECOVERY-TECHNICAL.md is staged on the disc"
else
  F "RECOVERY-TECHNICAL.md not staged — the recoverer has no recipe"
  printf '  %d passed, %d failed\n' "$pass" "$fail"; exit 1
fi

# =====================================================================================
hdr "every 'scripts/' toolkit dir the runbook references actually exists on the disc"
if grep -q 'scripts/' "$runbook"; then
  if [ -n "$(find "$burn_dir" -type d -name scripts -print -quit 2>/dev/null)" ]; then
    P "runbook says scripts/ and a scripts/ dir is on the disc"
  else
    F "runbook tells the recoverer to use 'scripts/' but NO scripts/ dir is on the disc"
  fi
else
  P "runbook does not reference a nonexistent scripts/ dir"
fi

# =====================================================================================
hdr "if the runbook claims SECRETS.md is on the disc, it must actually be staged"
if grep -q 'SECRETS\.md' "$runbook"; then
  if [ -n "$(find "$burn_dir" -name 'SECRETS.md' -print -quit 2>/dev/null)" ]; then
    P "runbook cites SECRETS.md and it is on the disc"
  else
    F "runbook cites 'SECRETS.md (on disc)' but no SECRETS.md is staged — dead reference"
  fi
else
  P "runbook does not cite a nonexistent SECRETS.md"
fi

# =====================================================================================
hdr "the toolkit dir the recoverer cd's into co-locates the tools + wheels/ + requirements.txt"
tool="$(find "$burn_dir" -name bip39-slip39-backup.py -print -quit 2>/dev/null)"
if [ -n "$tool" ]; then
  tdir="$(dirname "$tool")"
  ok=1
  [ -d "$tdir/wheels" ] && ls "$tdir"/wheels/*.whl >/dev/null 2>&1 || ok=0
  [ -e "$tdir/requirements.txt" ] || ok=0
  if [ "$ok" -eq 1 ]; then
    P "wheels/ + requirements.txt sit beside the tools (the runbook's relative pip cmd resolves)"
  else
    F "the runbook's 'pip install --find-links wheels/ -r requirements.txt' won't resolve from the toolkit dir ($tdir)"
  fi
else
  F "bip39-slip39-backup.py not staged in the toolkit"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
