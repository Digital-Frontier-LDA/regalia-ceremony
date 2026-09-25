#!/usr/bin/env bash
# test-optical-fault-injection.sh — regression guard for the `optical-verify` self-test.
#
# route-coverage.sh ROUTE 6 uses `optical-verify --fault` to PROVE the cross-drive M-DISC
# verify actually catches a bad burn. That proof is only meaningful if the injected fault
# corrupts a file that the manifest COVERS. The original --fault picked
# `find "$out" -type f | head -1` and *appended* 'X' to it. Two defects:
#
#   1. Non-deterministic + can select the extracted manifest.sha256 itself. Appending 'X'
#      to a manifest leaves its real checksum lines intact, so `sha256sum -c` reports the
#      data files OK and merely warns about one malformed line — exit 0. The verify then
#      claims "burn is sound" and the self-test's negative case silently passes without ever
#      proving a corrupt read-back is caught (flaky: depends on extraction order).
#
#   2. It never modelled the real M-DISC weakness: a truncated/subset manifest that omits a
#      file present on the disc. `sha256sum -c` only checks listed files, so an uncovered
#      (possibly corrupt/blank) file sails through.
#
# This test drives the REAL bin/optical-verify against real emulated ISOs and asserts:
#   A. --fault ALWAYS forces a REJECT (exit != 0), regardless of extraction order.
#   B. A manifest that does not cover every file on the disc is REJECTED (subset guard).
#   C. A faithful burn with a complete manifest still PASSES (no false rejection).
#
# Needs xorriso (+ the growisofs shim); self-skips if xorriso is unavailable.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../bin"
export PATH="$BIN:$PATH"

pass=0; fail=0; skip=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
S(){ printf '  \033[33mSKIP\033[0m %s\n' "$1"; skip=$((skip+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

sha256(){ sha256sum "$@" 2>/dev/null || shasum -a 256 "$@"; }

if ! command -v xorriso >/dev/null 2>&1; then
  hdr "optical-verify fault injection"
  S "xorriso not installed — skipping (runs on the Linux emulator/CI host)"
  printf '\n  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
  exit 0
fi

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export EMU_OPTICAL_DIR="$W/optical"

# ---- burn a faithful recovery kit exactly like route-coverage.sh ROUTE 6 --------------
burn_src="$W/burn"; mkdir -p "$burn_src"
echo "recovery-kit" > "$burn_src/RECOVERY-START-HERE.txt"
echo "share data"   > "$burn_src/share1.txt"
( cd "$burn_src" && find . -type f ! -name manifest.sha256 -print0 | xargs -0 sha256sum > manifest.sha256 )
growisofs -dvd-compat -Z /dev/sr0 -R -J "$burn_src" >/dev/null 2>&1 \
  || { F "growisofs(emu) burn failed"; printf '\n  %d passed, %d failed\n' "$pass" "$fail"; exit 1; }
ISO="$EMU_OPTICAL_DIR/sr0.iso"

# ---- A. --fault must ALWAYS reject (run several times to defeat extraction-order luck) --
hdr "A. --fault must force a REJECT every time (never a false 'burn is sound')"
fault_ok=1
for i in 1 2 3 4 5; do
  if optical-verify --image "$ISO" --manifest manifest.sha256 --fault >/dev/null 2>&1; then
    fault_ok=0
    break
  fi
done
if [ "$fault_ok" = 1 ]; then
  P "--fault consistently REJECTED the burn (fault hit a manifest-covered file)"
else
  F "--fault reported the burn SOUND — the injected fault was not caught (corrupted the manifest or an uncovered file)"
fi

# ---- B. a subset/truncated manifest (omits a file on the disc) must be REJECTED --------
hdr "B. a manifest that does not cover every file on the disc must be REJECTED"
sub_src="$W/burn-subset"; mkdir -p "$sub_src"
echo "recovery-kit" > "$sub_src/RECOVERY-START-HERE.txt"
echo "share data"   > "$sub_src/share1.txt"
# manifest deliberately lists ONLY one of the two files (models a short/corrupt manifest)
( cd "$sub_src" && find . -type f -name 'RECOVERY-START-HERE.txt' -print0 | xargs -0 sha256sum > manifest.sha256 )
export EMU_OPTICAL_DIR="$W/optical-subset"
growisofs -Z /dev/sr0 -R -J "$sub_src" >/dev/null 2>&1
if optical-verify --image "$W/optical-subset/sr0.iso" --manifest manifest.sha256 >/dev/null 2>&1; then
  F "subset manifest ACCEPTED — an uncovered file on the disc goes unverified"
else
  P "subset manifest REJECTED (every file on the disc must be covered)"
fi

# ---- C. a faithful, fully-covered burn must still PASS ---------------------------------
hdr "C. a faithful burn with a complete manifest must PASS"
export EMU_OPTICAL_DIR="$W/optical"
if optical-verify --image "$ISO" --manifest manifest.sha256 >/dev/null 2>&1; then
  P "good burn passes (no false rejection of a faithful burn)"
else
  F "good burn was REJECTED — the verify is broken the other way"
fi

hdr "RESULT"
printf '  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ] && exit 0 || exit 1
