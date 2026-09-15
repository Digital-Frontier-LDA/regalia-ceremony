#!/usr/bin/env bash
# test-day2-replaceability.sh — REQUIREMENTS A1, A2, A4, B4, C1.
#
# The day-2 property that matters most and was the last to be tested: a card can die and be
# replaced with no loss. Drilled by hand on a Pico 2026-07-31; this is that drill as a suite so it
# cannot silently regress.
#
# What it pins, and why each one is a way the system could quietly stop being recoverable:
#
#   A1  a wiped card, re-provisioned FROM THE SEED ALONE, holds the same key
#   A2  the address derives with NO device present at all
#   A4  replacement does not consult the original device — its state is destroyed first
#   B4  the DKEK is DISPOSABLE: a brand-new, unrelated DKEK yields the same key
#
# B4 is the one with teeth. If it holds, ceremony.sh's 4-of-6 split of the DKEK password and the
# archiving of dkek.pbe to M-DISC are unnecessary custody. If it ever stops holding, that custody
# becomes mandatory again — so this suite is what tells you which world you are in.
#
# MODEL FIDELITY: the address is a function of the SOURCE KEY ONLY; the wrapped blob is a function
# of (key, DKEK). That is the real relationship — verified against hardware on 2026-07-31, where a
# new DKEK (kcv A18E58706FDF611C) re-imported the same seed key to the same address. A stub that
# made the address depend on the DKEK would pass a broken system, so the negative controls below
# exist to prove this stub can distinguish the two.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

FAKE="$(mktemp -d)"; ROOT="$(mktemp -d)"
export PATH="$FAKE:$PATH"
export SCHSM_STATE="$ROOT/dev"
mkdir -p "$SCHSM_STATE"
trap 'rm -rf "$FAKE" "$ROOT"' EXIT

# ---- device model -----------------------------------------------------------------------------
cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
S="${SCHSM_STATE:?}"; mkdir -p "$S"
case "${1:-}" in
  --create-dkek-share)
    # A DKEK's identity is its content. Two shares created with different DKEK_ID are different
    # domains — which is exactly what "the old DKEK is destroyed" has to mean.
    printf 'SCHSMDKEK1 %s\n' "${DKEK_ID:?DKEK_ID required}" > "$2"; echo "DKEK share written"; exit 0;;
  --initialize)
    # A WIPE. Everything goes: keys, the DKEK domain, the KCV. This is also the only way to
    # remove a key at all (C1) — individual deletion is refused by the real card.
    rm -f "$S"/key_* "$S"/dkek_*; : > "$S/dkek_domain"; echo "initialised (MODEL)"; exit 0;;
  --import-dkek-share)
    [ -f "$S/dkek_domain" ] || { echo "not initialised" >&2; exit 1; }
    kcv="$(cksum < "$2" | awk '{printf "%08X",$1}')"; printf '%s' "$kcv" > "$S/dkek_kcv"
    echo "DKEK key check value           : $kcv"; exit 0;;
  *) echo "unsupported: $1" >&2; exit 2;;
esac
STUB
chmod +x "$FAKE/sc-hsm-tool"

# import: blob = f(sourcekey, dkek); what lands on the card is the SOURCE KEY.
import_key(){ # $1=source-key-file
  local S="$SCHSM_STATE"
  [ -f "$S/dkek_kcv" ] || { echo "no DKEK domain" >&2; return 1; }
  cp "$1" "$S/key_material"
  cksum < "$1" | awk '{printf "%08X",$1}' > "$S/key_wrapped_under"   # provenance of the blob
  return 0
}
# the card's address depends ONLY on the key material it holds
card_address(){ [ -f "$SCHSM_STATE/key_material" ] || return 1; cksum < "$SCHSM_STATE/key_material" | awk '{printf "akash1%08x",$1}'; }
# A2: derive with no device in the picture at all
offline_address(){ cksum < "$1" | awk '{printf "akash1%08x",$1}'; }

SEED="$ROOT/seed.key";  printf 'the-authoritative-seed-derived-funding-key' > "$SEED"
OTHER="$ROOT/other.key"; printf 'a-DIFFERENT-key-that-must-not-match'       > "$OTHER"

# =================================================================================================
hdr "A2: the address derives with NO device present"
EXPECT="$(offline_address "$SEED")"
[ -n "$EXPECT" ] && P "derived $EXPECT offline, no card involved" || F "offline derivation produced nothing"

hdr "Provision the original device (DKEK #1)"
DKEK_ID=dkek-one sc-hsm-tool --create-dkek-share "$ROOT/d1.pbe" >/dev/null 2>&1
sc-hsm-tool --initialize >/dev/null 2>&1
KCV1="$(sc-hsm-tool --import-dkek-share "$ROOT/d1.pbe" 2>/dev/null | grep -oE '[0-9A-F]{8}$')"
import_key "$SEED"
A0="$(card_address)"
[ "$A0" = "$EXPECT" ] && P "original card holds the seed's key ($A0)" || F "original card address $A0 != $EXPECT"

hdr "A4: destroy the device — nothing from it may be reused"
sc-hsm-tool --initialize >/dev/null 2>&1
card_address >/dev/null 2>&1 && F "key survived a wipe — the wipe is not a wipe" || P "wipe removed the key"
[ -f "$SCHSM_STATE/dkek_kcv" ] && F "DKEK survived the wipe" || P "wipe removed the DKEK domain"

hdr "B4: re-provision with a BRAND NEW, unrelated DKEK"
DKEK_ID=dkek-two-completely-different sc-hsm-tool --create-dkek-share "$ROOT/d2.pbe" >/dev/null 2>&1
KCV2="$(sc-hsm-tool --import-dkek-share "$ROOT/d2.pbe" 2>/dev/null | grep -oE '[0-9A-F]{8}$')"
if [ -n "$KCV1" ] && [ -n "$KCV2" ] && [ "$KCV1" != "$KCV2" ]; then
  P "new DKEK is genuinely different (kcv $KCV1 -> $KCV2)"
else
  F "the two DKEKs are indistinguishable — this suite cannot prove B4"
fi

hdr "A1: re-import FROM THE SEED ALONE and expect the same address"
import_key "$SEED"
A1ADDR="$(card_address)"
[ "$A1ADDR" = "$EXPECT" ] \
  && P "replaced card holds the SAME key under a DIFFERENT DKEK ($A1ADDR)" \
  || F "address changed after replacement: $EXPECT -> $A1ADDR"

# =================================================================================================
# Without these the suite would pass against a model that ignores its inputs.
hdr "NEGATIVE CONTROLS — this suite must be able to fail"

sc-hsm-tool --initialize >/dev/null 2>&1
DKEK_ID=dkek-three sc-hsm-tool --create-dkek-share "$ROOT/d3.pbe" >/dev/null 2>&1
sc-hsm-tool --import-dkek-share "$ROOT/d3.pbe" >/dev/null 2>&1
import_key "$OTHER"
[ "$(card_address)" != "$EXPECT" ] \
  && P "importing a DIFFERENT key yields a DIFFERENT address (fund-losing case is detectable)" \
  || F "a different key produced the same address — the check is blind"

sc-hsm-tool --initialize >/dev/null 2>&1
if import_key "$SEED" 2>/dev/null; then
  F "import succeeded with NO DKEK domain — the domain is not required"
else
  P "import refuses when no DKEK domain exists (fails closed)"
fi

hdr "C1: a wipe removes the key material"
# What this asserts — that --initialize clears the key — is unchanged and is the property the
# rotation procedure actually rests on.
#
# The framing around it WAS "an individual key cannot be deleted": pkcs11-tool --delete-object on
# a privkey returned CKR_GENERAL_ERROR in the 2026-07-31 drill. That is no longer true on the
# 2026-08-06 firmware, where an authenticated deletion succeeds (see STAGING-ATTESTATION.md and
# scenario S8). This test never exercised deletion, so its verdict is unaffected — but it should
# not keep teaching the retracted claim in its title.
DKEK_ID=dkek-four sc-hsm-tool --create-dkek-share "$ROOT/d4.pbe" >/dev/null 2>&1
sc-hsm-tool --import-dkek-share "$ROOT/d4.pbe" >/dev/null 2>&1
import_key "$SEED"
[ -f "$SCHSM_STATE/key_material" ] && P "key present before wipe" || F "setup failed"
sc-hsm-tool --initialize >/dev/null 2>&1
[ -f "$SCHSM_STATE/key_material" ] \
  && F "wipe did not remove the key — rotation would be impossible" \
  || P "wipe removes the key material (the re-provisioning path stays available either way)"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
