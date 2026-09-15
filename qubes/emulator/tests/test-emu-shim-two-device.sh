#!/usr/bin/env bash
# test-emu-shim-two-device.sh — guards the emulator shims' TWO-DEVICE model.
#
# THE DEFECT THIS EXISTS FOR: SoftHSM2 is a single shared token, but the ceremony now drives two
# cards (primary + clone target), each modelled by its own $EMU_SCHSM_STATE directory. The shim
# used to serve a restored pubkey only at the hardcoded id 02, so a clone-target read of id 01
# fell through to the shared token and returned the PRIMARY card's key. The ceremony's
# restore-verify byte-compare would then PASS while proving nothing — the single worst outcome
# available, because it declares a funding address safe on the strength of a fake proof.
#
# Runs natively (bash only): every assertion here exercises a shim path that returns BEFORE the
# real OpenSC binary is invoked, and EMU_PKCS11_REAL points at a stub for the rest. No SoftHSM2.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../bin"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
DEV_A="$ROOT/devA"; DEV_B="$ROOT/devB"; mkdir -p "$DEV_A" "$DEV_B"

# A stub standing in for the real OpenSC pkcs11-tool. If a shim path that should have returned
# early ever reaches it, it emits a marker we assert on — that is how a fall-through is caught.
cat > "$ROOT/fake-pkcs11" <<'STUB'
#!/usr/bin/env bash
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
case "$*" in
  *--list-objects*) echo "Public Key Object; EC"; echo "  label:      PRIMARY-CARD-KEY"; exit 0;;
  *--read-object*)  [ -n "$out" ] && printf 'PRIMARY-CARD-PUBKEY' > "$out"; exit 0;;
  *--keypairgen*)   echo "Key pair generated"; exit 0;;
esac
exit 0
STUB
chmod +x "$ROOT/fake-pkcs11"
export EMU_PKCS11_REAL="$ROOT/fake-pkcs11"

p11(){ EMU_SCHSM_STATE="$1" "$BIN/pkcs11-tool" "${@:2}"; }

# =====================================================================================
hdr "A modelled card with an EMPTY registry must enumerate as BLANK (not borrow the shared token)"
out="$(p11 "$DEV_B" --list-objects --type pubkey 2>&1)"; rc=$?
[ "$rc" = 0 ] && P "blank modelled card enumerates successfully (exit 0)" \
              || F "blank card enumeration exited $rc — a guard would read this as an error"
[ -z "$out" ] && P "blank modelled card lists NO objects" \
              || F "BUG: blank card reported objects from the shared token: $out"
grep -q "PRIMARY-CARD-KEY" <<< "$(echo "$out")" \
  && F "BUG: blank clone target enumerated the PRIMARY card's key (guard would refuse a blank card)" \
  || P "blank card did not fall through to the shared token"

# =====================================================================================
hdr "A modelled card enumerates its OWN registry entries"
printf '1:akash-funding\n' > "$DEV_A/objects"
out="$(p11 "$DEV_A" --list-objects --type pubkey 2>&1)"
grep -q "akash-funding" <<< "$out" && P "card A lists its own funding key" \
                                      || F "card A did not list its registered key"
grep -q "PRIMARY-CARD-KEY" <<< "$(echo "$out")" \
  && F "BUG: registry-backed listing still leaked the shared token's objects" \
  || P "listing came from the per-device registry, not the shared token"

# =====================================================================================
hdr "THE REGRESSION: a clone target must serve the RESTORED key at the unwrapped key-reference"
# Model what sc-hsm-tool --unwrap-key --key-reference 1 leaves behind on the clone target.
printf 'RESTORED-CLONE-PUBKEY' > "$DEV_B/restored-pub.der"
printf '1\n' > "$DEV_B/restored.keyref"
printf '1:akash-funding\n' > "$DEV_B/objects"
p11 "$DEV_B" --read-object --type pubkey --id 01 -o "$ROOT/got.der" >/dev/null 2>&1
if [ "$(cat "$ROOT/got.der" 2>/dev/null)" = "RESTORED-CLONE-PUBKEY" ]; then
  P "id 01 on the clone target returns the RESTORED key"
elif [ "$(cat "$ROOT/got.der" 2>/dev/null)" = "PRIMARY-CARD-PUBKEY" ]; then
  F "BUG: clone target returned the PRIMARY card's key — restore-verify would pass on a FAKE proof"
else
  F "clone target returned neither the restored nor the primary key (got: $(cat "$ROOT/got.der" 2>/dev/null))"
fi

# =====================================================================================
hdr "Same-card scratch restore (key-reference 2) still serves at id 02 — no regression"
printf 'RESTORED-SCRATCH-PUBKEY' > "$DEV_A/restored-pub.der"
printf '2\n' > "$DEV_A/restored.keyref"
printf '1:akash-funding\n2:akash-funding\n' > "$DEV_A/objects"
p11 "$DEV_A" --read-object --type pubkey --id 02 -o "$ROOT/got2.der" >/dev/null 2>&1
[ "$(cat "$ROOT/got2.der" 2>/dev/null)" = "RESTORED-SCRATCH-PUBKEY" ] \
  && P "id 02 still serves the same-card scratch restore" \
  || F "same-card restore-verify path regressed (got: $(cat "$ROOT/got2.der" 2>/dev/null))"

# =====================================================================================
hdr "A card must NOT export an object it does not hold (no borrowing from the shared token)"
rm -f "$ROOT/got3.der"
mkdir -p "$ROOT/devC"
p11 "$ROOT/devC" --read-object --type pubkey --id 01 -o "$ROOT/got3.der" >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ] && P "reading an absent object FAILS on a modelled card" \
               || F "BUG: a card with no such object still returned one (exit 0)"
[ "$(cat "$ROOT/got3.der" 2>/dev/null)" = "PRIMARY-CARD-PUBKEY" ] \
  && F "BUG: absent-object read fell through and returned the shared token's key" \
  || P "absent-object read did not borrow the shared token's key"

# =====================================================================================
hdr "An UNRESTORABLE backup (keyref pinned, no restored pubkey) must fail the read"
mkdir -p "$ROOT/devD"; printf '1\n' > "$ROOT/devD/restored.keyref"
p11 "$ROOT/devD" --read-object --type pubkey --id 01 -o "$ROOT/got4.der" >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ] && P "a pinned restore with no restored pubkey fails closed" \
               || F "BUG: read succeeded with no restored pubkey present"

# =====================================================================================
hdr "keypairgen registers the new key against the generating device ONLY"
mkdir -p "$ROOT/devE"
p11 "$ROOT/devE" --login --keypairgen --key-type EC:secp256k1 --label akash-funding --id 01 >/dev/null 2>&1
grep -q "^1:akash-funding$" "$ROOT/devE/objects" 2>/dev/null \
  && P "generated key is registered on the generating device" \
  || F "keypairgen did not register the key (blank-card guard would miss it on re-init)"
[ ! -s "$ROOT/devC/objects" ] \
  && P "no other modelled device was touched by the keygen" \
  || F "BUG: keygen registered an object on an unrelated device"

# =====================================================================================
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
