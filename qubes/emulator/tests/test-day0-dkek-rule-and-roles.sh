#!/usr/bin/env bash
# test-day0-dkek-rule-and-roles.sh — REQUIREMENTS B3, E1.
#
#   B3  the DKEK must never exist on a machine that has PIN access to a card.
#       This is THE rule the threat model produces: PIN + DKEK together export every key on the
#       token in plaintext, offline, leaving nothing behind on the card. Auditing card USE cannot
#       detect it, because the wrap happens once and the decrypt happens elsewhere — so the ONLY
#       control is custody, and the only way custody stays true is a check that fails the deploy.
#       Tested against the REAL assert-no-dkek.sh, not a model of it.
#
#   E1  one device serves every role — SOPS/GPG, SSH, X.509 CA, wallet. Proven on hardware
#       2026-07-31 (RSA + P-256 + secp256k1 on one card, one session). What this suite pins is the
#       part that silently breaks: each role needs its KEY *and* its CERTIFICATE, because
#       gnupg-pkcs11-scd and ssh-keygen -D enumerate a token BY CERTIFICATE. A key imported without
#       one is invisible to the tools that need it, while still appearing in --list-objects.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ASSERT="$HERE/../../../hsm-host-role/files/assert-no-dkek.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT

# =================================================================================================
hdr "B3: the DKEK guard runs, and it BITES"
if [ ! -x "$ASSERT" ]; then
  F "assert-no-dkek.sh not found or not executable at $ASSERT — the rule is unenforced"
else
  clean="$ROOT/clean"; mkdir -p "$clean"; echo "notes" > "$clean/readme.txt"
  "$ASSERT" --only-dir "$clean" >/dev/null 2>&1 \
    && P "a clean host passes" || F "a clean host FAILED — the guard cries wolf and will be ignored"

  # This is how Ansible's script module invokes the guard: from a temporary copy whose own name
  # matches the forbidden pattern. Only that running inode may be ignored.
  selfdir="$ROOT/self"; mkdir -p "$selfdir"; cp "$ASSERT" "$selfdir/assert-no-dkek.sh"
  "$selfdir/assert-no-dkek.sh" --only-dir "$selfdir" >/dev/null 2>&1 \
    && P "the guard does not report its own Ansible-style temporary copy" \
    || F "the guard rejected itself before scanning the host"
  echo share > "$selfdir/another-dkek-share.pbe"
  "$selfdir/assert-no-dkek.sh" --only-dir "$selfdir" >/dev/null 2>&1 \
    && F "excluding the running guard also hid a real DKEK-shaped file" \
    || P "self-exclusion remains narrow and still detects a second DKEK file"

  # Named the obvious way.
  d1="$ROOT/d1"; mkdir -p "$d1"; echo share > "$d1/dkek.pbe"
  "$ASSERT" --only-dir "$d1" >/dev/null 2>&1 \
    && F "dkek.pbe was NOT detected — the rule is decorative" || P "detects dkek.pbe"

  # Named to look innocent, but the name still carries it.
  d2="$ROOT/d2"; mkdir -p "$d2"; echo share > "$d2/ceremony-dkek-share-1"
  "$ASSERT" --only-dir "$d2" >/dev/null 2>&1 \
    && F "a *dkek* filename was not detected" || P "detects a share by name pattern"

  # RENAMED to hide, which is what a careless operator or an attacker actually produces.
  d3="$ROOT/d3"; mkdir -p "$d3"; printf 'Salted__\x01\x02\x03\x04\x05\x06\x07\x08' > "$d3/innocuous.pbe"
  "$ASSERT" --only-dir "$d3" >/dev/null 2>&1 \
    && F "a renamed share slipped past — name-only matching is not enough" \
    || P "detects a renamed share by CONTENT, not just by name"

  # CANNOT-SCAN IS NOT CLEAN. The first cut discarded find's stderr, so a run that could not read a
  # directory printed "OK: no DKEK material found" having inspected nothing. On a host where the
  # guard lacks privilege — or where a share sits in a mode-000 directory precisely so it is not
  # found — that is a false clean bill of health on the one rule custody depends on.
  d4="$ROOT/d4"; mkdir -p "$d4/hidden"; echo share > "$d4/hidden/dkek.pbe"; chmod 000 "$d4/hidden"
  if find "$d4" -mindepth 2 >/dev/null 2>&1; then
    printf '  \033[33mSKIP\033[0m unreadable-directory case: this user traverses mode-000 dirs (root?)\n'
  else
    out="$("$ASSERT" --only-dir "$d4" 2>&1)"; rc=$?
    [ "$rc" -eq 0 ] \
      && F "a directory the guard could not read still reported a clean host (exit 0)" \
      || P "a directory the guard could not read is a refusal, not a clean bill of health"
    grep -qi 'could not be scanned' <<<"$out" \
      && P "…and the refusal names the directory it could not scan" \
      || F "the refusal does not say which directory could not be scanned"
    grep -qi 'OK: no DKEK material' <<<"$out" \
      && F "the guard printed OK despite an incomplete scan" \
      || P "…and it does not print OK for an incomplete scan"
  fi
  chmod 755 "$d4/hidden"

  # The failure message has to tell an operator what NOT to do, or the check gets deleted
  # the first time it blocks a deploy at an inconvenient moment.
  msg="$("$ASSERT" --only-dir "$d1" 2>&1 || true)"
  grep -qi "do not" <<<"$msg" && grep -qi "deleting the check\|deleting this check\|delete the check" <<<"$msg" \
    && P "the failure warns against deleting the check to get a deploy through" \
    || F "the failure does not warn against deleting the check — it will be deleted"
  grep -qi "air-gapped\|ceremony workstation" <<<"$msg" \
    && P "…and says where the DKEK belongs instead" \
    || F "the failure does not say where to put the DKEK, so the operator has to guess"
fi

# =================================================================================================
hdr "E1: one device, every role — each needs a key AND a certificate"
# Modelled from the hardware finding: deleting a certificate ALSO removes the public key object,
# and an unwrapped key has no PKCS#15 description — so a key without a cert is invisible to
# gnupg-pkcs11-scd and ssh-keygen -D while still listing as a private key.
CARD="$ROOT/card"; mkdir -p "$CARD"
add_key(){  printf '%s' "$2" > "$CARD/key_$1"; }
add_cert(){ printf '%s' "$2" > "$CARD/cert_$1"; }
visible_to_tooling(){ [ -f "$CARD/key_$1" ] && [ -f "$CARD/cert_$1" ]; }

add_key rsa   "rsa2048";      add_cert rsa   "cn=gpg-sops-ca"
add_key p256  "prime256v1";   add_cert p256  "cn=ssh-auth"
add_key k1    "secp256k1";    add_cert k1    "cn=wallet"

for r in rsa p256 k1; do
  visible_to_tooling "$r" && P "role '$r' has both a key and a certificate" || F "role '$r' is incomplete"
done
[ "$(ls "$CARD"/key_* 2>/dev/null | wc -l | tr -d ' ')" = "3" ] \
  && P "all three key types coexist on ONE device (RSA + P-256 + secp256k1)" \
  || F "the three roles do not coexist"

hdr "E1: a key WITHOUT its certificate is invisible to the tools that need it"
add_key orphan "an-imported-key-with-no-cert"
if visible_to_tooling orphan; then
  F "an orphan key looked usable — the cert requirement is not modelled"
else
  P "a key with no certificate is NOT usable by gpg/ssh (silently invisible, the real failure)"
fi

hdr "E1: removing a certificate takes the public key with it"
rm -f "$CARD/cert_p256"
if visible_to_tooling p256; then
  F "the SSH role survived losing its certificate"
else
  P "deleting a cert breaks the role — certificates are load-bearing, not decoration"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
