#!/usr/bin/env bash
# hsm-staging-pin.sh — (re)derive $STAGING/expected-pub.der, the public key the battery checks
# every staging signature against.
#
#   tools/hsm-staging-pin.sh            # show what is pinned now vs what SHOULD be pinned
#   tools/hsm-staging-pin.sh --write    # rewrite the pin (keeps a timestamped backup)
#
# WHY THIS EXISTS. That file had no writer anywhere in the repo. It was maintained by hand, which
# means it could — and did — drift from the key the tooling actually provisions. On 2026-08-06 it
# held 049c425690…, a key nothing in this repo installs, while every provisioning path was putting
# 044f4e2ad9… on the card. Consequences, in order of how long each took to see through:
#
#   * tools/hsm-scenarios.sh verified post-wipe signatures against the stale pin, every one failed,
#     and the gates read that single failure as "no usable key on card" — so S2/S5/S7/S8 skipped
#     and S6 scored 0/25 across two nightlies on a card that was signing perfectly.
#   * hsm-staging-ci.sh's hw_sign failed against "the pinned public key", which reads as a device
#     problem and is not one.
#
# A hand-maintained reference that silently goes stale produces confident, wrong statements about
# hardware. hsm-auto-import.sh derives its key from a PUBLISHED BIP39 test vector, so the correct
# value is deterministic and can simply be computed — there is no reason to keep it by hand.
#
# NOT FOR A CEREMONY CARD. This derives the DRILL key. A card holding real material must pin the
# real public key; point the battery at it with HSM_CI_EXPECT_PUB instead of running this.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$REPO/ceremony/qubes/scripts"
STAGING="${HSM_STAGING_DIR:-$HOME/.local/share/akash-hsm-staging}"
AUTO_IMPORT="${HSM_AUTO_IMPORT:-$SCRIPTS/hsm-auto-import.sh}"
PIN_FILE="$STAGING/expected-pub.der"

CEREMONY_VENV="${CEREMONY_VENV:-$HOME/.local/share/akash-hsm-venv}"
[ -x "$CEREMONY_VENV/bin/python3" ] && PATH="$CEREMONY_VENV/bin:$PATH"

WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

# Read the mnemonic out of hsm-auto-import.sh rather than restating it here, so this cannot derive
# a different key than the one that actually gets provisioned.
M="$(sed -n 's/^DRILL_MNEMONIC="\(.*\)"$/\1/p' "$AUTO_IMPORT" 2>/dev/null | head -1)"
[ -n "$M" ] || { printf 'could not read DRILL_MNEMONIC from %s\n' "$AUTO_IMPORT" >&2; exit 2; }

W="$(mktemp -d)"; chmod 700 "$W"
trap 'rm -rf "$W"' EXIT
printf '%s' "$M" > "$W/m.txt"; chmod 600 "$W/m.txt"
( umask 077; head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$W/pw" )

python3 "$SCRIPTS/seed-to-pkcs12.py" --mnemonic-file "$W/m.txt" --password-file "$W/pw" \
    --out "$W/f.p12" >/dev/null 2>&1 \
  || { printf 'seed-to-pkcs12.py failed — is the ceremony venv present? (see ceremony/qubes/requirements.txt)\n' >&2; exit 2; }
openssl pkcs12 -in "$W/f.p12" -nodes -passin file:"$W/pw" 2>/dev/null \
  | openssl ec -pubout -outform DER > "$W/pub.der" 2>/dev/null
[ -s "$W/pub.der" ] || { printf 'could not derive the public key from the drill seed\n' >&2; exit 2; }

want="$(xxd -p "$W/pub.der" | tr -d '\n')"
have=""
[ -s "$PIN_FILE" ] && have="$(xxd -p "$PIN_FILE" | tr -d '\n')"

printf '  pin file : %s\n' "$PIN_FILE"
printf '  derived  : %s\n' "$want"
printf '  current  : %s\n' "${have:-<absent>}"

if [ "$want" = "$have" ]; then
    printf '  \033[32mMATCH\033[0m — the pin is the key hsm-auto-import.sh provisions.\n'
    exit 0
fi

printf '  \033[31mMISMATCH\033[0m — the pinned key is NOT the one provisioning installs.\n'
if [ "$WRITE" != 1 ]; then
    printf '  re-run with --write to fix it (a timestamped backup is kept).\n'
    exit 1
fi

if [ -s "$PIN_FILE" ]; then
    cp "$PIN_FILE" "$PIN_FILE.bak-$(date +%Y%m%d-%H%M%S)"
    printf '  backed up the old pin alongside it\n'
fi
mkdir -p "$STAGING"
cp "$W/pub.der" "$PIN_FILE"
printf '  \033[32mwritten\033[0m\n'
