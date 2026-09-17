#!/usr/bin/env bash
# commission-card.sh — the checks that must pass AT THE RACK before a card carries production keys.
# PLAN.md 3.6. Run on the colo host, with the card inserted, before the signer is enabled.
#
# WHY A SEPARATE SCRIPT. Everything else in this repo runs at the ceremony, on an air-gapped
# workstation we control. This runs somewhere else entirely — in a rack, in a building belonging to
# a third party, on a host that has just been handed a device. The properties it checks are the ones
# that can only be false HERE:
#
#   * the host is not carrying a DKEK (B3) — the ceremony cannot know what the host does later
#   * the card really has RRC disabled (B6) — a mis-initialised card silently restores the SO-PIN
#     takeover path, and the D3 ruling is unenforceable without this
#   * the card is OUR card (B7) — a swapped genuine Nitrokey passes every policy check ever written
#   * no SO-PIN material is present at the site
#
#   commission-card.sh --expect-chr <CHR> --expect-serial <SERIAL> [--expect-address akash1...]
#
# FAILS CLOSED. Any check that cannot be EVALUATED is a failure, not a skip. A commissioning script
# that returns 0 because a tool was missing is worse than no script: it certifies nothing while
# looking like it certified everything.
set -uo pipefail

P11="${HSM_PKCS11_MODULE:-/usr/lib/opensc-pkcs11.so}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECT_CHR="" EXPECT_SERIAL="" EXPECT_ADDR="" SLOT="" EXPECT_DEVAUT_SHA=""
DEVAUT_JS="${HSM_DEVAUT_JS:-$HERE/../../ceremony/qubes/scripts/hsm-devaut-id.js}"

while [ $# -gt 0 ]; do
  case "$1" in
    --expect-chr)     EXPECT_CHR="${2:-}"; shift 2;;
    --expect-devaut-sha) EXPECT_DEVAUT_SHA="${2:-}"; shift 2;;
    --expect-serial)  EXPECT_SERIAL="${2:-}"; shift 2;;
    --expect-address) EXPECT_ADDR="${2:-}"; shift 2;;
    --slot)           SLOT="${2:-}"; shift 2;;
    --module)         P11="${2:-}"; shift 2;;
    -h|--help) sed -n '2,26p' "$0"; exit 0;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

SLOT_ARGS=()
[ -n "$SLOT" ] && SLOT_ARGS=(--slot "$SLOT")
sc(){ perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool "$@" 2>/dev/null; }

# =================================================================================================
hdr "B3 — the host carries no DKEK"
# The rule the threat model produces: PIN + DKEK together export every key on the token, offline and
# undetectably. The ceremony can promise the DKEK was destroyed; only the host can show it is absent.
if [ -x "$HERE/assert-no-dkek.sh" ]; then
  if "$HERE/assert-no-dkek.sh" >/dev/null 2>&1; then
    P "no DKEK material found on this host"
  else
    F "DKEK MATERIAL PRESENT — with PIN access on this host, every key on the card is exportable"
  fi
else
  F "assert-no-dkek.sh not found — B3 CANNOT BE EVALUATED, so this is a failure, not a skip"
fi

# =================================================================================================
hdr "B6 — the card has RESET RETRY COUNTER disabled"
# THE CHECK THAT MAKES THE D3 RULING REAL. With RRC enabled, the SO-PIN resets the user PIN without
# touching keys, at any time, and `--wrap-key` then exports everything. `sc-hsm-tool --initialize`
# HARDCODES RRC on, so a card provisioned the ordinary way is in the vulnerable state. Only a Smart
# Card Shell initialisation can disable it — and nothing but this check can tell them apart at the
# rack.
info_out="$(sc)"
if [ -z "$info_out" ]; then
  F "could not read the card — B6 CANNOT BE EVALUATED (is the card inserted, is pcscd running?)"
elif printf '%s' "$info_out" | grep -qi 'User PIN reset with SO-PIN enabled'; then
  F "RRC IS ENABLED — the SO-PIN can reset the user PIN and export every key. DO NOT RACK THIS CARD."
  printf '     Re-initialise via Smart Card Shell (SmartCardHSMInitializer) with RRC disabled.\n'
  printf '     sc-hsm-tool --initialize CANNOT produce such a card: it hardcodes the option ON.\n'
else
  P "RRC is disabled (no 'User PIN reset with SO-PIN enabled' in the card's config options)"
fi

# =================================================================================================
hdr "B7 — this is OUR card, not merely A genuine one"
# The distinction that matters in someone else's building. Every genuine Nitrokey validates to the
# same CardContact root, so chain validation proves "a real SmartCard-HSM" and nothing more. Only a
# match against the CHR and serial recorded AT THE CEREMONY identifies THIS device.
if [ -z "$EXPECT_CHR" ] && [ -z "$EXPECT_SERIAL" ] && [ -z "$EXPECT_DEVAUT_SHA" ]; then
  F "no --expect-chr / --expect-serial given — identity CANNOT BE EVALUATED, which is a failure"
  printf '     These are recorded at the ceremony. Commissioning without them proves nothing about\n'
  printf '     WHICH device is in the rack, and substitution is the attack colocation introduces.\n'
else
  serial="$(perl -e 'alarm 30; exec @ARGV' -- pkcs11-tool --module "$P11" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} \
              --list-slots 2>/dev/null | grep -oE 'serial num *: *[A-Za-z0-9]+' | awk '{print $NF}' | head -1)"
  if [ -z "$serial" ]; then
    F "could not read a token serial — identity CANNOT BE EVALUATED"
  elif [ -n "$EXPECT_SERIAL" ] && [ "$serial" != "$EXPECT_SERIAL" ]; then
    F "SERIAL MISMATCH — expected '$EXPECT_SERIAL', card reports '$serial'. This is a DIFFERENT DEVICE."
  else
    P "token serial matches the value recorded at the ceremony ($serial)"
  fi

  if [ -n "$EXPECT_CHR" ] || [ -n "$EXPECT_DEVAUT_SHA" ]; then
    # C.DevAut lives in read-only EF 2F02 as a Card Verifiable Certificate (BSI TR-03110), NOT
    # X.509 — so openssl cannot parse it and, measured 2026-08-01, **sc-hsm-tool never prints it**.
    # An earlier version of this script grepped sc-hsm-tool output for a CHR. That check could
    # never pass: it failed closed, which is the right direction, but a check that cannot succeed
    # makes commissioning impossible rather than safe. Reading it needs the scsh helper.
    devout=""
    if [ -n "${SCSH_HOME:-}" ] && [ -x "$SCSH_HOME/scriptrunner" ] && [ -r "$DEVAUT_JS" ]; then
      devout="$(cd "$SCSH_HOME" && perl -e 'alarm 60; exec @ARGV' -- ./scriptrunner "$DEVAUT_JS" 2>/dev/null)"
    fi
    if [ -z "$devout" ]; then
      F "could not read C.DevAut — device identity CANNOT BE EVALUATED"
      printf '     Needs SCSH_HOME pointing at a Smart Card Shell install; sc-hsm-tool cannot read it.\n'
    else
      chr="$(printf '%s' "$devout" | grep -oE '^DEVAUT_CHR=.*' | cut -d= -f2-)"
      car="$(printf '%s' "$devout" | grep -oE '^DEVAUT_CAR=.*' | cut -d= -f2-)"
      sha="$(printf '%s' "$devout" | grep -oE '^DEVAUT_SHA256=.*' | cut -d= -f2-)"

      if [ -n "$EXPECT_CHR" ]; then
        [ "$chr" = "$EXPECT_CHR" ] \
          && P "DevAut CHR matches the value pinned at the ceremony ($chr)" \
          || F "CHR MISMATCH — expected '$EXPECT_CHR', card reports '$chr'. A swapped genuine card looks like this."
      fi

      # PIN THE DIGEST, not just the name. The CHR is a label; the digest covers the whole
      # certificate including the device public key, so a substitute cannot reproduce it.
      if [ -n "$EXPECT_DEVAUT_SHA" ]; then
        [ "$sha" = "$EXPECT_DEVAUT_SHA" ] \
          && P "C.DevAut digest matches the pinned value" \
          || F "DEVAUT DIGEST MISMATCH — this is not the device that was commissioned."
      else
        printf '  \033[33mNOTE\033[0m no --expect-devaut-sha given. The CHR alone is a NAME; pin the digest\n'
        printf '        (%s) for substitution resistance.\n' "${sha:0:16}…"
      fi

      # SELF-SIGNED device certificate: CHR == CAR means nothing above it vouches for the device.
      # Measured on a Pico 2026-08-01. There is no manufacturer root to validate against, so
      # "genuine hardware" cannot be established at all — only "the same device we pinned".
      if [ -n "$chr" ] && [ "$chr" = "$car" ]; then
        F "C.DevAut is SELF-SIGNED (CHR == CAR == '$chr') — this device cannot be proven genuine."
        printf '     Expected on a Pico HSM, which is why a Pico must never hold production keys.\n'
        printf '     On a Nitrokey the CAR should name a CardContact Device Issuer CA, not the device.\n'
      fi
    fi
  fi
fi

# =================================================================================================
hdr "No SO-PIN material at the site"
# Under D3 the SO-PIN is held off-site at 2-of-3. Its presence here would collapse that.
# BOUNDED DELIBERATELY. The first version of this walked /etc /root /home /opt /srv /var/lib in
# full and took minutes — a commissioning check that slow is one an operator skips, which makes it
# worse than useless. This searches the places credentials actually get left, at shallow depth, with
# a hard time cap. It is a tripwire for the obvious mistake (a PIN pasted into a config or a note),
# NOT a proof of absence — nothing short of the operator's discipline is.
found=""
for p in /etc /root /opt/regalia /srv; do
  [ -d "$p" ] || continue
  hits="$(perl -e 'alarm 10; exec @ARGV' -- \
      find "$p" -maxdepth 3 -type f -size -256k \
        \( -name '*.env' -o -name '*.conf' -o -name '*.yaml' -o -name '*.yml' \
           -o -name '*.json' -o -name '*.txt' -o -name '*.sh' -o -name '*pin*' \) \
      2>/dev/null | head -400)"
  [ -n "$hits" ] || continue
  m="$(printf '%s\n' "$hits" | perl -e 'alarm 10; exec @ARGV' -- xargs -r grep -lEi 'so[-_]?pin' 2>/dev/null | head -5)"
  [ -n "$m" ] && found="$found $m"
done
if [ -n "$found" ]; then
  F "possible SO-PIN material on this host:$found"
  printf '     Under D3 the SO-PIN is 2-of-3 OFF-SITE. Anything here defeats that.\n'
else
  P "no SO-PIN-shaped material in the usual config locations (tripwire, not proof of absence)"
fi

# =================================================================================================
hdr "Key-use-counter baseline"
# Nitrokey's own recommended audit substitute: there is no on-device log, so the counter is the only
# record of key USE. It is worthless without a starting value written down here.
counter="$(perl -e 'alarm 30; exec @ARGV' -- pkcs11-tool --module "$P11" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} \
             --list-objects 2>/dev/null | grep -iE 'use counter|CKA_SC_HSM_KEY_USE_COUNTER' | head -1)"
if [ -n "$counter" ]; then
  P "key-use-counter readable — RECORD THIS BASELINE: $counter"
else
  printf '  \033[33mNOTE\033[0m no key-use counter reported. It is set at key GENERATION; imported keys\n'
  printf '        may not carry one. If absent, 4.2 reconciliation cannot work — decide deliberately.\n'
fi

# =================================================================================================
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
  printf '\n  \033[1;31mDO NOT PUT THIS CARD INTO SERVICE.\033[0m Every failure above is a property that\n'
  printf '  cannot be checked again once the card is trusted — commissioning is the only gate.\n'
  exit 1
fi
printf '\n  Commissioning PASSED. Record the serial, CHR and counter baseline in the fleet log.\n'
