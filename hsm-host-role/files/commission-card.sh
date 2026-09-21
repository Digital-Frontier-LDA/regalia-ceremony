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
#   commission-card.sh --expect-serial <SERIAL> --expect-devaut-sha <SHA256>
#                      [--expect-chr <CHR>] [--expect-address akash1… [--wallet-id 01]]
#
# BOTH --expect-serial AND --expect-devaut-sha are required. A serial is self-reported by the card
# and a CHR is only a name; the digest of C.DevAut covers the device public key, which is what a
# substituted genuine Nitrokey cannot reproduce. Accepting any one of the three — which this script
# used to do — let a run that pinned only the CHR report a commissioned card while never checking
# WHICH device answered.
#
# FAILS CLOSED. Any check that cannot be EVALUATED is a failure, not a skip. A commissioning script
# that returns 0 because a tool was missing is worse than no script: it certifies nothing while
# looking like it certified everything.
set -uo pipefail

P11="${HSM_PKCS11_MODULE:-/usr/lib/opensc-pkcs11.so}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECT_CHR="" EXPECT_SERIAL="" EXPECT_ADDR="" SLOT="" EXPECT_DEVAUT_SHA=""
WALLET_ID="01"
# Helpers live in qubes/scripts/ of the ceremony repo. The default used to name
# ../../ceremony/qubes/scripts/, a path that exists only in the retired monorepo layout — so on the
# published repo the C.DevAut read could never succeed and commissioning could never pass.
find_helper() {
  local name="$1" c
  for c in "$HERE/../../qubes/scripts/$name" "$HERE/../../ceremony/qubes/scripts/$name"; do
    [ -r "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}
DEVAUT_JS="${HSM_DEVAUT_JS:-$(find_helper hsm-devaut-id.js)}"
DEVAUT_SH="${HSM_DEVAUT_READ_SH:-$(find_helper hsm-devaut-read.sh)}"
DERIVE_PY="${HSM_DERIVE_ADDRESS_PY:-$(find_helper derive-akash-address.py)}"

while [ $# -gt 0 ]; do
  case "$1" in
    --expect-chr)     EXPECT_CHR="${2:-}"; shift 2;;
    --expect-devaut-sha) EXPECT_DEVAUT_SHA="${2:-}"; shift 2;;
    --expect-serial)  EXPECT_SERIAL="${2:-}"; shift 2;;
    --expect-address) EXPECT_ADDR="${2:-}"; shift 2;;
    --wallet-id)      WALLET_ID="${2:-}"; shift 2;;
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
# No arguments on purpose: this reads the card's configuration options and nothing else. It is
# time-capped because an unresponsive reader must FAIL the gate, not hang it.
card_info(){ perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool 2>/dev/null; }

# =================================================================================================
hdr "B3 — the host carries no DKEK"
# The rule the threat model produces: PIN + DKEK together export every key on the token, offline and
# undetectably. The ceremony can promise the DKEK was destroyed; only the host can show it is absent.
ASSERT_NO_DKEK="${HSM_ASSERT_NO_DKEK:-$HERE/assert-no-dkek.sh}"
if [ -x "$ASSERT_NO_DKEK" ]; then
  # THREE OUTCOMES, NOT TWO. The guard exits 0 clean, 1 when it found material, and 2 when it could
  # not scan a directory at all. Collapsing 1 and 2 into "DKEK MATERIAL PRESENT" sends an operator
  # hunting for a share that does not exist while the real fault — a scan that never ran — goes
  # unnamed. Both still fail commissioning.
  dkek_out="$("$ASSERT_NO_DKEK" 2>&1)"; dkek_rc=$?
  case "$dkek_rc" in
    0) P "no DKEK material found on this host";;
    1) F "DKEK MATERIAL PRESENT — with PIN access on this host, every key on the card is exportable";;
    *) F "the DKEK scan could not complete — B3 CANNOT BE EVALUATED (run as root, or fix the paths it names)"
       printf '%s\n' "$dkek_out" | sed 's/^/     /';;
  esac
else
  F "assert-no-dkek.sh not found — B3 CANNOT BE EVALUATED, so this is a failure, not a skip"
fi

# =================================================================================================
hdr "The staging registry must not still list this card as wipeable"
# THE WAY OUT OF THE WIPE LIST, ENFORCED RATHER THAN REMEMBERED (regalia#481, decision 2026-09-21).
# Future-production units are registered as `staging` so the drills that qualify them can run —
# which means automation may erase them on schedule. Commissioning is the moment that stops being
# acceptable: after this, the card holds production keys. So the last step of qualification is
# removing it from the registry, and this refuses to certify a card the registry still lists.
_cc_reg="${HSM_STAGING_REGISTRY_FILE:-}"
if [ -z "$_cc_reg" ]; then
  for c in "$HERE/../../tools/hsm-staging-registry.json" /etc/regalia/hsm-staging-registry.json; do
    [ -r "$c" ] && { _cc_reg="$c"; break; }
  done
fi
if [ -z "$EXPECT_SERIAL" ]; then
  : # already failed above; nothing to look up
elif [ -z "$_cc_reg" ] || [ ! -r "$_cc_reg" ]; then
  # CANNOT-EVALUATE IS A FAILURE HERE TOO. A note let a normal run certify a card without ever
  # proving it had left the wipe list — and "the registry was not on this host" is exactly the
  # state a card is in when nobody checked. The friction is the point: commissioning is the one
  # moment that can still stop a production key landing on a card automation may erase.
  F "no staging registry found, so 'has this card left the wipe list' CANNOT BE EVALUATED"
  printf '     Point HSM_STAGING_REGISTRY_FILE at the fleet registry (the copy the batteries diff\n'
  printf '     against the runner). If this fleet keeps no staging registry at all, pass an empty\n'
  printf '     one — {"schema":"regalia.staging-hardware/v1","environment":"staging","devices":[]}\n'
  printf '     — so the answer is recorded rather than assumed.\n'
elif ! command -v python3 >/dev/null; then
  F "a staging registry is present but python3 is not — the wipeable interlock CANNOT BE EVALUATED"
else
  _cc_role="$(python3 - "$_cc_reg" "$EXPECT_SERIAL" <<'PYREG'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    hits = [d for d in (data.get("devices") or [])
            if isinstance(d, dict) and d.get("token_serial") == sys.argv[2]]
    print(hits[0].get("role") if len(hits) == 1 else ("ambiguous" if hits else "absent"))
except Exception:
    print("unreadable")
PYREG
)"
  case "$_cc_role" in
    absent)     P "the staging registry does not list $EXPECT_SERIAL — it is not wipeable by automation";;
    staging)    F "THIS CARD IS STILL LISTED staging IN $_cc_reg — the drills may wipe it on schedule."
                printf '     Remove the entry in a reviewed change BEFORE putting the card into service;\n'
                printf '     a production key on a card automation may erase is not custody.\n';;
    unreadable) F "the staging registry at $_cc_reg could not be read — the interlock CANNOT BE EVALUATED";;
    ambiguous)  F "$EXPECT_SERIAL is listed more than once in $_cc_reg — refusing to interpret it";;
    *)          P "the staging registry lists $EXPECT_SERIAL with role '$_cc_role', not staging";;
  esac
fi

# =================================================================================================
hdr "B6 — the card has RESET RETRY COUNTER disabled"
# THE CHECK THAT MAKES THE D3 RULING REAL. With RRC enabled, the SO-PIN resets the user PIN without
# touching keys, at any time, and `--wrap-key` then exports everything. `sc-hsm-tool --initialize`
# HARDCODES RRC on, so a card provisioned the ordinary way is in the vulnerable state. Only a Smart
# Card Shell initialisation can disable it — and nothing but this check can tell them apart at the
# rack.
info_out="$(card_info)"
if [ -z "$info_out" ]; then
  F "could not read the card — B6 CANNOT BE EVALUATED (is the card inserted, is pcscd running?)"
elif grep -qi 'User PIN reset with SO-PIN enabled' <<< "$info_out"; then
  # A here-string, not `printf … | grep -q`: under pipefail a grep that exits on its first match can
  # leave the pipeline status non-zero, and THIS predicate inverting means a card with RRC ENABLED
  # falls through to the else branch and is reported as compliant.
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
if [ -z "$EXPECT_SERIAL" ] || [ -z "$EXPECT_DEVAUT_SHA" ]; then
  F "--expect-serial AND --expect-devaut-sha are both required — identity CANNOT BE EVALUATED"
  printf '     Both are recorded at the ceremony. Commissioning without them proves nothing about\n'
  printf '     WHICH device is in the rack, and substitution is the attack colocation introduces.\n'
  printf '     Pinning just one of serial/CHR/digest is not a weaker check, it is no check against\n'
  printf '     a substituted genuine card: the serial is self-reported and the CHR is a name, while\n'
  printf '     only the digest covers the device public key.\n'
else
  serial="$(perl -e 'alarm 30; exec @ARGV' -- pkcs11-tool --module "$P11" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} \
              --list-slots 2>/dev/null | grep -oE 'serial num *: *[A-Za-z0-9]+' | awk '{print $NF}' | head -1)"
  if [ -z "$serial" ]; then
    F "could not read a token serial — identity CANNOT BE EVALUATED"
  elif [ "$serial" != "$EXPECT_SERIAL" ]; then
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
    if [ -n "${SCSH_HOME:-}" ] && [ -x "$SCSH_HOME/scriptrunner" ] && [ -n "$DEVAUT_JS" ] && [ -r "$DEVAUT_JS" ]; then
      devout="$(cd "$SCSH_HOME" && perl -e 'alarm 60; exec @ARGV' -- ./scriptrunner "$DEVAUT_JS" 2>/dev/null)"
    fi
    # NO JAVA AT THE RACK. hsm-devaut-read.sh reads the same EF 2F02 with opensc-tool alone, verified
    # byte-identical to the scsh reader on DENK0404144 (2026-09-18). Requiring a Smart Card Shell
    # install in a colocation cage is how a mandatory check turns into a skipped one.
    if [ -z "$devout" ] && [ -n "$DEVAUT_SH" ] && [ -r "$DEVAUT_SH" ]; then
      devout="$(perl -e 'alarm 60; exec @ARGV' -- bash "$DEVAUT_SH" --expect-serial "$EXPECT_SERIAL" 2>/dev/null)"
    fi
    if [ -z "$devout" ]; then
      F "could not read C.DevAut — device identity CANNOT BE EVALUATED"
      printf '     Needs qubes/scripts/hsm-devaut-read.sh (opensc-tool only) or SCSH_HOME pointing\n'
      printf '     at a Smart Card Shell install. sc-hsm-tool itself cannot read C.DevAut.\n'
    else
      chr="$(grep -oE '^DEVAUT_CHR=.*' <<< "$devout" | cut -d= -f2-)"
      car="$(grep -oE '^DEVAUT_CAR=.*' <<< "$devout" | cut -d= -f2-)"
      sha="$(grep -oE '^DEVAUT_SHA256=.*' <<< "$devout" | cut -d= -f2-)"

      if [ -n "$EXPECT_CHR" ]; then
        if [ "$chr" = "$EXPECT_CHR" ]; then
          P "DevAut CHR matches the value pinned at the ceremony ($chr)"
        else
          F "CHR MISMATCH — expected '$EXPECT_CHR', card reports '$chr'. A swapped genuine card looks like this."
        fi
      fi

      # PIN THE DIGEST, not just the name. The CHR is a label; the digest covers the whole
      # certificate including the device public key, so a substitute cannot reproduce it.
      if [ -n "$EXPECT_DEVAUT_SHA" ]; then
        if [ "$sha" = "$EXPECT_DEVAUT_SHA" ]; then
          P "C.DevAut digest matches the pinned value"
        else
          F "DEVAUT DIGEST MISMATCH — this is not the device that was commissioned."
        fi
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
hdr "Funding address — the key in this card controls the money we think it controls"
# --expect-address used to be ACCEPTED AND IGNORED: the flag parsed, nothing compared it, and the
# operator read "Commissioning PASSED" believing the funding address had been confirmed. A silently
# ignored expectation is worse than an absent one — it manufactures confidence.
if [ -z "$EXPECT_ADDR" ]; then
  printf '  \033[33mNOTE\033[0m no --expect-address given; the on-chain identity of the wallet key was not\n'
  printf '        checked. Pass the akash1… address recorded at the ceremony to check it here.\n'
elif [ -z "$DERIVE_PY" ] || [ ! -r "$DERIVE_PY" ]; then
  F "--expect-address given but derive-akash-address.py was not found — CANNOT BE EVALUATED"
  printf '     Point HSM_DERIVE_ADDRESS_PY at qubes/scripts/derive-akash-address.py.\n'
elif ! command -v python3 >/dev/null; then
  F "--expect-address given but python3 is absent — CANNOT BE EVALUATED"
else
  # Read the wallet public key from the token. --wallet-id names WHICH key: a card that serves every
  # role (REQUIREMENTS E1) carries several, and deriving an address from the SSH key would compare
  # the wrong thing and fail for the wrong reason.
  objs="$(perl -e 'alarm 30; exec @ARGV' -- pkcs11-tool --module "$P11" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} \
            --list-objects --type pubkey 2>/dev/null)"
  read -r point params <<< "$(awk -v want="$WALLET_ID" '
      /EC_POINT:/  { p=$2 }
      /EC_PARAMS:/ { q=$2 }
      /^[[:space:]]*ID:/ { if ($2 == want) { print p, q; exit } }' <<< "$objs")"
  # 06052b8104000a is secp256k1. An akash address derived from a P-256 or RSA key is a well-formed
  # string that corresponds to nothing — exactly the kind of green check this file exists to refuse.
  if [ -z "$point" ]; then
    F "no public key with ID $WALLET_ID on this token — the funding key CANNOT BE EVALUATED"
  elif [ "$params" != "06052b8104000a" ]; then
    F "key ID $WALLET_ID is not secp256k1 (EC_PARAMS=$params) — an akash address from it would be meaningless"
  else
    # pkcs11-tool prints the DER OCTET STRING wrapper (0441 / 0421) around the EC point; strip it.
    case "$point" in
      0441*) point="${point#0441}";;
      0421*) point="${point#0421}";;
    esac
    got="$(perl -e 'alarm 30; exec @ARGV' -- python3 "$DERIVE_PY" --hex "$point" 2>/dev/null | tr -d '[:space:]')"
    if [ -z "$got" ]; then
      F "could not derive an address from the key on this card — CANNOT BE EVALUATED"
    elif [ "$got" = "$EXPECT_ADDR" ]; then
      P "the wallet key on this card derives to the expected address ($got)"
    else
      F "ADDRESS MISMATCH — this card holds $got, not $EXPECT_ADDR. It is not the funding key."
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
