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
#                      [--kek-id <PKCS#11 hex id> --kek-ref <SC-HSM key ref 1..255>]
#                      [--reader <PC/SC reader index>] [--slot <PKCS#11 slot id>]
#
# --kek-id/--kek-ref PRODUCE THE CUSTODY PIN (ADR-0002 D1, regalia#447/#448). regalia-kms identifies
# its KEK by device serial plus public_key_sha256 — the SHA-256 of the key's SubjectPublicKeyInfo —
# because the daemon cannot read the card's device certificate or key attestation (PKCS#11 does not
# reach those files). So the one moment "this key was GENERATED on THIS genuine card" can be proven
# is here: the attestation in EF CE<kek-ref> is verified against C.DevAut, C.DevAut against the
# CardContact root, and the attested public key against the public key at --kek-id — RSA (the
# envelope KEK, modulus and exponent) or EC (point and curve), the two types the card attests. Only
# then is a MANIFEST_BINDING_PINS line printed for the custody manifest binding. Give both or neither: the id
# names the key PKCS#11 sees, the ref names the file its attestation lives in, and the two numbers
# are different (key id 0a is key ref 1 on DENK0404144 — `pkcs15-tool --list-keys` shows both).
# Its Python runs under the interpreter tools/ceremony-python.sh resolves (pycvc and cryptography;
# CEREMONY_VENV picks one), never whichever python3 happens to be first on PATH.
#
# --reader names the PC/SC reader the OpenSC readers use, and --slot the PKCS#11 slot. Resolve both
# BY SERIAL (tools/hsm-reader-select.sh: hsm_reader_for / hsm_slot_id_for), never by position. The
# C.DevAut and attestation readers still refuse a reader holding any serial but --expect-serial.
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
EXPECT_CHR="" EXPECT_SERIAL="" EXPECT_ADDR="" SLOT="" EXPECT_DEVAUT_SHA="" READER=""
KEK_ID="" KEK_REF=""
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
ATTEST_SH="${HSM_KEY_ATTEST_READ_SH:-$(find_helper hsm-key-attestation-read.sh)}"
ATTEST_PY="${HSM_KEY_ATTEST_VERIFY_PY:-$(find_helper hsm-key-attestation-verify.py)}"
# The interpreter resolver (tools/ceremony-python.sh). The KEK section runs Python that needs pycvc
# and cryptography, which live in the ceremony venv, not in the system interpreter — see the KEK
# section for what running the bare `python3` did on the bench.
CEREMONY_PY_SH="${HSM_CEREMONY_PYTHON_SH:-}"
if [ -z "$CEREMONY_PY_SH" ]; then
  for c in "$HERE/../../tools/ceremony-python.sh" "$HERE/../../ceremony/tools/ceremony-python.sh"; do
    [ -r "$c" ] && { CEREMONY_PY_SH="$c"; break; }
  done
fi
# The bin dir of the first interpreter that imports what the KEK section needs. Called in a command
# substitution, so the resolver it sources is loaded into a subshell: this script wants its answer,
# not its functions.
kek_python_bin() {
  # shellcheck source=/dev/null
  . "$CEREMONY_PY_SH" && ceremony_python_find cryptography cvc
}
# The CardContact root the device certificate must chain to. Not a helper script, so resolved here
# the same two ways find_helper resolves them.
TRUST_DIR="${HSM_TRUST_DIR:-}"
if [ -z "$TRUST_DIR" ]; then
  for c in "$HERE/../../qubes/trust-anchors/smartcard-hsm" "$HERE/../../ceremony/qubes/trust-anchors/smartcard-hsm"; do
    [ -d "$c" ] && { TRUST_DIR="$(cd "$c" && pwd)"; break; }
  done
fi

need_val() { [ "$#" -ge 2 ] && [ -n "$2" ] && [ "${2#--}" = "$2" ] || { echo "$1 needs a value" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
  case "$1" in
    --expect-chr)     need_val "$1" "${2-}"; EXPECT_CHR="$2"; shift 2;;
    --expect-devaut-sha) need_val "$1" "${2-}"; EXPECT_DEVAUT_SHA="$2"; shift 2;;
    --expect-serial)  need_val "$1" "${2-}"; EXPECT_SERIAL="$2"; shift 2;;
    --expect-address) need_val "$1" "${2-}"; EXPECT_ADDR="$2"; shift 2;;
    --wallet-id)      need_val "$1" "${2-}"; WALLET_ID="$2"; shift 2;;
    --slot)           need_val "$1" "${2-}"; SLOT="$2"; shift 2;;
    --module)         need_val "$1" "${2-}"; P11="$2"; shift 2;;
    --reader)         need_val "$1" "${2-}"; READER="$2"; shift 2;;
    --kek-id)         need_val "$1" "${2-}"; KEK_ID="$2"; shift 2;;
    --kek-ref)        need_val "$1" "${2-}"; KEK_REF="$2"; shift 2;;
    -h|--help) sed -n '2,46p' "$0"; exit 0;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done

pass=0; fail=0
devaut_hex="" kek_pin=""
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

SLOT_ARGS=()
[ -n "$SLOT" ] && SLOT_ARGS=(--slot "$SLOT")
# --reader goes to every OpenSC tool that talks to the card directly. Without it they take OpenSC's
# default reader, which with two cards attached is whichever enumerated first.
READER_ARGS=() RD_ARGS=()
[ -n "$READER" ] && { READER_ARGS=(--reader "$READER"); RD_ARGS=(-r "$READER"); }
# No options on purpose (beyond the reader): this reads the card's configuration options and nothing
# else. It is time-capped because an unresponsive reader must FAIL the gate, not hang it.
card_info(){ perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool ${RD_ARGS[@]+"${RD_ARGS[@]}"} 2>/dev/null; }

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
  # THE SERIAL OF THE SELECTED SLOT, NOT THE FIRST ONE LISTED. `--list-slots` lists EVERY slot
  # whatever --slot says, and this used to take the first serial it printed — so with two cards
  # attached (the bench has a Pico beside the Nitrokey) B7 could compare the WRONG card's serial and
  # pass. The block for --slot's id is the one read; with no --slot, more than one token present is
  # refused as ambiguous rather than guessed.
  slots="$(perl -e 'alarm 30; exec @ARGV' -- pkcs11-tool --module "$P11" --list-slots 2>/dev/null)"
  # Slot ids are compared as canonical lowercase hex STRINGS: strtonum is gawk-only, and a Debian
  # rack host runs mawk.
  want_hex=""
  [ -n "${SLOT:-}" ] && want_hex="$(printf '0x%x' "$SLOT" 2>/dev/null)"
  serial="$(awk -v want="$want_hex" -v selected="${SLOT:-}" '
      /^Slot [0-9]+ \(0x[0-9a-fA-F]+\)/ { match($0, /\(0x[0-9a-fA-F]+\)/); id = tolower(substr($0, RSTART + 1, RLENGTH - 2)); next }
      /serial num *:/ { v = $NF; if (selected == "") { n++; last = v } else if (id == want) { print v; exit } }
      END { if (selected == "" && n == 1) print last; else if (selected == "" && n > 1) print "AMBIGUOUS" }' <<< "$slots")"
  if [ "$serial" = "AMBIGUOUS" ]; then
    F "more than one token is attached and no --slot was given — WHICH card is being commissioned CANNOT BE EVALUATED"
    printf '     Pass --slot <id> (and --reader) for the card under commissioning.\n'
  elif [ -z "$serial" ]; then
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
      devout="$(perl -e 'alarm 60; exec @ARGV' -- bash "$DEVAUT_SH" ${READER_ARGS[@]+"${READER_ARGS[@]}"} \
                  --expect-serial "$EXPECT_SERIAL" 2>/dev/null)"
    fi
    if [ -z "$devout" ]; then
      F "could not read C.DevAut — device identity CANNOT BE EVALUATED"
      printf '     Needs qubes/scripts/hsm-devaut-read.sh (opensc-tool only) or SCSH_HOME pointing\n'
      printf '     at a Smart Card Shell install. sc-hsm-tool itself cannot read C.DevAut.\n'
    else
      chr="$(grep -oE '^DEVAUT_CHR=.*' <<< "$devout" | cut -d= -f2-)"
      car="$(grep -oE '^DEVAUT_CAR=.*' <<< "$devout" | cut -d= -f2-)"
      sha="$(grep -oE '^DEVAUT_SHA256=.*' <<< "$devout" | cut -d= -f2-)"
      # Kept for the KEK section below: the attestation is verified against THESE bytes, the ones
      # whose digest was just compared with the ceremony's pin.
      devaut_hex="$(grep -oE '^DEVAUT_HEX=[0-9A-Fa-f]*' <<< "$devout" | cut -d= -f2-)"

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
hdr "KEK provenance — the key regalia-kms will pin was GENERATED on THIS genuine card (ADR-0002 D1)"
# WHY THIS IS HERE AND NOWHERE ELSE. regalia-kms identifies its KEK by device_serial plus
# public_key_sha256 (regalia-kms#26). It cannot check where that key came from: CKA_LOCAL answers
# nothing on an SC-HSM (#447), and the two files that do — C.DevAut in EF 2F02 and the key
# attestation in EF CE<keyref> — are out of PKCS#11's reach. So the daemon trusts a PIN, and the pin
# is only worth what was proven before it was written down. This is where that proof happens: a
# pin printed without it would carry an imported key, a mismatched id/ref pairing or a clone's key
# into the manifest with exactly the same authority as the real thing.
#
# THE PIN AND THE ATTESTED KEY COME FROM ONE READ. The SubjectPublicKeyInfo handed to the verifier
# as --expect-spki is the SAME file whose bytes are hashed into the pin. Comparing the key from one
# pkcs11-tool call and hashing the output of another would verify one key and pin whatever the second
# call returned.
#
# RSA AND EC BOTH. This section used to extract an EC point and pass --expect-point, so an RSA key —
# ADR-0002 D1's envelope KEK, the main key this pin exists for — FAILED as "not an EC public key this
# can parse" before its attestation was even read (regalia#28 criterion 4 rehearsal, DENK0404144,
# 2026-09-23). The card attests both: the verifier now compares the whole key (modulus AND exponent,
# or point AND curve) against the SPKI itself. A key of any other type cannot have been generated
# with an attestation on a SmartCard-HSM, so it is a named failure, never a skip.
#
# THE INTERPRETER IS RESOLVED, NOT ASSUMED. Every Python this section runs needs cryptography, and the
# chain walk needs pycvc — the hash-pinned deps that live in the ceremony venv. The same rehearsal ran
# this section under the system python3: the verifier could not import pycvc and the KEK FAILED as
# "C.DevAut does not validate to an anchor", while the same verifier under the venv verified the
# same bytes. A genuine card was reported as not genuine because of which interpreter was first on
# PATH. tools/ceremony-python.sh is the repo's one answer to "which interpreter has the deps"; it is
# used for every Python below, and no interpreter with them is its own named failure.
#
# THE MANIFEST FRAGMENT IS PRINTED ONLY IF COMMISSIONING PASSES AS A WHOLE (see RESULT). A pin for a
# card that failed B6 or B7 is a line someone will copy anyway.
if [ -z "$KEK_ID" ] && [ -z "$KEK_REF" ]; then
  printf '  \033[33mNOTE\033[0m no --kek-id/--kek-ref given; the KEK pin (public_key_sha256) was NOT\n'
  printf '        produced, and nothing here proved the KEK was generated on this card. Pass the\n'
  printf '        KEK'"'"'s PKCS#11 id and SC-HSM key reference to produce the manifest binding pin.\n'
elif [ -z "$KEK_ID" ] || [ -z "$KEK_REF" ]; then
  # ONE WITHOUT THE OTHER IS A FAILURE, NOT A NOTE. The operator asked for the pin; answering with a
  # note would let "Commissioning PASSED" stand over a pin that was never produced.
  F "--kek-id and --kek-ref must be given TOGETHER — the KEK pin CANNOT BE EVALUATED from one of them"
  printf '     --kek-id is the PKCS#11 id the daemon uses; --kek-ref is the SC-HSM key reference whose\n'
  printf '     EF CE<ref> holds its attestation. They differ (pkcs15-tool --list-keys prints both).\n'
elif ! [[ "$KEK_ID" =~ ^([0-9A-Fa-f]{2})+$ ]]; then
  F "--kek-id '$KEK_ID' is not a hex PKCS#11 id (e.g. 0a) — the KEK pin CANNOT BE EVALUATED"
elif [ -z "$EXPECT_SERIAL" ] || [ -z "$EXPECT_DEVAUT_SHA" ]; then
  F "the KEK pin needs the pinned identity (--expect-serial, --expect-devaut-sha) — CANNOT BE EVALUATED"
elif [ -z "$devaut_hex" ]; then
  # The attestation is signed by the device key INSIDE C.DevAut. Without those bytes there is
  # nothing to verify it against — and fetching them again here would be a second read that
  # nobody compared with the ceremony's digest.
  F "C.DevAut bytes (DEVAUT_HEX) were not obtained above — the attestation CANNOT BE EVALUATED"
elif [ -z "$ATTEST_SH" ] || [ ! -r "$ATTEST_SH" ]; then
  F "hsm-key-attestation-read.sh not found — the KEK attestation CANNOT BE EVALUATED"
  printf '     Point HSM_KEY_ATTEST_READ_SH at qubes/scripts/hsm-key-attestation-read.sh.\n'
elif [ -z "$ATTEST_PY" ] || [ ! -r "$ATTEST_PY" ]; then
  F "hsm-key-attestation-verify.py not found — the KEK attestation CANNOT BE EVALUATED"
  printf '     Point HSM_KEY_ATTEST_VERIFY_PY at qubes/scripts/hsm-key-attestation-verify.py.\n'
elif [ -z "$TRUST_DIR" ] || [ ! -d "$TRUST_DIR" ]; then
  # No anchor, no genuineness: the verifier's other arm (--devaut-already-verified) is an assertion,
  # and nothing earlier in THIS script validated the chain — B7 compares a digest, it does not
  # verify a signature. So the anchor is mandatory here.
  F "no SmartCard-HSM trust anchor directory — the device chain CANNOT BE EVALUATED"
  printf '     Point HSM_TRUST_DIR at qubes/trust-anchors/smartcard-hsm.\n'
elif [ -z "$CEREMONY_PY_SH" ] || [ ! -r "$CEREMONY_PY_SH" ]; then
  F "tools/ceremony-python.sh not found — the interpreter for the KEK attestation CANNOT BE RESOLVED, so it CANNOT BE EVALUATED"
  printf '     Point HSM_CEREMONY_PYTHON_SH at tools/ceremony-python.sh.\n'
elif ! kek_py_bin="$(kek_python_bin)" \
     || [ ! -x "$kek_py_bin/python3" ]; then
  F "no Python interpreter here can import pycvc and cryptography — the KEK attestation CANNOT BE EVALUATED"
  printf '     Not a verdict on the card: the device chain needs pycvc. tools/ceremony-python.sh looked in\n'
  printf '     $CEREMONY_VENV, /opt/dev-bin/regalia-venv, the historical venv paths and the system python3.\n'
  printf '     Build the venv (qubes/requirements.txt, --require-hashes) or set CEREMONY_VENV.\n'
else
  KEK_PY="$kek_py_bin/python3"
  kek_tmp="$(mktemp -d)"
  # C.DevAut must be the bytes whose digest B7 compared against the ceremony's pin. Recomputed here
  # from DEVAUT_HEX rather than trusting the reader's DEVAUT_SHA256 field, which is a separate line
  # a reader could get wrong independently of the bytes.
  printf '%s' "$devaut_hex" | "$KEK_PY" -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))' \
    > "$kek_tmp/devaut.bin" 2>/dev/null
  devaut_recomputed="$(sha256sum < "$kek_tmp/devaut.bin" | awk '{print $1}')"
  if [ ! -s "$kek_tmp/devaut.bin" ] || [ "$devaut_recomputed" != "$EXPECT_DEVAUT_SHA" ]; then
    F "the C.DevAut bytes read above do not hash to the pinned digest — the attestation would be checked against an UNPINNED device"
  else
    perl -e 'alarm 30; exec @ARGV' -- pkcs11-tool --module "$P11" ${SLOT_ARGS[@]+"${SLOT_ARGS[@]}"} \
      --read-object --type pubkey --id "$KEK_ID" -o "$kek_tmp/kek.der" >/dev/null 2>&1
    # What kind of key the token holds at --kek-id: rsa, ec, another type's name, or nothing when the
    # bytes are not a SubjectPublicKeyInfo. Only to NAME the failure for the last two — the verifier
    # compares the key itself, so this answer never decides a pass.
    kek_type="$( [ -s "$kek_tmp/kek.der" ] && "$KEK_PY" - "$kek_tmp/kek.der" 2>/dev/null <<'PYTYPE'
import sys
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
k = load_der_public_key(open(sys.argv[1], "rb").read())
print("rsa" if isinstance(k, rsa.RSAPublicKey) else "ec" if isinstance(k, ec.EllipticCurvePublicKey)
      else type(k).__name__)
PYTYPE
)"
    att_out="$(perl -e 'alarm 60; exec @ARGV' -- bash "$ATTEST_SH" ${READER_ARGS[@]+"${READER_ARGS[@]}"} \
                 --expect-serial "$EXPECT_SERIAL" --key-ref "$KEK_REF" 2>"$kek_tmp/att.err")"; att_rc=$?
    att_hex="$(grep -oE '^ATTEST_HEX=[0-9A-Fa-f]*' <<< "$att_out" | cut -d= -f2-)"
    if [ ! -s "$kek_tmp/kek.der" ]; then
      F "no public key with ID $KEK_ID on this token — the KEK pin CANNOT BE EVALUATED"
    elif [ -z "$kek_type" ]; then
      F "key ID $KEK_ID is not a SubjectPublicKeyInfo this can parse — the KEK attestation CANNOT BE EVALUATED"
    elif [ "$kek_type" != rsa ] && [ "$kek_type" != ec ]; then
      F "key ID $KEK_ID is neither an RSA nor an EC key ($kek_type) — a SmartCard-HSM attests only those, so it cannot be proven generated on this card. DO NOT PIN IT."
    elif [ "$att_rc" -ne 0 ] || [ -z "$att_hex" ]; then
      # Named, because the likeliest causes are different operator actions: a wrong --kek-ref, or a
      # key that was IMPORTED and so has no attestation at all — which must never be pinned.
      F "could not read the attestation at key reference $KEK_REF — the KEK's provenance CANNOT BE EVALUATED"
      # The reader's own named reason when it gave one; otherwise the tail of whatever it printed.
      att_why="$(grep '^hsm-key-attestation-read:' "$kek_tmp/att.err")"
      [ -n "$att_why" ] || att_why="$(grep -v '^[[:space:]]*$' "$kek_tmp/att.err" | tail -3)"
      printf '%s\n' "$att_why" | sed 's/^/     /'
    else
      printf '%s' "$att_hex" | "$KEK_PY" -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))' \
        > "$kek_tmp/attest.bin" 2>/dev/null
      ver_out="$(perl -e 'alarm 60; exec @ARGV' -- "$KEK_PY" "$ATTEST_PY" --devaut "$kek_tmp/devaut.bin" \
                   --attestation "$kek_tmp/attest.bin" --trust-dir "$TRUST_DIR" \
                   --expect-spki "$kek_tmp/kek.der" 2>&1)"; ver_rc=$?
      # THE EXIT CODE AND THE THREE VERDICT LINES, ALL OF THEM. A zero exit alone would accept a
      # verifier that returned early, or one run without --expect-spki by a future edit; requiring
      # each line pins what was actually checked: the chain, the device signature, and that the
      # attested key IS the key at --kek-id (the very bytes hashed into the pin below).
      if [ "$ver_rc" -eq 0 ] \
         && grep -qx 'DEVAUT_CHAIN=verified' <<< "$ver_out" \
         && grep -qx 'ATTEST_SIGNATURE=verified' <<< "$ver_out" \
         && grep -qx 'ATTESTED_KEY_MATCHES=yes' <<< "$ver_out"; then
        kek_pin="sha256:$(sha256sum < "$kek_tmp/kek.der" | awk '{print $1}')"
        P "C.DevAut chains to the CardContact root in $TRUST_DIR"
        P "EF $(printf 'CE%02X' "$KEK_REF") is signed by this device and attests the $(tr a-z A-Z <<< "$kek_type") key at ID $KEK_ID — generated on this card"
        P "KEK public_key_sha256 = $kek_pin (SubjectPublicKeyInfo of ID $KEK_ID)"
      elif grep -q '^DEPENDENCY_MISSING=' <<< "$ver_out"; then
        # The resolver said this interpreter imports the deps; the verifier disagrees. Still not a
        # verdict on the card, so not worded as one.
        F "the KEK attestation verifier is missing a dependency under $KEK_PY — CANNOT BE EVALUATED (not a verdict on the card)"
        grep -E '^(hsm-key-attestation-verify|DEPENDENCY_MISSING)' <<< "$ver_out" | sed 's/^/     /'
      elif grep -qx 'DEVAUT_CHAIN=not-evaluated' <<< "$ver_out"; then
        # The chain could not be CHECKED (an empty or malformed C.DevAut read, a chain walker that
        # exited on its own error). That is the environment talking, not a verdict on the card, and
        # wording it as "not a genuine card" is the misreport this section exists to avoid (review of
        # regalia-ceremony#40). Still a FAIL: nothing is pinned without a verified chain.
        F "the C.DevAut chain could NOT BE EVALUATED — no verdict on the card; re-read C.DevAut and check the verifier's reason below"
        grep -E '^(hsm-key-attestation-verify|cvc-devaut-verify) |^DEVAUT_CHAIN=' <<< "$ver_out" | sed 's/^/     /' | head -6
      else
        F "the KEK attestation DID NOT VERIFY — imported key, wrong --kek-ref for --kek-id, or not a genuine card. DO NOT PIN IT."
        # The verifier's named reasons FIRST, then its verdict lines. A tail of the combined output
        # used to show whichever lines came last, which on the bench was not the one that said why.
        { grep -E '^(hsm-key-attestation-verify|cvc-devaut-verify) ' <<< "$ver_out"
          grep -E '^[A-Z_]+=' <<< "$ver_out" | grep -vE '^(ATTESTED_POINT|DEVAUT_CHR|ATTEST_CAR)='; } \
          | sed 's/^/     /' | head -10
      fi
    fi
  fi
  rm -rf "$kek_tmp"
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
  [ -n "$kek_pin" ] && printf '\n  The KEK attestation verified, but NO MANIFEST_BINDING_PINS line is printed for a card\n  that failed commissioning.\n'
  exit 1
fi
printf '\n  Commissioning PASSED. Record the serial, CHR and counter baseline in the fleet log.\n'
# The custody pin, ONLY now: every check above passed, including the attestation that makes it mean
# "generated on this genuine card". One JSON line, prefixed so it can be grepped out of a transcript
# and pasted into the manifest binding without retyping a digest.
if [ -n "$kek_pin" ]; then
  printf '\n  Custody manifest binding pins for the KEK (ADR-0002 D1) — copy this line:\n'
  printf 'MANIFEST_BINDING_PINS {"device_serial":"%s","public_key_sha256":"%s"}\n' "$EXPECT_SERIAL" "$kek_pin"
fi
