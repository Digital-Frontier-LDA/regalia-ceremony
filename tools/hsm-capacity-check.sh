#!/usr/bin/env bash
# hsm-capacity-check.sh — is the card out of room? Ask before blaming the firmware.
#
#   ./tools/hsm-capacity-check.sh [--free N]
#
# WHY THIS EXISTS.
#
# A full card fails writes with CKR_GENERAL_ERROR — the same symptom as a genuine firmware fault,
# with nothing in the message to distinguish them. On 2026-08-10 that cost two wrong diagnoses in a
# row: a candidate ordering fix was declared to have broken keygen, and then the stock build was
# declared broken too. Both were wrong. The card held 128 objects and simply had no space. Deleting
# 60 keys restored 2/2 keygens on the same binary that had just "failed".
#
# The tell was available the whole time and took one command to read. So read it first, always,
# before attributing a write failure to code.
set -uo pipefail

MOD="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"
PIN="${HSM_USER_PIN:-648219}"
# The role registry gate lives in the resolver, sourced for the --free path below.
_cap_rr="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hsm-reader-select.sh"
# A missing resolver is NOT silently tolerated: --free checks `command -v hsm_assert_staging` and
# refuses before any pkcs11-tool call when the gate did not load.
# shellcheck source=hsm-reader-select.sh
[ -f "$_cap_rr" ] && . "$_cap_rr"

# TARGET ONE CARD. Two Pico HSMs can be attached; with no --slot, pkcs11-tool answers for whichever
# slot it picks, so "the card is out of room" could be a report about the other device entirely.
# HSM_SLOT_ID is what the batteries export; falling back to no flag keeps single-card hosts as-is.
# AN ARRAY, AND A VALIDATED ID. Built as one string and expanded unquoted, a slot id carrying
# spaces or a stray flag becomes EXTRA ARGUMENTS to pkcs11-tool — silently changing the command
# instead of failing. This script deletes private keys on --free, so a malformed id must be a
# refusal, not a differently-aimed command. Reader/slot ids are numeric here (PKCS#11 slot id).
SLOTARG=()
if [ -n "${HSM_SLOT_ID:-}" ]; then
  case "$HSM_SLOT_ID" in
    *[!0-9]*|"") echo "REFUSING: HSM_SLOT_ID='$HSM_SLOT_ID' is not a numeric PKCS#11 slot id" >&2; exit 2 ;;
    *) SLOTARG=(--slot "$HSM_SLOT_ID") ;;
  esac
fi
LIMIT="${HSM_OBJECT_LIMIT:-128}"          # observed ceiling on this card
WANT="${2:-8}"                             # headroom required, in objects

# --free N: delete N private keys (and their public halves) to make room. Destructive by request.
if [ "${1:-}" = "--free" ]; then
    # THE ROLE REGISTRY GATE — deletion is destructive, so the card must PROVE which slot it is
    # and be registered staging before anything is removed. Unnamed slot on a multi-slot host:
    # pkcs11-tool would pick the slot itself, which is not a target we can vouch for. A card with
    # no readable serial is refused — an unreadable card is not "safe to prune", and a blank card
    # has nothing to delete anyway.
    if ! command -v hsm_assert_staging >/dev/null 2>&1; then
      echo "REFUSING: the role registry gate ($(dirname "${BASH_SOURCE[0]}")/hsm-reader-select.sh) is unavailable — --free does not run without it." >&2; exit 2
    fi
    _cap_slots="$(hsm_slot_table 2>/dev/null | grep -c .)"
    if [ -z "${HSM_SLOT_ID:-}" ] && [ "${_cap_slots:-0}" -gt 1 ]; then
      echo "REFUSING: $_cap_slots slots are present and none was named. --free deletes keys; set HSM_SLOT_ID to the slot you mean." >&2; exit 2
    fi
    _cap_ser="$(hsm_serial_at_slot_id "${HSM_SLOT_ID:-0}" 2>/dev/null)" || _cap_ser=""
    [ -n "$_cap_ser" ] || { echo "REFUSING: no readable serial at slot id ${HSM_SLOT_ID:-0} — cannot prove it is a registered staging card." >&2; exit 2; }
    hsm_assert_staging "$_cap_ser" || exit 2
    want="${2:-40}"
    ids="$(perl -e 'alarm 90; exec @ARGV' -- pkcs11-tool --module "$MOD" "${SLOTARG[@]}" --login --pin "$PIN" \
           --list-objects 2>/dev/null \
           | awk '/^Private Key Object/{p=1} p&&/^  ID:/{print $NF; p=0}' \
           | tr -d '()' | sed 's/^0x//' | head -"$want")"
    d=0
    while read -r id; do
        [ -z "$id" ] && continue
        perl -e 'alarm 20; exec @ARGV' -- pkcs11-tool --module "$MOD" "${SLOTARG[@]}" --login --pin "$PIN" \
            --delete-object --type privkey --id "$id" >/dev/null 2>&1 && d=$((d + 1))
    done <<< "$ids"
    printf 'deleted %s key(s)\n' "$d"
fi

n="$(perl -e 'alarm 90; exec @ARGV' -- pkcs11-tool --module "$MOD" "${SLOTARG[@]}" --login --pin "$PIN" \
     --list-objects 2>/dev/null | grep -c 'Key Object')"

# "0 OBJECTS" AND "NO CARD" ARE NOT THE SAME ANSWER.
#
# grep -c returns 0 both when the card genuinely holds no keys and when pkcs11-tool printed nothing
# at all — no reader, card mid-wedge, login refused. MEASURED 2026-08-11: a poll taken while the
# card was wedged reported "objects 0 / 128", which I read as the filesystem having been wiped by
# the recovery ladder. It had not been. After recovery the same card listed 66 objects, PINs intact.
#
# That misreading was one step from a serious and false claim about the device — that automatic
# recovery destroys keys. So prove the card is answering BEFORE trusting a count of zero.
if [ -z "$n" ]; then
    echo "CAPACITY=UNKNOWN — could not list objects (card absent, wrong PIN, or reader busy)" >&2
    exit 2
fi

if [ "$n" = "0" ]; then
    # SETTLE FIRST. pkcs11-tool has just released the reader, and polling sc-hsm-tool immediately
    # races it — the card answers, but this check saw a failure and reported UNKNOWN on a healthy
    # card with a genuinely empty filesystem. A guard that cries wolf gets ignored, which defeats it.
    sleep 5
    # CAPTURE, THEN MATCH — never `producer | grep -q` under pipefail. grep -q exits on the first
    # match, the producer takes SIGPIPE and dies 141, and pipefail reports 141 — so the predicate
    # reads FALSE exactly when the card ANSWERED. Here that would print "the card is not answering
    # at all" about a healthy card and exit 2. Flagged by tools/hsm-lint-predicates.sh.
    _cap_out="$(perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool ${HSM_PCSC_INDEX:+-r "$HSM_PCSC_INDEX"} 2>&1)"
    if ! LC_ALL=C grep -qai '^Version' <<< "$_cap_out"; then
        echo "CAPACITY=UNKNOWN — the card is not answering at all, so a count of 0 means nothing." >&2
        echo "  Do NOT read this as an empty or wiped filesystem. Recover the card and re-check." >&2
        exit 2
    fi
    echo "  (card answers and genuinely lists no key objects)"
fi

free=$(( LIMIT - n ))
printf 'objects %s / %s  (free %s)\n' "$n" "$LIMIT" "$free"

if [ "$free" -lt "$WANT" ]; then
    cat >&2 <<MSG
CAPACITY=EXHAUSTED

  The card has $free object slot(s) free and the caller wants $WANT.

  A write failing here is EXPECTED and says nothing about the firmware. CKR_GENERAL_ERROR from a
  full card is indistinguishable from a real fault by its message alone — do not attribute it to
  code, a patch, or a regression until this reads healthy.

  Free space with:
    ./tools/hsm-capacity-check.sh --free 40
MSG
    exit 1
fi
echo "CAPACITY=OK"
exit 0
