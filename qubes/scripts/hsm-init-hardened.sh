#!/usr/bin/env bash
# hsm-init-hardened.sh — initialise a SmartCard-HSM with PIN-RESET DISABLED, using ONLY the OpenSC
# tools. No Java, no Smart Card Shell. The APDU replacement for hsm-init-hardened.js (regalia#486,
# decided 2026-09-21: the ceremony path drops scsh rather than pinning a JVM on the machine that
# mints keys).
#
# WHY THE POSTURE MATTERS. `sc-hsm-tool --initialize` hardcodes RESET RETRY COUNTER on
# (`param.options[1] = 0x01`, no CLI flag) and so does C_InitToken. On such a card the SO-PIN alone
# sets a user PIN of the attacker's choosing and then uses every key — measured on hardware
# 2026-08-01, doc/drills/2026-08-01-so-pin-reset.md. The options byte has two independent bits that
# the sc-hsm-tool interface hides completely:
#
#   bit 0 (0x01)  RESET RETRY COUNTER enabled at all
#   bit 5 (0x20)  PIN reset DISABLED  (SmartCardHSM.js: isPINResetEnabled() is (options & 0x20)==0)
#
#   --rrc off         options 0x0000 — the ratified D3 posture, and the only one MEASURED to block
#                     the attack. An honest lockout is then unrecoverable: re-provision.
#   --rrc reset-only  options 0x0021 — in spec the SO-PIN may unblock but not re-set the PIN. The
#                     Pico firmware silently drops bit 5 (doc/drills/2026-08-01-rrc-disabled.md), so
#                     there it behaves exactly like RRC-enabled. Never select it for custody until
#                     it has been re-measured on the device in hand.
#
# DESTRUCTIVE: INITIALIZE DEVICE erases every key, certificate and file on the target.
#
#   HSM_SO_PIN=<16 hex digits> HSM_USER_PIN=<pin> \
#     hsm-init-hardened.sh --reader 0 --expect-serial DENK0404144 [--rrc off] [--dkek-shares 1] \
#                          [--retries 3] [--label regalia] [--pka-keys N --pka-required M]
#
# THE PINS NEVER REACH argv. `opensc-tool -s <apdu>` would put the whole INITIALIZE DEVICE command —
# both PINs inside it — in the process table, where any local user reading /proc sees them. The
# APDU goes to opensc-explorer on STDIN instead.
set -uo pipefail

READER="" ; EXPECT_SERIAL="" ; RRC="off" ; DKEK_SHARES=1 ; RETRIES=3 ; LABEL="regalia"
PKA_KEYS=0 ; PKA_REQUIRED=0
AID="E82B0601040181C31F0201"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die(){ printf 'hsm-init-hardened: %s\n' "$*" >&2; exit 2; }
say(){ printf '  %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --reader)        READER="${2:-}"; shift 2;;
    --expect-serial) EXPECT_SERIAL="${2:-}"; shift 2;;
    --rrc)           RRC="${2:-}"; shift 2;;
    --dkek-shares)   DKEK_SHARES="${2:-}"; shift 2;;
    --retries)       RETRIES="${2:-}"; shift 2;;
    --label)         LABEL="${2:-}"; shift 2;;
    --pka-keys)      PKA_KEYS="${2:-}"; shift 2;;
    --pka-required)  PKA_REQUIRED="${2:-}"; shift 2;;
    -h|--help)       sed -n '2,32p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

command -v opensc-explorer >/dev/null || die "opensc-explorer not found (install opensc)"
[ -n "$READER" ] || die "--reader is required: this WIPES the card it reaches, and it may not guess which"
[ -n "${HSM_SO_PIN:-}" ]   || die "HSM_SO_PIN (16 hex digits) is required"
[ -n "${HSM_USER_PIN:-}" ] || die "HSM_USER_PIN is required"
# Here-strings, not `printf … | grep -q`: under pipefail a grep that exits on its first match can
# leave a non-zero pipeline status, and THESE predicates decide whether a PIN is well formed before
# it is written into a card's security state (tools/hsm-lint-predicates.sh flags the shape).
grep -qE '^[0-9A-Fa-f]{16}$' <<< "$HSM_SO_PIN" || die "HSM_SO_PIN must be exactly 16 hex digits (8 bytes)"
grep -qE '^[0-9]{6,16}$' <<< "$HSM_USER_PIN" || die "HSM_USER_PIN must be 6-16 digits"
case "$RRC" in off|reset-only) ;; *) die "--rrc must be 'off' or 'reset-only'";; esac
# EVERY VALUE MUST FIT THE FIELD IT IS ENCODED INTO. `printf '%02X' 256` is "100" — three hex
# digits, an odd-length TLV value, and every byte after it in the APDU shifts by half a byte. The
# card would then be initialised from a command nobody wrote. A label long enough to push Lc past
# 255 breaks the short APDU the same way.
for n in "$DKEK_SHARES" "$RETRIES" "$PKA_KEYS" "$PKA_REQUIRED"; do
  case "$n" in *[!0-9]*|"") die "counts must be whole numbers, got '$n'";; esac
  [ "$n" -le 255 ] || die "$n does not fit in the single byte its TLV encodes (max 255)"
done
[ "$RETRIES" -ge 1 ] || die "--retries must be at least 1; 0 would lock the card on its first wrong PIN"
# BYTES, NOT CHARACTERS. ${#LABEL} counts characters in a UTF-8 locale, so a 200-character label
# can encode to far more than 200 bytes — and then the one-byte TLV length and the short-APDU Lc
# are both wrong, after the card has already been wiped.
_label_bytes="$(LC_ALL=C printf '%s' "$LABEL" | wc -c | tr -d ' ')"
[ "$_label_bytes" -le 200 ] || die "--label encodes to $_label_bytes bytes; keep it under 200 so the TokenInfo write stays a short APDU"

# The published pico-hsm example values must never reach a card that will hold anything. The same
# list is in the JS and in the ceremony; it is repeated because a guard that lives only upstream is
# not a guard for a script that runs on its own.
if [ "${CEREMONY_MODE:-dev}" = "prod" ]; then
  for d in 648219 3537363231383830 CHANGEME TODO FILL_IN; do
    [ "$HSM_SO_PIN" = "$d" ] || [ "$HSM_USER_PIN" = "$d" ] \
      && die "CEREMONY_MODE=prod and a PIN is a published dev default — refusing"
  done
fi

# ---- identity: prove the card before wiping it -----------------------------------------------
# INITIALIZE DEVICE erases every key on whatever card this reaches, so the serial in EF 2F02 is
# checked first. A BLANK card legitimately has no EF 2F02 — and this script is how a blank card
# gets provisioned — so absence falls back to the same contract the JS enforces: the caller must
# supply a board id it has verified out of band, and that id must agree with the expected serial.
devaut_read="${HSM_DEVAUT_READ_SH:-$HERE/hsm-devaut-read.sh}"
if [ -n "$EXPECT_SERIAL" ]; then
  got=""
  if [ -r "$devaut_read" ]; then
    got="$(bash "$devaut_read" --reader "$READER" 2>/dev/null | sed -n 's/^DEVAUT_CHR=//p' | head -1)"
  fi
  if [ -n "$got" ]; then
    case "$got" in
      *"$EXPECT_SERIAL"*) say "identity: EF 2F02 carries $EXPECT_SERIAL (CHR $got)";;
      *) die "REFUSING TO INITIALIZE: reader $READER holds CHR '$got', which does not carry $EXPECT_SERIAL. This is a DIFFERENT CARD.";;
    esac
  else
    # No readable certificate. Blank, or unreadable — and "blank" says nothing about WHICH card.
    [ -n "${HSM_EXPECT_BOARD:-}" ] && [ "${HSM_BOARD_VERIFIED:-}" = "1" ] || die \
      "REFUSING TO INITIALIZE: expected $EXPECT_SERIAL but EF 2F02 is absent, so this card cannot
  identify itself. That is normal for a blank device — identity must then come from the USB/OTP
  board id, which the caller verifies: set HSM_EXPECT_BOARD and HSM_BOARD_VERIFIED=1."
    want="${EXPECT_SERIAL#ESP}"; want="$(printf '%s' "$want" | tr 'a-f' 'A-F')"
    got_suffix="$(printf '%s' "${HSM_EXPECT_BOARD: -${#want}}" | tr 'a-f' 'A-F')"
    [ -n "$want" ] && [ "$got_suffix" = "$want" ] || die \
      "REFUSING TO INITIALIZE: HSM_EXPECT_BOARD ($HSM_EXPECT_BOARD) does not end in the bytes
  $EXPECT_SERIAL is derived from ($want). Both were supplied by the caller and must describe the
  SAME device; disagreeing values mean the board map or the environment is wrong."
    say "identity: EF 2F02 absent (blank device); proceeding on the verified board id $HSM_EXPECT_BOARD"
  fi
fi

# ---- build INITIALIZE DEVICE ------------------------------------------------------------------
# 80 50 00 00 Lc <TLVs>, exactly the structure SmartCardHSMInitializer builds (SmartCardHSM.js
# initialize(): the SEQUENCE's VALUE, not the wrapper):
#   80 02 <options>      81 <user PIN, ASCII>   82 <SO-PIN, 8 bytes>
#   91 01 <retries>      92 01 <DKEK shares>    93 02 <pub keys><required>   (PKA, optional)
case "$RRC" in
  off)        OPTIONS="0000" ;;   # bit 0 clear: RESET RETRY COUNTER disabled entirely
  reset-only) OPTIONS="0021" ;;   # bit 0 set + bit 5 set: RRC reachable, PIN CHANGE forbidden
esac

ascii_hex(){ printf '%s' "$1" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F'; }
tlv(){ printf '%s%02X%s' "$1" "$(( ${#2} / 2 ))" "$2"; }

pin_hex="$(ascii_hex "$HSM_USER_PIN")"
so_hex="$(printf '%s' "$HSM_SO_PIN" | tr 'a-f' 'A-F')"
data="$(tlv 80 "$OPTIONS")"
data="$data$(tlv 81 "$pin_hex")"
data="$data$(tlv 82 "$so_hex")"
data="$data$(tlv 91 "$(printf '%02X' "$RETRIES")")"
data="$data$(tlv 92 "$(printf '%02X' "$DKEK_SHARES")")"
if [ "$PKA_KEYS" -gt 0 ]; then
  [ "$PKA_REQUIRED" -ge 1 ] && [ "$PKA_REQUIRED" -le "$PKA_KEYS" ] \
    || die "--pka-required must be between 1 and --pka-keys"
  data="$data$(tlv 93 "$(printf '%02X%02X' "$PKA_KEYS" "$PKA_REQUIRED")")"
fi
apdu="805000$(printf '00%02X' "$(( ${#data} / 2 ))")$data"

say "options: mode=$RRC — options=0x$OPTIONS, dkek-shares=$DKEK_SHARES, retries=$RETRIES"
say "initializing (this ERASES the card)"

# ---- label (EF 2F03 TokenInfo), built now because it travels in the SAME session ---------------
# 00 D7 2F 03, data = 54 02 0000 || 53 <len> <TokenInfo>, the shape the scsh initializer writes.
#
# IT MUST BE THE SAME SESSION AS THE INITIALIZE. Sent from a second opensc-explorer run the write
# answers 6982 (security condition not satisfied) — measured on DENK0404144 — because the card is
# no longer in the state INITIALIZE DEVICE left it in. The label is what `pkcs11-tool -L` shows and
# what the drills match on, so losing it is not cosmetic for the tooling that reads it.
label_hex="$(ascii_hex "$LABEL")"
seq_body="020100$(tlv 80 "$label_hex")03020500"
labeldata="54020000$(tlv 53 "$(tlv 30 "$seq_body")")"
lapdu="00D72F03$(printf '%02X' "$(( ${#labeldata} / 2 ))")$labeldata"

# STDIN, NOT argv (see the header). opensc-explorer reads its commands from stdin, so the APDUs —
# which contain both PINs — never appear in the process table.
send_init(){
  # `env -u`: the PINs are already inside the APDU on stdin, so the child has no use for them —
  # and a child that inherits them can leak them through its own /proc/<pid>/environ, a core dump
  # or a crash reporter. The variables are removed for the whole exec chain (perl included).
  printf 'apdu 00A4040C0B%s\napdu %s\napdu %s\nquit\n' "$AID" "$apdu" "$lapdu" \
    | env -u HSM_SO_PIN -u HSM_USER_PIN perl -e 'alarm 120; exec @ARGV' -- \
        opensc-explorer -r "$READER" 2>&1
}
sws(){ sed -n 's/.*SW1=0x\([0-9A-Fa-f]*\), SW2=0x\([0-9A-Fa-f]*\).*/\1\2/p' <<< "$1" \
       | tr 'a-f' 'A-F'; }
out="$(send_init)" || true
# Three answers, in order: SELECT, INITIALIZE DEVICE, the label write.
sw="$(sws "$out" | sed -n '2p')"
lsw="$(sws "$out" | sed -n '3p')"

# A card that drops off the bus mid-command reports nothing, and that is NOT failure: INITIALIZE
# DEVICE re-enumerates a Pico HSM. The status is therefore not the verdict — the posture read back
# below is, and the behavioural check the footer prints is what actually settles it.
case "$sw" in
  9000) say "INITIALIZE DEVICE: 9000" ;;
  6A84) # JCOP garbage collection: the first call can run out of memory, the second succeeds.
        say "INITIALIZE DEVICE returned 6A84 (JCRE memory) — retrying once, as the scsh initializer does"
        out="$(send_init)" || true
        sw="$(sws "$out" | sed -n '2p')"; lsw="$(sws "$out" | sed -n '3p')"
        say "INITIALIZE DEVICE (retry): ${sw:-no answer}" ;;
  "")   say "no status word came back — expected if the card left the bus mid-command; verifying by behaviour" ;;
  *)    printf '%s\n' "$out" | tail -5 >&2
        die "INITIALIZE DEVICE answered SW=$sw — the card was NOT initialised" ;;
esac

case "$(printf '%s' "${lsw:-}" | tr 'a-f' 'A-F')" in
  9000) say "label: '$LABEL' written to EF 2F03" ;;
  # A KNOWN ERROR IS NOT COSMETIC. The label is what `pkcs11-tool -L` shows and what the drills and
  # the restore match on, so a card that answered 6982 and a script that says "complete" disagree
  # about what is on the device. The init itself succeeded, so this says exactly that rather than
  # implying the card is unusable.
  "")   say "label: no answer — expected if the card left the bus; the label is UNVERIFIED, re-read"
        say "       it with \`pkcs11-tool -L\` before recording this card as provisioned" ;;
  *)    die "INITIALIZE DEVICE succeeded but the label write to EF 2F03 answered $lsw, so this card
  does NOT carry the label '$LABEL'. The posture is set; re-run to write the label, or record the
  card with the label it actually has." ;;
esac

printf '\n'
say "*** INIT COMPLETE — BUT NOT VERIFIED ***"
say "An options readout is NOT evidence: it has been measured contradicting the card's behaviour"
say "(isResetRetryCounterEnabled() lies on the Pico, doc/drills/2026-08-01-rrc-disabled.md)."
say "Verify BEHAVIOURALLY before custody:"
say "  pkcs11-tool --login --login-type so --so-pin <SO> --init-pin --new-pin 999999"
say "    -> must FAIL with CKR_GENERAL_ERROR (the SO-PIN reset attack is refused)"
say "  pkcs11-tool --login --pin 999999 --list-objects   -> must be REFUSED"
say "  pkcs11-tool --login --pin <original user PIN> --list-objects  -> must WORK"
