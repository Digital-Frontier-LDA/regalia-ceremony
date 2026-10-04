# shellcheck shell=bash
# shellcheck disable=SC2034  # SLOT_ID, READER, DEVOUT, CARD_DKEK and CARD_KCV are set for the script that sources this
# hsm-card.sh — sourced, not run: finding ONE SmartCard-HSM by its serial, the reader that holds it, and its
# DKEK state, for the scripts that act on one card at a time (hsm-signing-key.sh, hsm-domain.sh).
#
# ONE DEFINITION. Each rule here decides which card a destructive step reaches, or which DKEK domain a card
# is in; a drifted second copy would let one script address a card the other refuses. The caller defines
# die() and sets MODULE (the PKCS#11 module), DEVAUT_SH (hsm-devaut-read.sh) and SERIAL before calling.

# The one token attached, by serial: sets SLOT_ID. Refused unless exactly one token is attached and it is
# SERIAL: sc-hsm-tool and pkcs11-tool address a card without asking which, so a second card on the table is
# a card a mistake can reach.
hsm_only_token(){
  local slots line cur="" s n=0 total=0
  slots="$(timeout 60 pkcs11-tool --module "$MODULE" --list-token-slots 2>/dev/null)" || die "cannot list the PKCS#11 token slots of $MODULE"
  SLOT_ID=""
  while IFS= read -r line; do
    case "$line" in
      "Slot "*"(0x"*")"*) cur="${line#*(}"; cur="${cur%%)*}";;
      *"serial num"*:*)
        total=$((total + 1))
        s="${line#*:}"; s="$(printf '%s' "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        if [ -n "$cur" ] && [ "$s" = "$SERIAL" ]; then SLOT_ID="$cur"; n=$((n + 1)); fi
        cur="";;
    esac
  done <<< "$slots"
  [ "$n" -eq 1 ] || die "serial $SERIAL matches $n tokens — attach exactly that card"
  [ "$total" -eq 1 ] || die "$total tokens are attached; attach ONLY card $SERIAL (one card on the table is one card a mistake can reach)"
}

# The reader that holds THIS card: the readers in order, the first whose card reports serial $SERIAL
# (opensc-tool numbers readers, and a laptop's own empty reader may be number 0). Sets READER and DEVOUT.
find_reader(){
  local r out
  READER="" DEVOUT=""
  for r in $(timeout 30 opensc-tool --list-readers 2>/dev/null | sed -n 's/^[[:space:]]*\([0-9][0-9]*\)[[:space:]].*/\1/p'); do
    if out="$(timeout 60 bash "$DEVAUT_SH" --reader "$r" --expect-serial "$SERIAL" 2>/dev/null)" && grep -q '^DEVAUT_HEX=' <<< "$out"; then
      READER="$r"; DEVOUT="$out"; return 0
    fi
  done
  die "no reader holds card $SERIAL with a readable device certificate (EF 2F02)"
}

# The card's DKEK state, from sc-hsm-tool's status (no PIN), on the reader find_reader set. Sets CARD_DKEK to
# "none" (no DKEK shares configured), "pending" (shares still missing) or "complete", and CARD_KCV to the key
# check value (sixteen upper-case hex digits) when complete. sc-hsm-tool prints "DKEK key check value : <16 hex>"
# only once every share is in; while an import is pending it prints the shares still missing instead. A status
# that says complete without exactly one well-formed key check value is refused, not read as some state.
hsm_dkek_state(){
  local status
  status="$(timeout 60 sc-hsm-tool --reader "$READER" </dev/null 2>&1)" || die "sc-hsm-tool could not read card $SERIAL's status"
  CARD_KCV="$(sed -n 's/^DKEK key check value[[:space:]]*:[[:space:]]*\([0-9A-Fa-f]\{16\}\)[[:space:]]*$/\1/p' <<< "$status" | tr 'a-f' 'A-F')"
  if grep -q '^DKEK import pending' <<< "$status"; then
    CARD_DKEK=pending; CARD_KCV=""
  elif [ "$(grep -c '^DKEK key check value' <<< "$status")" -eq 1 ] && [ -n "$CARD_KCV" ]; then
    CARD_DKEK=complete
  elif grep -qi 'dkek' <<< "$status"; then
    die "card $SERIAL's DKEK status is not one this script reads: $(grep -i dkek <<< "$status" | tr '\n' ' ')"
  else
    CARD_DKEK=none; CARD_KCV=""
  fi
}
