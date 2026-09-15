#!/usr/bin/env bash
# test-chipcard-step.sh — adversarial tests for ceremony.sh step_chipcard, which writes a
# SLIP-39 share to an SLE-4442 memory card.
#
# THE IRREVERSIBLE RISK: the SLE-4442 PSC error counter allows THREE wrong attempts and then
# the card is permanently locked — no unblock path exists, unlike the HSM's SO-PIN or the
# YubiKey's PUK. A write spends an attempt when the PSC is wrong, so a step that writes first
# and checks later can destroy a card (and any share already on it) with one slip. The gate
# must therefore refuse to write at 0 or 1 attempts left, refuse a payload that cannot fit the
# card's 256 bytes, and never put the share on the terminal.
#
# Runs natively with a stubbed sle4442-manager modelling the counter, capacity and read-back.
set -uo pipefail
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
CARD="$(mktemp -d)"; export CARD
trap 'rm -rf "$FAKE" "$CARD" "${WORK:-}"' EXIT

# Stubbed sle4442-manager: models the PSC attempt counter, the 256-byte capacity, and the
# verify-read-back that the real tool performs internally.
cat > "$FAKE/sle4442-manager" <<'STUB'
#!/usr/bin/env bash
C="${CARD:?}"
att="${STUB_ATTEMPTS:-3}"
case "${1:-}" in
  info)
    if [ "${STUB_INFO_FAIL:-0}" = 1 ]; then echo "cannot connect to reader" >&2; exit 1; fi
    echo "card: SLE4442 (emulated or real)"
    echo "  error counter   : 0x07  ($att PSC attempts left)"
    echo "  memory          : 256 bytes (contents not shown; use \`read\` to display)"
    exit 0;;
  store)
    tf=""; prev=""
    for a in "$@"; do [ "$prev" = "--text-file" ] && tf="$a"; prev="$a"; done
    [ -s "$tf" ] || { echo "no text file" >&2; exit 1; }
    n=$(wc -c < "$tf" | tr -d ' ')
    [ "$n" -le 256 ] || { echo "payload too large for the card at that address" >&2; exit 1; }
    if [ "${STUB_STORE_FAIL:-0}" = 1 ]; then echo "verify-read mismatch after store" >&2; exit 1; fi
    cp "$tf" "$C/stored"
    echo "stored and verified $n bytes at 0"
    exit 0;;
  read) echo "THE-CARD-WOULD-PRINT-THE-SHARE-HERE"; exit 0;;
esac
exit 0
STUB
chmod +x "$FAKE/sle4442-manager"

# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
pause(){ :; }
# shellcheck disable=SC2034
PRINTER=""
init_work
# Silence the wizard's command echo. Unlike the abort suites, nothing here inspects WHAT was
# shown, so capturing it into LAST_SHOWN was dead weight (0 reads) — dropped.
show(){ :; }
ask(){ return 0; }

SHARE="$WORK/w1"
mk_share(){ printf 'tuna acid academic academic advance broken carbon chubby cinema civil clay column' > "$SHARE"; }
mk_psc(){ printf 'A1B2C3' > "$WORK/sle4442.psc"; chmod 600 "$WORK/sle4442.psc"; }
reset(){ rm -f "$CARD/stored"; mk_share; mk_psc; }

# =====================================================================================
hdr "HAPPY PATH: a share that fits is stored and verify-read by the card"
reset
out="$(step_chipcard "$SHARE" 2>&1)"
[ -s "$CARD/stored" ] && P "share written to the card" || F "nothing was written"
cmp -s "$SHARE" "$CARD/stored" && P "stored bytes match the share exactly" || F "card holds different bytes"
grep -qi "verify-read back" <<< "$out" && P "step reports the read-back verification" \
                                          || F "step did not mention read-back verification"

# =====================================================================================
hdr "NEAR-LOCK GATE: refuse to write with ONE PSC attempt left (a slip destroys the card)"
reset
out="$(STUB_ATTEMPTS=1 step_chipcard "$SHARE" 2>&1)"
[ ! -s "$CARD/stored" ] && P "no write attempted at 1 attempt remaining" \
                        || F "BUG: wrote to a card one wrong PSC from permanent destruction"
grep -qi "only ONE PSC attempt left" <<< "$out" && P "explains the one-attempt risk" \
                                                   || F "did not warn about the single remaining attempt"

# =====================================================================================
hdr "LOCKED CARD: refuse a card with zero attempts left"
reset
out="$(STUB_ATTEMPTS=0 step_chipcard "$SHARE" 2>&1)"
[ ! -s "$CARD/stored" ] && P "no write attempted on a locked card" || F "BUG: wrote to a locked card"
grep -qi "LOCKED" <<< "$out" && P "reports the card as locked" || F "did not report the locked card"

# =====================================================================================
hdr "TWO ATTEMPTS: warn but allow (still recoverable from one mistake)"
reset
out="$(STUB_ATTEMPTS=2 step_chipcard "$SHARE" 2>&1)"
[ -s "$CARD/stored" ] && P "allows the write at 2 attempts left" || F "over-refused a usable card"
grep -qi "only 2 PSC attempts left" <<< "$out" && P "warns at 2 attempts" || F "no warning at 2 attempts"

# =====================================================================================
hdr "CAPACITY: refuse anything larger than the card's 256 bytes"
reset
big="$WORK/payload.age"; head -c 1400 /dev/urandom | base64 | head -c 1400 > "$big"
out="$(step_chipcard "$big" 2>&1)"
[ ! -s "$CARD/stored" ] && P "refused a payload that cannot fit" || F "BUG: attempted to store an oversized payload"
grep -qi "an SLE-4442 holds 256" <<< "$(echo "$out")" \
  && P "explains the 256-byte limit and points the payload elsewhere" \
  || F "did not explain the capacity limit"

# =====================================================================================
hdr "UNREADABLE CARD: fail closed rather than writing blind"
reset
out="$(STUB_INFO_FAIL=1 step_chipcard "$SHARE" 2>&1)"
[ ! -s "$CARD/stored" ] && P "no write when the card cannot be read at all" \
                        || F "BUG: wrote to a card whose state could not be determined"

# =====================================================================================
hdr "STORE FAILURE: a card that does not persist must be reported, not assumed good"
reset
out="$(STUB_STORE_FAIL=1 step_chipcard "$SHARE" 2>&1)"
grep -qi "store failed" <<< "$(echo "$out")" \
  && P "reports a failed store instead of claiming success" \
  || F "BUG: a failed store was not surfaced"
grep -qi "attempts has been spent" <<< "$(echo "$out")" \
  && P "tells the operator a PSC attempt may have been consumed" \
  || F "did not mention the spent attempt after a failure"

# =====================================================================================
hdr "The share NEVER reaches the terminal"
reset
out="$(step_chipcard "$SHARE" 2>&1)"
grep -qF "tuna acid academic" <<< "$out" && F "LEAKED the share to the terminal" \
                                            || P "share words never printed"
grep -qF "THE-CARD-WOULD-PRINT-THE-SHARE-HERE" <<< "$(echo "$out")" \
  && F "BUG: step used 'sle4442-manager read', which prints the stored share" \
  || P "step never calls the read subcommand (which would echo the share)"
grep -qi "Do NOT run 'sle4442-manager read'" <<< "$(echo "$out")" \
  && P "warns the operator not to 'verify' by reading the card back" \
  || F "no warning against reading the card back to check"

# =====================================================================================
hdr "MISSING SHARE FILE: refuse rather than storing nothing"
reset
out="$(step_chipcard "$WORK/does-not-exist" 2>&1)"
[ ! -s "$CARD/stored" ] && P "refused a missing share file" || F "BUG: wrote something for a missing file"

# =====================================================================================
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
