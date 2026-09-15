#!/usr/bin/env bash
# test-go-nogo-sle4442-counter.sh — the go/no-go gate must catch an SLE-4442 that is one (or
# zero) wrong-PSC attempts away from PERMANENT lockout BEFORE any key-touching step, exactly
# like it already does for a YubiKey one wrong PIN from PUK lockout. A near-locked memory card
# passes the SELECT capability probe but bricks the instant the operator mistypes the PSC while
# storing a share — so the gate must READ SECURITY MEMORY (FF B1) and STOP on a low counter.
#
# Runs natively, no daemons: `timeout` and `opensc-tool` are stubbed on PATH so the SLE-4442
# security-memory read returns a configurable error counter. We assert on the SLE-4442 section
# only (preflight noise on a non-vault host is irrelevant to these checks).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GN="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/go-nogo.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

FAKE="$(mktemp -d)"
cleanup(){ rm -rf "$FAKE"; }
trap cleanup EXIT
export PATH="$FAKE:$PATH"

# `timeout <secs> cmd …` -> just run cmd (macOS/native host has no coreutils timeout).
cat > "$FAKE/timeout" <<'EOS'
#!/usr/bin/env bash
shift
exec "$@"
EOS
# opensc-tool stub: answers --atr, the SLE-4442 SELECT, and the FF B1 security-memory read.
# The error-counter byte is taken from $STUB_CTR (hex), matching the emulator model's
# `FF B1 00 00 04` -> <errctr> FF FF FF response.
#
# The FF B1 data line is emitted in the REAL opensc-tool shape: response bytes are rendered
# through util_hex_dump_asc, which prints the hex bytes followed by an ASCII sidebar column
# ('07 FF FF FF ....'). The gate's counter parse must tolerate that trailing ASCII column;
# a stub that only echoed the bare hex would not regression-guard the real hardware output.
#
# $STUB_STRICT_SESSION=1 models a REAL synchronous-memory reader (Identiv/SCM) whose FF B1
# security-memory read only succeeds when the FF A4 SELECT_CARD_TYPE precedes it IN THE SAME
# reader session (same opensc-tool invocation). A bare FF B1 session (no select) returns no
# parsable counter line, exactly as such hardware does — unlike the vpicc emulator, which
# answers FF B1 unconditionally. This is what makes the two-invocation guard degrade to WARN
# on real hardware while looking healthy under the emulator.
cat > "$FAKE/opensc-tool" <<'EOS'
#!/usr/bin/env bash
case "$*" in
  *--atr*)  echo "3B0492231091"; exit 0;;
esac
# FF B1 present in this invocation?
case "$*" in
  *FF:B1:*)
    # Strict reader: B1 needs the A4 select in the SAME session (invocation).
    if [ -n "${STUB_STRICT_SESSION:-}" ]; then
      case "$*" in
        *FF:A4:*)
          echo "Sending: FF A4 00 00 01 06"; echo "Received (SW1=0x90, SW2=0x00)"
          echo "Sending: FF B1 00 00 04"; echo "Received (SW1=0x90, SW2=0x00):"; echo "${STUB_CTR:-07} FF FF FF ...."; exit 0;;
        *)
          # No select in this session -> real reader cannot read security memory.
          echo "Sending: FF B1 00 00 04"; echo "Received (SW1=0x6F, SW2=0x00)"; exit 0;;
      esac
    fi
    # Lenient reader/emulator: answers B1 regardless of a preceding select.
    case "$*" in *FF:A4:*) echo "Sending: FF A4 00 00 01 06"; echo "Received (SW1=0x90, SW2=0x00)";; esac
    echo "Sending: FF B1 00 00 04"; echo "Received (SW1=0x90, SW2=0x00):"; echo "${STUB_CTR:-07} FF FF FF ...."; exit 0;;
  *FF:A4:*) echo "Sending: FF A4 00 00 01 06"; echo "Received (SW1=0x90, SW2=0x00)"; exit 0;;
esac
exit 0
EOS
chmod +x "$FAKE/timeout" "$FAKE/opensc-tool"

run(){ STUB_CTR="$1" "$GN" --need sle4442 2>&1 || true; }
run_strict(){ STUB_STRICT_SESSION=1 STUB_CTR="$1" "$GN" --need sle4442 2>&1 || true; }

hdr "counter = 0x01 (one PSC attempt left) -> STOP (near lockout, would brick on one slip)"
out="$(run 01)"
grep -qiE 'SLE-4442 .*attempts left = 1|one wrong PSC permanently locks' <<< "$out" \
  && P "STOPs on 1 attempt left (one wrong PSC bricks the card during the store)" \
  || { F "no STOP for a near-locked SLE-4442 (1 attempt left) — false GO possible"; echo "$out" | sed 's/^/      /'; }

hdr "counter = 0x00 (card already locked) -> STOP (cannot store a share at all)"
out="$(run 00)"
grep -qiE 'SLE-4442 .*attempts left = 0|is LOCKED' <<< "$out" \
  && P "STOPs on a card that is already locked" \
  || F "no STOP for an already-locked SLE-4442"

hdr "counter = 0x07 (3 attempts, healthy) -> reports OK, no lockout STOP"
out="$(run 07)"
grep -qiE 'SLE-4442 .*attempts left = 3' <<< "$(echo "$out")" \
  && P "reports 3 attempts left on a healthy card" \
  || F "did not read/report the healthy SLE-4442 error counter"
grep -qiE 'attempts left = 1|attempts left = 0|permanently locks' <<< "$out" \
  && F "wrongly flagged a healthy card as near lockout" \
  || P "no false lockout STOP on a healthy card"

hdr "REAL per-session reader: counter = 0x01 -> must still STOP (select+B1 in ONE session)"
# A real synchronous-memory reader reads security memory only when the SELECT_CARD_TYPE and
# the FF B1 read share one reader session. If the gate reads FF B1 in a session of its own
# (a separate opensc-tool invocation, no preceding select), the counter comes back unparsable
# and the near-lock STOP silently degrades to the manual-confirm WARN -> a 1-attempt card is
# NOT auto-rejected. The gate must issue the select and the B1 read in the same invocation.
out="$(run_strict 01)"
grep -qiE 'SLE-4442 .*attempts left = 1|one wrong PSC permanently locks' <<< "$out" \
  && P "STOPs on 1 attempt left even on a per-session reader (select+B1 in one session)" \
  || { F "near-lock STOP degraded to WARN on a real per-session reader (1-attempt card not auto-rejected)"; echo "$out" | sed 's/^/      /'; }

hdr "REAL per-session reader: counter = 0x00 -> must still STOP (already locked)"
out="$(run_strict 00)"
grep -qiE 'SLE-4442 .*attempts left = 0|is LOCKED' <<< "$out" \
  && P "STOPs on an already-locked card on a per-session reader" \
  || { F "already-locked STOP degraded to WARN on a real per-session reader"; echo "$out" | sed 's/^/      /'; }

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
