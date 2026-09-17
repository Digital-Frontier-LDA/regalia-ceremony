#!/usr/bin/env bash
# test-hsm-scenarios-targeting.sh — tools/hsm-scenarios.sh runs `sc-hsm-tool --initialize`, so which
# card it resolved is a safety property, not a convenience.
#
# WHY THIS EXISTS. Its own header says "an ordering flip pointed at reader 0 is a wipe of the wrong
# device", and then the untargeted fallback did exactly that: with HSM_TARGET_SERIAL unset, READER
# defaulted to 0 — "whichever board enumerated first" — and wipe_and_provision initialised it.
# MEASURED 2026-09-11, reader 0 was ESP41D722E2, the card this bench is NOT pinned to. The promise
# the fallback exists to keep is "single-card hosts are unchanged", so the refusal must fire ONLY
# when a second card makes the default ambiguous. Both halves of that are asserted here.
#
# No hardware: opensc-tool and pkcs15-tool are stubbed on PATH.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
UNDER_TEST="$REPO/tools/hsm-scenarios.sh"
[ -f "$UNDER_TEST" ] || { echo "missing $UNDER_TEST" >&2; exit 1; }

pass=0; fail=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT
cat > "$BIN/opensc-tool" <<'EOF'
#!/usr/bin/env bash
printf '# Detected readers (pcsc)\n'
printf 'Nr.  Card  Features  Name\n'
i=0
for n in ${FAKE_NAMES:-}; do printf '%-3s  %-4s  %-8s  %s\n' "$i" "Yes" "" "${n//_/ }"; i=$((i+1)); done
EOF
cat > "$BIN/pkcs15-tool" <<'EOF'
#!/usr/bin/env bash
idx=""; while [ $# -gt 0 ]; do case "$1" in -r) idx="$2"; shift 2;; *) shift;; esac; done
var="FAKE_SERIAL_${idx}"; val="${!var-}"
[ -n "$val" ] || exit 0
printf 'PKCS#15 Card [Pico-HSM]:\n\tSerial number  : %s\n' "$val"
EOF
# --initialize must never be reached in these runs. If it is, that is the defect, so record it.
cat > "$BIN/sc-hsm-tool" <<'EOF'
#!/usr/bin/env bash
case "$*" in *--initialize*) printf 'REACHED-INITIALIZE %s\n' "$*" >> "${FAKE_WIPE_LOG:-/dev/null}";; esac
printf 'Version              : 4.1\n'
EOF
# Emit a slot per faked card, with the NON-CONTIGUOUS ids the real bench has (0x0 and 0x4), so the
# resolver is exercised against an id that is not its ordinal. Emitting only one slot made the
# two-card targeting case unresolvable and accused the script of a defect that was in this fake.
cat > "$BIN/pkcs11-tool" <<'EOF'
#!/usr/bin/env bash
case "$*" in *--list-token-slots*)
  printf 'Available slots:\n'
  [ -n "${FAKE_SERIAL_0:-}" ] && printf 'Slot 0 (0x0): Reader 0\n  token label        : staging\n  serial num         : %s\n' "$FAKE_SERIAL_0"
  [ -n "${FAKE_SERIAL_1:-}" ] && printf 'Slot 1 (0x4): Reader 1\n  token label        : staging\n  serial num         : %s\n' "$FAKE_SERIAL_1"
  ;;
esac
EOF
chmod +x "$BIN"/*
export PATH="$BIN:$PATH"

TWO='Pico_Key_CCID_Interface_01 Pico_Key_CCID_Interface'
ONE='Pico_Key_CCID_Interface'

run(){ OUT="$(env "$@" perl -e 'alarm 60; exec @ARGV' -- bash "$UNDER_TEST" S1 2>&1)"; RC=$?; }

printf '\n\033[1m### two cards and no named target: a wipe must be refused, not aimed at reader 0\033[0m\n'
WIPE="$(mktemp)"
run FAKE_NAMES="$TWO" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A FAKE_WIPE_LOG="$WIPE" HSM_TARGET_SERIAL=
if [ "$RC" = 2 ]; then ok "it exits 2"; else no "it exits 2 (got $RC)"; fi
case "$OUT" in *"no card was named"*) ok "the refusal says no card was named" ;; *) no "the refusal does not explain itself: ${OUT:0:120}" ;; esac
case "$OUT" in *"reader 0 is whichever board enumerated first"*) ok "…and names why reader 0 is not an identity" ;; *) no "…but does not say why reader 0 is wrong" ;; esac
if [ -s "$WIPE" ]; then no "NO --initialize may be issued: $(head -1 "$WIPE")"; else ok "no --initialize was issued"; fi
rm -f "$WIPE"

printf '\n\033[1m### the promise the fallback exists to keep: one card, unchanged\033[0m\n'
run FAKE_NAMES="$ONE" FAKE_SERIAL_0=ESP2202E14A HSM_TARGET_SERIAL=
case "$OUT" in *"no card was named"*) no "a single-card host must NOT be refused" ;; *) ok "a single-card host is not refused" ;; esac

printf '\n\033[1m### two cards WITH a named target: resolved by serial, not refused\033[0m\n'
run FAKE_NAMES="$TWO" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A HSM_TARGET_SERIAL=ESP2202E14A
case "$OUT" in *"no card was named"*) no "a named target must not be refused" ;; *) ok "a named target is not refused" ;; esac
case "$OUT" in *"targeting card ESP2202E14A"*"reader 1"*) ok "and it targets reader 1, where that serial is" ;; *) no "it did not report targeting reader 1: ${OUT:0:140}" ;; esac

printf '\n\033[1m### an already-resolved index from a parent is still honoured\033[0m\n'
run FAKE_NAMES="$TWO" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A HSM_TARGET_SERIAL= HSM_PCSC_INDEX=1
case "$OUT" in *"no card was named"*) no "an explicit HSM_PCSC_INDEX must not be refused" ;; *) ok "an explicit HSM_PCSC_INDEX is honoured" ;; esac

printf '\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
