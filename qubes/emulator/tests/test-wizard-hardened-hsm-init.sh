#!/usr/bin/env bash
# test-wizard-hardened-hsm-init.sh — the wizard initialises a real HSM HARDENED (ADR-0002 D15):
# hsm-init-hardened.sh --rrc off --retries 10 on the card it has identified as a Nitrokey, with the
# PINs from step 0 in the environment and never on argv. It refuses an unidentified card, a Pico, a
# missing step 0 and a missing reader; under the emulator (CEREMONY_SIMULATE=1) the modelled
# `sc-hsm-tool --initialize` runs, byte-identical to what the step always ran.
# hsm-devaut-read.sh and hsm-init-hardened.sh are stubbed; they record what they receive.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cat > "$T/hsm-devaut-read.sh" <<'SH'
#!/usr/bin/env bash
echo "devaut $*" >> "$REC"; [ -n "${STUB_CHR:-}" ] && echo "DEVAUT_CHR=$STUB_CHR"; exit 0
SH
cat > "$T/hsm-init-hardened.sh" <<'SH'
#!/usr/bin/env bash
{ echo "init-argv $*"; echo "init-env-so ${HSM_SO_PIN:-<unset>}"; echo "init-env-user ${HSM_USER_PIN:-<unset>}"; } >> "$REC"; exit "${STUB_RC:-0}"
SH
chmod +x "$T"/*.sh
USER_A=4172935068 SO_A=9F3C2A7710B4E6D5
# drive <answer to the ERASE question> <reader> [simulate]: prints the transcript, then RC=
drive(){ ( source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1
  HERE="$T"; export REC="$T/rec"
  ask(){ [ "$ANSWER" = y ]; }; pause(){ :; }
  run(){ echo "RUN: $*"; }
  # shellcheck disable=SC2034  # these are read by the sourced init_hsm
  if [ "${3:-}" = sim ]; then CEREMONY_SIMULATE=1; else unset CEREMONY_SIMULATE; fi
  # shellcheck disable=SC2034
  [ "${NO_STEP0:-}" = 1 ] || { state_step0_done=1; hsm_a_user_pin=$USER_A; hsm_a_so_pin=$SO_A; }
  ANSWER="$1" init_hsm "the funding HSM (A)" "$2" hsm_a_user_pin hsm_a_so_pin "" 0; echo "RC=$?" ) 2>&1 | sed $'s/\033\\[[0-9;]*m//g'; }

hdr "a Nitrokey on reader 2: hardened init with --rrc off --retries 10, PINs in the environment only"
: > "$T/rec"; out="$(STUB_CHR=DENK040414400000 drive y 2)"
grep -q "RC=0" <<< "$out" && P "succeeds" || F "failed: $out"
grep -qx "init-argv --reader 2 --expect-serial DENK0404144 --rrc off --retries 10 --dkek-shares 1 --label akash-funding" "$T/rec" && P "exact arguments" || F "arguments: $(grep init-argv "$T/rec")"
grep -qx "init-env-so $SO_A" "$T/rec" && grep -qx "init-env-user $USER_A" "$T/rec" && P "both PINs reach it through the environment" || F "PINs not in the environment"
grep "init-argv" "$T/rec" | grep -qE "$USER_A|$SO_A" && F "a PIN is on argv" || P "no PIN on argv"
grep -qE "$USER_A|$SO_A" <<< "$out" && F "a PIN was printed" || P "no PIN printed"
grep -q "reader 2 holds DENK0404144" <<< "$out" && P "names the card before erasing it" || F "card not named"

hdr "no reader given: card A defaults to reader 0, as the import step does"
: > "$T/rec"; STUB_CHR=DENK040414400000 drive y "" >/dev/null
grep -q "init-argv --reader 0 " "$T/rec" && P "reader 0" || F "default reader: $(cat "$T/rec")"

hdr "the operator declines: nothing is erased"
: > "$T/rec"; out="$(STUB_CHR=DENK040414400000 drive n 1)"
grep -q "RC=100" <<< "$out" && ! grep -q init-argv "$T/rec" && P "skipped, not called" || F "declined but: $out"

hdr "refusals: nothing erased"
: > "$T/rec"; out="$(STUB_CHR="" drive y 1)"
grep -q "RC=1" <<< "$out" && grep -q "does not identify as a Nitrokey" <<< "$out" && ! grep -q init-argv "$T/rec" && P "unidentified card refused" || F "unidentified: $out"
: > "$T/rec"; out="$(STUB_CHR=ESPICOHSMTR0000 drive y 1)"
grep -q "RC=1" <<< "$out" && ! grep -q init-argv "$T/rec" && P "a Pico refused (never holds a real key)" || F "Pico: $out"
: > "$T/rec"; out="$(STUB_CHR=DENK040414400000 NO_STEP0=1 drive y 1)"
grep -q "RC=1" <<< "$out" && grep -q "run step 0 first" <<< "$out" && ! grep -q init-argv "$T/rec" && P "no step 0: refused" || F "no step 0: $out"
: > "$T/rec"; out="$(STUB_CHR=DENK040414400000 drive y 'x;rm')"
grep -q "RC=1" <<< "$out" && grep -q "no PC/SC reader index" <<< "$out" && ! grep -q init-argv "$T/rec" && P "a non-numeric reader refused" || F "reader: $out"
: > "$T/rec"; out="$(STUB_CHR=DENK040414400000 STUB_RC=3 drive y 1)"
grep -q "RC=3" <<< "$out" && P "the init script's failure is returned" || F "failure swallowed: $out"

hdr "emulator: the modelled command, byte-identical to before"
out="$(drive y "" sim)"
grep -qx "RUN: sc-hsm-tool --initialize --dkek-shares 1 --label 'akash-funding'" <<< "$out" && P "card A: unchanged command" || F "sim A: $(grep RUN <<< "$out")"
out="$( ( source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1; run(){ echo "RUN: $*"; }; CEREMONY_SIMULATE=1 init_hsm B 3 x y "EMU_SCHSM_STATE=/s" ) 2>&1)"
grep -qx "RUN: EMU_SCHSM_STATE=/s sc-hsm-tool --reader 3 --initialize --dkek-shares 1 --label 'akash-funding'" <<< "$out" && P "card B: unchanged command" || F "sim B: $out"

hdr "the wizard calls it for both cards, and no bare --initialize is left"
grep -q 'init_hsm "the funding HSM (A)"' "$SCRIPTS/ceremony.sh" && grep -q 'init_hsm "the SECOND HSM (B)"' "$SCRIPTS/ceremony.sh" && P "both call sites" || F "a call site is missing"
[ "$(grep -v '^\s*#' "$SCRIPTS/ceremony.sh" | grep -c 'sc-hsm-tool.*--initialize')" = 1 ] && P "the only --initialize left is the emulator branch" || F "a bare --initialize remains"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
