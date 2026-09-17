#!/usr/bin/env bash
# test-hsm-swd-role-gate.sh — the three SWD flash tools must prove WHICH board they reach, and
# that it is registered staging, BEFORE anything is programmed.
#
# WHY THIS EXISTS. tools/hsm-usb-delay-sweep.sh, tools/hsm-verify-lastbase.sh and
# tools/hsm-verify-scan-guard.sh rewrote flash on whatever board the DEFAULT OpenOCD probe found:
# no --probe, no OTP read-back, no role check. Every PC/SC-path tool had spent a year learning to
# resolve by identity; the flash path had none at all. With a second board on the bench — or the
# day a production card is attached — that is a destructive step aimed by accident of probe order.
#
# The gate under test is the pair wired into all three tools as MANDATORY flags:
#   hsm_verify_board_over_probe  (--probe/--expect-board: RP2350 OTP read-back)
#   hsm_assert_staging_board     (HSM_BOARD_MAP reverse lookup -> the committed role registry)
#
# No hardware: openocd is stubbed, and its invocation LOG is the proof. A refusal is only proven
# by the absence of any program/dump/erase command in that log — an exit code alone could be any
# failure, and a refusal that still flashed is not a refusal.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
TOOLS="$REPO/tools"
pass=0; fail=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT
# The stub is deliberately NOT named "openocd": hsm-usb-delay-sweep.sh runs
# pkill -f "$(basename "$OCD_BIN")" per arm, and a stub named openocd would kill any REAL OpenOCD
# session on the bench that runs this suite. FAKE_OCD_BOARD = the board the "probe" claims to
# reach (word-swapped to look like mdw output); unset = a mute probe (unreadable OTP).
cat > "$BIN/hsmocdstub" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${OCD_LOG:?OCD_LOG unset}"
[ -n "${FAKE_OCD_BOARD:-}" ] || exit 0
b="$FAKE_OCD_BOARD"
printf '0x40130000: %s %s\n' "$(printf '%s' "${b: -8}" | tr 'A-F' 'a-f')" "$(printf '%s' "${b:0:8}" | tr 'A-F' 'a-f')"
EOF
chmod +x "$BIN/hsmocdstub"

# Fixtures: a registry with one staging and one prod token; a board map pairing both to boards.
REG="$BIN/registry.json"
printf '{"schema": "regalia.staging-hardware/v1", "devices": [{"token_serial": "ESPAAAAAAAA", "role": "staging"}, {"token_serial": "ESPBBBBBBBB", "role": "prod"}]}\n' > "$REG"
MAP="ESPAAAAAAAA:C858BA452202E14A ESPBBBBBBBB:8625B32841D722E2"
LOG="$BIN/ocd-calls.log"

run_tool(){ # env assignments then the tool + args; captures stdout+stderr, resets the log
  : > "$LOG"
  # 2>&1 INSIDE the substitution: outside it, stderr escapes $OUT_T and every refusal assertion
  # below would grep a stream it never captured.
  OUT_T="$(env PATH="$BIN:$PATH" OCD_BIN="$BIN/hsmocdstub" OCD_LOG="$LOG" \
    HSM_STAGING_REGISTRY_FILE="$REG" HSM_BOARD_MAP="$MAP" HOME="$BIN" "$@" 2>&1)"
  RC_T=$?
}

refused(){ # $1 = fragment the refusal must contain
  # Herestring, never a filename argument: "$OUT_T" is CAPTURED TEXT, and passing it as a file
  # makes grep look for a file named after the whole tool output ("File name too long").
  if [ "$RC_T" != 0 ] && grep -qa "$1" <<< "$OUT_T"; then ok "refused, naming '$1'"
  else no "wanted refusal '$1' (rc=$RC_T): ${OUT_T:0:200}"; fi
}
no_flash(){ # nothing destructive may have reached the (stubbed) debugger
  if grep -qaE 'program |dump_image|write_image|erase' "$LOG"; then
    no "a destructive openocd command ran despite the refusal: $(grep -aE 'program |dump_image|write_image|erase' "$LOG" | head -1)"
  else ok "no destructive openocd command was issued"; fi
}
gate_ran(){ # the OTP verification itself must have run (mdw), proving the gate executed
  if grep -qa 'mdw 0x40130000' "$LOG"; then ok "the OTP verification ran"; else no "no OTP read in the log — the gate did not run"; fi
}

printf '\n\033[1m### hsm-verify-scan-guard.sh — captures and REWRITES the filesystem\033[0m\n'
run_tool "$TOOLS/hsm-verify-scan-guard.sh"
refused "REFUSING"; no_flash

run_tool FAKE_OCD_BOARD=C858BA452202E14A "$TOOLS/hsm-verify-scan-guard.sh" \
    --probe E6647C74038B9430 --expect-board 999999992202E14A
refused "reaches board"; gate_ran; no_flash

run_tool FAKE_OCD_BOARD=999999992202E14A "$TOOLS/hsm-verify-scan-guard.sh" \
    --probe E6647C74038B9430 --expect-board 999999992202E14A
refused "HSM_BOARD_MAP"; gate_ran; no_flash

run_tool FAKE_OCD_BOARD=8625B32841D722E2 "$TOOLS/hsm-verify-scan-guard.sh" \
    --probe E6647C74038B9430 --expect-board 8625B32841D722E2
refused "not registered as staging"; gate_ran; no_flash

# The pass case: staging board, identity verified — the tool gets PAST the gate and proceeds to
# its own prerequisites (the stub dump writes no image, so it exits 2 at the fs-orig check). The
# assertions are that the gate neither refused nor blocked: a dump_image command ran.
touch "$BIN/patched.elf" "$BIN/unpatched.elf"
run_tool FAKE_OCD_BOARD=C858BA452202E14A HSM_ELF_PATCHED="$BIN/patched.elf" \
    HSM_ELF_UNPATCHED="$BIN/unpatched.elf" \
  "$TOOLS/hsm-verify-scan-guard.sh" --probe E6647C74038B9430 --expect-board C858BA452202E14A
if grep -qa 'REFUSING' <<< "$OUT_T"; then no "a staging board was refused: ${OUT_T:0:160}"
elif grep -qa 'dump_image' "$LOG"; then ok "a staging board passes the gate and the capture runs"
else no "no refusal, but no dump either — the tool stalled: ${OUT_T:0:160}"; fi

printf '\n\033[1m### hsm-verify-lastbase.sh — rewrites the card filesystem image\033[0m\n'
run_tool "$TOOLS/hsm-verify-lastbase.sh"
refused "REFUSING"; no_flash

run_tool FAKE_OCD_BOARD=8625B32841D722E2 "$TOOLS/hsm-verify-lastbase.sh" \
    --probe E6647C74038B9430 --expect-board 8625B32841D722E2
refused "not registered as staging"; gate_ran; no_flash

run_tool FAKE_OCD_BOARD=C858BA452202E14A "$TOOLS/hsm-verify-lastbase.sh" \
    --probe E6647C74038B9430 --expect-board C858BA452202E14A
refused "no dangling image"; no_flash

# Pass case: gate open, image present — the flash command in run_arm must actually run.
printf 'fs' > "$BIN/fs-dangling.bin"
touch "$BIN/patched.elf" "$BIN/unpatched.elf"
run_tool FAKE_OCD_BOARD=C858BA452202E14A HSM_ELF_PATCHED="$BIN/patched.elf" \
    HSM_ELF_UNPATCHED="$BIN/unpatched.elf" HSM_DANGLING_IMAGE="$BIN/fs-dangling.bin" \
  "$TOOLS/hsm-verify-lastbase.sh" --probe E6647C74038B9430 --expect-board C858BA452202E14A
if grep -qa 'REFUSING' <<< "$OUT_T"; then no "a staging board was refused: ${OUT_T:0:160}"
elif grep -qa 'program ' "$LOG"; then ok "a staging board passes the gate and the flash arm runs"
else no "no refusal, but no program either — the tool stalled: ${OUT_T:0:160}"; fi

printf '\n\033[1m### hsm-usb-delay-sweep.sh — programs firmware on every arm\033[0m\n'
run_tool "$TOOLS/hsm-usb-delay-sweep.sh" 1 "$BIN/sweepout"
refused "REFUSING"; no_flash

run_tool FAKE_OCD_BOARD=8625B32841D722E2 "$TOOLS/hsm-usb-delay-sweep.sh" 1 "$BIN/sweepout" \
    --probe E6647C74038B9430 --expect-board 8625B32841D722E2
refused "not registered as staging"; gate_ran; no_flash

# Pass case: gate open. The build step cannot succeed on a test host (no pico-hsm tree), so the
# observable is that the sweep ENTERED its arm loop ("BUILD FAILED" from its own prerequisite)
# without any gate refusal — and that the OTP verification ran.
run_tool FAKE_OCD_BOARD=C858BA452202E14A "$TOOLS/hsm-usb-delay-sweep.sh" 1 "$BIN/sweepout2" \
    --probe E6647C74038B9430 --expect-board C858BA452202E14A
if grep -qa 'REFUSING' <<< "$OUT_T"; then no "a staging board was refused: ${OUT_T:0:160}"
elif grep -qa 'BUILD FAILED' <<< "$OUT_T"; then ok "a staging board passes the gate and the sweep proceeds"
else no "no refusal, but no arm ran either: ${OUT_T:0:160}"; fi
gate_ran

printf '\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
