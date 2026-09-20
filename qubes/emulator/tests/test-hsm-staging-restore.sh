#!/usr/bin/env bash
# Regression test for tools/hsm-staging-restore.sh — the script that puts the staging card back
# into the documented posture. It runs INITIALIZE DEVICE, so every assertion here is about aiming
# that wipe at a PROVEN device and about refusing when the target cannot be proven.
#
# WHY THIS EXISTS (#395). Run on 2026-09-11 against a two-board bench, this script:
#   * resolved its target from $HSM_SLOT, default 0 — "whichever board enumerated first", which was
#     ESP41D722E2, the card it is NOT pinned to, one failed login from lockout;
#   * handed Smart Card Shell a reader NAME for a reader scsh cannot address (scsh matches names by
#     PREFIX, and the pinned card's name is a strict prefix of the other's), so the init reached the
#     WRONG card and its identity guard refused;
#   * discarded that refusal, because "the init's exit status means nothing", and printed
#     "card is back" — which was true and irrelevant;
#   * then aimed `--import-dkek-share --so-pin` at the unproven card;
#   * and reported "RRC OFF" in step 1 while RRC remained ENABLED on both cards.
#
# No hardware: opensc-tool, pkcs15-tool, pkcs11-tool, sc-hsm-tool and scsh's scriptrunner are
# stubbed on PATH and driven by FAKE_* variables.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
UNDER_TEST="$REPO/tools/hsm-staging-restore.sh"
[ -f "$UNDER_TEST" ] || { echo "missing $UNDER_TEST" >&2; exit 1; }

pass=0; fail=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

# run_restore <env assignments...> — returns rc in RC and combined output in OUT.
run_restore(){
  local work bin staging scsh
  work="$(mktemp -d)"; bin="$work/bin"; staging="$work/staging"; scsh="$work/scsh"
  mkdir -p "$bin" "$staging" "$scsh"
  printf 'dkek-blob\n' > "$staging/dkek.pbe"
  printf 'dkek-password\n' > "$staging/dkek.pw"

  # Reader list. FAKE_NAMES is "idx=name" pairs, newline separated. The Name column must start at
  # the same byte as the header's "Name", because hsm_reader_name cuts by that column.
  cat > "$bin/opensc-tool" <<'EOF'
#!/usr/bin/env bash
printf '# Detected readers (pcsc)\n'
printf 'Nr.  Card  Features  Name\n'
printf '%s\n' "${FAKE_NAMES:-}" | while IFS= read -r pair; do
  [ -n "$pair" ] || continue
  printf '%-3s  %-4s  %-8s  %s\n' "${pair%%=*}" "Yes" "" "${pair#*=}"
done
EOF
  # FAKE_SERIAL_<idx> is the token serial at that reader; unset means the read produced nothing,
  # which every resolver here must treat as "cannot prove", never as "not the protected card".
  cat > "$bin/pkcs15-tool" <<'EOF'
#!/usr/bin/env bash
idx=""; while [ $# -gt 0 ]; do case "$1" in -r) idx="$2"; shift 2;; *) shift;; esac; done
var="FAKE_SERIAL_${idx}"; val="${!var-}"
[ -n "$val" ] || exit 0
printf 'PKCS#15 Card [Pico-HSM]:\n\tSerial number  : %s\n' "$val"
EOF
  # FAKE_SLOTS is "id serial" lines, feeding hsm_slot_table.
  cat > "$bin/pkcs11-tool" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *--list-token-slots*)
    printf '%s\n' "${FAKE_SLOTS:-}" | while IFS= read -r l; do
      [ -n "$l" ] || continue
      printf 'Slot 0 (0x%x): Reader\n  serial num         : %s\n' "${l%% *}" "${l#* }"
    done ;;
  *--sign*) exit "${FAKE_SIGN_RC:-1}" ;;
esac
EOF
  # sc-hsm-tool. The bare form reports posture; --import-dkek-share is step 2.
  cat > "$bin/sc-hsm-tool" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *--import-dkek-share*) exit "${FAKE_DKEK_RC:-1}" ;;
esac
[ "${FAKE_ANSWERS:-1}" = 1 ] || { echo "Failed to connect to card"; exit 1; }
# FAKE_FAIL_AFTER=N: answer the first N bare calls, then stop answering. wait_card makes call 1
# (liveness) and the posture read is call 2, so N=1 isolates "the card was alive and then the
# posture read failed" from "the card never came back" — two different guards with two different
# messages, and only the second one is about posture.
if [ -n "${FAKE_FAIL_AFTER:-}" ] && [ -n "${FAKE_CALL_COUNT:-}" ]; then
  n=$(( $(cat "$FAKE_CALL_COUNT" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FAKE_CALL_COUNT"
  [ "$n" -gt "$FAKE_FAIL_AFTER" ] && { echo "Failed to connect to card"; exit 1; }
fi
printf 'Version              : 4.1\n'
[ "${FAKE_RRC:-off}" = on ] && printf 'User PIN reset with SO-PIN enabled\n'
printf 'User PIN tries left  : %s\n' "${FAKE_TRIES:-3}"
printf 'DKEK shares          : 1\n'
exit 0
EOF
  chmod +x "$bin"/*
  # scsh's scriptrunner. Its stdout/stderr is what lands in the init log.
  cat > "$scsh/scriptrunner" <<'EOF'
#!/usr/bin/env bash
# FAKE_INIT_ECHO_EXPECT=1 reports the identity the wrapper actually handed the initializer. The
# banner naming the right card and the JS RECEIVING the right card are two different claims: the
# wrapper kept a SECOND copy of the default serial on the scsh invocation line, so it printed
# "target: ESP41D722E2" and then passed HSM_EXPECT_SERIAL=ESP2202E14A, and the JS refused.
if [ "${FAKE_INIT_ECHO_EXPECT:-0}" = 1 ]; then
  printf 'REFUSING: received HSM_EXPECT_SERIAL=%s\n' "${HSM_EXPECT_SERIAL:-<unset>}"
  exit 0
fi
printf '%s\n' "${FAKE_INIT_OUT:-STEP connect: Version 6.6}"
exit "${FAKE_INIT_RC:-0}"
EOF
  chmod +x "$scsh/scriptrunner"

  # The script has no default card, so every case names one. ESP2202E14A is the card these cases were
  # written around; a case that means something else overrides it, and the no-card case clears it.
  OUT="$(env PATH="$bin:$PATH" \
      HSM_STAGING_DIR="$staging" SCSH_HOME="$scsh" FAKE_CALL_COUNT="$work/calls" \
      HSM_PKCS11_MODULE="$work/fake.so" HSM_RESTORE_SERIAL=ESP2202E14A \
      "$@" bash "$UNDER_TEST" 2>&1)"; RC=$?
  rm -rf "$work"
}

# The two-board bench as measured on 2026-09-11: the pinned card holds the PREFIX name.
TWO_BOARDS='0=Pol Henarejos Pico Key CCID Interface 01
1=Pol Henarejos Pico Key CCID Interface'
# The same two readers after a replug that lands the PINNED card on the longer, addressable name.
# The NAMES do not move — PC/SC assigns "01" to the second interface it enumerates — so what a
# replug changes is which serial sits behind which name. Defining this with the names swapped
# instead put the pinned card back on the prefix name and every "addressable" case below hit the
# prefix gate; the control arm is what exposed it.
TWO_SWAPPED="$TWO_BOARDS"

want(){ # want <desc> <expected-rc> <substring>
  local d="$1" erc="$2" sub="$3"
  if [ "$RC" != "$erc" ]; then no "$d (rc $RC, wanted $erc)"; printf '%s\n' "$OUT" | sed 's/^/        /' | head -4; return; fi
  case "$OUT" in *"$sub"*) ok "$d" ;; *) no "$d (output lacks '$sub')"; printf '%s\n' "$OUT" | sed 's/^/        /' | head -4 ;; esac
}
wantnot(){ # wantnot <desc> <substring that must be ABSENT>
  case "$OUT" in *"$2"*) no "$3 ('$2' should be absent)" ;; *) ok "$3" ;; esac
}

printf '\n\033[1m### the target is resolved by SERIAL, not by enumeration order\033[0m\n'

# NO DEFAULT CARD. With nothing named, a restore used to aim INITIALIZE DEVICE at ESP2202E14A -- on
# 2026-09-14 the card holding #435's Cosmos key. It must refuse before any card or tool is touched.
run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A \
            env -u HSM_RESTORE_SERIAL -u HSM_TARGET_SERIAL
want "naming no card is a refusal, never a default target" 1 "REFUSING: no card named"
wantnot . "target:" "and no target was resolved or announced"

run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A \
            FAKE_SLOTS="4 ESP2202E14A" HSM_RESTORE_SERIAL=ESP2202E14A
want "pinned card at reader 1 is targeted at reader 1, not reader 0" 1 \
     "target: ESP2202E14A at PC/SC reader 1"
want "and the PKCS#11 slot ID comes from the slot table, not the index" 1 "slot id 4"

run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP41D722E2 HSM_RESTORE_SERIAL=ESP2202E14A
want "an ambiguous serial is refused, never resolved to the first hit" 1 \
     "cannot resolve ESP2202E14A"

run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 HSM_RESTORE_SERIAL=ESP2202E14A
want "the pinned card being absent is a refusal, not a fallback to reader 0" 1 \
     "cannot resolve ESP2202E14A"

printf '\n\033[1m### the parent battery pins the card, and this script must honour that\033[0m\n'
# hsm-staging-ci.sh resolves the staging card and exports HSM_TARGET_SERIAL with HSM_PCSC_INDEX before
# running this script as posture_restore. Reading only HSM_RESTORE_SERIAL made this compare the
# parent's reader against its own hardcoded default and refuse — the single failure in an otherwise
# green destructive nightly on 2026-09-11, which left the card outside posture because the step that
# restores it declined to run.
run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A \
            HSM_RESTORE_SERIAL= HSM_TARGET_SERIAL=ESP41D722E2 HSM_PCSC_INDEX=0 FAKE_SLOTS="0 ESP41D722E2"
want "a parent-pinned serial is adopted, not overridden by the built-in default" 1 \
     "target: ESP41D722E2 at PC/SC reader 0"
wantnot . "REFUSING: reader 0 holds" "and the identity guard does not fire against the parent's own card"

# Precedence: an explicit override still wins over the parent's value.
run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A \
            HSM_TARGET_SERIAL=ESP41D722E2 HSM_RESTORE_SERIAL=ESP2202E14A FAKE_SLOTS="4 ESP2202E14A"
want "an explicit HSM_RESTORE_SERIAL outranks the parent's pin" 1 \
     "target: ESP2202E14A at PC/SC reader 1"

# THE BANNER IS NOT THE HANDOFF. Assert what the initializer actually receives.
run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A \
            HSM_RESTORE_SERIAL= HSM_TARGET_SERIAL=ESP41D722E2 HSM_PCSC_INDEX=0 FAKE_SLOTS="0 ESP41D722E2" \
            FAKE_INIT_ECHO_EXPECT=1
want "the initializer is handed the SAME serial the target line names" 1 \
     "HSM_EXPECT_SERIAL=ESP41D722E2"

printf '\n\033[1m### an on-card writer proves the card first (the sc-hsm-tool steps had no guard)\033[0m\n'

run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A \
            HSM_PCSC_INDEX=0
want "an explicit index pointing at the wrong card is refused" 1 \
     "REFUSING: reader 0 holds ESP41D722E2, not ESP2202E14A"

run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_1=ESP2202E14A HSM_PCSC_INDEX=0
want "a reader that answers with NO serial is refused, not assumed safe" 1 \
     "did not answer with a serial"

printf '\n\033[1m### scsh cannot address a prefix-named reader, so the wipe is refused\033[0m\n'

run_restore FAKE_NAMES="$TWO_BOARDS" FAKE_SERIAL_0=ESP41D722E2 FAKE_SERIAL_1=ESP2202E14A \
            FAKE_SLOTS="4 ESP2202E14A"
want "the prefix-named pinned card refuses before INITIALIZE DEVICE runs" 1 "strict PREFIX"
wantnot . "card is back" "and the init never ran (no liveness message)"

printf '\n\033[1m### a refusal is not a success, and liveness is not posture\033[0m\n'

run_restore FAKE_NAMES="$TWO_SWAPPED" FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESP41D722E2 \
            FAKE_SLOTS="0 ESP2202E14A" \
            FAKE_INIT_OUT="Error: REFUSING TO INITIALIZE: connected to the WRONG CARD."
want "a REFUSING init is a failure even though its exit status is 0" 1 \
     "the hardened init REFUSED"
wantnot . "DKEK imported" "and step 2 never spends an SO-PIN after a refused init"

run_restore FAKE_NAMES="$TWO_SWAPPED" FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESP41D722E2 \
            FAKE_SLOTS="0 ESP2202E14A" FAKE_RRC=on
want "RRC still enabled after the init is a failure, not a printed 'RRC OFF'" 1 \
     "RRC is still ENABLED"

# The card is ALIVE for wait_card and then stops answering, so the only thing that can fail is the
# posture read itself. Without the '^Version' precondition an empty read contains no RRC tell, so
# `grep -qi 'reset with SO-PIN'` finds nothing and the script certifies a posture it never read.
run_restore FAKE_NAMES="$TWO_SWAPPED" FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESP41D722E2 \
            FAKE_SLOTS="0 ESP2202E14A" FAKE_FAIL_AFTER=1
want "an unread posture is a failure, not an absent RRC tell" 1 "cannot verify the posture"
wantnot . "RRC verified OFF" "and it is not reported as verified"

printf '\n\033[1m### control: an addressable card in the right posture proceeds\033[0m\n'

run_restore FAKE_NAMES="$TWO_SWAPPED" FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESP41D722E2 \
            FAKE_SLOTS="0 ESP2202E14A" FAKE_RRC=off
want "step 1 verifies the posture and the run reaches step 2" 1 "RRC verified OFF"
want "  (step 2 is where this run stops, on the faked DKEK failure)" 1 "DKEK import failed"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
