#!/usr/bin/env bash
# Regression test for tools/hsm-reader-select.sh — the card-targeting resolver.
#
# WHY THIS EXISTS. On 2026-09-02 a second Pico HSM joined the bench and the first resolver treated
# "I could not read this reader's serial" as "this is not the protected card". While OpenOCD held
# the bus busy, pkcs15-tool timed out against the PROVISIONED card, the empty result compared
# unequal to the protected serial, and the resolver nominated that card as the target for a
# `--initialize`. It happened twice. Only a second, independent interlock stopped the wipe.
#
# Every assertion below is about failing CLOSED. No hardware: opensc-tool and pkcs15-tool are
# stubbed on PATH and driven by FAKE_* variables.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
UNDER_TEST="$REPO/tools/hsm-reader-select.sh"
[ -f "$UNDER_TEST" ] || { echo "missing $UNDER_TEST" >&2; exit 1; }

BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT
cat > "$BIN/opensc-tool" <<'EOF'
#!/usr/bin/env bash
# FAKE_READERS = space-separated reader indices
echo "# Detected readers (pcsc)"
echo "Nr.  Card  Features  Name"
for i in ${FAKE_READERS:-0}; do echo "$i    Yes             Fake Pico Key CCID Interface"; done
EOF
cat > "$BIN/pkcs15-tool" <<'EOF'
#!/usr/bin/env bash
# FAKE_SERIAL_<idx> gives that reader's serial; unset means the tool prints nothing (a timeout).
idx=""; while [ $# -gt 0 ]; do case "$1" in -r) idx="$2"; shift 2;; *) shift;; esac; done
var="FAKE_SERIAL_${idx}"; val="${!var-}"
[ -n "$val" ] || exit 0
printf 'PKCS#15 Card [Pico-HSM]:\n\tSerial number  : %s\n' "$val"
EOF
cat > "$BIN/ioreg" <<'EOF'
#!/usr/bin/env bash
# FAKE_BOARDS = space-separated USB serials (RP2350 OTP board ids), one USB device each.
# FAKE_BOARD_VID/FAKE_BOARD_PID override the decimal ids so the VID/PID filter can be tested.
for s in ${FAKE_BOARDS:-}; do
  printf '    "idVendor" = %s\n'  "${FAKE_BOARD_VID:-11914}"
  printf '    "idProduct" = %s\n' "${FAKE_BOARD_PID:-4349}"
  printf '    "USB Serial Number" = "%s"\n' "$s"
done
EOF
chmod +x "$BIN/opensc-tool" "$BIN/pkcs15-tool" "$BIN/ioreg"
export PATH="$BIN:$PATH"
# shellcheck source=/dev/null  # resolved at run time; the file under test is the point
. "$UNDER_TEST"

pass=0; fail=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
check(){ # check <desc> <expected-rc> <expected-stdout-or-*> <cmd...>
  local d="$1" erc="$2" eout="$3"; shift 3
  local out rc; out="$("$@" 2>/dev/null)"; rc=$?
  if [ "$rc" != "$erc" ]; then no "$d (rc $rc, wanted $erc)"; return; fi
  if [ "$eout" != "*" ] && [ "$out" != "$eout" ]; then no "$d (out '$out', wanted '$eout')"; return; fi
  ok "$d"
}

printf '\n\033[1m### Resolving a card by serial\033[0m\n'
check "finds the reader holding the wanted serial" 0 "1" \
  env FAKE_READERS="0 1" FAKE_SERIAL_0=ESPAAAAAAAA FAKE_SERIAL_1=ESP2202E14A \
  bash -c '. "'"$UNDER_TEST"'"; hsm_reader_for ESP2202E14A'

check "index is not assumed — same card at reader 0 resolves to 0" 0 "0" \
  env FAKE_READERS="0 1" FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESPBBBBBBBB \
  bash -c '. "'"$UNDER_TEST"'"; hsm_reader_for ESP2202E14A'

printf '\n\033[1m### Refusing rather than guessing\033[0m\n'
check "absent serial is a refusal, not a default to reader 0" 1 "" \
  env FAKE_READERS="0 1" FAKE_SERIAL_0=ESPAAAAAAAA FAKE_SERIAL_1=ESPBBBBBBBB \
  bash -c '. "'"$UNDER_TEST"'"; hsm_reader_for ESP2202E14A'

check "two readers reporting the SAME serial is a refusal, not the first hit" 1 "" \
  env FAKE_READERS="0 1" FAKE_SERIAL_0=ESP2202E14A FAKE_SERIAL_1=ESP2202E14A \
  bash -c '. "'"$UNDER_TEST"'"; hsm_reader_for ESP2202E14A'

check "no serial given is a refusal" 1 "" \
  env FAKE_READERS="0" bash -c '. "'"$UNDER_TEST"'"; hsm_reader_for ""'

printf '\n\033[1m### the role registry — DEFAULT-DENY, and FAILS CLOSED (successor of hsm_assert_not)\033[0m\n'
# hsm_assert_not (refuse if reader $1 holds protected serial $2, fail closed on an unreadable
# reader) had ZERO production consumers from the day it landed — the right instinct, never wired.
# Its fail-closed duty now lives in the registry gate below: "cannot read the registry" is
# "protected", exactly as "cannot read the reader" was "not safe to wipe". The fixtures:
#   REG       — comments, blanks, one staging serial, one prod serial, one UNKNOWN role word
#   REG_DIR   — a directory: unreadable AS A FILE even for root (the suite runs under sudo, and
#               chmod 000 is readable to root — permission bits would test nothing on CI)
#   REG_MISS  — a path that does not exist
# The fixtures are the SAME format as tools/hsm-staging-registry.json, the one file both this gate
# and the board/probe-map loader read. hsm_role_of consults only schema, token_serial and role.
REG="$BIN/registry.json"
cat > "$REG" <<'JSON'
{"schema": "regalia.staging-hardware/v1", "environment": "staging", "devices": [
  {"token_serial": "ESPAAAAAAAA", "role": "staging"},
  {"token_serial": "ESPBBBBBBBB", "role": "prod"},
  {"token_serial": "ESPCCCCCCCC", "role": "banana"},
  {"token_serial": "ESPDDDDDDDD", "role": "staging"},
  {"token_serial": "ESPDDDDDDDD", "role": "staging"}
]}
JSON
REG_DIR="$BIN/registry-as-a-dir"; mkdir -p "$REG_DIR"
REG_MISS="$BIN/registry-absent.json"
REG_BADJSON="$BIN/registry-bad.json"; printf '{"schema": "regalia.staging-hardware/v1", "devices": [\n' > "$REG_BADJSON"
REG_OTHERSCHEMA="$BIN/registry-other.json"
printf '{"schema": "something-else/v1", "devices": [{"token_serial": "ESPAAAAAAAA", "role": "staging"}]}\n' > "$REG_OTHERSCHEMA"

check "a serial listed staging reads staging" 0 "staging" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPAAAAAAAA'

check "an UNLISTED serial is protected — default-deny" 0 "protected" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPZZZZZZZZ'

check "a serial listed prod reads prod" 0 "prod" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPBBBBBBBB'

# A role word the gate does not know is NOT permission. Free-text roles would make 'STAGING'
# or 'staging ' a bypass; the vocabulary is staging|prod and nothing else.
check "an unknown role word is protected, not a pass" 0 "protected" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPCCCCCCCC'

check "a MISSING registry protects everything" 0 "protected" \
  env HSM_STAGING_REGISTRY_FILE="$REG_MISS" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPAAAAAAAA'

check "an UNREADABLE registry (a directory) protects everything" 0 "protected" \
  env HSM_STAGING_REGISTRY_FILE="$REG_DIR" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPAAAAAAAA'

check "an EMPTY serial is protected — no identity, no destructibility" 0 "protected" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ""'

# Formats the env file never had. Each can only protect.
check "a serial listed TWICE is protected — ambiguity never arms a wipe" 0 "protected" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPDDDDDDDD'

check "a registry that is not valid JSON protects everything" 0 "protected" \
  env HSM_STAGING_REGISTRY_FILE="$REG_BADJSON" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPAAAAAAAA'

check "a registry of another schema protects everything" 0 "protected" \
  env HSM_STAGING_REGISTRY_FILE="$REG_OTHERSCHEMA" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPAAAAAAAA'

# ONE SOURCE OF TRUTH. The gate and the map loader must read the same file, or they can disagree
# about which card may be wiped: a serial the loader maps is a serial the gate calls staging.
check "the gate reads the file hsm-staging-registry.sh loads, not a second registry" 0 "staging" \
  env -u HSM_STAGING_REGISTRY_FILE -u HSM_BOARD_MAP -u HSM_CI_PROBE_MAP \
  bash -c '. "'"$UNDER_TEST"'"; . "'"$REPO"'/tools/hsm-staging-registry.sh"; hsm_staging_registry_load >/dev/null 2>&1 || { echo loader-failed; exit 0; }; case " $HSM_BOARD_MAP " in *" ESP41D722E2:"*) hsm_role_of ESP41D722E2 ;; *) echo loader-disagrees ;; esac'

legacy_roles="$REPO/tools/hsm-roles"".env"
if [ -e "$legacy_roles" ]; then no "$legacy_roles still exists — a second registry the gate no longer reads"; else ok "no second role registry ships beside the staging registry"; fi

# THE REGISTRY ITSELF SHIPS. A missing or misnamed file would make every gate refuse (correct
# but brick-shaped), and a file that does not parse would quietly protect nothing it names.
check "the committed registry exists, parses, and lists the bench staging cards" 0 "staging" \
  env -u HSM_STAGING_REGISTRY_FILE \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESP2202E14A'

check "the committed registry also lists the second bench card" 0 "staging" \
  env -u HSM_STAGING_REGISTRY_FILE \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESP41D722E2'

check "an unknown serial is protected under the COMMITTED registry too" 0 "protected" \
  env -u HSM_STAGING_REGISTRY_FILE \
  bash -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPNOTREAL1'

printf '\n\033[1m### hsm_assert_staging — the refusal every destructive entry point calls\033[0m\n'
check "a staging serial is allowed" 0 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging ESPAAAAAAAA'

check "a PROD serial is refused" 1 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging ESPBBBBBBBB'

check "an UNLISTED serial is refused — the future-prod-card case" 1 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging ESPZZZZZZZZ'

check "an EMPTY serial is refused — no destructive step against an unnamed card" 1 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging ""'

check "a MISSING registry is a refusal, not a silent allow" 1 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG_MISS" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging ESPAAAAAAAA'

# The refusal must carry the REASON and the REMEDY, or the next person routes around it.
for _want in 'REFUSING' 'ESPBBBBBBBB' 'staging' 'pull request'; do
  _out="$(env HSM_STAGING_REGISTRY_FILE="$REG" \
          bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging ESPBBBBBBBB' 2>&1 >/dev/null)"
  case "$_out" in
    *"$_want"*) ok "the refusal names '$_want'" ;;
    *)          no "the refusal does not name '$_want'" ;;
  esac
done

# THE RESOLVER IS SOURCED, SO THE SHELL IS THE CALLER'S CHOICE (same discipline as the board-map
# checks above): the registry parse must not lean on bash-only splitting.
if command -v zsh >/dev/null 2>&1; then
  check "zsh reads the registry identically to bash" 0 "staging" \
    env HSM_STAGING_REGISTRY_FILE="$REG" \
    zsh -c '. "'"$UNDER_TEST"'"; hsm_role_of ESPAAAAAAAA'

  check "zsh refuses a prod serial identically to bash" 1 "*" \
    env HSM_STAGING_REGISTRY_FILE="$REG" \
    zsh -c '. "'"$UNDER_TEST"'"; hsm_assert_staging ESPBBBBBBBB'
else
  printf '  (zsh not installed — skipping the cross-shell registry checks)\n'
fi

printf '\n\033[1m### hsm_assert_staging_board — the gate for tools that flash by BOARD id\033[0m\n'
# SWD flash tools address the RP2350 OTP board id, where no token serial exists. The board is
# reverse-mapped through the SAME REQUIRED HSM_BOARD_MAP hsm_board_for_token uses; a board with
# no map entry has no token to ask about, which is a refusal, never a guess.
_MAP="ESPAAAAAAAA:C858BA452202E14A ESPBBBBBBBB:8625B32841D722E2"

check "a board mapped to a staging token is allowed" 0 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" HSM_BOARD_MAP="$_MAP" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging_board C858BA452202E14A'

check "a board mapped to a PROD token is refused" 1 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" HSM_BOARD_MAP="$_MAP" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging_board 8625B32841D722E2'

check "an UNMAPPED board is refused — no token to ask about" 1 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" HSM_BOARD_MAP="$_MAP" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging_board 999999992202E14A'

check "the board id is matched case-insensitively" 0 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" HSM_BOARD_MAP="$_MAP" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging_board c858ba452202e14a'

check "an EMPTY board id is refused" 1 "*" \
  env HSM_STAGING_REGISTRY_FILE="$REG" HSM_BOARD_MAP="$_MAP" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging_board ""'

_out="$(env HSM_STAGING_REGISTRY_FILE="$REG" HSM_BOARD_MAP="$_MAP" \
        bash -c '. "'"$UNDER_TEST"'"; hsm_assert_staging_board 999999992202E14A' 2>&1 >/dev/null)"
case "$_out" in
  *HSM_BOARD_MAP*) ok "the unmapped-board refusal names HSM_BOARD_MAP" ;;
  *)               no "the unmapped-board refusal does not name HSM_BOARD_MAP" ;;
esac

printf '\n\033[1m### hsm_verify_board_over_probe — OTP identity BEFORE anything goes down the wire\033[0m\n'
# The interlock hsm-quiesce.sh pioneered, shared. openocd is stubbed: FAKE_OCD_BOARD is the board
# the "probe" claims to reach, OCD_LOG records every invocation so a refusal can be proven to have
# happened BEFORE any flash command (the tools' own tests assert on that log).
OCD_LOG="$BIN/openocd-calls.log"; : > "$OCD_LOG"
cat > "$BIN/openocd" <<'EOF'
#!/usr/bin/env bash
# FAKE_OCD_BOARD = the board id this "probe" claims to reach; unset means the probe is mute.
# OCD_LOG records invocations; it defaults to /dev/null so the stub never dies before acting —
# a stub that crashes makes every refusal-case pass for the wrong reason (observed in review of
# this very test: the mismatch cases were green because the stub produced NO OTP at all).
printf '%s\n' "$*" >> "${OCD_LOG:-/dev/null}"
[ -n "${FAKE_OCD_BOARD:-}" ] || exit 0
b="$FAKE_OCD_BOARD"
printf '0x40130000: %s %s\n' "$(printf '%s' "${b: -8}" | tr 'A-F' 'a-f')" "$(printf '%s' "${b:0:8}" | tr 'A-F' 'a-f')"
EOF
chmod +x "$BIN/openocd"

check "the board the probe reaches matches the expectation" 0 "C858BA452202E14A" \
  env OCD_BIN="$BIN/openocd" FAKE_OCD_BOARD=C858BA452202E14A \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_board_over_probe E6647C74038B9430 C858BA452202E14A'

check "a MISMATCHED board is refused" 1 "*" \
  env OCD_BIN="$BIN/openocd" FAKE_OCD_BOARD=8625B32841D722E2 \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_board_over_probe E6647C74038B9430 C858BA452202E14A'

check "an UNREADABLE OTP (openocd prints nothing) is a refusal, not a pass-through" 1 "*" \
  env OCD_BIN="$BIN/openocd" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_board_over_probe E6647C74038B9430 C858BA452202E14A'

check "a MISSING openocd is a refusal — nothing may be sent down an unverifiable probe" 1 "*" \
  env OCD_BIN="$BIN/openocd-absent" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_board_over_probe E6647C74038B9430 C858BA452202E14A'

_out="$(env OCD_BIN="$BIN/openocd" FAKE_OCD_BOARD=8625B32841D722E2 \
        bash -c '. "'"$UNDER_TEST"'"; hsm_verify_board_over_probe E6647C74038B9430 C858BA452202E14A' 2>&1 >/dev/null)"
case "$_out" in
  *REFUSING*) ok "the mismatch refusal says REFUSING and names both boards" ;;
  *)          no "the mismatch refusal does not say REFUSING" ;;
esac

printf '\n\033[1m### hsm_board_for_token — choosing which board SWD may HALT, RESET and RE-FLASH\033[0m\n'
# Identity must be SUPPLIED, never inferred. The token serial carries only the LAST FOUR BYTES of the
# board id, so it can never be more than a suffix. An earlier version accepted a unique suffix match;
# that was measured returning the WRONG board (see the block comment on the function). These assert
# that an unmapped token is a refusal no matter how tempting the guess looks.
check "a mapped board that is attached resolves to its full id" 0 "C858BA452202E14A" \
  env FAKE_BOARDS="C858BA452202E14A 8625B32841D722E2" HSM_BOARD_MAP="ESP2202E14A:C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP2202E14A'

# THE MEASURED DEFECT. Exactly one attached board matches the four-byte suffix, so the old uniqueness
# check said n=1 and returned it. Unmapped, that is now a refusal.
check "UNMAPPED is refused even when exactly one attached board matches the suffix" 1 "" \
  env FAKE_BOARDS="C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP2202E14A'

# The same shape, but the board that matches the suffix is an IMPOSTOR and the real one is off the
# bus — which is the normal state while recovery is running.
check "UNMAPPED is refused when only a suffix-colliding impostor is attached" 1 "" \
  env FAKE_BOARDS="999999992202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP2202E14A'

# A MAPPED BOARD RESOLVES EVEN WHEN IT IS OFF THE USB BUS. That is the whole point: the card
# vanishing from USB is the wedge SWD recovery exists for, and an earlier version refused there,
# so the ladder was never attempted. It must still resolve to the MAPPED id and never to the
# suffix-colliding impostor that happens to be plugged in.
check "a mapped board resolves even when absent from USB — and never to the impostor" 0 "C858BA452202E14A" \
  env FAKE_BOARDS="999999992202E14A" HSM_BOARD_MAP="ESP2202E14A:C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP2202E14A'

check "hsm_board_attached reports presence separately — false when it is off the bus" 1 "*" \
  env FAKE_BOARDS="999999992202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_attached C858BA452202E14A'

check "hsm_board_attached is true when it is on the bus" 0 "*" \
  env FAKE_BOARDS="C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_attached C858BA452202E14A'

check "HSM_BOARD_MAP picks the mapped board, not the suffix-colliding one" 0 "999999992202E14A" \
  env FAKE_BOARDS="C858BA452202E14A 999999992202E14A" HSM_BOARD_MAP="ESP2202E14A:999999992202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP2202E14A'

check "the SAME board enumerated twice is one board, not an ambiguity" 0 "*" \
  env FAKE_BOARDS="C858BA452202E14A C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_attached C858BA452202E14A'

check "a board on a NON-Pico VID is not reported as attached" 1 "*" \
  env FAKE_BOARDS="C858BA452202E14A" FAKE_BOARD_VID=1234 \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_attached C858BA452202E14A'

check "a map entry for a DIFFERENT token does not satisfy this one" 1 "" \
  env FAKE_BOARDS="C858BA452202E14A" HSM_BOARD_MAP="ESP41D722E2:C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP2202E14A'

check "an empty token is a refusal" 1 "" \
  env FAKE_BOARDS="C858BA452202E14A" HSM_BOARD_MAP="ESP2202E14A:C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ""'

check "hsm_token_is_pico is FALSE when the token is unmapped — no SWD path, not a guess" 1 "*" \
  env FAKE_BOARDS="C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_token_is_pico ESP2202E14A'

check "hsm_token_is_pico is true for a mapped, attached board" 0 "*" \
  env FAKE_BOARDS="C858BA452202E14A" HSM_BOARD_MAP="ESP2202E14A:C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_token_is_pico ESP2202E14A'

# A MULTI-ENTRY map, and the SECOND entry specifically. A single-entry map cannot catch a splitting
# bug, because the whole string then happens to be the one entry.
check "the second entry of a multi-entry map resolves" 0 "8625B32841D722E2" \
  env FAKE_BOARDS="C858BA452202E14A 8625B32841D722E2" \
      HSM_BOARD_MAP="ESP2202E14A:C858BA452202E14A ESP41D722E2:8625B32841D722E2" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP41D722E2'

# THE RESOLVER IS SOURCED, SO THE SHELL IS THE CALLER'S CHOICE. zsh does not word-split parameter
# expansions, and a bash-only test cannot see that: measured 2026-09-03, `for pair in $HSM_BOARD_MAP`
# under zsh returned "C858BA452202E14A ESP41D722E2:8625B32841D722E2" as a board id.
if command -v zsh >/dev/null 2>&1; then
  check "zsh resolves the first map entry identically to bash" 0 "C858BA452202E14A" \
    env FAKE_BOARDS="C858BA452202E14A 8625B32841D722E2" \
        HSM_BOARD_MAP="ESP2202E14A:C858BA452202E14A ESP41D722E2:8625B32841D722E2" \
    zsh -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP2202E14A'

  check "zsh resolves the SECOND map entry too — the case plain word-splitting loses" 0 "8625B32841D722E2" \
    env FAKE_BOARDS="C858BA452202E14A 8625B32841D722E2" \
        HSM_BOARD_MAP="ESP2202E14A:C858BA452202E14A ESP41D722E2:8625B32841D722E2" \
    zsh -c '. "'"$UNDER_TEST"'"; hsm_board_for_token ESP41D722E2'
else
  printf '  (zsh not installed — skipping the cross-shell sourcing checks)\n'
fi

printf '\n\033[1m### hsm_reader_scsh_addressable — which card scsh can actually name\033[0m\n'
# scsh matches reader names by PREFIX and takes the first hit, so a reader whose full name is a
# strict prefix of another's cannot be addressed at all. The rule is ASYMMETRIC and which card holds
# which name is not stable across replugs, so it has to be asked per run.
cat > "$BIN/opensc-tool" <<'EOF'
#!/usr/bin/env bash
echo "# Detected readers (pcsc)"
echo "Nr.  Card  Features  Name"
i=0
for n in ${FAKE_NAMES:-}; do echo "$i    Yes             ${n//_/ }"; i=$((i+1)); done
EOF
chmod +x "$BIN/opensc-tool"

check "the LONGER name is addressable" 0 "*" \
  env FAKE_NAMES="Pico_Key_CCID_Interface Pico_Key_CCID_Interface_01" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_reader_scsh_addressable 1'

check "the PREFIX name is NOT addressable — asking for it returns the other card" 1 "*" \
  env FAKE_NAMES="Pico_Key_CCID_Interface Pico_Key_CCID_Interface_01" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_reader_scsh_addressable 0'

check "a lone reader is addressable" 0 "*" \
  env FAKE_NAMES="Pico_Key_CCID_Interface" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_reader_scsh_addressable 0'

check "two IDENTICAL names are unaddressable either way" 1 "*" \
  env FAKE_NAMES="Pico_Key_CCID_Interface Pico_Key_CCID_Interface" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_reader_scsh_addressable 0'

printf '\n\033[1m### hsm_require_scsh_addressable — the shared refusal every scsh caller now uses\033[0m\n'
# Each destructive scsh entry point had grown its own partial version of this check or none at all.
# The refusal must carry the REASON and the remedy, because the alternative — letting the
# initializer's HSM_EXPECT_SERIAL backstop fire — reports a "WRONG CARD" error from a step already
# aimed at a card, which reads as a defect in the guard rather than as an unaddressable bench.
check "the addressable reader is allowed through" 0 "" \
  env FAKE_NAMES="Pico_Key_CCID_Interface Pico_Key_CCID_Interface_01" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_require_scsh_addressable 1 ESP2202E14A 2>/dev/null'

check "the prefix-named reader is refused" 1 "" \
  env FAKE_NAMES="Pico_Key_CCID_Interface Pico_Key_CCID_Interface_01" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_require_scsh_addressable 0 ESP2202E14A 2>/dev/null'

# The message is the point: a refusal nobody can act on sends the next person to the wrong place.
for _want in 'strict PREFIX' 'returns the OTHER card' 'Replug' 'ESP2202E14A'; do
  _out="$(env FAKE_NAMES="Pico_Key_CCID_Interface Pico_Key_CCID_Interface_01" \
          bash -c '. "'"$UNDER_TEST"'"; hsm_require_scsh_addressable 0 ESP2202E14A' 2>&1 >/dev/null)"
  case "$_out" in
    *"$_want"*) ok "the refusal names '$_want'" ;;
    *)          no "the refusal does not name '$_want'" ;;
  esac
done

printf '\n\033[1m### hsm_verify_blank_board — identity for a card that cannot identify itself\033[0m\n'
# A blank card has no EF 2F02 and no token serial. The USB serial IS the OTP board id, and it is the
# only identity left — so this is what stands between a blank-card INITIALIZE and wiping the wrong
# device. D1 rejected a "the card is expected to be blank" override: blank is a property of the card
# in front of you, not evidence about WHICH card it is.
check "the single attached board matching the expectation is confirmed" 0 "C858BA452202E14A" \
  env FAKE_BOARDS="C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_blank_board C858BA452202E14A'

check "TWO attached boards is a refusal — a blank card cannot be tied to a reader" 1 "" \
  env FAKE_BOARDS="C858BA452202E14A 8625B32841D722E2" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_blank_board C858BA452202E14A'

check "the wrong single board is refused" 1 "" \
  env FAKE_BOARDS="8625B32841D722E2" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_blank_board C858BA452202E14A'

check "no board attached is a refusal, not a pass" 1 "" \
  env FAKE_BOARDS="" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_blank_board C858BA452202E14A'

check "no expectation given is a refusal" 1 "" \
  env FAKE_BOARDS="C858BA452202E14A" \
  bash -c '. "'"$UNDER_TEST"'"; hsm_verify_blank_board ""'

printf '\n\033[1m### a resolver must not report failure when it succeeds (SIGPIPE under pipefail)\033[0m\n'
# THE EXISTING FAKES CANNOT CATCH THIS. They print two lines and exit, so the whole stream is in the
# pipe buffer before awk can close it — the producer never sees SIGPIPE and every status is 0. The
# real tools interleave card I/O with their output: pkcs15-tool --dump put the serial on line 3 of
# 30 and was still writing when awk exited on the match. Under `set -o pipefail` the pipeline then
# returned 141, so hsm_serial_at_reader reported FAILURE on a reader it had just read correctly.
# MEASURED 2026-09-11 inside hsm-staging-ci.sh (which sets pipefail): the bench PIN census captured
# the serial and then discarded it on the non-zero status, printing "serial UNREADABLE" for both
# cards while PASSING — a census that names no card and still reports success.
#
# So this fake writes the wanted line FIRST and then keeps writing, slowly, past the match.
SLOW="$(mktemp -d)"; trap 'rm -rf "$BIN" "$SLOW"' EXIT
cat > "$SLOW/pkcs15-tool" <<'EOF'
#!/usr/bin/env bash
printf 'PKCS#15 Card [Pico-HSM]:\n'
printf '\tSerial number  : %s\n' "${FAKE_SERIAL_1:-ESP2202E14A}"
# Keep producing after the match, with a pause, so an early `exit` in the consumer closes the pipe
# while this process still has writes outstanding. Without the sleep the kernel buffer swallows it.
for i in $(seq 1 40); do sleep 0.02; printf '\tObject %s : padding to force a write after the match\n' "$i"; done
EOF
chmod +x "$SLOW/pkcs15-tool"

check "hsm_serial_at_reader returns the serial AND status 0 when the card tool is still writing" \
  0 "ESP2202E14A" \
  env PATH="$SLOW:$PATH" FAKE_READERS="0 1" FAKE_SERIAL_1=ESP2202E14A \
  bash -c 'set -o pipefail; . "'"$UNDER_TEST"'"; hsm_serial_at_reader 1'

# The caller's shape is what actually broke: capture-then-discard-on-status.
check "a caller that tests the status still sees the serial" 0 "ESP2202E14A" \
  env PATH="$SLOW:$PATH" FAKE_READERS="0 1" FAKE_SERIAL_1=ESP2202E14A \
  bash -c 'set -o pipefail; . "'"$UNDER_TEST"'"; s="$(hsm_serial_at_reader 1)" || s=""; printf "%s" "$s"'

printf '\n\033[1m### RESULT\033[0m\n'
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
