#!/usr/bin/env bash
# test-hsm-auto-import.sh — coverage for the UNATTENDED import path (hsm-auto-import.sh/.js).
# REQUIREMENTS C2 — provisioning is automatable: the domain is created over APDU rather than by re-initialising.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE — read this before trusting a green run.
#
# CAN (and does): every guard, every fail-closed branch, secret hygiene, and that the script
# uses the specific scsh3 APIs that were established the hard way against real hardware. These
# are pure software properties and a green result here is real evidence.
#
# CANNOT: the APDU exchange itself. createDKEKKeyDomain (80 52 01), importEncryptedKeyShare and
# unwrapKey talk to a card. The emulator's sc-hsm-tool shim models the CLI subcommands only —
# it has NO scsh3/APDU backend — so nothing here proves the Pico accepts a secp256k1 unwrap.
# That question is OPEN (PROOF-OF-WORKS.md) and is settled only by the hardware run.
# Per doctrine §11: a hermetic pass is a precondition, not a substitute.
#
# The API-usage assertions below are REGRESSION tests. Each one encodes a mistake that actually
# cost debugging time against the real device, so a future edit cannot silently reintroduce it.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
SH="$SCRIPTS/hsm-auto-import.sh"
JS="$SCRIPTS/hsm-auto-import.js"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -r "$SH" ] || { echo "  (skipping: $SH not found)"; exit 0; }
[ -r "$JS" ] || { echo "  (skipping: $JS not found)"; exit 0; }

# Emit only EXECUTABLE lines of a JS file: drop /* … */ block-comment bodies (which in this
# file are '*'-prefixed), whole-line '//' comments, and trailing '// …' tails.
#
# WHY THIS EXISTS: the "does the code do X?" assertions below were first written as a plain
# grep over the whole file, and they fired on the COMMENTS that explain why the code avoids X.
# The naive fix — deleting the prose to go green — would have destroyed the very documentation
# that stops the trap being reintroduced. The property under test is about code, so the input
# must be code (doctrine §4: fix the input, not the assertion, once you know which is wrong).
code_only() {
  sed -e 's://.*::' "$1" \
    | sed -e '/^[[:space:]]*\*/d' -e '/^[[:space:]]*\/\*/d' -e '/^[[:space:]]*$/d'
}

# The stripper is itself load-bearing, so prove it BOTH ways before relying on it: it must keep
# real code and drop commentary. A stripper that ate everything would make every assertion below
# pass vacuously (doctrine §7: a guard that matches nothing is as bad as one that matches all).
_stripped="$(code_only "$JS")"
_shell_code="$(python3 "$HERE/source_lexing.py" shell "$SH")" \
  || { echo "source lexer failed" >&2; exit 2; }
grep -q "createDKEKKeyDomain" <<< "$(printf '%s\n' "$_stripped")" \
  && P "comment-stripper keeps executable lines" \
  || F "BUG: comment-stripper ate real code — every assertion below would pass vacuously"
grep -q "WHY createDKEKKeyDomain AND NOT" <<< "$(printf '%s\n' "$_stripped")" \
  && F "BUG: comment-stripper left block-comment prose in place" \
  || P "comment-stripper removes commentary"

# =====================================================================================
hdr "Both files are syntactically valid"
bash -n "$SH" 2>/dev/null && P "hsm-auto-import.sh parses" || F "hsm-auto-import.sh has a syntax error"
# node parses the JS well enough to catch unbalanced braces/strings even though the scsh3
# globals are absent at parse time.
if command -v node >/dev/null 2>&1; then
  node --check "$JS" 2>/dev/null && P "hsm-auto-import.js parses" \
    || F "hsm-auto-import.js has a syntax error"
else
  echo "   (node absent — skipping JS parse)"
fi

# =====================================================================================
hdr "THE REFUSAL: --initialize must be rejected, because it needs a physical replug"
# Measured on real hardware: every --initialize drops the Pico off the USB bus. An unattended
# run that reaches it is dead until a human intervenes. A guard is only verified by a failing
# case, so invoke it and assert the refusal (doctrine §7).
out="$("$SH" --initialize 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && P "exits 2 on --initialize (rc=$rc)" || F "expected exit 2, got $rc"
grep -qi "REFUSED" <<< "$out" && P "says REFUSED" || F "no REFUSED in output"
grep -qi "replug" <<< "$(echo "$out")" \
  && P "explains WHY (needs a physical replug), not just that it refused" \
  || F "refusal does not explain the USB-bus reason — an operator would just retry"
out2="$("$SH" --init 2>&1)"; rc2=$?
if [ "$rc2" -eq 2 ] && grep -qi "REFUSED" <<< "$out2"; then
  P "the --init abbreviation is refused too, and says so"
else
  F "--init slipped through or was not reported as REFUSED (rc=$rc2)"
fi

# =====================================================================================
hdr "SECRET HYGIENE: no secret is inlined, and none reaches argv"
# An earlier throwaway draft hardcoded the PKCS#12 password as a literal. That is the exact
# defect this asserts against.
grep -qE '(iBUueVUu|password[[:space:]]*=[[:space:]]*"[A-Za-z0-9]{12,}")' "$JS" \
  && F "BUG: a literal secret appears in hsm-auto-import.js" \
  || P "no hardcoded secret literal in the JS"
# Every secret must arrive as a FILE PATH via the environment, never as a value.
for v in HSM_P12_PW_FILE HSM_DKEK_PW_FILE HSM_USER_PIN_FILE; do
  grep -q "$v" <<<"$_stripped" || { F "JS does not read $v"; break; }
done
grep -q "HSM_USER_PIN_FILE" <<<"$_stripped" && P "secrets arrive as file PATHS via env, not as values" \
                                  || F "secret-by-path contract not honoured"
# sc-hsm-tool must get the DKEK password via env:VAR, never as a literal argument.
grep -q -- "--password env:" <<<"$_shell_code" \
  && P "sc-hsm-tool gets the DKEK password via env:VAR (never on argv)" \
  || F "DKEK password is not passed via env: — it would be visible in ps"
grep -qE -- "--password[[:space:]]+[^e]" <<<"$_shell_code" \
  && F "BUG: a --password value appears directly on argv" \
  || P "no --password literal on argv"

# =====================================================================================
hdr "THE AUTOMATION CLAIM: the domain is created over APDU, not by re-initialising"
grep -q "createDKEKKeyDomain" <<<"$_stripped" \
  && P "uses createDKEKKeyDomain (APDU 80 52 01) to establish the domain" \
  || F "does not use createDKEKKeyDomain — the path is not automatable without it"
grep -qE '(^|[^-])--initialize' <<< "$(code_only "$JS")" \
  && F "BUG: the JS reaches for --initialize, which breaks unattended operation" \
  || P "the JS never invokes --initialize (comments explaining why are expected and fine)"

# =====================================================================================
hdr "REGRESSION: the four scsh3 API traps that cost real debugging time"
# 1. new ByteString(path, BASE64) DECODES THE PATH STRING as base64 — it does not read a file.
grep -qE 'new ByteString\([^,]*,[[:space:]]*BASE64' <<< "$(code_only "$JS")" \
  && F "BUG: ByteString(path, BASE64) used to read a file — it decodes the path as base64" \
  || P "files are not read via ByteString(path, BASE64)"
grep -q "readFileFromDisk" <<<"$_stripped" \
  && P "uses PKIXCommon.readFileFromDisk to read files" \
  || F "no readFileFromDisk — how is the DKEK share being read?"
# 2. DKEK needs a plain Crypto (has .digest); sc.getCrypto() returns SmartCardHSMCrypto (no .digest).
grep -q "new DKEK(new Crypto())" <<<"$_stripped" \
  && P "DKEK is constructed with a plain new Crypto() (which has .digest)" \
  || F "DKEK not built from a plain Crypto — sc.getCrypto() lacks .digest and will throw"
grep -q "new DKEK(sc.getCrypto())" <<<"$_stripped" \
  && F "BUG: DKEK built from sc.getCrypto(), which has no .digest" \
  || P "does not pass SmartCardHSMCrypto to DKEK"
# 3. KeyStore wants plain JS strings for path+password.
grep -qE 'new KeyStore\("BC",[[:space:]]*"PKCS12",[[:space:]]*P12,[[:space:]]*P12_PW\)' <<<"$_stripped" \
  && P "KeyStore is given plain strings for path and password" \
  || F "KeyStore call does not use plain string path/password"
# 4. The DKEK share password is the LITERAL ASCII string, not hex bytes.
grep -qE 'ByteString\(DKEK_PW,[[:space:]]*ASCII\)' <<<"$_stripped" \
  && P "DKEK password passed as ASCII (matches sc-hsm-tool --password env:VAR)" \
  || F "DKEK password not passed as ASCII — HEX fails the decrypt"

# =====================================================================================
hdr "FAIL-CLOSED: a partially-satisfied DKEK domain must abort before wrapping"
# If the domain still wants more shares, the blob would be encoded under a DIFFERENT DKEK than
# the card holds — which is precisely the unexplained SW=6400 from the hardware run.
grep -q "outstanding" <<<"$_stripped" \
  && P "checks the domain's outstanding-share count" \
  || F "does not check outstanding shares — would wrap under the wrong DKEK"
grep -qE 'outstanding [!>]' <<<"$_stripped" \
  && P "aborts when shares are still outstanding" \
  || F "outstanding count read but not enforced"

# =====================================================================================
hdr "FAIL-CLOSED: preflight refuses when no card is present"
FAKE="$(mktemp -d)"; trap 'rm -rf "$FAKE"' EXIT
cat > "$FAKE/opensc-tool" <<'STUB'
#!/usr/bin/env bash
exit 1          # model: reader present, no card -> no ATR
STUB
cat > "$FAKE/sc-hsm-tool" <<'STUB'
#!/usr/bin/env bash
echo "SmartCard-HSM has never been initialized."
STUB
chmod +x "$FAKE/opensc-tool" "$FAKE/sc-hsm-tool"
out="$(PATH="$FAKE:$PATH" "$SH" --check 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "--check fails closed with no card (rc=$rc)" \
                || F "BUG: --check returned 0 with no card attached"
grep -qi "no ATR" <<< "$out" && P "names the reason (no ATR)" || F "unclear no-card message"

hdr "FAIL-CLOSED: an uninitialised device is reported as needing one-time provisioning"
cat > "$FAKE/opensc-tool" <<'STUB'
#!/usr/bin/env bash
case "$*" in *--atr*) echo "3bfe1800008131fe458031815448534d31738021408107fa"; exit 0;; esac
exit 0
STUB
chmod +x "$FAKE/opensc-tool"
out="$(PATH="$FAKE:$PATH" "$SH" --check 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "--check fails on an uninitialised device (rc=$rc)" \
                || F "BUG: accepted an uninitialised device"
grep -qi "NOT initialised" <<< "$(echo "$out")" \
  && P "tells the operator to run the one-time provisioning" \
  || F "does not explain that provisioning is required"
grep -qi "5448534d31\|THSM1" <<< "$out" \
  && P "still recognises the THSM1 ATR (hex-text match, not the literal string)" \
  || F "ATR recognition broken"

# =====================================================================================
hdr "The ATR check matches the HEX TEXT of THSM1, not the literal string"
# The variable holds hex characters ("…5448534d31…"); a *THSM1* glob can never match it.
# This exact confusion made the hardware-mode gate skip on a card that was plainly present.
grep -q "5448534d31" <<<"$_shell_code" \
  && P "matches 5448534d31 (hex text of ASCII THSM1)" \
  || F "BUG: ATR matched as a literal string — will never fire against hex output"

# =====================================================================================
hdr "Provisioning is documented in the file the operator will actually read"
# These three assertions deliberately inspect comments: the documentation is their subject.
# Running them against executable-only text makes both command checks fail, which is the control
# proving this is an intentional raw-source scan rather than an overlooked false positive.
grep -qi "one-time" "$SH" && P "labels --initialize as one-time provisioning" \
                          || F "no one-time provisioning note"
# The command must name the READER too: with two identically-named Pico readers on the bench,
# `sc-hsm-tool --initialize` without -r aims a full wipe by enumeration order. So this matches the
# essential flags in order rather than one exact literal, which broke when -r "$READER" was added.
grep -qE 'sc-hsm-tool .*--initialize .*--so-pin' "$SH" \
  && P "gives the exact provisioning command" \
  || F "operator would have to reconstruct the provisioning command"
grep -qE 'sc-hsm-tool -r [^ ]+ --initialize' "$SH" \
  && P "and that command names the reader, so it cannot wipe by enumeration order" \
  || F "the documented provisioning command omits -r — it would target whichever card enumerated first"

# =====================================================================================
hdr "EXECUTION: the non-APDU stages of --run actually work against the emulator"
# Everything above is STATIC (it greps the source). Static checks prove the script SAYS the
# right thing; they cannot prove it DOES it. This block runs the real container build and the
# real DKEK-share creation against the emulator shim, with ONLY the scsh3/APDU step stubbed —
# because that step needs a card and the shim has no APDU backend (doctrine §11).
if ! command -v openssl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  echo "   (openssl/python3 absent — skipping execution block)"
else
  EX="$(mktemp -d)"
  EMUBIN="$HERE/../bin"
  export EMU_SCHSM_STATE="$EX/schsm"
  # Stub only what genuinely needs hardware: the card probe and the scriptrunner.
  mkdir -p "$EX/bin/scsh"
  cat > "$EX/bin/opensc-tool" <<'STUB'
#!/usr/bin/env bash
case "$*" in *--atr*) echo "3bfe1800008131fe458031815448534d31738021408107fa"; exit 0;; esac
exit 0
STUB
  # A card that reports as initialised with one DKEK share reserved.
  cat > "$EX/bin/sc-hsm-tool" <<STUB
#!/usr/bin/env bash
# delegate everything real to the emulator shim; only the bare status call is modelled here
if [ \$# -eq 0 ]; then
  echo "Version              : 4.1"
  echo "DKEK shares          : 1"
  exit 0
fi
exec "$EMUBIN/sc-hsm-tool" "\$@"
STUB
  cat > "$EX/bin/scsh/scriptrunner" <<'STUB'
#!/usr/bin/env bash
# The APDU step cannot be emulated (no scsh3/APDU backend). Assert the driver passed every
# secret BY PATH and that each path is readable, then report the success marker.
for v in HSM_P12 HSM_P12_PW_FILE HSM_DKEK_SHARE HSM_DKEK_PW_FILE HSM_USER_PIN_FILE; do
  eval "p=\${$v:-}"
  [ -n "$p" ] || { echo "STUB-FAIL $v unset"; exit 1; }
  [ -r "$p" ] || { echo "STUB-FAIL $v not readable: $p"; exit 1; }
done
echo "STUB: all secrets arrived as readable paths"
echo "IMPORT-OK"
STUB
  chmod +x "$EX/bin/opensc-tool" "$EX/bin/sc-hsm-tool" "$EX/bin/scsh/scriptrunner"

  runout="$(PATH="$EX/bin:$PATH" HSM_AUTO_DIR="$EX/work" SCSH_HOME="$EX/bin/scsh" \
            CEREMONY_SCRIPTS="$SCRIPTS" "$SH" --run 2>&1)"; runrc=$?

  [ "$runrc" -eq 0 ] && P "--run completes unattended (rc=0), no prompt, no hardware" \
                     || { F "--run failed (rc=$runrc)"; printf '%s\n' "$runout" | tail -12 | sed 's/^/      /'; }
  grep -q "IMPORT-OK" <<< "$runout" && P "reaches the import step and gets IMPORT-OK" \
                                       || F "never reached IMPORT-OK"
  grep -q "STUB: all secrets arrived as readable paths" <<< "$(echo "$runout")" \
    && P "every secret reached the scriptrunner BY PATH (never as a value)" \
    || F "secrets were not all passed by readable path"

  # The container is the real artifact — assert it exists and carries the pinned vector.
  [ -s "$EX/work/funding.p12" ] && P "a real PKCS#12 container was built" \
                                || F "no PKCS#12 produced by --run"
  grep -q "akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0" <<< "$(echo "$runout")" \
    && P "container derives the pinned BIP39 vector address" \
    || F "expected address absent — derivation changed or the build failed"
  [ -s "$EX/work/dkek.pbe" ] && P "a real DKEK share was created via --password env:VAR" \
                             || F "no DKEK share produced"

  # Secret hygiene on the real run output.
  leaked=0
  for f in p12.pw dkek.pw pin.txt; do
    [ -s "$EX/work/$f" ] || continue
    v="$(cat "$EX/work/$f")"
    [ -n "$v" ] && grep -qF "$v" <<< "$runout" && { F "LEAKED $f to stdout"; leaked=1; }
  done
  [ "$leaked" = 0 ] && P "no secret value appeared in --run output"

  # Workdir must be owner-only: it holds the container password and the PIN.
  #
  # PORTABILITY TRAP (caught by CI on Linux, invisible on macOS): `stat -f` means completely
  # different things on the two platforms. On BSD/macOS it is the FORMAT flag; on GNU/Linux it
  # is "display filesystem status" — which SUCCEEDS, printing 'File: "..."'. So ordering the
  # fallback as `stat -f … || stat -c …` never reaches the GNU branch on Linux and yields
  # garbage instead of a mode. Try GNU FIRST: `stat -c` is invalid on macOS and fails cleanly,
  # so the fallback direction actually works.
  perm="$(stat -c '%a' "$EX/work" 2>/dev/null || stat -f '%Lp' "$EX/work" 2>/dev/null)"
  [ "$perm" = "700" ] && P "workdir is 0700 (holds the PIN and container password)" \
                      || F "workdir perms are '$perm', expected 700"
  rm -rf "$EX"
fi

# =================================================================================================
hdr "PROD must never provision a card with the PUBLISHED example PIN (B6, B7)"
# WHAT THIS FOUND. The line was `${HSM_USER_PIN:-648219}` — unset meant the card silently received
# the documented pico-hsm PIN. ceremony.sh's dev-default guard does NOT catch it: that guard checks
# the PIN written into the tier-0 PAYLOAD (hsm_a_user_pin et al) and its regex blocks 648219 there,
# but NOTHING connects that value to this one. A prod ceremony could pass every guard, escrow a
# strong PIN on metal, and hand the rack a card whose real PIN is in the vendor docs.
#
# WHAT THIS CANNOT PROVE. These are STATIC assertions. The guard sits after preflight, which needs a
# real card, so no test here executes it. It proves the refusal is WRITTEN, not that it FIRES —
# that belongs to the hardware drill. Said plainly so a green run is not mistaken for the stronger
# claim.
CER="$SCRIPTS/ceremony.sh"

grep -q 'CEREMONY_MODE:-dev' <<<"$_shell_code" && grep -qE '^\s*prod\)' <<<"$_shell_code" \
  && P "a prod branch exists around the PIN decision" \
  || F "no prod branch — an unset HSM_USER_PIN still defaults silently"

grep -q 'HSM_USER_PIN is unset' <<<"$_shell_code" \
  && P "prod REFUSES when HSM_USER_PIN is unset (never defaults)" \
  || F "prod does not refuse on unset — the published PIN can still reach a production card"

grep -q 'recognised dev default' <<<"$_shell_code" \
  && P "prod also refuses an EXPLICITLY supplied dev default" \
  || F "supplying 648219 by hand is still accepted in prod"

# The message has to name the consequence, or an operator hitting it at 2am just exports the
# variable with whatever is at hand.
msg="$(grep -A3 'HSM_USER_PIN is unset' <<<"$_shell_code" || true)"
grep -qi 'escrowed PIN will not open the card\|recovery burns attempts' <<<"$msg" \
  && P "…and explains that a mismatched PIN costs recovery attempts" \
  || F "the refusal does not explain the cost, so it reads as bureaucracy"

hdr "The two dev-default lists must not DRIFT apart"
# ceremony.sh guards the payload value; hsm-auto-import.sh guards the card value. They are separate
# code paths that must agree on what counts as a dev default — otherwise one accepts what the other
# rejects, which is precisely the disconnect that produced this bug.
if [ -r "$CER" ]; then
  missing=""
  for d in 648219 3537363231383830 CHANGEME TODO FILL_IN; do
    grep -q "$d" <<<"$_shell_code" || missing="$missing $d"
  done
  [ -z "$missing" ] && P "hsm-auto-import.sh rejects every default ceremony.sh rejects" \
                    || F "drift: ceremony.sh blocks these but the import path does not:$missing"
else
  printf '  \033[33mSKIP\033[0m ceremony.sh not readable — cannot check for drift\n'
fi

hdr "REGRESSION: an unwrapped key is DESCRIBED, or no PKCS#11 consumer can see it"
# Measured on a Nitrokey HSM 2 (DENK0404144, fw 4.1, 2026-09-17): unwrapKey alone left only EF CCxx
# on the card, and OpenSC listed no private key even logged in. The Pico hid this by listing the key
# anyway. The description (EF C4xx) must be written, and written AFTER the unwrap succeeded.
_unwrap_line="$(grep -n 'sc.unwrapKey(' <<<"$_stripped" | head -1 | cut -d: -f1)"
_prkd_line="$(grep -n 'buildPrkDforECC(' <<<"$_stripped" | head -1 | cut -d: -f1)"
_upd_line="$(grep -n 'updateBinary(.*PRKDPREFIX' <<<"$_stripped" | head -1 | cut -d: -f1)"
if [ -n "$_unwrap_line" ] && [ -n "$_prkd_line" ] && [ -n "$_upd_line" ] \
   && [ "$_prkd_line" -gt "$_unwrap_line" ] && [ "$_upd_line" -gt "$_prkd_line" ]; then
  P "the PrKD is built and written to C4xx after unwrapKey"
else
  F "no PKCS#15 description is written after unwrapKey (unwrap=$_unwrap_line build=$_prkd_line write=$_upd_line): the key will be invisible on a genuine SmartCard-HSM"
fi

hdr "PORTABILITY: no xxd on the secret path, and an empty password is refused"
# xxd is absent from minimal Debian and from the vault-tools image; without set -e its absence
# produced an empty DKEK password file and a green "DKEK share created" (2026-09-17).
if grep -qE '(^|[^[:alnum:]_-])xxd([^[:alnum:]_-]|$)' <<<"$_shell_code"; then
  F "hsm-auto-import.sh still calls xxd"
else
  P "hsm-auto-import.sh does not depend on xxd"
fi
if grep -q 'dkek.pw").*-eq 32' <<<"$_shell_code"; then
  P "the generated DKEK password length is asserted"
else
  F "nothing refuses an empty or short DKEK password file"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
