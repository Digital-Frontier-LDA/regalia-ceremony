#!/usr/bin/env bash
# dress-rehearsal.sh — drive the REAL ceremony.sh wizard end-to-end against the faithful
# emulators (not the tools in isolation — the actual wizard code: its menu, prompt parsing,
# share-regex, printer handling, file flow, secret hygiene). The only thing faked is the
# air-gap network probe (a one-line `ip` stub, like the other harnesses); every hardware
# tool is the real emulator (SoftHSM2, the SLE-4442 over PC/SC, cups-pdf, age, xorriso).
#
# Run inside the emulator image (entrypoint boots the emulators):
#   docker run --rm --privileged ceremony-emu dress-rehearsal
#
# Goal: by the real ceremony day you have watched the actual wizard produce real artifacts
# (an akash address, a printed PDF, reconstructable shares, a wrapped key) so nothing about
# the SCRIPT is a surprise — only the physical tokens are new.
set -uo pipefail
# this harness legitimately stubs the air-gap probe + runs off a non-Qubes box:
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 CEREMONY_ASSERT_UNATTENDED=1
RUN="${EMU_RUN:-/run/vault-emu}"
[ -f "$RUN/env.sh" ] && . "$RUN/env.sh"
SCRIPTS="${CEREMONY_SCRIPTS:-/opt/vault-ceremony/scripts}"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# A recognizable throwaway secret that must NEVER appear in wizard stdout.
MARKER="LEAKCANARY-dress-$$"

# This rehearsal exercises the born-in-HSM funding path deliberately (it is the DKEK + wrap +
# restore-verify route the emulator models). That path is UNSUPPORTED and gated off by default in
# the wizard; opt in explicitly, which also regression-checks that the gate exists.
export CEREMONY_ALLOW_BORN_IN_HSM=1

# --- fake ONLY the air-gap probe; everything else is a real emulator ----------------
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
cat > "$FAKE/ip" <<'S'
#!/usr/bin/env bash
exit 0   # report no routes so preflight treats this container as air-gapped (rehearsal)
S
chmod +x "$FAKE/ip"

# The funding HSM here is SoftHSM2 (pure PKCS#11) — it has NO PC/SC ATR at all, so the wizard's
# device-identity guard (assert_expected_device, which reads `opensc-tool --atr` and looks for the
# real SmartCard-HSM 'THSM1' marker) cannot be satisfied by the emulator. Stub opensc-tool to
# present the genuine Nitrokey HSM 2 ATR for --atr, so the guard runs its real code path against a
# faithful fingerprint; delegate every other opensc-tool call to the real binary so nothing else
# changes. This keeps the guard EXERCISED in CI rather than bypassed.
cat > "$FAKE/opensc-tool" <<'S'
#!/usr/bin/env bash
case " $* " in
  *" --atr "*|*" -a "*) echo "3b:de:96:ff:81:91:fe:1f:c3:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:92"; exit 0;;
esac
for real in /usr/bin/opensc-tool /usr/local/bin/opensc-tool; do
  [ -x "$real" ] && exec "$real" "$@"
done
exit 0
S
chmod +x "$FAKE/opensc-tool"

# --- emulator environment the wizard's tools need -----------------------------------
export EMU_HSM_PIN="648219"
# Assign separately so a failing mktemp is CAUGHT. Inline "$(mktemp -d)/x" masks the exit
# status, so a failure would silently yield "/x" and write test state to the filesystem root.
_emu_schsm="$(mktemp -d)" || { echo "mktemp failed" >&2; exit 1; }
_emu_age="$(mktemp -d)"   || { echo "mktemp failed" >&2; exit 1; }
export EMU_SCHSM_STATE="$_emu_schsm/schsm"
export EMU_AGE_IDENTITY_DIR="$_emu_age/age"
# Isolate our SoftHSM2 token in a FRESH config/tokendir. Otherwise, when this runs after
# route-coverage (which also inits an 'akash-funding' token), the wizard's unqualified
# `pkcs11-tool --keypairgen --id 01` lands on the other suite's slot-0 token and collides.
_SHSM_TOKENS="$(mktemp -d)"
export SOFTHSM2_CONF="$(mktemp -d)/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$_SHSM_TOKENS" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label akash-funding \
  --so-pin 3537363231383830 --pin "$EMU_HSM_PIN" >/dev/null 2>&1

# --- source the real wizard (its sourcing-guard means main() does NOT auto-run) ------
# shellcheck disable=SC1090
source "$SCRIPTS/ceremony.sh"
ask(){ return 0; }     # auto-confirm every "run it?" so real commands actually execute
pause(){ :; }          # don't wait for Enter
# keep the real cleanup (shred workdir); also drop the fake-bin
cleanup(){ [ -n "${WORK:-}" ] && find "$WORK" -type f -exec shred -u {} + 2>/dev/null; rm -rf "${WORK:-}" "$FAKE" 2>/dev/null; }

CAP="$(mktemp)"   # capture all wizard output for the leak scan

# =====================================================================================
hdr "WIZARD PREFLIGHT (real preflight.sh; only air-gap faked)"
if "$SCRIPTS/preflight.sh" >>"$CAP" 2>&1; then P "preflight.sh exits 0 (GO)"; else F "preflight.sh failed — see below"; tail -20 "$CAP" | sed 's/^/      /'; fi
grep -q "PREFLIGHT OK" "$CAP" && P "preflight reports PREFLIGHT OK" || F "no PREFLIGHT OK"

init_work
PRINTER="${EMU_PRINTER:-vault-pdf}"   # the wizard's pick_printer would set this; inject it
info "rehearsal printer: $PRINTER"

# =====================================================================================
hdr "WIZARD STEP 1 — step_yubikey_ops (real age identity behind the plugin)"
out="$(step_yubikey_ops 2>&1)"; echo "$out" >>"$CAP"
grep -qE 'age1[a-z0-9]+' <<< "$out" && P "wizard surfaced a real age recipient" || F "no age recipient from the wizard"
grep -qi updatekeys <<< "$out" && P "wizard shows the .sops.yaml updatekeys follow-up" || F "missing updatekeys guidance"
grep -q "touch policy: never" <<< "$out" && P "wizard selected unattended touch_policy=never" || F "wizard did not prove touch_policy=never"

# =====================================================================================
hdr "WIZARD STEP 2a — #464: a DKEK share file its own shares cannot open stops the ceremony"
# OpenSC 0.27.1 drops a leading zero byte from the password it rebuilds from the shares, so 1 share
# file in 128 cannot be imported with its correct shares (#460). Force that case in the model and
# run the real step: it must stop at the round trip, before any key exists, and tell the room to
# re-mint. It runs before step 2 because it stops before keygen, leaving the token blank.
out="$(EMU_SCHSM_PWD_LEADING_BYTE=zero step_hsm_funding 2>&1)"; echo "$out" >>"$CAP"
grep -q "Error decrypting DKEK share" <<< "$out" \
  && P "the model refused the correct shares of a leading-zero password, as OpenSC does" \
  || F "the forced leading-zero share file was not refused by the import"
grep -q "RE-MINT NOW, before anyone leaves the room" <<< "$out" \
  && P "wizard stops at the round trip and tells the room to re-mint" \
  || F "wizard did not stop at a refused share round trip"
grep -q "EC:secp256k1" <<< "$out" \
  && F "wizard went on to generate a key after the round trip was refused" \
  || P "no key generation after a refused round trip"

# =====================================================================================
hdr "WIZARD STEP 2 — step_hsm_funding (SoftHSM2 keygen/pubkey + DKEK model)"
out="$(step_hsm_funding 2>&1)"; echo "$out" >>"$CAP"
grep -q "pwd-shares-threshold 4 --pwd-shares-total 6" <<< "$out" && P "wizard runs DKEK 4-of-6" || F "no DKEK 4-of-6"
grep -qF -- "--import-dkek-share '$WORK/dkek.pbe' --pwd-shares-total 4" <<< "$out" \
  && P "wizard imports the DKEK share through --pwd-shares-total 4, the way a recovery does" \
  || F "wizard's DKEK import does not go through the share path"
[ ! -e "$WORK/dkek-shares.txt" ] \
  && P "the captured DKEK shares do not outlive the step" \
  || F "the captured DKEK shares were left in the workdir"
grep -q "EC:secp256k1" <<< "$out" && P "wizard runs secp256k1 keygen on the HSM" || F "no secp256k1 keygen"
[ -s "$WORK/funding-pub.der" ] && P "wizard exported the funding pubkey DER" || F "no funding pubkey exported"
if grep -qE 'FUNDING ADDRESS.*akash1[a-z0-9]+' <<< "$out"; then
  P "wizard derived + displayed a real akash funding address: $(echo "$out" | grep -oE 'akash1[a-z0-9]+' | head -1)"
else
  F "wizard did NOT surface an akash address (the --der path may need the real card's SPKI export)"
  echo "$out" | grep -i address | sed 's/^/      /'
fi
[ -s "$WORK/funding-wrapped.bin" ] && P "wizard wrapped the key for DR (DKEK)" || F "no wrapped key produced"
grep -qi "restore-verify OK" <<< "$(echo "$out")" \
  && P "wizard RESTORE-VERIFIED the wrapped backup (unwrap round-trip + restored-pubkey match) before declaring the address fundable" \
  || F "wizard did not restore-verify the DKEK backup — an unrestorable born-in-HSM backup would go undetected"

# =====================================================================================
hdr "WIZARD STEP 3 — step_shamir (ssss 4-of-6) + real printing of each share"
printf '%s' "$MARKER" > "$WORK/secret.in"
out="$(printf 'a\n' | step_shamir 2>&1)"; echo "$out" >>"$CAP"
[ "$(grep -c . "$WORK/shares.txt" 2>/dev/null)" = 6 ] && P "wizard split into 6 ssss shares" || F "expected 6 ssss shares"
# the wizard's print_share sends each share to cups-pdf — assert real PDFs landed. The first
# job after a cold cupsd compiles filters and can take >10s, so poll up to 30s.
npdf=0
for _ in $(seq 1 60); do
  npdf="$(find "${EMU_PDF_OUTDIR:-/var/spool/cups-pdf/out}" -name '*.pdf' 2>/dev/null | wc -l | tr -d ' ')"
  [ "${npdf:-0}" -ge 1 ] && break
  sleep 0.5
done
[ "${npdf:-0}" -ge 1 ] && P "wizard's print_share produced real PDF(s) via cups-pdf ($npdf in outdir)" || F "no PDF produced by the wizard's print path"
# real round-trip from the wizard's OWN shares
R="$( (sed -n '1p;3p;4p;6p' "$WORK/shares.txt") | ssss-combine -t 4 -q 2>&1 )"
[ "$R" = "$MARKER" ] && P "4 of the wizard's 6 shares reconstruct the secret" || F "wizard shares do not reconstruct (got '$R')"

# =====================================================================================
hdr "WIZARD STEP 6 — step_recovery_card (DVD-case card; no secrets) + print"
out="$(printf 'DF-BG-01\nHOLO-000001\n' | step_recovery_card 2>&1)"; echo "$out" >>"$CAP"
ls "$WORK"/recovery-card.ps >/dev/null 2>&1 && P "wizard generated the recovery card (PostScript)" || F "no recovery card generated"

# =====================================================================================
hdr "WIZARD MENU SMOKE — drive main() through the real interactive loop"
# feed: pick_printer queue, then menu choices (1,2,3 + shamir 'a', 5 drill, q). ask/pause
# are overridden so only direct reads consume stdin.
smoke="$(printf '%s\n1\n2\n3\na\n5\nq\n' "$PRINTER" | main 2>&1)"; echo "$smoke" >>"$CAP"
grep -q "Choose a step" <<< "$smoke" && P "main() rendered the interactive menu" || F "menu never rendered"
grep -qi "workdir shredded on exit" <<< "$smoke" && P "main() ran the full loop to a clean exit" || F "main() did not reach clean exit"

# =====================================================================================
hdr "SECRET-LEAK SCAN across the whole rehearsal"
if grep -q "$MARKER" "$CAP"; then F "secret MARKER leaked into wizard output!"; grep -n "$MARKER" "$CAP" | head
else P "no secret value ever printed to stdout across the whole wizard"; fi

rm -f "$CAP"
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && { echo "  REAL WIZARD DRIVEN END-TO-END ON THE EMULATORS — no script surprises expected on the day"; exit 0; } \
                  || { echo "  WIZARD REHEARSAL HAD FAILURES — fix before the real ceremony"; exit 1; }
