#!/usr/bin/env bash
# test-step0-generated-credentials.sh — step 0 generates the credentials (owner, 2026-09-29).
# Driven through a real pseudo-terminal, like the vault's xterm: the driver reads each day-to-day
# PIN off the "screen" and types it back, as the operator does from paper. No test hook exists in
# the generator: the values come from `secrets`, and the test learns them only as a person would.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# drive <mode> <workdir>: mode = gen-ok | gen-wrong | typed. Prints the (ANSI-stripped) screen,
# then DRIVER: lines describing what was shown.
drive(){ python3 - "$1" "$2" "$SCRIPTS" <<'PY'
import os, pty, re, sys, time, select
mode, work, scripts = sys.argv[1:4]
cmd = ('source "%s/ceremony.sh" >/dev/null 2>&1; HERE="%s"; WORK="%s"; CEREMONY_MODE=prod; '
       'step_set_pins; rc=$?; cp -p "$WORK/pins.env" "%s.kept" 2>/dev/null; echo "RC=$rc"') % (scripts, scripts, work, work)
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.execvp("bash", ["bash", "-c", cmd])
screen, shown, pending = "", {}, ""
typed = {"hsm_a_user_pin": "73100482", "hsm_b_user_pin": "55120963", "yubikey_piv_pin": "908172"}
def send(s): os.write(fd, s.encode())
deadline = time.time() + 60
ansi = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1)
    if not r:
        continue
    try:
        chunk = os.read(fd, 4096).decode(errors="replace")
    except OSError:
        break
    chunk = ansi.sub("", chunk); screen += chunk; pending += chunk
    if "RC=" in pending and re.search(r"RC=\d+", pending):
        break
    if pending.rstrip().endswith("[g/e]"):
        send("g\n"); pending = ""
    elif "yourself instead" in pending and pending.rstrip().endswith("[y/N]"):
        send("y\n" if mode == "typed" else "n\n"); pending = ""
    elif re.search(r"press Enter to SHOW the (\S+)", pending) and pending.rstrip().endswith("…"):
        send("\n"); pending = ""
    elif "press Enter to CLEAR" in pending and pending.rstrip().endswith("…"):
        hits = re.findall(r"(\S+) — write it down by hand[ =]*\n\s*(\S+)\s*\n", screen)
        if hits: shown[hits[-1][0]] = hits[-1][1]        # the one on screen now, not an earlier one
        send("\n"); pending = ""
    elif re.search(r"type the (\S+) back FROM YOUR PAPER \(hidden\): $", pending):
        name = re.search(r"type the (\S+) back", pending).group(1)
        send(("00000000" if mode == "gen-wrong" else shown.get(name, "?")) + "\n"); pending = ""
    elif re.search(r"(\S+) (\(hidden\)|again): $", pending):
        name = re.search(r"(\S+) (\(hidden\)|again): $", pending).group(1)
        send(typed[name] + "\n"); pending = ""
print(screen)
for k, v in shown.items(): print("DRIVER: shown %s=%s" % (k, v))
PY
}
# The wizard shreds its workdir on exit (its EXIT trap); the driver keeps a copy as <workdir>.kept.
field(){ sed -n "s/^$1=//p" "$2.kept"; }

hdr "generate: recovery credentials generated and never shown; day-to-day PINs shown once, typed back"
W="$T/gen"; mkdir -p "$W"; out="$(drive gen-ok "$W")"
grep -q "RC=0" <<< "$out" && P "step 0 succeeds (PROD mode)" || F "step 0 failed: $(tail -15 <<< "$out")"
[ "$(grep -c '^DRIVER: shown' <<< "$out")" = 3 ] && P "three day-to-day PINs shown" || F "shown: $(grep DRIVER <<< "$out")"
[ -f "$W.kept" ] && [ "$(stat -c %a "$W.kept")" = 600 ] && P "pins.env is 0600" || F "pins.env missing or wrong mode"
ok=1
for k in hsm_a_so_pin hsm_b_so_pin; do [[ "$(field $k "$W")" =~ ^[0-9A-F]{16}$ ]] || ok=0; done
[[ "$(field yubikey_mgmt_key "$W")" =~ ^[0-9A-F]{48}$ ]] || ok=0
[[ "$(field yubikey_piv_puk "$W")" =~ ^[0-9]{8}$ ]] || ok=0
for k in hsm_a_user_pin hsm_b_user_pin yubikey_piv_pin; do [[ "$(field $k "$W")" =~ ^[0-9]{8}$ ]] || ok=0; done
[ "$ok" = 1 ] && P "every field has its device's shape" || F "a field is malformed"
leak=0; for k in hsm_a_so_pin hsm_b_so_pin yubikey_piv_puk yubikey_mgmt_key; do grep -qF "$(field $k "$W")" <<< "$(grep -v '^DRIVER' <<< "$out")" && leak=1; done
[ "$leak" = 0 ] && P "no SO-PIN, PUK or management key appeared on the screen" || F "a recovery credential was shown"
match=1; for k in hsm_a_user_pin hsm_b_user_pin yubikey_piv_pin; do grep -qx "DRIVER: shown $k=$(field $k "$W")" <<< "$out" || match=0; done
[ "$match" = 1 ] && P "the PINs shown are the PINs stored" || F "shown and stored PINs differ"
grep -q "every loaded credential is distinct" <<< "$out" && P "credential separation passed" || F "separation not reported"

hdr "generate twice: different values (not a fixed or seeded generator)"
W2="$T/gen2"; mkdir -p "$W2"; drive gen-ok "$W2" >/dev/null
[ "$(field hsm_a_so_pin "$W")" != "$(field hsm_a_so_pin "$W2")" ] && [ "$(field yubikey_mgmt_key "$W")" != "$(field yubikey_mgmt_key "$W2")" ] && P "values differ between runs" || F "the same values twice"

hdr "a PIN copied wrongly three times: no PIN file kept, step 0 fails"
W="$T/wrong"; mkdir -p "$W"; out="$(drive gen-wrong "$W")"
grep -q "RC=1" <<< "$out" && [ ! -e "$W.kept" ] && grep -q "three mismatches" <<< "$out" && P "refused, nothing kept" || F "wrong copies accepted: $(tail -8 <<< "$out")"

hdr "typed: the operator chooses the day-to-day PINs; recovery credentials still generated"
W="$T/typed"; mkdir -p "$W"; out="$(drive typed "$W")"
grep -q "RC=0" <<< "$out" && P "step 0 succeeds" || F "typed path failed: $(tail -10 <<< "$out")"
[ "$(field hsm_a_user_pin "$W")" = 73100482 ] && [ "$(field hsm_b_user_pin "$W")" = 55120963 ] && [ "$(field yubikey_piv_pin "$W")" = 908172 ] && P "typed PINs stored" || F "typed PINs not stored"
[[ "$(field hsm_a_so_pin "$W")" =~ ^[0-9A-F]{16}$ ]] && P "SO-PIN still generated" || F "SO-PIN not generated"
grep -q '^DRIVER: shown' <<< "$out" && F "a typed PIN was displayed" || P "typed PINs are not displayed"
grep -qE "73100482|55120963|908172" <<< "$out" && F "a typed PIN was echoed" || P "typed PINs not echoed"

hdr "an existing pins.env is loaded as before (hand-made files still work)"
W="$T/file"; mkdir -p "$W"
printf 'hsm_a_user_pin=31415926\nhsm_a_so_pin=A1B2C3D4E5F60718\nhsm_b_user_pin=27182818\nhsm_b_so_pin=0F1E2D3C4B5A6978\nyubikey_piv_pin=161803\nyubikey_piv_puk=14142135\nyubikey_mgmt_key=%s\n' "$(printf 'AB%.0s' {1..24})" > "$W/pins.env"   # a 48-hex placeholder, built so no key-shaped literal sits in the repo
# shellcheck disable=SC2034  # WORK and CEREMONY_MODE are read by the sourced step_set_pins
out="$( ( source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1; HERE="$SCRIPTS"; WORK="$W"; CEREMONY_MODE=prod; step_set_pins </dev/null; echo "RC=$?" ) 2>&1 )"
grep -q "RC=0" <<< "$out" && ! grep -q "generate the credentials" <<< "$out" && P "loaded without asking to generate" || F "file path changed: $(tail -5 <<< "$out")"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
