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
       'step_set_pins; rc=$?; cp -p "$WORK/pins.env" "%s.kept" 2>/dev/null; cp -rp "$WORK/pin-blobs" "%s.blobs" 2>/dev/null; cp -p "$WORK/escrow-mac.kcv" "%s.kcv" 2>/dev/null; echo "RC=$rc"') % (scripts, scripts, work, work, work, work)
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.execvp("bash", ["bash", "-c", cmd])
screen, shown, pending = "", {}, ""
# Each PIN is a queue: in mode "typed-weak" the first entries are refused (a date, a run, a reuse of
# another device's PIN, a too-short YubiKey PIN) and the prompt must ask again; the last is accepted.
typed = {"hsm_a_user_pin": ["7310048261"], "hsm_b_user_pin": ["5512096374"], "hsm_c_user_pin": ["4096128803"],
         "yubikey_a_piv_pin": ["90817263"], "yubikey_b_piv_pin": ["63517240"], "yubikey_c_piv_pin": ["27481059"]}
if mode == "typed-weak":
    # DDMMYYYY, a run, a repeating pattern, one repeated digit, two digits non-periodic, then accepted
    typed["hsm_a_user_pin"] = ["0101199012", "1234567890", "1231231231", "1111111111", "1212121122", "7310048261"]
    # reuse of hsm_a's PIN, YYYYMMDD, MMDDYYYY, then accepted
    typed["hsm_b_user_pin"] = ["7310048261", "1990010112", "1225198500", "5512096374"]
    typed["yubikey_a_piv_pin"] = ["908172", "25121985", "90817263"]
seen = {}
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
        send("y\n" if mode.startswith("typed") else "n\n"); pending = ""
    elif "as encrypted blobs for KMS hosts" in pending and pending.rstrip().endswith("[y/N]"):
        send("y\n" if mode == "typed-blob" else "n\n"); pending = ""
    elif re.search(r"public key file of the host for (HSM|YubiKey) (\S+) \(empty to skip\): $", pending):
        m = re.search(r"for (HSM|YubiKey) (\S+) \(empty", pending)
        want = {("HSM", "A"): "BLOB_PUB", ("YubiKey", "B"): "BLOB_PUB"}.get((m.group(1), m.group(2)))
        send((os.environ.get(want, "") if want else "") + "\n"); pending = ""
    elif re.search(r"fingerprint, from your handwritten note: $", pending):
        send(os.environ.get("BLOB_FP", "") + "\n"); pending = ""
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
        m = re.search(r"(\S+) (\(hidden\)|again): $", pending)
        name, which = m.group(1), m.group(2)
        if which == "(hidden)":
            seen[name] = seen.get(name, -1) + 1
        queue = typed[name]
        send(queue[min(seen.get(name, 0), len(queue) - 1)] + "\n"); pending = ""
print(screen)
for k, v in shown.items(): print("DRIVER: shown %s=%s" % (k, v))
PY
}
# The wizard shreds its workdir on exit (its EXIT trap); the driver keeps a copy as <workdir>.kept.
field(){ sed -n "s/^$1=//p" "$2.kept"; }

hdr "generate: recovery credentials generated and never shown; day-to-day PINs shown once, typed back"
W="$T/gen"; mkdir -p "$W"; out="$(drive gen-ok "$W")"
grep -q "RC=0" <<< "$out" && P "step 0 succeeds (PROD mode)" || F "step 0 failed: $(tail -15 <<< "$out")"
[ "$(grep -c '^DRIVER: shown' <<< "$out")" = 7 ] && P "six day-to-day PINs and the escrow MAC key shown (HSM A-C, YubiKey A-C)" || F "shown: $(grep DRIVER <<< "$out")"
[[ "$(field escrow_mac_key "$W")" =~ ^[0-9A-F]{32}$ ]] && grep -qx "DRIVER: shown escrow_mac_key=$(field escrow_mac_key "$W")" <<< "$out" \
  && P "the escrow MAC key is generated (32 hex), stored, and shown once for the PIN card" || F "escrow MAC key missing, malformed or not shown"
[ -s "$W.kcv" ] && [ "$(cat "$W.kcv")" = "$(python3 "$SCRIPTS/escrow/pin_escrow_mac.py" kcv <<< "$(field escrow_mac_key "$W")")" ] \
  && P "escrow-mac.kcv is the stored key's check value" || F "escrow-mac.kcv missing or wrong"
[ -f "$W.kept" ] && [ "$(stat -c %a "$W.kept")" = 600 ] && P "pins.env is 0600" || F "pins.env missing or wrong mode"
ok=1
for k in hsm_a_so_pin hsm_b_so_pin hsm_c_so_pin; do [[ "$(field $k "$W")" =~ ^[0-9A-F]{16}$ ]] || ok=0; done
for k in hsm_a_user_pin hsm_b_user_pin hsm_c_user_pin; do [[ "$(field $k "$W")" =~ ^[0-9]{10}$ ]] || ok=0; done
for y in a b c; do [[ "$(field yubikey_${y}_piv_pin "$W")" =~ ^[0-9]{8}$ ]] && [[ "$(field yubikey_${y}_piv_puk "$W")" =~ ^[0-9]{8}$ ]] \
  && [[ "$(field yubikey_${y}_mgmt_key "$W")" =~ ^[0-9A-F]{48}$ ]] || ok=0; done
[ "$ok" = 1 ] && P "every field has its device's shape" || F "a field is malformed"
leak=0; for k in hsm_a_so_pin hsm_b_so_pin hsm_c_so_pin yubikey_a_piv_puk yubikey_b_piv_puk yubikey_c_piv_puk yubikey_a_mgmt_key yubikey_b_mgmt_key yubikey_c_mgmt_key; do grep -qF "$(field $k "$W")" <<< "$(grep -v '^DRIVER' <<< "$out")" && leak=1; done
[ "$leak" = 0 ] && P "no SO-PIN, PUK or management key appeared on the screen" || F "a recovery credential was shown"
match=1; for k in hsm_a_user_pin hsm_b_user_pin hsm_c_user_pin yubikey_a_piv_pin yubikey_b_piv_pin yubikey_c_piv_pin; do grep -qx "DRIVER: shown $k=$(field $k "$W")" <<< "$out" || match=0; done
[ "$match" = 1 ] && P "the PINs shown are the PINs stored" || F "shown and stored PINs differ"
grep -q "every loaded credential is distinct" <<< "$out" && P "credential separation passed" || F "separation not reported"

hdr "generate twice: different values (not a fixed or seeded generator)"
W2="$T/gen2"; mkdir -p "$W2"; drive gen-ok "$W2" >/dev/null
[ "$(field hsm_a_so_pin "$W")" != "$(field hsm_a_so_pin "$W2")" ] && [ "$(field yubikey_a_mgmt_key "$W")" != "$(field yubikey_a_mgmt_key "$W2")" ] && [ -n "$(field yubikey_a_mgmt_key "$W")" ] && P "values differ between runs" || F "the same values twice"

hdr "a PIN copied wrongly three times: no PIN file kept, step 0 fails"
W="$T/wrong"; mkdir -p "$W"; out="$(drive gen-wrong "$W")"
grep -q "RC=1" <<< "$out" && [ ! -e "$W.kept" ] && grep -q "three mismatches" <<< "$out" && P "refused, nothing kept" || F "wrong copies accepted: $(tail -8 <<< "$out")"

hdr "typed: the operator chooses the day-to-day PINs; recovery credentials still generated"
W="$T/typed"; mkdir -p "$W"; out="$(drive typed "$W")"
grep -q "RC=0" <<< "$out" && P "step 0 succeeds" || F "typed path failed: $(tail -10 <<< "$out")"
[ "$(field hsm_a_user_pin "$W")" = 7310048261 ] && [ "$(field hsm_c_user_pin "$W")" = 4096128803 ] && [ "$(field yubikey_a_piv_pin "$W")" = 90817263 ] && [ "$(field yubikey_c_piv_pin "$W")" = 27481059 ] && P "typed PINs stored" || F "typed PINs not stored"
[[ "$(field hsm_c_so_pin "$W")" =~ ^[0-9A-F]{16}$ ]] && P "SO-PINs still generated" || F "SO-PIN not generated"
grep '^DRIVER: shown' <<< "$out" | grep -qv '^DRIVER: shown escrow_mac_key=' && F "a typed PIN was displayed" || P "typed PINs are not displayed (only the generated escrow MAC key is)"
grep -qE "7310048261|5512096374|4096128803|90817263|63517240|27481059" <<< "$out" && F "a typed PIN was echoed" || P "typed PINs not echoed"
grep -q "print the blank PIN card yourself\|blank PIN card sent" <<< "$out" && P "the blank PIN card is offered in typed mode too" || F "no PIN card in typed mode"

hdr "typed: guessable, reused and short PINs are refused, and the prompt asks again"
W="$T/weak"; mkdir -p "$W"; out="$(drive typed-weak "$W")"
grep -q "RC=0" <<< "$out" && P "step 0 succeeds once acceptable PINs are typed" || F "typed-weak path failed: $(tail -10 <<< "$out")"
[ "$(grep -c "refused: it contains a date" <<< "$out")" -ge 4 ] && P "dates are refused in every order (DDMMYYYY, YYYYMMDD, MMDDYYYY, and as a YubiKey PIN)" || F "dates not refused: $(grep -c 'contains a date' <<< "$out")"
grep -q "refused: it is one digit repeated" <<< "$out" && P "a repeated digit is refused" || F "repeated digit not refused"
grep -q "refused: it uses only two different digits" <<< "$out" && P "two distinct digits are refused" || F "two-digit PIN not refused"
leaked=0; for v in 0101199012 1234567890 1231231231 1111111111 1212121122 1990010112 1225198500 908172 25121985 01011990 19900101 12251985; do grep -qF "$v" <<< "$(grep -v '^DRIVER' <<< "$out")" && leaked=1; done
[ "$leaked" = 0 ] && P "no digit sequence of a refused PIN appears on the screen" || F "a refused PIN's digits were printed"
grep -q "3<<< \"\$1\"" "$SCRIPTS/ceremony.sh" && ! grep -q 'python3 - "\$1"' "$SCRIPTS/ceremony.sh" && P "the PIN reaches the checker on a file descriptor, not argv" || F "the PIN may be on argv"
grep -q "refused: it is a run of consecutive digits" <<< "$out" && P "a run of digits is refused" || F "run not refused"
grep -q "refused: it repeats a short pattern" <<< "$out" && P "a repeating pattern is refused" || F "pattern not refused"
grep -q "already used for another device" <<< "$out" && P "a PIN reused across devices is refused" || F "reuse not refused"
grep -q "a YubiKey PIN is 8 digits" <<< "$out" && P "a 6-digit YubiKey PIN is refused" || F "short YubiKey PIN accepted"
[ "$(field hsm_a_user_pin "$W")" = 7310048261 ] && [ "$(field hsm_b_user_pin "$W")" = 5512096374 ] && [ "$(field yubikey_a_piv_pin "$W")" = 90817263 ] \
  && P "only the accepted PINs are stored" || F "a refused PIN was stored"

hdr "typed-blob: HSM A's PIN is written as a TPM import blob for its host (ADR-0002 D21)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$T/host.key" 2>/dev/null
openssl pkey -in "$T/host.key" -pubout -out "$T/host.pub.pem"
fp="$(openssl pkey -pubin -in "$T/host.pub.pem" -outform der | sha256sum | cut -c1-16)"
W="$T/blob"; mkdir -p "$W"; out="$(BLOB_PUB="$T/host.pub.pem" BLOB_FP="$fp" drive typed-blob "$W")"
grep -q "RC=0" <<< "$out" && P "step 0 succeeds" || F "typed-blob path failed: $(tail -10 <<< "$out")"
[ -s "$W.blobs/pin-hsm_a.blob" ] && P "pin-hsm_a.blob written" || F "no blob for HSM A"
[ ! -e "$W.blobs/pin-hsm_b.blob" ] && P "HSM B skipped (no public key given)" || F "a blob for a skipped HSM"
[ -s "$W.blobs/pin-yubikey_b.blob" ] && P "pin-yubikey_b.blob written (YubiKey PIV PINs go to the TPM too)" || F "no blob for YubiKey B"
got="$(openssl pkeyutl -decrypt -inkey "$T/host.key" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$W.blobs/pin-yubikey_b.blob" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
[ -n "$got" ] && [ "$got" = "$(printf '%s' "$(field yubikey_b_piv_pin "$W")" | od -An -tx1 | tr -d ' \n')" ] && P "the YubiKey blob opens to exactly YubiKey B's PIV PIN" || F "the YubiKey blob does not open to its PIN"
got="$(openssl pkeyutl -decrypt -inkey "$T/host.key" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$W.blobs/pin-hsm_a.blob" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
[ -n "$got" ] && [ "$got" = "$(printf '%s' "$(field hsm_a_user_pin "$W")" | od -An -tx1 | tr -d ' \n')" ] && P "the blob opens to exactly HSM A's PIN bytes" || F "the blob does not open to HSM A's PIN"

hdr "an existing pins.env is loaded as before (hand-made files still work)"
W="$T/file"; mkdir -p "$W"
# 48-hex placeholders built at runtime, so no key-shaped literal sits in the repo (gitleaks).
{ printf 'hsm_a_user_pin=3141592653\nhsm_a_so_pin=A1B2C3D4E5F60718\nhsm_b_user_pin=2718281828\nhsm_b_so_pin=0F1E2D3C4B5A6978\nhsm_c_user_pin=1414213562\nhsm_c_so_pin=7E8F90A1B2C3D4E5\n'
  printf 'yubikey_a_piv_pin=161803\nyubikey_a_piv_puk=17320508\nyubikey_a_mgmt_key=%s\n' "$(printf 'AB%.0s' {1..24})"
  printf 'yubikey_b_piv_pin=223606\nyubikey_b_piv_puk=24494897\nyubikey_b_mgmt_key=%s\n' "$(printf 'CD%.0s' {1..24})"
  printf 'yubikey_c_piv_pin=264575\nyubikey_c_piv_puk=28284271\nyubikey_c_mgmt_key=%s\n' "$(printf 'EF%.0s' {1..24})"
  printf 'escrow_mac_key=%s\n' "$(printf 'E5%.0s' {1..16})"; } > "$W/pins.env"   # a 48-hex placeholder, built so no key-shaped literal sits in the repo
# shellcheck disable=SC2034  # WORK and CEREMONY_MODE are read by the sourced step_set_pins
out="$( ( source "$SCRIPTS/ceremony.sh" >/dev/null 2>&1; HERE="$SCRIPTS"; WORK="$W"; CEREMONY_MODE=prod; step_set_pins </dev/null; echo "RC=$?" ) 2>&1 )"
grep -q "RC=0" <<< "$out" && ! grep -q "generate the credentials" <<< "$out" && P "loaded without asking to generate" || F "file path changed: $(tail -5 <<< "$out")"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
