#!/usr/bin/env bash
# test-no-pin-on-argv.sh — a PIN, an SO-PIN or a DKEK password never goes on a command line (#94).
#
# argv is public: any local user reads it from /proc/<pid>/cmdline for as long as the command runs,
# and an HSM initialise runs for minutes. pkcs11-tool and sc-hsm-tool (OpenSC 0.26.1) read --pin,
# --so-pin, --new-pin, --puk and --password through util_get_pin, which takes `env:NAME`; so every
# call here passes the NAME on the command line and the value in that one command's environment.
#
#   1  hsm-fleet-drill.sh --run, the whole drill, against RECORDING stubs: every PIN-bearing verb is
#      reached, no secret is in any recorded argv, and each call did receive its secret
#   2  the instrument: the same check, given an argv with a PIN in it, says so
#   3  every non-test script: no token-tool option takes a secret from a shell variable on argv
#   4  the emulator's sc-hsm-tool refuses a PIN on its command line, so a regression fails the suites
#
# NO HARDWARE CAN BE REACHED. Every tool that talks to a card is a stub first on PATH, and PC/SC
# itself is pointed at a socket that does not exist, so a tool this list forgot cannot find a reader
# either. (A "hardware-free" suite once spent two PIN retries on a bench card: test-fleet-device-selection.sh.)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
DRILL="$ROOT/qubes/scripts/hsm-fleet-drill.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir "$T/bin"; : > "$T/fake-module.so"
export PCSCLITE_CSOCK_NAME="$T/no-pcscd.sock"

# The secrets of this run: distinctive, so that finding one in an argv cannot be a coincidence.
PIN_A=424242; PIN_B=535353; SO_PIN=3132333435363738

# ---- recording stubs ---------------------------------------------------------------------------------
# Each call appends "ARGV <tool> <args…>" to $T/calls; "ENV NAME=value" for each secret variable the
# call was given; and "MISSING NAME" when an option says env:NAME and NAME is empty (the real tool
# would then PROMPT, or try an empty PIN).
for t in pkcs11-tool sc-hsm-tool pkcs15-tool opensc-tool opensc-explorer scriptrunner scsh3 pcsc_scan ykman java; do
  cat > "$T/bin/$t" <<STUB
#!/usr/bin/env bash
{ printf 'ARGV %s' "$t"; printf ' %s' "\$@"; printf '\n'
  for v in REGALIA_PIN REGALIA_SO_PIN REGALIA_NEW_PIN REGALIA_DKEK_PW; do [ -n "\${!v:-}" ] && printf 'ENV %s=%s\n' "\$v" "\${!v}"; done
  for a in "\$@"; do case "\$a" in env:*) n="\${a#env:}"; [ -n "\${!n:-}" ] || printf 'MISSING %s\n' "\$n";; esac; done; } >> "$T/calls"
case "$t \$*" in
  pkcs11-tool*--list-slots*)
    for i in 0 1; do printf 'Slot %s (0x%s): Virtual Reader %s\n  token label        : card-%s\n  token manufacturer : stub\n  serial num         : SERIAL%s\n' "\$i" "\$i" "\$i" "\$i" "\$i"; done ;;
  opensc-tool*) printf '# Detected readers (pcsc)\nNr.  Card  Features  Name\n0    Yes             Pol Henarejos Pico Key CCID Interface\n1    Yes             Pol Henarejos Pico Key CCID Interface 01\n' ;;
  pkcs15-tool*) idx=0; while [ \$# -gt 0 ]; do case "\$1" in -r|--reader) idx="\$2";; esac; shift; done
    printf 'PKCS#15 Card [Pico-HSM]:\n\tSerial number  : SERIAL%s\n' "\$idx" ;;
  sc-hsm-tool*) printf 'Version              : 6.6\nSO-PIN tries left    : 15\nUser PIN tries left  : 3\nDKEK shares          : 1\nDKEK key check value : 0123456789ABCDEF\n'
    f=""; prev=""; for a in "\$@"; do case "\$prev" in --create-dkek-share|--wrap-key) f="\$a";; esac; prev="\$a"; done
    [ -z "\$f" ] || printf 'stub' > "\$f" ;;
esac
exit 0
STUB
  chmod +x "$T/bin/$t"
done

# leaks <calls file> <secret…>: the ARGV lines that carry a secret, or a PIN-taking option whose value is
# not env:NAME. Nothing printed means clean.
leaks(){ local calls="$1" s; shift
  for s in "$@"; do [ -n "$s" ] && grep -F -- "$s" <<< "$(grep '^ARGV ' "$calls")"; done
  # word by word: the word after each secret-taking option must be env:NAME, on every occurrence
  awk '$1 == "ARGV" { for (i = 3; i < NF; i++)
         if ($i ~ /^--(so-pin|new-pin|pin|puk|password)$/ && $(i + 1) !~ /^env:[A-Za-z_][A-Za-z0-9_]*$/) { print; break } }' "$calls"; }

hdr "1  hsm-fleet-drill.sh --run, the whole drill, against recording stubs"
[ -r "$DRILL" ] || { echo "no hsm-fleet-drill.sh at $DRILL" >&2; exit 1; }
# The drill's own checks FAIL here (the stubs do no cryptography); what is under test is what it
# put on its command lines on the way.
out="$(cd "$T" && env PATH="$T/bin:$PATH" HOME="$T" TMPDIR="$T" HSM_PKCS11_MODULE="$T/fake-module.so" \
        HSM_PIN_A="$PIN_A" HSM_PIN_B="$PIN_B" HSM_SO_PIN="$SO_PIN" \
        timeout 300 bash "$DRILL" --run --a 0 --b 1 <<< "WIPE BOTH" 2>&1)"
calls="$T/calls"
[ -s "$calls" ] || { F "the drill made no token-tool call at all: $(tail -5 <<< "$out")"; : > "$calls"; }
n="$(grep -c '^ARGV ' "$calls")"
argv="$(grep '^ARGV ' "$calls")"
for verb in "sc-hsm-tool .*--initialize" "sc-hsm-tool .*--create-dkek-share" "sc-hsm-tool .*--import-dkek-share" \
            "sc-hsm-tool .*--wrap-key" "sc-hsm-tool .*--unwrap-key" "pkcs11-tool .*--login .*--sign" "pkcs11-tool .*--login .*--read-object"; do
  grep -qE -- "^ARGV $verb" <<< "$argv" && P "reached: ${verb//.\*/ … }" || F "the drill never ran: $verb ($n calls recorded)"
done
found="$(leaks "$calls" "$PIN_A" "$PIN_B" "$SO_PIN")"
[ -z "$found" ] && P "no PIN, SO-PIN or password in any of the $n recorded command lines" || F "a secret on a command line: $found"
# The DKEK passwords are generated by the drill itself; the stub saw them in the environment.
dkpw="$(sed -n 's/^ENV REGALIA_DKEK_PW=//p' "$calls" | sort -u)"
[ -n "$dkpw" ] && ! grep -qFf <(printf '%s\n' "$dkpw") <<< "$argv" && P "nor any DKEK share password ($(wc -l <<< "$dkpw") generated, each delivered in the environment)" \
  || F "a DKEK password is missing from the environment, or present on a command line"
# Delivered, not just removed: each secret reached the tool that needed it.
for want in "REGALIA_PIN=$PIN_A" "REGALIA_PIN=$PIN_B" "REGALIA_SO_PIN=$SO_PIN"; do
  grep -qxF "ENV $want" "$calls" && P "delivered in the environment: ${want%%=*} (${want#*=})" || F "never delivered: $want"
done
missing="$(grep '^MISSING ' "$calls" | sort -u)"
[ -z "$missing" ] && P "no call named a variable that was empty (the real tool would have prompted)" || F "env:NAME given with NAME empty: $missing"
grep -qF "$PIN_A" <<< "$out" || grep -qF "$PIN_B" <<< "$out" || grep -qF "$SO_PIN" <<< "$out" && F "a PIN appears in the drill's own output" || P "no PIN appears in the drill's output either"

hdr "2  the instrument: a PIN on a command line is seen"
printf 'ARGV pkcs11-tool --module m --login --pin %s --list-objects\n' "$PIN_A" > "$T/planted"
[ -n "$(leaks "$T/planted" "$PIN_A")" ] && P "a recorded argv carrying the PIN is reported" || F "the check does not see a PIN on a command line"
printf 'ARGV sc-hsm-tool --initialize --so-pin 9999999999999999 --pin env:REGALIA_PIN\n' > "$T/planted"
[ -n "$(leaks "$T/planted" "$PIN_A")" ] && P "a literal value after --so-pin is reported even when it is not one of the known secrets" || F "a literal --so-pin value is not reported"
printf 'ARGV sc-hsm-tool --initialize --so-pin env:REGALIA_SO_PIN --pin env:REGALIA_PIN\n' > "$T/planted"
[ -z "$(leaks "$T/planted" "$PIN_A" "$SO_PIN")" ] && P "and env:NAME forms are not" || F "a clean argv is reported as a leak"

hdr "3  every non-test script: no token-tool option takes a secret from a variable on the command line"
# A secret option followed by a shell expansion ($VAR, "$VAR", "$(…)", or a value spliced into a
# quoted script). Comment lines aside.
PATTERN='--(so-pin|new-pin|pin|puk|password)[ =]+("?\$|"?'"'"'")'
hits="$(cd "$ROOT" && find . -name '*.sh' -not -path './.git/*' -not -path './qubes/emulator/*' -print0 | sort -z \
        | xargs -0 grep -nE -- "$PATTERN" /dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)"
[ -z "$hits" ] && P "no script passes a PIN, SO-PIN, PUK or password from a variable on a command line" || F "secrets on command lines: $hits"
uses="$(cd "$ROOT" && find . -name '*.sh' -not -path './.git/*' -not -path './qubes/emulator/*' -print0 | xargs -0 grep -hoE -- '--(so-pin|new-pin|pin|password) env:[A-Z_]+' | sort | uniq -c | wc -l)"
[ "$uses" -ge 4 ] && P "and the scripts do pass them as env:NAME ($uses distinct forms in use)" || F "only $uses env:NAME forms found: the sweep may be matching nothing"

hdr "4  the emulator's sc-hsm-tool refuses a PIN on its command line"
# So a script that regresses fails the emulator suites, not only this test.
MODEL="$ROOT/qubes/emulator/bin/sc-hsm-tool"; mkdir -p "$T/model"
model(){ env EMU_SCHSM_STATE="$T/model" "$@" python3 "$MODEL" --initialize --so-pin "$SOARG" --pin "$PINARG" 2>&1; }
SOARG="$SO_PIN" PINARG=env:P; out="$(model P="$PIN_A")"; rc=$?
[ "$rc" != 0 ] && grep -q -- "--so-pin was given a value on the command line" <<< "$out" && P "a literal --so-pin is refused" || F "literal --so-pin (exit $rc): $out"
SOARG=env:S PINARG="$PIN_A"; out="$(model S="$SO_PIN")"; rc=$?
[ "$rc" != 0 ] && grep -q -- "--pin was given a value on the command line" <<< "$out" && P "a literal --pin is refused" || F "literal --pin (exit $rc): $out"
SOARG=env:S PINARG=env:P; out="$(model S="$SO_PIN")"; rc=$?
[ "$rc" != 0 ] && grep -q "P is unset/empty (the real tool would prompt)" <<< "$out" && P "env:NAME with NAME unset is refused (the real tool would prompt)" || F "unset name (exit $rc): $out"
out="$(model S="$SO_PIN" P="$PIN_A")"; rc=$?
[ "$rc" = 0 ] && P "env:NAME with both variables set is accepted" || F "env: forms refused (exit $rc): $out"
grep -qF "$PIN_A" <<< "$out" || grep -qF "$SO_PIN" <<< "$out" && F "the model printed a PIN" || P "and the model prints no PIN"

echo; echo "test-no-pin-on-argv: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
