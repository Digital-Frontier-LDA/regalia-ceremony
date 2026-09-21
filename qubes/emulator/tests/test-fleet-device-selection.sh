#!/usr/bin/env bash
# test-fleet-device-selection.sh — REQUIREMENTS A3, A5, A6.
#
# WHY THIS EXISTS. Until now every script in this repo assumed EXACTLY ONE card was attached.
# hsm-auto-import.sh says "no ATR — no card in the reader", singular, and hsm-import-key.sh had no
# slot selector at all: it called pkcs11-tool with no --slot and bound to whatever PC/SC enumerated
# first. That enumeration order is not stable across replugs.
#
# With a two-device fleet that is a live hazard rather than an inconvenience. Provisioning is
# DESTRUCTIVE to the slot it lands in — it initialises the device and imports a key. "Provision the
# standby" pointed at an unstable default has a real chance of re-provisioning the primary, and
# nobody finds out until the two addresses disagree, by which time both cards have been rewritten.
#
# So the rule is: with more than one token attached and no explicit --slot, REFUSE. This suite
# proves the refusal actually happens, because a guard that has never been fired is a comment.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMPORT="$HERE/../../scripts/hsm-import-key.sh"
DRILL="$HERE/../../scripts/hsm-fleet-drill.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

for f in "$IMPORT" "$DRILL"; do
  [ -r "$f" ] || { echo "  (skipping: $f not found)"; exit 0; }
done

FAKE="$(mktemp -d)"; ROOT="$(mktemp -d)"; export PATH="$FAKE:$PATH"
trap 'rm -rf "$FAKE" "$ROOT"' EXIT

# A pkcs11-tool stub whose token count is controlled by TOKENS. Everything after slot selection is
# irrelevant here, so it refuses to do real work — this suite is ONLY about which card gets picked.
cat > "$FAKE/pkcs11-tool" <<'STUB'
#!/usr/bin/env bash
args="$*"
case "$args" in
  *--list-slots*)
    n="${TOKENS:-1}"
    for i in $(seq 0 $((n-1))); do
      printf 'Slot %s (0x%s): Virtual Reader %s\n  token label        : card-%s\n  serial num         : SERIAL%s\n' "$i" "$i" "$i" "$i" "$i"
    done
    exit 0;;
  *--list-objects*) exit 0;;
  *) echo "STUB: refusing real work"; exit 9;;
esac
STUB
chmod +x "$FAKE/pkcs11-tool"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKE/openssl"; chmod +x "$FAKE/openssl"

# STUB EVERY TOOL THAT CAN REACH A CARD — not just pkcs11-tool.
#
# MEASURED 2026-09-03: this suite stubbed only pkcs11-tool and openssl, so the drill's sc-hsm-tool
# and pkcs15-tool calls went to the REAL bench. One run of this "hardware-free" suite consumed TWO
# user-PIN retries on the pinned staging card (3 -> 1). Run it a few times with nothing watching and
# the card reaches 0 and LOCKS — and with the D3 posture in force the SO-PIN cannot reset it, so the
# only way back is a full re-initialise. A unit suite must not be able to brick the bench.
#
# TRIPWIRE, not just silence: PIN-bearing and destructive calls are recorded so the suite can ASSERT
# that none escaped, rather than trusting that the stub list is complete.
for _t in sc-hsm-tool pkcs15-tool opensc-tool scriptrunner scsh3; do
  cat > "$FAKE/$_t" <<STUB
#!/usr/bin/env bash
printf '%s\n' "$_t \$*" >> "$ROOT/hw-calls"
case " \$* " in
  *--initialize*|*--login*|*--so-pin*|*--unwrap-key*|*--wrap-key*|*--pin\ *)
      printf '%s\n' "$_t \$*" >> "$ROOT/hw-danger" ;;
esac
case "$_t" in
  opensc-tool)
      echo "# Detected readers (pcsc)"
      echo "Nr.  Card  Features  Name"
      for i in \$(seq 0 \$(( \${TOKENS:-1} - 1 ))); do
        if [ "\$i" = 0 ]; then
          echo "\$i    Yes             Pol Henarejos Pico Key CCID Interface"
        else
          echo "\$i    Yes             Pol Henarejos Pico Key CCID Interface 0\$i"
        fi
      done ;;
  pkcs15-tool)
      idx=0
      while [ \$# -gt 0 ]; do [ "\$1" = "-r" ] && idx="\$2"; shift; done
      printf 'PKCS#15 Card [Pico-HSM]:\n\tSerial number  : SERIAL%s\n' "\$idx" ;;
  sc-hsm-tool)
      echo "Version              : 6.6"
      echo "SO-PIN tries left    : 15"
      echo "User PIN tries left  : 3"
      echo "DKEK shares          : 1" ;;
esac
exit 0
STUB
  chmod +x "$FAKE/$_t"
done

# Minimal inputs so the script reaches the slot check rather than dying on argument validation.
: > "$ROOT/x.p12"; : > "$ROOT/x.crt"; echo pw > "$ROOT/pw"; echo 111111 > "$ROOT/pin"
: > "$ROOT/dkek.pbe"; echo dk > "$ROOT/dkek.pw"
common=(--p12 "$ROOT/x.p12" --pw-file "$ROOT/pw" --cert "$ROOT/x.crt" --id 33 --label l
        --dkek "$ROOT/dkek.pbe" --dkek-pw "$ROOT/dkek.pw" --pin-file "$ROOT/pin"
        --module "$FAKE/fake-module.so")
: > "$FAKE/fake-module.so"

# =================================================================================================
hdr "TWO tokens attached and no --slot: the import must REFUSE"
out="$(TOKENS=2 "$IMPORT" "${common[@]}" 2>&1)"; rc=$?
if [ "$rc" = 2 ] && grep -qi "the default target is whichever" <<<"$out"; then
  P "refuses with exit 2 rather than picking a card"
else
  F "did NOT refuse (rc=$rc) — provisioning the standby could re-provision the primary"
fi
grep -qi "no --slot was given" <<<"$out" \
  && P "the message names the missing flag" || F "the operator is not told what to pass"
grep -qE 'Slot|serial' <<<"$out" \
  && P "…and lists the attached slots so the operator can choose" \
  || F "refuses without showing the choices, so the operator has to go hunting"

# MATCHED ON THE GUARD'S OWN SENTENCE, not on the word "REFUSING". Every refusal in a careful
# script says something like "refusing", so a bare word match identifies no particular guard: when
# hsm-import-key.sh grew a second, unrelated refusal (no Smart Card Shell on a CI runner), these
# rows reported that the slot flag did not work. The sentence below belongs to the slot guard and
# to nothing else.
hdr "ONE token and no --slot: unambiguous, so it must NOT refuse"
# The guard must not become a nuisance on the single-card case, or it gets removed.
out1="$(TOKENS=1 "$IMPORT" "${common[@]}" 2>&1)"; rc1=$?
if [ "$rc1" = 2 ] && grep -qi "the default target is whichever" <<<"$out1"; then
  F "refused with only ONE token attached — the guard cries wolf and will be deleted"
else
  P "proceeds past slot selection with a single token"
fi

hdr "An explicit --slot is honoured even with two attached"
out2="$(TOKENS=2 "$IMPORT" "${common[@]}" --slot 1 2>&1)"; rc2=$?
if [ "$rc2" = 2 ] && grep -qi "the default target is whichever" <<<"$out2"; then
  F "refused despite an explicit --slot — the flag does not work"
else
  P "an explicit --slot resolves the ambiguity"
fi
grep -q "slot: 1" <<<"$out2" && P "echoes which slot it will write to" \
  || F "does not echo the target slot — the operator cannot confirm before it writes"

hdr "A non-numeric --slot is rejected, not silently coerced"
out3="$(TOKENS=2 "$IMPORT" "${common[@]}" --slot "0; rm -rf /" 2>&1)"; rc3=$?
[ "$rc3" = 2 ] && P "rejects a non-numeric slot" || F "accepted a non-numeric slot (rc=$rc3)"
# THE CAPTURED OUTPUT WAS NEVER READ, so this row passed on ANY exit-2 — including one from a
# later, unrelated refusal that never examined --slot at all. Assert it failed for the stated
# reason, and that the injected text did not reach a shell.
grep -qi 'slot' <<<"$out3" && P "…and says it was the slot, so the rejection is the one this row means" \
  || F "exit 2 with nothing about the slot: $(tail -2 <<<"$out3")"
# NOT "[ -d /home ]" — that is true whatever the script did, and a PASS that cannot fail is
# noise. What is actually checkable here is that the injected text was treated as DATA: it is
# echoed back inside the rejection rather than having been word-split into a command.
grep -qF -- '0; rm -rf /' <<<"$out3" \
  && P "…quoting the rejected value back whole, so it was carried as data and never split" \
  || F "the rejected slot value is not echoed back intact: $(tail -2 <<<"$out3")"

# =================================================================================================
hdr "The fleet drill refuses to run against ONE card twice"
# The failure this prevents is subtle: pointing --a and --b at the same slot would pass every
# assertion in the drill while proving nothing about two devices agreeing.
out4="$(TOKENS=2 "$DRILL" --run --a 1 --b 1 2>&1)"; rc4=$?
# Match the PROPERTY, not one wording. Serial-based targeting made the drill refuse earlier, on
# reader identity (hsm-fleet-drill.sh:141), so it now says "same reader" before it ever reaches the
# slot-level check. Both are the same refusal; pinning the old phrase failed a correct behaviour.
if [ "$rc4" != 0 ] && grep -qiE "same (reader|slot|card|device)" <<<"$out4"; then
  P "--a and --b pointing at one card is refused"
else
  F "the drill accepted one card as both devices (rc=$rc4) — it would pass while proving nothing"
fi

hdr "The drill states that D1 remains open regardless of outcome"
# A green two-Pico run must never be mistaken for evidence about the Nitrokey.
DRILL_CODE="$(python3 "$HERE/source_lexing.py" shell "$DRILL")" \
  || { echo "source lexer failed" >&2; exit 2; }
grep -q "D1 IS STILL OPEN" <<<"$DRILL_CODE" \
  && P "the drill prints that D1 stays open on a Pico" \
  || F "nothing stops a green Pico run from being read as production evidence"
grep -qi "stand-in\|STAND-IN" <<<"$DRILL_CODE" \
  && P "…and says the Picos are standing in for the Nitrokey" \
  || F "the drill does not say what the devices are"

hdr "No real hardware was touched"
# The point of the stubs is that this suite CANNOT reach a card. Assert it rather than assume it.
#
# WHAT THIS DOES AND DOES NOT COVER. It catches a dangerous call made through a tool we DID stub —
# proven falsifiable: silent on `sc-hsm-tool -r 0`, fires on `--initialize`. It cannot see a tool
# nobody stubbed, because such a call bypasses the recorder entirely. The definitive evidence that
# this suite is hardware-free is therefore the measurement: the pinned card's user-PIN retry counter
# read 3 before and 3 after (it read 3 -> 1 before the stubs were added). Re-measure that way, not
# by trusting this assertion, whenever this suite gains a new external command.
if [ -s "$ROOT/hw-danger" ]; then
  F "a destructive or PIN-bearing call escaped the stubs: $(head -1 "$ROOT/hw-danger")"
else
  P "no destructive or PIN-bearing call escaped the stubs"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
