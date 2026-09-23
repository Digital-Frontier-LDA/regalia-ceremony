#!/usr/bin/env bash
# step_yubikey_ops on a FACTORY YubiKey 5.7 (default PIN, default AES192 management key). Measured
# on 2026-09-23: age-plugin-yubikey 0.5.0 refuses that management key outright, and on a default PIN
# it sets the PUK to the new PIN. So the step must, IN THIS ORDER, change the PIN, change the PUK,
# switch to a PIN-protected TDES management key, and only then generate. It must also report a
# failed generation as a failure, not as success.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin"
export CALLS="$ROOT/calls" PATH="$ROOT/bin:$PATH"
cat > "$ROOT/bin/ykman" <<'S'
#!/usr/bin/env bash
echo "ykman $*" >> "$CALLS"
if [ "$*" = "piv info" ]; then
  printf '%s\n' "PIV version:              5.7.4" "PIN tries remaining:      3/3" \
    "Management key algorithm: AES192" "WARNING: Using default PIN!" "WARNING: Using default PUK!" \
    "WARNING: Using default Management key!"
fi
S
cat > "$ROOT/bin/age-plugin-yubikey" <<'S'
#!/usr/bin/env bash
echo "age-plugin-yubikey $*" >> "$CALLS"
[ -n "${PLUGIN_FAILS:-}" ] && { echo "Custom unprotected non-TDES management keys are not supported." >&2; exit 1; }
echo "age1yubikey1qFACTORY000recipient"
S
chmod +x "$ROOT/bin/"*

# shellcheck disable=SC1090
source "$HERE/../../scripts/ceremony.sh"
ask(){ return 0; }
pause(){ :; }

pass=0; fail=0
P(){ printf '  PASS %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }

out="$(step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" = 0 ] && P "the step succeeds on a factory card" || F "the step failed (rc=$rc): $out"
order="$(grep -oE 'change-pin|change-puk|change-management-key -a TDES --protect|--generate' "$CALLS" | tr '\n' ' ')"
[ "$order" = "change-pin change-puk change-management-key -a TDES --protect --generate " ] \
  && P "PIN, then a distinct PUK, then a protected TDES management key, then generate" \
  || F "wrong preparation order: '$order'"

: > "$CALLS"
out="$(PLUGIN_FAILS=1 step_yubikey_ops 2>&1)"; rc=$?
[ "$rc" != 0 ] && P "a failed generation is reported as a failure" || F "a failed generation returned success"
grep -q "no identity was created" <<< "$out" && P "the failure says no identity exists" || F "no failure message: $out"

printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
