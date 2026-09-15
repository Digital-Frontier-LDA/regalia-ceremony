#!/usr/bin/env bash
# test-ceremony.sh — LOCAL dry-run harness for ceremony.sh.
# Walks every wizard step on a normal (networked) machine, with the hardware +
# printer tools STUBBED and the real crypto tools (ssss, shamir, qrencode, age)
# doing actual work. Proves the control flow, file handling, share parsing, and
# — critically — that no secret value leaks to stdout. Uses only throwaway data.
#
#   bash qubes/scripts/test-ceremony.sh
#
# This is a TEST tool. It does not touch real keys and is never run in a ceremony.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# this harness legitimately uses stubbed tools and may run off-Linux (no tmpfs):
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# A recognizable throwaway secret — must NEVER appear in captured stdout.
MARKER="LEAKCANARY-do-not-use-$$"

# ---- fake bin: stub the tools we can't run locally --------------------------
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH"
mk(){ cat > "$FAKE/$1"; chmod +x "$FAKE/$1"; }
# air-gap check: report NO default route so preflight passes on a networked box
mk ip      <<'S'
#!/usr/bin/env bash
case "$*" in *"route show default"*) exit 0;; *"addr show scope global"*) exit 0;; *) exit 0;; esac
S
mk age-plugin-yubikey <<'S'
#!/usr/bin/env bash
echo "age1yubikey1qFAKE000recipient000string000for000local000dryrun000zzzz"
S
mk sc-hsm-tool <<'S'
#!/usr/bin/env bash
# create any -o / positional output file so later steps see it; never print secrets
for a in "$@"; do case "$a" in *.pbe|*.bin) : >"$a";; esac; done
case "$*" in
  *--create-dkek-share*)
    # six placeholder shares in OpenSC's format, for the wizard's share round trip (#464)
    for i in 1 2 3 4 5 6; do
      printf '\nPrime       : 7f:00:00:00:00:00:00:6b\nShare ID    : %s\nShare value : 0%s:0%s\n' "$i" "$i" "$i"
    done;;
  *--import-dkek-share*--pwd-shares-total*) cat >/dev/null;;
esac
echo "[stub sc-hsm-tool] $*"
S
mk pkcs11-tool <<'S'
#!/usr/bin/env bash
prev=""; for a in "$@"; do [ "$prev" = "-o" ] && : >"$a"; prev="$a"; done
echo "[stub pkcs11-tool] $*"
S
mk ykman   <<'S'
#!/usr/bin/env bash
echo "[stub ykman] device present"
S
mk lpstat  <<'S'
#!/usr/bin/env bash
echo "printer FakeBrother is idle.  enabled since today"
S
mk lp      <<'S'
#!/usr/bin/env bash
# simulate printing: confirm the file exists, but DO NOT cat it (no secret echo)
f="${!#}"; if [ -f "$f" ]; then echo "[stub lp] would print: $f ($(wc -c <"$f") bytes) to $*"; else echo "[stub lp] missing file $f"; fi
S
cleanup(){ rm -rf "$FAKE"; [ -n "${WORK:-}" ] && rm -rf "$WORK" 2>/dev/null; }
trap cleanup EXIT

# ---- ensure the real crypto tools are reachable -----------------------------
export PATH="$PATH:$HOME/.local/bin:/opt/homebrew/bin"
for t in ssss-split ssss-combine shamir qrencode age age-keygen; do
  command -v "$t" >/dev/null || { echo "missing real tool: $t (install ssss, shamir-mnemonic, qrencode, age)"; exit 2; }
done

# ---- source the real ceremony.sh, then neutralise interactivity -------------
# shellcheck disable=SC1090
source "$HERE/ceremony.sh"          # sourcing guard means main() does NOT run
ask(){ return 0; }                  # auto-yes every confirmation
pause(){ :; }                       # no waiting
# sourcing re-armed `trap cleanup EXIT` (ceremony.sh's), replacing ours — so redefine
# cleanup to mirror the real shred-then-remove AND drop the fake-bin dir on exit.
cleanup(){ [ -n "${WORK:-}" ] && find "$WORK" -type f -exec shred -u {} + 2>/dev/null; rm -rf "${WORK:-}" "$FAKE" 2>/dev/null; }

CAP="$(mktemp)"   # everything the wizard prints goes here too, for leak-scanning

# =============================================================================
hdr "STEP 0 — preflight (air-gap + tools, with stubs)"
if "$HERE/preflight.sh" >>"$CAP" 2>&1; then P "preflight exits 0 (air-gap OK via ip stub)"; else F "preflight failed"; fi
grep -q "PREFLIGHT OK" "$CAP" && P "preflight reports OK" || F "no PREFLIGHT OK line"

hdr "STEP 1 — YubiKey ops identity"
init_work
out="$(step_yubikey_ops 2>&1)"; echo "$out" >>"$CAP"
grep -q "age1yubikey1qFAKE" <<< "$out" && P "ran age-plugin-yubikey, surfaced recipient" || F "no yubikey recipient"
grep -qi "updatekeys" <<< "$out" && P "instructs the .sops.yaml updatekeys follow-up" || F "missing updatekeys guidance"

hdr "STEP 2 — Nitrokey HSM 2 funding key (born-in-HSM path: GATED OFF by default)"
# step_hsm_funding is refused unless CEREMONY_ALLOW_BORN_IN_HSM=1 (a born-in-HSM key is
# not reconstructible from the 4-of-6 Shamir shares — see the banner in ceremony.sh).
# Prove BOTH postures: the gate refuses by default (and names its opt-in), and the
# deliberately opted-in path still runs. If the gate disappears the first three checks
# go red; if the path itself breaks the last three do.
out="$(step_hsm_funding 2>&1)"; echo "$out" >>"$CAP"
grep -q "born-in-HSM key generation is UNSUPPORTED" <<< "$out" && P "born-in-HSM path refuses by default (custody gate shut)" || F "gate missing: step ran without CEREMONY_ALLOW_BORN_IN_HSM"
grep -q "CEREMONY_ALLOW_BORN_IN_HSM=1" <<< "$out" && P "refusal names the deliberate opt-in" || F "refusal banner does not name the opt-in"
[ ! -f "$WORK/dkek.pbe" ] && P "no dkek.pbe produced while gated" || F "gated step still produced dkek.pbe"
out="$(CEREMONY_ALLOW_BORN_IN_HSM=1 step_hsm_funding 2>&1)"; echo "$out" >>"$CAP"
grep -q "pwd-shares-threshold 4 --pwd-shares-total 6" <<< "$out" && P "DKEK 4-of-6 threshold command shown/run (opt-in)" || F "no DKEK threshold"
grep -q "EC:secp256k1" <<< "$out" && P "secp256k1 on-device keygen (opt-in)" || F "no secp256k1 keygen"
[ -f "$WORK/dkek.pbe" ] && P "dkek.pbe produced (stub, opt-in)" || F "no dkek.pbe"

hdr "STEP 3a — Shamir split (ssss, age-key string)"
printf '%s' "$MARKER" > "$WORK/secret.in"
out="$(printf 'a\n' | step_shamir 2>&1)"; echo "$out" >>"$CAP"
[ "$(wc -l < "$WORK/shares.txt" | tr -d ' ')" = 6 ] && P "ssss produced 6 shares" || F "expected 6 ssss shares"
ls "$WORK"/*.png >/dev/null 2>&1 && P "QR PNGs rendered for shares" || F "no QR PNGs"
# real round-trip: any 4 ssss shares reconstruct the marker
R=$( (sed -n '1p;3p;5p;6p' "$WORK/shares.txt") | ssss-combine -t 4 -q 2>&1 )
[ "$R" = "$MARKER" ] && P "4-of-6 ssss shares reconstruct the secret" || F "ssss reconstruct mismatch"
rm -f "$WORK"/*.png "$WORK"/*.txt "$WORK/shares.txt"

hdr "STEP 3b — Shamir split (SLIP-0039 mnemonic)"
out="$(printf 'b\n' | step_shamir 2>&1)"; echo "$out" >>"$CAP"
n=$(ls "$WORK"/*.png 2>/dev/null | wc -l | tr -d ' ')
[ "$n" = 6 ] && P "exactly 6 SLIP-39 shares rendered (header not miscounted)" || F "expected 6 SLIP-39 shares, got $n"

hdr "STEP 4 — M-DISC archive manifest"
out="$(step_archive 2>&1)"; echo "$out" >>"$CAP"
# The archive now burns a CURATED staging dir ($WORK/mdisc), not the whole tmpfs workdir,
# so plaintext share files from step 3 are never committed to disc. Manifest lives there.
[ -f "$WORK/mdisc/manifest.sha256" ] && P "sha256 manifest generated (in the curated burn dir)" || F "no manifest"
if ls "$WORK"/sh[1-9] "$WORK"/w[1-9] "$WORK"/secret.in "$WORK"/slip39.txt >/dev/null 2>&1; then
  # Catch EVERY plaintext-secret artifact the wizard can leave in the workdir: ssss shares
  # (sh1..sh6), SLIP-39 word-shares (w1..w6) + slip39.txt from step 3b/c, and secret.in.
  grep -qE 'sh[1-9]|w[1-9]|secret\.in|slip39\.txt' "$WORK/mdisc/manifest.sha256" 2>/dev/null \
    && F "plaintext share/secret files are in the M-DISC burn manifest — they'd be burned to disc" \
    || P "no plaintext share/secret files in the burn set (curated staging excludes them)"
fi

hdr "STEP 5 — recovery drill guidance"
out="$(step_drill 2>&1)"; echo "$out" >>"$CAP"
grep -qi "ssss-combine -t 4" <<< "$out" && P "drill explains ssss recover" || F "no drill guidance"

hdr "SECRET-LEAK SCAN (the important one)"
if grep -q "$MARKER" "$CAP"; then
  F "secret MARKER leaked into wizard output!"; grep -n "$MARKER" "$CAP" | head
else
  P "no secret value ever printed to stdout across all steps"
fi

rm -f "$CAP"
hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && { echo "  ALL WIZARD STEPS OK (dry run)"; exit 0; } || { echo "  SOME CHECKS FAILED"; exit 1; }
