#!/usr/bin/env bash
# recital-ceremony.sh — full DRESS REHEARSAL of the wizard (no real keys).
# Goes beyond test-ceremony.sh's per-step smoke test: it drives the real
# interactive main() menu end-to-end, exercises the failure paths (air-gap
# refusal, missing tool, declined confirmation), and does REAL k-of-n
# reconstruction from the shares the wizard itself emits — all on throwaway data.
#
#   bash qubes/scripts/recital-ceremony.sh [--show]
#       --show  also print the full interactive transcript (the "recital")

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# this harness legitimately uses stubbed tools and may run off-Linux (no tmpfs):
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
SHOW=0; [ "${1:-}" = "--show" ] && SHOW=1
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
MARKER="RECITAL-canary-do-not-use-$$"

# ---- stub the hardware/printer tools ----------------------------------------
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH:$HOME/.local/bin:/opt/homebrew/bin"
mk(){ cat > "$FAKE/$1"; chmod +x "$FAKE/$1"; }
mk ip <<'S'
#!/usr/bin/env bash
# honors FAKE_HAS_NET=1 to simulate a NON-air-gapped box (for the refusal test)
case "$*" in
  *"route show default"*) [ -n "${FAKE_HAS_NET:-}" ] && echo "default via 10.0.0.1 dev eth0"; exit 0;;
  *) exit 0;;
esac
S
mk age-plugin-yubikey <<'S'
#!/usr/bin/env bash
echo "age1yubikey1qFAKE000recipient000string000local000dryrun000zzzzzzzz"
S
mk sc-hsm-tool <<'S'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in *.pbe|*.bin) : >"$a";; esac; done
echo "[stub sc-hsm-tool] $*"
S
mk pkcs11-tool <<'S'
#!/usr/bin/env bash
# on a pubkey export, emit a FIXED valid secp256k1 SPKI DER (reproducible vector
# whose akash address is akash1dc66jys4v4ckt0sxq63ksps34ylra5n9m2qw85)
prev=""; out=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
DER=3056301006072a8648ce3d020106052b8104000a034200047f41ffa6c0c377ce7660dfd2716ab96f18f9dbd7de5a6d360b3e89efbbae906cd5188e7d696b936777d5383256af1246980098dd9a16826a4f4984a136fbeab6
case "$*" in
  *--read-object*pubkey*) [ -n "$out" ] && python3 -c "import binascii;open('$out','wb').write(binascii.unhexlify('$DER'))";;
  *) [ -n "$out" ] && : >"$out";;
esac
echo "[stub pkcs11-tool] $*"
S
mk ykman  <<'S'
#!/usr/bin/env bash
echo "[stub ykman] device present"
S
mk lpstat <<'S'
#!/usr/bin/env bash
echo "printer FakeBrother is idle.  enabled since today"
S
mk lp <<'S'
#!/usr/bin/env bash
f="${!#}"; if [ -f "$f" ]; then echo "[stub lp] would print $f ($(wc -c <"$f")B)"; else echo "[stub lp] missing $f"; fi
S
trap 'rm -rf "$FAKE" "${WORK:-/nonexistent}" 2>/dev/null' EXIT
for t in ssss-split ssss-combine shamir qrencode age age-keygen; do
  command -v "$t" >/dev/null || { echo "missing real tool: $t"; exit 2; }
done

# shellcheck disable=SC1090
source "$HERE/ceremony.sh"   # sourcing guard => main() does not auto-run
# sourcing re-armed ceremony.sh's `trap cleanup EXIT`, replacing ours — redefine
# cleanup to mirror the real shred-then-remove AND also drop the fake-bin dir.
cleanup(){ [ -n "${WORK:-}" ] && find "$WORK" -type f -exec shred -u {} + 2>/dev/null; rm -rf "${WORK:-}" "$FAKE" 2>/dev/null; }

# =============================================================================
hdr "NEGATIVE 1 — wizard REFUSES to start when not air-gapped"
if FAKE_HAS_NET=1 "$HERE/preflight.sh" >/tmp/r_pf 2>&1; then
  F "preflight should have FAILED with a network route present"
else
  grep -q "PREFLIGHT FAILED" /tmp/r_pf && grep -qi "has network" /tmp/r_pf \
    && P "air-gap violation detected -> fails closed" || F "wrong failure output"
fi

hdr "NEGATIVE 2 — gated by default; with the deliberate opt-in, a missing tool still aborts"
# step_hsm_funding now refuses at the custody gate BEFORE touching tools. Prove both
# postures: default -> the gate banner (no tool use at all); opt-in + missing sc-hsm-tool
# -> the missing-tool abort.
out="$( PATH="/usr/bin:/bin" bash -c "source '$HERE/ceremony.sh'; WORK=/tmp; step_hsm_funding" 2>&1 )"
grep -q "born-in-HSM key generation is UNSUPPORTED" <<< "$out" && P "HSM step refuses by default (custody gate shut)" || F "gate missing: step ran without CEREMONY_ALLOW_BORN_IN_HSM"
out="$( PATH="/usr/bin:/bin" bash -c "source '$HERE/ceremony.sh'; WORK=/tmp; CEREMONY_ALLOW_BORN_IN_HSM=1 step_hsm_funding" 2>&1 )"
grep -qi "sc-hsm-tool (OpenSC) missing" <<< "$out" && P "opted-in HSM step errors out without sc-hsm-tool" || F "did not detect missing tool"

hdr "NEGATIVE 2b — stub guard refuses a real run when stubbed tools are on PATH"
# the fake-bin (stubs) is on PATH; with CEREMONY_SIMULATE unset, guard_no_stubs must abort
( unset CEREMONY_SIMULATE; guard_no_stubs ) >/dev/null 2>&1 \
  && F "stub guard did NOT fire (it should exit)" \
  || P "stub guard fires when a stub is on PATH and CEREMONY_SIMULATE is unset"

hdr "NEGATIVE 3 — declined confirmation does NOT run the command"
init_work
printf 'n\n' | run "touch '$WORK/SHOULD_NOT_EXIST'" >/dev/null 2>&1
[ -f "$WORK/SHOULD_NOT_EXIST" ] && F "command ran despite 'n'" || P "answering 'n' skips the command"
printf 'y\n' | run "touch '$WORK/should_exist'" >/dev/null 2>&1
[ -f "$WORK/should_exist" ] && P "answering 'y' runs the command (gating works both ways)" || F "'y' did not run command"

# ---- from here, auto-confirm + no pausing for the unattended run ------------
ask(){ return 0; }
pause(){ :; }

hdr "RECITAL — drive the real interactive main() menu end-to-end"
# stream: printer name, then menu 1,2,3->a,4,5, a bad choice, then quit
TRANSCRIPT="$(mktemp)"
# step 6 now asks the funding-custody model (hsm/seed) since the stub HSM fails closed and
# leaves no funding-wrapped.bin artifact to auto-detect; answer 'seed' (default SLIP-39 path).
{ printf 'FakeBrother\n'; printf '1\n'; printf '2\n'; printf '3\na\n'; printf '4\n'; printf '5\n'; printf '6\nDF-BG-01\nHOLO-000001\nseed\n'; printf 'zzz\n'; printf 'q\n'; } | main >"$TRANSCRIPT" 2>&1 || true
for sig in "YubiKey" "Nitrokey HSM 2" "Shamir split" "Archive to M-DISC" "Recovery drill" "recovery instruction card"; do
  grep -q "$sig" "$TRANSCRIPT" && P "menu reached: $sig" || F "menu never reached: $sig"
done
grep -qE "pick 1-[0-9]+ or q" "$TRANSCRIPT" && P "rejects an invalid menu choice" || F "bad choice not handled"
grep -q "Done —" "$TRANSCRIPT" && P "quits cleanly via 'q'" || F "did not quit cleanly"
# step_hsm_funding is fail-CLOSED. Its default posture is now the custody gate: a born-in-HSM
# key is UNSUPPORTED (not reconstructible from the 4-of-6 shares), so menu step 2 must refuse
# and name the opt-in — surfacing NO fundable address. If the gate is deliberately lifted, it
# records a fundable address ONLY after a keypair-control sign-verify proof AND a backup
# restore-verify both pass; the recital's simple HSM stub cannot produce a signature that
# verifies against the exported pubkey, so the other acceptable outcome is a fail-closed
# refusal. Reject the dangerous middle (an address presented as fundable without the proof).
if grep -q "key-control PROVEN + backup RESTORE-VERIFIED" "$TRANSCRIPT"; then
  P "HSM funding address surfaced ONLY after key-control + restore-verify proofs"
elif grep -q "born-in-HSM key generation is UNSUPPORTED" "$TRANSCRIPT"; then
  P "HSM step REFUSES by default under the custody gate (no fundable address) — hardened"
elif grep -qiE "KEYPAIR-CONTROL PROOF FAILED|Do NOT fund" "$TRANSCRIPT"; then
  P "HSM step FAILS CLOSED without a verifiable key-control proof (no fundable address) — hardened"
else
  F "HSM step neither proved key control nor failed closed (a fundable address without proof would be catastrophic)"
fi

hdr "RECITAL — leak scan of the full interactive transcript"
# Match a REAL key body (AGE-SECRET-KEY-1 + bech32 chars) or a 32-hex master
# secret on a "secret:" line — not the descriptive help text "AGE-SECRET-KEY-1…".
if grep -Eq "AGE-SECRET-KEY-1[A-Z0-9]{20,}|master secret:[[:space:]]*[0-9a-f]{32}|$MARKER" "$TRANSCRIPT"; then
  F "a secret/key leaked into the interactive transcript"; grep -nE "AGE-SECRET-KEY-1[A-Z0-9]{20,}|master secret:[[:space:]]*[0-9a-f]{32}" "$TRANSCRIPT" | head
else
  P "no key / master-secret value printed during the whole interactive run"
fi

hdr "REAL ROUND-TRIP 1 — ssss shares the wizard emitted reconstruct (multiple subsets)"
init_work
printf '%s' "$MARKER" > "$WORK/secret.in"
printf 'a\n' | step_shamir >/dev/null 2>&1
[ "$(wc -l < "$WORK/shares.txt" | tr -d ' ')" = 6 ] && P "6 ssss shares emitted" || F "expected 6 shares"
r1=$( (sed -n '1p;2p;3p;4p' "$WORK/shares.txt") | ssss-combine -t 4 -q 2>&1 )
r2=$( (sed -n '3p;4p;5p;6p' "$WORK/shares.txt") | ssss-combine -t 4 -q 2>&1 )
[ "$r1" = "$MARKER" ] && P "subset {1,2,3,4} reconstructs" || F "subset {1,2,3,4} failed"
[ "$r2" = "$MARKER" ] && P "subset {3,4,5,6} reconstructs (any 4 work)" || F "subset {3,4,5,6} failed"
r2bad=$( (sed -n '1p;2p;3p' "$WORK/shares.txt") | ssss-combine -t 3 -q 2>&1 | tr -d '\n' )
[ "$r2bad" = "$MARKER" ] && F "THREE shares leaked the secret" || P "three shares (below threshold) do NOT reveal the secret"

hdr "REAL ROUND-TRIP 2 — SLIP-0039 shares the wizard emitted recover the master secret"
printf 'b\n' | step_shamir >/dev/null 2>&1
# the wizard writes each raw share to w1..wN (text) and a printable PNG per label
nshares=$(ls "$WORK"/w[1-9] 2>/dev/null | wc -l | tr -d ' ')
npages=$(ls "$WORK"/SLIP-0039_share_*.png 2>/dev/null | wc -l | tr -d ' ')
[ "$nshares" = 6 ] && P "6 SLIP-39 shares emitted (and $npages printable QR pages)" || F "expected 6 SLIP-39 shares, got $nshares"
# The minted master secret is (correctly) NOT written anywhere — slip39-mint.py never
# emits it (that was the old `shamir create` leak). So verify recoverability WITHOUT a
# reference: recover from two DIFFERENT 4-subsets and assert they agree + are non-empty.
gotA=$(printf '%s\n%s\n%s\n%s\n' "$(cat "$WORK/w1")" "$(cat "$WORK/w2")" "$(cat "$WORK/w3")" "$(cat "$WORK/w4")" | shamir recover 2>&1 | grep -ioE '[0-9a-f]{32}' | tail -1)
gotB=$(printf '%s\n%s\n%s\n%s\n' "$(cat "$WORK/w3")" "$(cat "$WORK/w4")" "$(cat "$WORK/w5")" "$(cat "$WORK/w6")" | shamir recover 2>&1 | grep -ioE '[0-9a-f]{32}' | tail -1)
[ -n "$gotA" ] && [ "$gotA" = "$gotB" ] && P "two different 4-share subsets recover the SAME secret (consistent, any-4-of-6)" || F "SLIP-39 recover mismatch (A=$gotA B=$gotB)"
grep -qiE "master secret|using master" "$WORK/slip39.txt" && F "master secret LEAKED into the shares file" || P "minted master secret is not written to the shares file"

hdr "DERIVE — akash address helper (offline, cosmjs-verified known vector)"
# vector cross-checked against @cosmjs/crypto: this compressed secp256k1 pubkey -> this akash addr
KV_PUB="03be0e04ab74bb9375c710c15c40775c3ba902937c4e77d6faa19f26373a359276"
KV_ADDR="akash1pymqpnzcnu254eu8pjd4l5cc7h6l8wrhnj3cv3"
got=$(python3 "$HERE/derive-akash-address.py" --hex "$KV_PUB" 2>&1)
[ "$got" = "$KV_ADDR" ] && P "derive-akash-address.py matches the cosmjs-verified vector" || F "derive mismatch: $got"

hdr "RECOVERY CARD — case/seal binding printed on the card"
cardps="$(mktemp)"
python3 "$HERE/make-recovery-card.py" -o "$cardps" --case-id DF-BG-07 --seal-serial HOLO-000099 --date 2026-06-29 >/dev/null 2>&1
grep -q "DF-BG-07" "$cardps" && grep -q "HOLO-000099" "$cardps" && P "card prints the case id + holo serial (anti-swap binding)" || F "card missing case/seal binding"
grep -q "%!PS-Adobe" "$cardps" && P "card is valid PostScript" || F "card not valid PS"
rm -f "$cardps"

hdr "OPTION B — BIP39 wallet seed -> SLIP-39 -> recover (exact round-trip)"
if python3 -c "import mnemonic, shamir_mnemonic" 2>/dev/null; then
  bt="$(mktemp -d)"
  BMN="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
  printf '%s' "$BMN" > "$bt/m.in"
  python3 "$HERE/bip39-slip39-backup.py" --in "$bt/m.in" --out "$bt/sh.txt" 2>/dev/null
  grep -q "RECONSTRUCT-VERIFIED" "$bt/sh.txt" && P "split auto reconstruct-verifies before emitting shares" || F "no reconstruct-verify"
  grep -vE '^#|^$' "$bt/sh.txt" | sed -n '1p;3p;5p;6p' > "$bt/c.txt"   # any 4 of 6
  brec=$(python3 "$HERE/bip39-slip39-backup.py" --recover --in "$bt/c.txt" 2>/dev/null)
  [ "$brec" = "$BMN" ] && P "BIP39 -> SLIP-39 4-of-6 -> recover returns the EXACT mnemonic (HSM-free)" || F "Option B round-trip mismatch"
  # dice/external entropy: all-zero 32B entropy must encode to the known BIP39 vector
  printf '%064d' 0 > "$bt/e.hex"
  fe=$(python3 "$HERE/bip39-slip39-backup.py" --from-entropy --in "$bt/e.hex" 2>/dev/null | awk '{print $1,$NF}')
  [ "$fe" = "abandon art" ] && P "--from-entropy encodes dice entropy to the known BIP39 vector (RNG out of trust path)" || F "--from-entropy vector mismatch ($fe)"
  rm -rf "$bt"
else
  printf '  \033[33m[SKIP]\033[0m mnemonic/shamir_mnemonic not importable here (verified standalone + cosmjs address-invariant; Qubes template installs both)\n'
fi

hdr "METAL PLATE — SLIP-39 stamping worksheet round-trips"
ms="$(mktemp -d)"
# Mint the throwaway share material with slip39-mint.py — NEVER `shamir create`, even here:
# the CLI prints the master secret to stdout (emulator README bug #13, Critical), and
# redirecting that into the shares file is exactly the leak this repo retired. The minter
# emits ONLY the shares (reconstruct-verified, 0600, master secret never written), which is
# all the worksheet round-trip needs: one 20-word share line, same shape `shamir create`
# used to produce among its leaky output.
python3 "$HERE/slip39-mint.py" --threshold 4 --shares 6 --out "$ms/s.txt" 2>/dev/null
sh=$(grep -E '^[a-z]+( [a-z]+){15,}$' "$ms/s.txt" | head -1); printf '%s' "$sh" > "$ms/share.in"
python3 "$HERE/metal-stamp-worksheet.py" --in "$ms/share.in" 2>/dev/null | grep -E '^[0-9]' | grep -oE '[0-9]{2} [A-Z]{4}' | awk '{print $2}' > "$ms/pref.txt"
rec=$(python3 "$HERE/metal-stamp-worksheet.py" --verify --in "$ms/pref.txt" 2>/dev/null | tail -2 | head -1)
[ "$rec" = "$sh" ] && P "metal worksheet -> 4-letter prefixes -> verify reconstructs the exact share" || F "metal stamping round-trip mismatch"
rm -rf "$ms"

hdr "HYGIENE — workdir shreds, leaving no secret behind"
leakfiles=$(grep -rl "$MARKER" "$WORK" 2>/dev/null | wc -l | tr -d ' ')
keep="$WORK"
cleanup            # the script's own shred-on-exit routine
[ ! -d "$keep" ] && P "cleanup() removed the RAM workdir" || F "workdir survived cleanup"
echo "  (note: $leakfiles in-workdir files held the marker pre-shred — expected; all shredded now)"

hdr "IDEMPOTENCY — re-running a step does not error"
init_work
printf 'a\n' | step_shamir >/dev/null 2>&1; rc1=$?
rm -f "$WORK"/*.png "$WORK"/*.txt "$WORK/shares.txt" 2>/dev/null
printf 'a\n' | step_shamir >/dev/null 2>&1; rc2=$?
[ "$rc1" = 0 ] && [ "$rc2" = 0 ] && P "step_shamir runs twice cleanly" || F "re-run errored (rc1=$rc1 rc2=$rc2)"

[ "$SHOW" = 1 ] && { hdr "FULL RECITAL TRANSCRIPT"; cat "$TRANSCRIPT" 2>/dev/null; }
rm -f "$TRANSCRIPT" /tmp/r_pf
hdr "RESULT"; printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && { echo "  RECITAL CLEAN — wizard rehearsed end-to-end, no real keys, no leaks."; exit 0; } || exit 1
