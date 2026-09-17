#!/usr/bin/env bash
# hsm-scenarios.sh — exercise a STAGING Pico HSM across scenarios the happy path never touches.
#
#   ./hsm-scenarios.sh              # all scenarios
#   ./hsm-scenarios.sh S1 S4        # only the named ones
#
#   S1  a key wrapped under a DIFFERENT DKEK is refused        S6  rapid-fire back-to-back ops
#   S2  throughput                                             S7  concurrent signers
#   S3  low-S canonicality (Cosmos)                            S8  key deletion matches the docs (C1)
#   S4  wrong PIN decrements then recovers                     S9  ECDSA nonce hygiene
#   S5  the key survives a reboot                              S10 device identity survives a wipe
#
# The provisioning soak (hsm-cycle-test.sh) proves the operational happy path: wipe, rebuild the
# DKEK domain, import a seed-derived key, sign, verify. Passing that 14 times says nothing about
# whether the device REFUSES what it should, how fast it is, or how it behaves when something goes
# wrong — and those are the properties an HSM is actually bought for.
#
# NEVER RUN THIS AGAINST A DEVICE HOLDING REAL KEYS. Several scenarios deliberately wipe the card,
# spend PIN attempts, and attempt operations that must fail.
set -u

# The ceremony's python dependencies (pycvc, shamir_mnemonic, mnemonic, pycryptodome) are
# hash-pinned and installed into a venv, NOT into the system interpreter. Prefer that venv so a
# bare `python3` resolves to it. MEASURED 2026-08-06: Homebrew moved python3 from 3.13 to 3.14 and
# orphaned the site-packages holding pycvc, which made the offline CVC check report the DEVICE
# certificate as unparseable when the real cause was a missing host library. Falls through to the
# system python3 when the venv is absent, so nothing breaks on a host that never made one.
CEREMONY_VENV="${CEREMONY_VENV:-$HOME/.local/share/akash-hsm-venv}"
[ -x "$CEREMONY_VENV/bin/python3" ] && PATH="$CEREMONY_VENV/bin:$PATH"

SO_PIN="${HSM_SO_PIN:-3537363231383830}"
USER_PIN="${HSM_USER_PIN:-648219}"
STAGING="${HSM_STAGING_DIR:-$HOME/.local/share/akash-hsm-staging}"
# Resolved RELATIVE TO THIS REPO. These previously pointed into a personal worktree
# ($HOME/code/Akash-Console-hsmfix/...), which meant the suite ran for exactly one person on
# exactly one machine and reported a clean skip for everyone else.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTO_IMPORT="${HSM_AUTO_IMPORT:-$REPO/ceremony/qubes/scripts/hsm-auto-import.sh}"
VERIFY="${HSM_VERIFY:-$REPO/ceremony/qubes/scripts/verify-hsm-control.py}"
P11="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"
. "$REPO/tools/hsm-bench-lock.sh"
hsm_bench_lock_acquire wait || exit $?

# TARGET SELECTION. From 2026-09-02 there are two Pico HSMs on this bench, so "the card" is not a
# thing any more. Every tool below used to default to PC/SC reader 0, and reader 0 is whichever
# board enumerated first — measured the same day to FLIP after a firmware reset (board #2 took 0
# and the provisioned card moved to 1). Several scenarios here wipe the card and spend PIN
# attempts, so an ordering flip pointed at reader 0 is a wipe of the wrong device.
#
# Set HSM_TARGET_SERIAL to pin this run to one card by its token serial, which is stable.
# Falls back to the historical reader-0 behaviour when unset, so single-card hosts are unchanged.
HSM_TARGET_SERIAL="${HSM_TARGET_SERIAL:-}"
READER="${HSM_PCSC_INDEX:-0}"
SLOTIX="${HSM_SLOT_INDEX:-0}"
SLOTID="${HSM_SLOT_ID:-0}"
# Sourced UNCONDITIONALLY. It used to be sourced only inside the targeted branch, which left
# hsm_reader_name undefined on the untargeted path — where it is still called below, silently
# yielding an empty name. The resolver defines functions and runs nothing, so sourcing it always
# costs nothing and makes the reader count available to the refusal immediately after.
# shellcheck source=/dev/null
[ -f "$REPO/tools/hsm-reader-select.sh" ] && . "$REPO/tools/hsm-reader-select.sh"

# THE UNTARGETED FALLBACK IS ONLY SAFE WITH ONE CARD ON THE BUS. The comment above says an ordering
# flip pointed at reader 0 is a wipe of the wrong device, and then the fallback did exactly that
# whenever HSM_TARGET_SERIAL was unset: wipe_and_provision runs `--initialize` against $READER, and
# untargeted that is reader 0, "whichever board enumerated first". MEASURED 2026-09-11, reader 0 was
# the card this bench is NOT pinned to. The promise the fallback was written to keep is "single-card
# hosts are unchanged", and that is kept exactly — this refuses only when a second card makes the
# default ambiguous, which is the only case where it was ever wrong.
if [ -z "$HSM_TARGET_SERIAL" ] && [ -z "${HSM_PCSC_INDEX:-}" ] \
   && command -v hsm_reader_indices >/dev/null 2>&1; then
    _sc_n="$(hsm_reader_indices 2>/dev/null | grep -c .)"
    if [ "${_sc_n:-0}" -gt 1 ]; then
        echo "FATAL: $_sc_n PC/SC readers are present and no card was named, but scenarios here run --initialize. Set HSM_TARGET_SERIAL to the card to wipe (or HSM_PCSC_INDEX if you have already resolved it); reader 0 is whichever board enumerated first and that is not an identity." >&2
        exit 2
    fi
fi
if [ -n "$HSM_TARGET_SERIAL" ]; then
    READER="$(hsm_reader_for "$HSM_TARGET_SERIAL")" || {
        echo "FATAL: cannot resolve HSM_TARGET_SERIAL=$HSM_TARGET_SERIAL to a reader" >&2; exit 2; }
    SLOTIX="$(hsm_slot_index_for "$HSM_TARGET_SERIAL")" || {
        echo "FATAL: cannot resolve HSM_TARGET_SERIAL=$HSM_TARGET_SERIAL to a PKCS#11 slot" >&2; exit 2; }
    # Address the slot by ID. The ordinal shifts when the other card leaves or rejoins the bus;
    # the ID does not. Measured 2026-09-03: ids 0x0 and 0x4 against ordinals 0 and 1.
    SLOTID="$(hsm_slot_id_for "$HSM_TARGET_SERIAL")" || {
        echo "FATAL: cannot resolve HSM_TARGET_SERIAL=$HSM_TARGET_SERIAL to a PKCS#11 slot id" >&2; exit 2; }
    printf 'targeting card %s  (PC/SC reader %s, PKCS#11 slot id %s)\n' \
        "$HSM_TARGET_SERIAL" "$READER" "$SLOTID"
fi

# THE ROLE REGISTRY GATE. Destructibility is a property of the SERIAL, recorded in the committed
# registry (tools/hsm-staging-registry.json) — not of this run's good intentions. The scenarios below wipe and
# re-provision whatever $READER holds, so the card we RESOLVED (named serial, or the reader a
# parent handed us, or the single-card fallback) must be registered staging. DEFAULT-DENY:
# unlisted, prod, and an unreadable registry all refuse. An unavailable gate is a refusal too —
# a broken checkout must not turn a wipe suite into an ungated one.
if ! command -v hsm_assert_staging >/dev/null 2>&1; then
    echo "FATAL: the role registry gate (tools/hsm-reader-select.sh) is unavailable — this suite" >&2
    echo "runs --initialize and refuses to do so without the default-deny gate." >&2
    exit 2
fi
if [ -n "$HSM_TARGET_SERIAL" ]; then
    hsm_assert_staging "$HSM_TARGET_SERIAL" || exit 2
else
    _sc_ser="$(hsm_serial_at_reader "$READER" 2>/dev/null)" || _sc_ser=""
    [ -n "$_sc_ser" ] || {
        echo "FATAL: reader $READER did not answer with a serial — cannot prove it is a registered" >&2
        echo "staging card, and this suite runs --initialize. A blank card is provisioned by the" >&2
        echo "bootstrap path, not by this suite; a wedged card must never be mistaken for a blank one." >&2
        exit 2; }
    hsm_assert_staging "$_sc_ser" || exit 2
fi
# Children resolve their own card from these. Two variables, because they are two things:
# HSM_PCSC_INDEX is what `sc-hsm-tool -r` wants; HSM_READER is a reader NAME, which is what
# scsh's `new Card()` wants (hsm-import-key.sh:104).
export HSM_PCSC_INDEX="$READER" HSM_SLOT_INDEX="$SLOTIX" HSM_SLOT_ID="$SLOTID"
# Assign, THEN export. `export X="$(cmd)"` masks the command's exit status, and an empty
# HSM_READER is not a harmless default: scsh matches reader names by PREFIX, so an empty name
# matches the FIRST reader — which is how a run reaches the wrong card.
_rn="$(hsm_reader_name "$READER" 2>/dev/null)" || _rn=""
if [ -n "$_rn" ]; then export HSM_READER="$_rn"; else
  printf 'WARNING: could not read the name of reader %s; leaving HSM_READER unset rather than empty\n' "$READER" >&2
fi
SCSH="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}"
if [ -n "${HSM_SCENARIOS_WORK_DIR:-}" ]; then
    WORK="$HSM_SCENARIOS_WORK_DIR"
    (umask 077; mkdir -p -- "$WORK") || { echo "FATAL: cannot create HSM_SCENARIOS_WORK_DIR=$WORK" >&2; exit 1; }
else
    WORK="$(mktemp -d)"
fi
WANT="$*"

pass=0; fail=0; skip=0
WEDGED=0
# A skip that says only "card not responding" reads as an independent, unexplained gap. When the
# card was wedged by S5's reboot every later skip has ONE cause, and saying so is the difference
# between "five mysterious skips" and "one hardware failure with five consequences".
why(){ [ "${WEDGED:-0}" = 1 ] && printf '%s' " — cascade: the card was left wedged by S5's reboot, not an independent failure"; }
P() { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
S() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; skip=$((skip+1)); }
hdr() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
want() { [ -z "$WANT" ] || case " $WANT " in *" $1 "*) return 0;; *) return 1;; esac; }

t() { perl -e "alarm ${2:-60}; exec @ARGV" -- ${1}; }   # bounded run
provision_failure() {
    local log="$1" phase="$2" detail
    detail="$(grep -m1 -E 'GPError|SW[0-9A-Fa-f]{2}/[0-9A-Fa-f]{2}|CKR_[A-Z0-9_]+' "$log" 2>/dev/null || true)"
    if [ -n "$detail" ]; then
        printf '  %s failed: %s (log: %s)\n' "$phase" "$detail" "$log" >&2
    else
        printf '  %s failed; no GPError/SW1/SW2/CKR_ diagnostic (log: %s)\n' "$phase" "$log" >&2
    fi
}
# JUDGE BY OUTPUT, NOT EXIT STATUS. sc-hsm-tool exits 0 while printing "Failed to connect to card:
# Card not present" — so this returned TRUE for a card that was not there, and the suite ran device
# checks against nothing. MEASURED 2026-08-07: a nightly reported S4 retry counters as " -> "
# (empty, because nothing was read), S6 as "0/25 refused to sign", and then "card still responsive
# after the burst" as a PASS — on a card absent from the USB bus. Every one of those is a statement
# about hardware that was never made. The recovery tooling already requires a real Version line;
# this is the same rule, and it is why the whole scenarios step finished in 8 seconds.
card_alive() { perl -e 'alarm 30; exec @ARGV' -- sc-hsm-tool -r "$READER" 2>&1 | grep -qi '^Version'; }

wipe_and_provision() {
    # --initialize's EXIT STATUS IS NOT A VERDICT. The Pico drops off the USB bus as it
    # re-initialises, so sc-hsm-tool can report failure for an initialise that worked — which is
    # why hsm-staging-e2e.sh phase d ignores it too and verifies by behaviour. Aborting here on a
    # non-zero status turns a successful wipe into "provisioning failed" and takes every scenario
    # after it. The real verification is the card coming back and the DKEK import succeeding.
    perl -e 'alarm 200; exec @ARGV' -- sc-hsm-tool -r "$READER" --initialize --so-pin "$SO_PIN" --pin "$USER_PIN" \
        --dkek-shares 1 --label scen < /dev/null >/dev/null 2>&1 || true
    for _ in $(seq 1 40); do sleep 1; card_alive && break; done
    # RECOVER, DON'T JUST GIVE UP. A wedge during re-provisioning strands every scenario after it:
    # measured 2026-08-07, S8's restore failed here and took S9, S10 and the whole recovery step
    # with it. S5 already had this escape hatch; wipe_and_provision did not, even though it
    # INITIALIZEs the card far more often than S5 reboots it.
    if ! card_alive && [ -n "${HSM_SCEN_RECOVER_CMD:-}" ]; then
        echo "  card did not return after INITIALIZE — running \$HSM_SCEN_RECOVER_CMD"
        sh -c "$HSM_SCEN_RECOVER_CMD" >/dev/null 2>&1 || true
        for _ in $(seq 1 30); do sleep 2; card_alive && break; done
    fi
    card_alive || return 1
    DKEK_LOG="$WORK/dkek-import.log"
    if ! DKEK_PW="$(cat "$STAGING/dkek.pw")" perl -e 'alarm 120; exec @ARGV' -- \
        sc-hsm-tool -r "$READER" --import-dkek-share "$STAGING/dkek.pbe" --password env:DKEK_PW \
        --so-pin "$SO_PIN" < /dev/null >"$DKEK_LOG" 2>&1; then
        provision_failure "$DKEK_LOG" "DKEK import"
        return 1
    fi
    HSM_AUTO_DIR="$STAGING/auto-import" SCSH_HOME="$SCSH" HSM_USER_PIN="$USER_PIN" \
    HSM_DKEK_SHARE_IN="$STAGING/dkek.pbe" HSM_DKEK_PW_IN="$STAGING/dkek.pw" \
        perl -e 'alarm 300; exec @ARGV' -- "$AUTO_IMPORT" --run >"$WORK/prov.log" 2>&1 || {
            provision_failure "$WORK/prov.log" "key provisioning"
            return 1
        }
    # The card now holds the seed-derived key, NOT whatever the staging pin was taken from. Point
    # the reference at the key that is actually on the card, or nothing downstream can verify.
    refresh_ref_pub
}

# The public key sign_and_verify checks against. $STAGING/expected-pub.der is pinned by the staging
# harness from whatever key the card happened to hold at setup — but wipe_and_provision REPLACES
# that key with the deterministic BIP39-vector key hsm-auto-import.sh installs. Verifying a
# post-wipe signature against the pre-wipe pin fails every time, and because the gates below read
# that as "no usable key", a perfectly healthy card reported four skips and S6 0/25.
# MEASURED 2026-08-06 (nightly #3): card EC_POINT 044f4e2ad9…, pin 049c425690… — the card was
# signing correctly the whole time and the REFERENCE was stale.
# Re-derive from the same seed auto-import uses, host-side, so the reference stays INDEPENDENT of
# the card rather than becoming the card's own claim about itself.
REF_PUB="$STAGING/expected-pub.der"

# Read the mnemonic out of the auto-import script rather than restating it, so the two cannot drift.
DRILL_MNEMONIC="$(sed -n 's/^DRILL_MNEMONIC="\(.*\)"$/\1/p' "$AUTO_IMPORT" 2>/dev/null | head -1)"

refresh_ref_pub() {
    [ -n "$DRILL_MNEMONIC" ] || { echo "  could not read DRILL_MNEMONIC from $AUTO_IMPORT" >&2; return 1; }
    printf '%s' "$DRILL_MNEMONIC" > "$WORK/ref-m.txt"; chmod 600 "$WORK/ref-m.txt"
    ( umask 077; head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$WORK/ref.pw" )
    python3 "$REPO/ceremony/qubes/scripts/seed-to-pkcs12.py" --mnemonic-file "$WORK/ref-m.txt" \
        --password-file "$WORK/ref.pw" --out "$WORK/ref.p12" >/dev/null 2>&1 || return 1
    openssl pkcs12 -in "$WORK/ref.p12" -nodes -passin file:"$WORK/ref.pw" 2>/dev/null \
        | openssl ec -pubout -outform DER > "$WORK/ref-pub.der" 2>/dev/null
    [ -s "$WORK/ref-pub.der" ] || return 1
    REF_PUB="$WORK/ref-pub.der"
}

# rc 0 = signed and verified; 1 = the card would not sign; 2 = it signed and the signature did not
# verify; 3 = the VERIFIER could not run. Collapsing 1 and 2 is what hid the stale reference for
# two nightlies, and collapsing 2 and 3 would repeat the mistake one level down: verify-hsm-
# control.py uses the same house contract as cvc-devaut-verify.py (0 pass / 1 FAILED / 2
# operator-input error), so a missing dependency or an unreadable file would otherwise be reported
# as the CARD producing an invalid signature.
sign_and_verify() {   # $1 = key id
    local vrc
    head -c 32 /dev/urandom > "$WORK/d.bin"
    pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$USER_PIN" --sign --mechanism ECDSA \
        --id "$1" --input-file "$WORK/d.bin" --output-file "$WORK/s.bin" >/dev/null 2>&1 || return 1
    python3 "$VERIFY" --der "$REF_PUB" --digest "$WORK/d.bin" --sig "$WORK/s.bin" >/dev/null 2>&1
    vrc=$?
    case $vrc in 0) return 0 ;; 1) return 2 ;; *) return 3 ;; esac
}

# Gate for the scenarios that need a working key. Sets PROBE_WHY to the ACCURATE reason, so a
# stale reference can never again be reported as a missing key.
PROBE_WHY=""
probe_key() {   # $1 = scenario tag
    local rc
    # probe_key owns the ENTIRE gate, card liveness included, so that every path which returns
    # non-zero has set PROBE_WHY. Leaving liveness to a separate `card_alive &&` short-circuits
    # before this function runs and prints a SKIP with a blank reason — which is strictly worse
    # than the vague message it replaced.
    if ! card_alive; then
        PROBE_WHY="$1: card not responding$(why)"
        return 1
    fi
    sign_and_verify 31; rc=$?
    case $rc in
        0) PROBE_WHY=""; return 0 ;;
        1) PROBE_WHY="$1: the card would not sign with key 31" ;;
        2) PROBE_WHY="$1: key 31 SIGNS but the signature does not verify against $REF_PUB — the reference is wrong or the on-card key is not the seed's" ;;
        3) PROBE_WHY="$1: the signature VERIFIER could not run (host/tooling problem) — the card was never evaluated" ;;
    esac
    PROBE_WHY="$PROBE_WHY$(why)"
    return 1
}

echo "workdir: $WORK"
card_alive || { echo "card not responding — replug and flash COMMITFIX first" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
if want S1; then
hdr "S1  SECURITY: a key wrapped under a DIFFERENT DKEK must be REFUSED"
# THE test for the fleet model. Cloning to a second device is only safe because a card that does
# not share the DKEK domain CANNOT unwrap the blob. That has been asserted all along and only ever
# checked in an emulator whose own header admits it cannot prove the real path. If this ever
# silently SUCCEEDS, the DKEK provides no isolation and the fleet design is unsound.
if wipe_and_provision; then
    ( umask 077; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 > "$WORK/bad.pw" )
    DKEK_PW="$(cat "$WORK/bad.pw")" sc-hsm-tool -r "$READER" --create-dkek-share "$WORK/bad.pbe" \
        --password env:DKEK_PW >/dev/null 2>&1
    if [ -s "$WORK/bad.pbe" ]; then
        # Wrap under the FOREIGN share while the card still holds the original domain.
        HSM_AUTO_DIR="$WORK/foreign" SCSH_HOME="$SCSH" HSM_USER_PIN="$USER_PIN" \
        HSM_DKEK_SHARE_IN="$WORK/bad.pbe" HSM_DKEK_PW_IN="$WORK/bad.pw" \
            perl -e 'alarm 300; exec @ARGV' -- "$AUTO_IMPORT" --run > "$WORK/foreign.log" 2>&1
        rc=$?
        if [ $rc -eq 0 ] && grep -q "IMPORT-OK" "$WORK/foreign.log"; then
            F "CARD ACCEPTED A FOREIGN-DKEK KEY — DKEK provides no isolation (SECURITY)"
        else
            P "foreign-DKEK key refused (rc=$rc, no IMPORT-OK)"
        fi
    else
        S "could not create a second DKEK share"
    fi
else
    S "S1: provisioning failed, cannot set up"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S2; then
hdr "S2  THROUGHPUT: how many signatures per second?"
# The quorum flagged throughput as a production concern for an always-on signing oracle and nobody
# ever measured it. A number beats an opinion.
if probe_key S2; then
    N=20; t0=$(python3 -c 'import time;print(time.time())')
    ok=0
    for _ in $(seq 1 $N); do sign_and_verify 31 && ok=$((ok+1)); done
    t1=$(python3 -c 'import time;print(time.time())')
    python3 - "$t0" "$t1" "$N" "$ok" <<'PY'
import sys
t0,t1,n,ok=float(sys.argv[1]),float(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
d=t1-t0
print(f"  {ok}/{n} signatures verified, {d:.1f}s total, {d/n*1000:.0f} ms/sig, {n/d:.2f} sig/s")
print("  NOTE: each iteration is a fresh pkcs11-tool process + PIN login, so this is an")
print("  UPPER BOUND on latency, not the card's raw speed. A persistent session would be faster.")
PY
    [ "$ok" = "$N" ] && P "all $N signatures verified under load" || F "only $ok/$N verified"
else
    S "$PROBE_WHY"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S3; then
hdr "S3  SIGNATURE CANONICALITY: low-S, as Cosmos requires"
# Cosmos REJECTS high-S signatures. tx-signer normalises via toLowSCompact(), but if the card emits
# high-S at any meaningful rate that normalisation is load-bearing rather than belt-and-braces,
# and anything that signs without it is broken. Measure the actual rate.
if card_alive; then
    high=0; tot=15
    for _ in $(seq 1 $tot); do
        head -c 32 /dev/urandom > "$WORK/d.bin"
        pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$USER_PIN" --sign --mechanism ECDSA --id 31 \
            --input-file "$WORK/d.bin" --output-file "$WORK/s.bin" >/dev/null 2>&1 || continue
        python3 - "$WORK/s.bin" <<'PY' && high=$((high+1))
import sys
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
sig=open(sys.argv[1],'rb').read()
s=int.from_bytes(sig[32:64],'big') if len(sig)==64 else 0
sys.exit(0 if s > N//2 else 1)
PY
    done
    echo "  high-S: $high of $tot signatures"
    if [ "$high" -gt 0 ]; then
        P "card DOES emit high-S ($high/$tot) — toLowSCompact() normalisation is REQUIRED, not optional"
    else
        P "no high-S observed in $tot (normalisation still required: absence is not a guarantee)"
    fi
else
    S "S3: card not responding"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S4; then
hdr "S4  WRONG PIN: signing must fail, and retries must decrement then recover"
# Deliberately spends ONE attempt of three, then immediately verifies with the correct PIN, which
# resets the counter. Never gets near a lockout.
if card_alive; then
    before=$(sc-hsm-tool -r "$READER" 2>/dev/null | grep -oE "User PIN tries left *: *[0-9]+" | grep -oE "[0-9]+$")
    head -c 32 /dev/urandom > "$WORK/d.bin"
    pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin 999999 --sign --mechanism ECDSA --id 31 \
        --input-file "$WORK/d.bin" --output-file "$WORK/s.bin" >/dev/null 2>&1
    if [ $? -eq 0 ]; then F "SIGNED WITH A WRONG PIN (SECURITY)"; else P "wrong PIN refused"; fi
    mid=$(sc-hsm-tool -r "$READER" 2>/dev/null | grep -oE "User PIN tries left *: *[0-9]+" | grep -oE "[0-9]+$")
    [ "${mid:-9}" -lt "${before:-9}" ] && P "retry counter decremented ($before -> $mid)" \
                                       || F "retry counter did NOT decrement ($before -> $mid)"
    sign_and_verify 31 >/dev/null 2>&1
    after=$(sc-hsm-tool -r "$READER" 2>/dev/null | grep -oE "User PIN tries left *: *[0-9]+" | grep -oE "[0-9]+$")
    [ "${after:-0}" -ge "${before:-9}" ] && P "counter restored after a correct PIN ($mid -> $after)" \
                                        || F "counter NOT restored ($mid -> $after)"
else
    S "S4: card not responding"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S5; then
hdr "S5  PERSISTENCE: the key survives a reboot"
# Provisioning is worthless if a restart loses the key. Reboot via the rescue app (stock firmware,
# measured 5/5) and confirm the SAME key still signs for the SAME public key afterwards.
if probe_key S5; then
    perl -e 'alarm 45; exec @ARGV' -- opensc-tool -s "00:A4:04:00:08:A0:58:3F:C1:9B:7E:4F:21" \
        -s "80:1F:00:00" >/dev/null 2>&1
    sleep 3
    # 30s was not enough. MEASURED 2026-08-06 in the first full nightly: the reboot left the card
    # enumerating on the USB bus but MUTE at the applet — sc-hsm-tool got nothing — and S5 gave up
    # while the card was still down. Recovered afterwards in three seconds by `reset run` over SWD.
    back=0
    for _ in $(seq 1 "${HSM_SCEN_REBOOT_WAIT:-60}"); do sleep 1; card_alive && { back=1; break; }; done
    if [ "$back" != 1 ] && [ -n "${HSM_SCEN_RECOVER_CMD:-}" ]; then
        # An escape hatch for an attached debug probe, e.g.
        #   HSM_SCEN_RECOVER_CMD='printf "reset run\nexit\n" | nc 127.0.0.1 4444'
        # This NEVER changes S5's verdict — the reboot either worked or it did not. It exists so
        # that one wedged reboot does not silently cost the five scenarios that follow it.
        echo "  attempting recovery: \$HSM_SCEN_RECOVER_CMD"
        eval "$HSM_SCEN_RECOVER_CMD" >/dev/null 2>&1 || true
        for _ in $(seq 1 20); do sleep 1; card_alive && { back=2; break; }; done
    fi
    case "$back" in
        1) sign_and_verify 31
           case $? in
               0) P "key survived the reboot and still signs for the seed's pubkey" ;;
               1) F "the card came back but would NOT sign after the reboot" ;;
               2) F "the card signed after the reboot but the signature did not verify — the key is not the one that went in" ;;
               3) S "the card came back but the VERIFIER could not run — persistence was not evaluated" ;;
           esac ;;
        # A SINGLE REBOOT CANNOT MEASURE A RATE, AND THIS ONE WAS TRYING TO.
        #
        # MEASURED 2026-08-08, 60 rescue-applet reboots on the identified binary: 53 returned
        # unaided, 7 did not, 6 of those cleared by a single `reset run`, and ZERO needed a
        # human. So ~12% of reboots legitimately need the automated ladder. A one-shot check that
        # demands an unaided return therefore fails about one nightly in eight while describing
        # perfectly normal behaviour — and a check that cries wolf at that rate stops being read.
        #
        # Worse, the old verdict skipped `sign_and_verify` entirely in this branch, so the thing
        # the scenario actually exists to prove — THE KEY SURVIVED THE REBOOT — went untested in
        # precisely the runs where a reboot had gone badly and persistence mattered most.
        #
        # So test the properties a single sample CAN establish, and leave the rate to the soak,
        # which has the sample size for it:
        #     * no human was required          -> still true here, the ladder is unattended
        #     * the key survived the reboot    -> now actually checked
        # A reboot that needs hands is `back=0` below and remains a failure.
        2) sign_and_verify 31
           case $? in
               0) P "key survived the reboot; the card needed the unattended ladder to return (~12% do — see the 60-reboot soak), no human involved" ;;
               1) F "the card was recovered but would NOT sign after the reboot" ;;
               2) F "the card signed after recovery but the signature did not verify — the key is not the one that went in" ;;
               3) S "the card was recovered but the VERIFIER could not run — persistence was not evaluated" ;;
           esac ;;
        *) F "device did not come back from the reboot"
           WEDGED=1 ;;
    esac
else
    S "$PROBE_WHY"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S6; then
hdr "S6  RAPID-FIRE: back-to-back operations without pauses"
# The soak is leisurely; a real signer is not. Hammer it and see whether anything wedges.
if card_alive; then
    ok=0; nosign=0; noverify=0; toolerr=0; n=25
    for _ in $(seq 1 $n); do
        sign_and_verify 31
        case $? in
            0) ok=$((ok+1)) ;; 1) nosign=$((nosign+1)) ;;
            2) noverify=$((noverify+1)) ;; *) toolerr=$((toolerr+1)) ;;
        esac
    done
    [ "$toolerr" = 0 ] || F "the verifier failed to RUN on $toolerr/$n iterations — those say nothing about the card"
    # Report the two failure modes separately. "0/25" alone reads as a wedged card; "0 refused to
    # sign, 25 did not verify" points straight at the reference key, which is what actually broke.
    [ "$ok" = "$n" ] && P "$ok/$n rapid signatures verified" \
        || F "only $ok/$n under rapid fire ($nosign refused to sign, $noverify signed but did not verify, $toolerr verifier could not run)"
    card_alive && P "card still responsive after the burst" || F "card wedged after the burst"
else
    S "S6: card not responding$(why)"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S7; then
hdr "S7  CONCURRENT SESSIONS: parallel signers must not produce a WRONG signature"
# doc/STAGING-ATTESTATION.md lists concurrency under "Untested", and it is the one untested item
# with a correctness consequence rather than a capacity one: an always-on signing oracle will have
# overlapping requests. One card is one serialisation point, so losers are EXPECTED and fine — a
# refused signature is a retry. What must never happen is a signature that comes back rc=0 and
# then fails verification, because the caller has no way to tell that apart from a good one.
if probe_key S7; then
    K=6
    for i in $(seq 1 $K); do
        head -c 32 /dev/urandom > "$WORK/c$i.bin"
        ( pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$USER_PIN" --sign --mechanism ECDSA --id 31 \
            --input-file "$WORK/c$i.bin" --output-file "$WORK/c$i.sig" >/dev/null 2>&1
          echo $? > "$WORK/c$i.rc" ) &
    done
    wait
    okc=0; refused=0; bad=0
    for i in $(seq 1 $K); do
        if [ "$(cat "$WORK/c$i.rc" 2>/dev/null)" = 0 ] && [ -s "$WORK/c$i.sig" ]; then
            if python3 "$VERIFY" --der "$REF_PUB" --digest "$WORK/c$i.bin" \
                 --sig "$WORK/c$i.sig" >/dev/null 2>&1; then okc=$((okc+1)); else bad=$((bad+1)); fi
        else
            refused=$((refused+1))
        fi
    done
    echo "  $K concurrent signers: $okc verified, $refused refused, $bad claimed success but did NOT verify"
    [ "$bad" = 0 ] && P "no concurrent signer produced an invalid signature (refusals are acceptable)" \
                   || F "SECURITY: $bad/$K signatures returned rc=0 and then failed verification under concurrency"
    [ "$okc" -gt 0 ] && P "$okc/$K got through concurrently" \
                     || F "not one concurrent signature succeeded — the card serialises to zero throughput"
    card_alive && P "card still responsive after concurrent access" \
               || F "card wedged under concurrent access"
else
    S "$PROBE_WHY"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S8; then
hdr "S8  KEY DELETION BEHAVIOUR IS WHAT THE DOCS SAY — pinning requirement C1"
# C1 recorded a MEASURED constraint (2026-07-31): an individual private key could not be deleted,
# only --initialize cleared it, so rotation was a whole-device re-provisioning and the ~300-key
# ceiling was one-way. That was load-bearing for the fleet design and it was a firmware behaviour
# a future release could quietly change — so this scenario was written as the tripwire.
#
# IT FIRED, and the finding has since been investigated and written up: on this firmware an
# authenticated deletion SUCCEEDS and the key is really gone (doc/STAGING-ATTESTATION.md,
# REQUIREMENTS.md C1). So the expectation is now INVERTED rather than the scenario left failing
# forever. A tripwire that reports the same known state on every run is not a signal, it is noise
# that trains people to skip the summary — and this battery's whole purpose is that a red line
# means something.
#
# It still guards BOTH directions: deletion silently going back to refused would be just as
# significant, and would fail here. Set HSM_SCEN_EXPECT_DELETE_REFUSED=1 for a device documented
# to refuse it — the Nitrokey HSM 2 is untested (requirement D1, RUNBOOK-NITROKEY-GATE row 5) and
# may well be that device.
if probe_key S8; then
    dout="$(pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$USER_PIN" \
        --delete-object --type privkey --id 31 2>&1)"; drc=$?
    sign_and_verify 31; src=$?
    # The follow-up sign means OPPOSITE things depending on what the card just answered, and
    # reporting it the same way in both cases is how a successful deletion got labelled "the
    # deletion attempt DAMAGED the key". The key being gone after a deletion that reported
    # success is the deletion WORKING, not damage.
    if [ "$drc" != 0 ]; then
        if [ "${HSM_SCEN_EXPECT_DELETE_REFUSED:-0}" = 1 ]; then
            P "private-key deletion is REFUSED, as configured for this device ($(printf '%s' "$dout" | tail -1 | cut -c1-60))"
        else
            F "deletion is REFUSED, but this firmware is documented to ALLOW it — the behaviour changed back, or the docs are stale again ($(printf '%s' "$dout" | tail -1 | cut -c1-60))"
        fi
        case $src in
            0) P "the key still signs after the refused deletion attempt" ;;
            1) F "the refused deletion attempt DAMAGED the key — it no longer signs" ;;
            2) F "the refused deletion attempt DAMAGED the key — it signs but no longer verifies" ;;
            3) S "the verifier could not run — whether the key survived was not evaluated" ;;
        esac
    else
        if [ "${HSM_SCEN_EXPECT_DELETE_REFUSED:-0}" = 1 ]; then
            F "DELETION SUCCEEDED on a device configured to REFUSE it — rotation semantics are not what this deployment assumes"
        else
            P "authenticated deletion SUCCEEDS, as documented for this firmware (C1 is a key operation here, not a device re-provision)"
        fi
        # A tool that REPORTS success without deleting would be a different and worse finding
        # than one that really deletes, so confirm which of the two this is.
        case $src in
            1) P "…and the deletion was REAL — the key is gone and no longer signs (C1's constraint does not hold here)" ;;
            0) F "…but the key STILL SIGNS — deletion is being REPORTED without being performed, which is worse than either outcome" ;;
            2) F "…and the key is left in a broken half-state — it signs but no longer verifies" ;;
            3) S "the verifier could not run — whether the deletion was real was not evaluated" ;;
        esac
        # S8 is destructive when deletion works. Put the key back, or every scenario after this
        # one inherits a card with no key — which is what turned S9 into "0 signatures produced"
        # and left S10 measuring identity on a card that had just lost its key.
        echo "  restoring the key S8 deleted, so later scenarios are not testing an empty card"
        wipe_and_provision && P "card re-provisioned after the destructive deletion test" \
                           || F "could not re-provision after S8 — scenarios after this one are unreliable"
    fi
else
    S "$PROBE_WHY"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S9; then
hdr "S9  ECDSA NONCE HYGIENE: r must never repeat across different digests"
# If the same r appears in two signatures over DIFFERENT digests, the nonce was reused and the
# private key falls out with grade-school algebra. This is the single cheapest catastrophic-bug
# check available for any ECDSA signer, and nothing in this repo performed it.
#
# Note what is NOT asserted: r repeating for the SAME digest is not a fault — it is what RFC 6979
# deterministic nonces do, and treating it as a failure would flag a correct implementation. So
# the collision test uses distinct digests, and same-digest behaviour is characterised, not judged.
if card_alive; then
    : > "$WORK/rs.txt"; n=12; got=0
    for _ in $(seq 1 $n); do
        head -c 32 /dev/urandom > "$WORK/d.bin"
        pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$USER_PIN" --sign --mechanism ECDSA --id 31 \
            --input-file "$WORK/d.bin" --output-file "$WORK/s.bin" >/dev/null 2>&1 || continue
        python3 - "$WORK/s.bin" >> "$WORK/rs.txt" <<'PY'
import sys
sig = open(sys.argv[1], 'rb').read()
print(sig[:32].hex() if len(sig) == 64 else "short")
PY
        got=$((got+1))
    done
    uniq="$(sort -u "$WORK/rs.txt" | grep -vc '^short$' || true)"
    if [ "$got" -lt 2 ]; then
        F "S9: only $got signatures were produced — nonce reuse could not be evaluated"
    elif [ "$uniq" = "$got" ]; then
        P "$got signatures over distinct digests produced $uniq distinct r values — no nonce reuse"
    else
        F "SECURITY: only $uniq distinct r values across $got signatures — a repeated nonce leaks the private key"
    fi
    # Characterise the nonce mode. Neither answer is a failure; both are worth recording, because
    # deterministic signatures make a signing oracle replay-comparable and random ones do not.
    head -c 32 /dev/urandom > "$WORK/same.bin"
    for k in 1 2; do
        pkcs11-tool --module "$P11" --slot "$SLOTID" --login --pin "$USER_PIN" --sign --mechanism ECDSA --id 31 \
            --input-file "$WORK/same.bin" --output-file "$WORK/same$k.sig" >/dev/null 2>&1 || true
    done
    if [ -s "$WORK/same1.sig" ] && [ -s "$WORK/same2.sig" ]; then
        if cmp -s "$WORK/same1.sig" "$WORK/same2.sig"; then
            echo "  nonce mode: DETERMINISTIC (RFC 6979) — same digest, identical signature"
        else
            echo "  nonce mode: RANDOM — same digest, different signature"
        fi
    fi
else
    S "S9: card not responding$(why)"
fi
fi

# ---------------------------------------------------------------------------------------------
if want S10; then
hdr "S10 DEVICE IDENTITY SURVIVES RE-PROVISIONING (commissioning pins depend on it)"
# commission-card.sh pins the device by DEVAUT_CHR and the SHA-256 of C.DevAut, and B7 rests on
# that pin surviving normal operations. C.DevAut lives in read-only EF 2F02, so a wipe SHOULD NOT
# touch it — but "should" is a reading of the spec, and the whole point of this suite is that the
# hardware gets the last word. If the digest changed on re-initialisation, every commissioning
# pin would break on every rotation and the advice to pin the digest would be actively wrong.
if [ ! -x "$SCSH/scriptrunner" ]; then
    S "S10: no Smart Card Shell at $SCSH — C.DevAut cannot be read (set SCSH_HOME)"
elif ! card_alive; then
    S "S10: card not responding$(why)"
else
    devaut_field(){ ( cd "$SCSH" && ./scriptrunner "$REPO/ceremony/qubes/scripts/hsm-devaut-id.js" ) 2>/dev/null \
                       | grep -E "^DEVAUT_$1=" | head -1 | cut -d= -f2-; }
    before="$(devaut_field CHR)"
    before_sha="$(devaut_field SHA256)"
    if [ -z "$before" ]; then
        F "S10: could not read C.DevAut before the wipe — identity is unevaluatable"
    elif wipe_and_provision; then
        after="$(devaut_field CHR)"
        after_sha="$(devaut_field SHA256)"
        if [ -z "$after" ]; then
            F "C.DevAut is UNREADABLE after re-provisioning — commissioning could never re-verify this card"
        elif [ "$before" = "$after" ]; then
            P "the CHR survives a wipe + re-provision unchanged ($after)"
            # THE DIGEST IS A DIFFERENT QUESTION, and conflating the two was wrong. MEASURED on
            # this board 2026-08-06: three re-initialisations in one morning produced three
            # different C.DevAut digests (567f0be2 / 475ae1ff / 2e213f69) under ONE unchanging
            # CHR. The Pico MINTS its device certificate at --initialize, so the digest is not a
            # stable identity there; the CHR is, because it is derived from the board id.
            #
            # A Nitrokey HSM 2 is the opposite case — C.DevAut is factory-issued in a read-only
            # EF and must survive initialisation — so on that device a changed digest IS a
            # failure. Set HSM_SCEN_DEVAUT_STABLE=1 to demand it and this becomes a hard check.
            if [ "$before_sha" = "$after_sha" ]; then
                P "…and so does the C.DevAut digest (${after_sha:0:16}…) — safe to pin for commissioning"
            elif [ "${HSM_SCEN_DEVAUT_STABLE:-0}" = 1 ]; then
                F "the C.DevAut digest CHANGED across a re-provision (${before_sha:0:16}… -> ${after_sha:0:16}…) on a device required to keep it stable"
            else
                P "the digest changed as expected on a self-minting device (${before_sha:0:16}… -> ${after_sha:0:16}…) — pin the CHR here, not the digest"
            fi
            # And the digest the card reports must still satisfy the offline verifier, so the
            # gate's authoritative parse and the card's own readout cannot drift apart.
            hexline="$( ( cd "$SCSH" && ./scriptrunner "$REPO/ceremony/qubes/scripts/hsm-devaut-id.js" ) \
                        2>/dev/null | grep '^DEVAUT_HEX=' | cut -d= -f2- )"
            if [ -n "$hexline" ]; then
                printf '%s' "$hexline" > "$WORK/devaut.hex"
                # cvc-devaut-verify.py's documented contract: 0 = passed, 1 = verification
                # FAILED, 2 = operator/input error (missing file, bad flags, pycvc not
                # installed). Treating 2 as 1 reports "the certificate no longer parses" when
                # the truth is that the VERIFIER could not run — which is what happened here
                # once Homebrew moved python3 to 3.14 and orphaned the site-packages holding
                # pycvc. The certificate was fine: 443 bytes, correct CHR/CAR, valid 7F21.
                cvcout="$(python3 "$REPO/ceremony/qubes/scripts/cvc-devaut-verify.py" \
                            --hex "$WORK/devaut.hex" 2>&1)"; cvcrc=$?
                case $cvcrc in
                    0) P "the post-wipe certificate still parses as a valid TR-03110 CVC offline" ;;
                    2) S "the offline CVC check could not RUN (rc=2: $(printf '%s' "$cvcout" | grep -ai 'ERROR' | head -1 | cut -c1-110)) — the certificate was not evaluated either way" ;;
                    *) F "the post-wipe certificate FAILED offline verification: $(printf '%s' "$cvcout" | grep -a 'FAILED:' | head -1 | cut -c1-110)" ;;
                esac
            fi
        else
            F "THE CHR CHANGED across a re-provision ('$before' -> '$after') — the board has no stable identity at all, so commissioning cannot pin anything and B7 is unenforceable on this device"
        fi
    else
        F "S10: re-provisioning failed, so identity stability could not be evaluated"
    fi
fi
fi

# LEAVE THE BENCH AS THE GATE EXPECTS TO FIND IT.
#
# This suite wipes and re-provisions the card repeatedly, and it finishes in whatever posture the
# last scenario needed — typically with RRC re-enabled by a plain --initialize and a different user
# PIN. MEASURED 2026-08-08: a standalone run of this script left the card so that the NEXT
# battery's pre-gate hw_rrc failed with "the D3 posture is NOT in force" — a message that reads
# exactly like a firmware regression and is not one.
#
# hsm-staging-ci.sh restores the posture once at the end of its own destructive tiers, so it sets
# HSM_SUITE_NO_RESTORE=1 when it invokes this and does not pay for a second restore. A standalone
# run has no such parent, and must clean up after itself.
if [ -z "${HSM_SUITE_NO_RESTORE:-}" ] && [ -x "$(dirname "${BASH_SOURCE[0]}")/hsm-staging-restore.sh" ]; then
    echo
    echo " restoring the documented staging posture (HSM_SUITE_NO_RESTORE=1 to skip)"
    "$(dirname "${BASH_SOURCE[0]}")/hsm-staging-restore.sh" >/dev/null 2>&1 \
        && echo " posture restored" \
        || echo " WARNING: posture restore FAILED — the next gate will report a posture failure"
fi

echo
echo "==================================================="
echo " scenarios: $pass passed, $fail failed, $skip skipped"
echo " workdir: $WORK"
echo "==================================================="
[ "$fail" -eq 0 ] || exit 1
