#!/usr/bin/env bash
# test-pka-threshold.sh — REQUIREMENTS B8, C5. Rehearses PLAN.md 1.4's PROCEDURAL half.
#
# WHY THIS EXISTS. Decision D2 ratified 2-of-3 public-key authentication replacing the static user
# PIN, and until now the suite had NO coverage of it at all. Worse, test-day1-fleet-pins-failover.sh
# used to model the SUPERSEDED design — "the standby holds NO PIN and therefore cannot sign" — so
# the emulator was validating an architecture we retired, and would have stayed green while the
# real one went untested. (Day 1 has since been reworked: it now models the PKA failover path and
# reuses this file's device model.)
#
# WHAT A STUB CAN AND CANNOT SETTLE. Two different kinds of claim live in B8:
#
#   FIRMWARE   does auth state really die on power-off? can an SO-PIN reset override PKA? does the
#              PIN stop working once custodians are enrolled? -> NOT modellable. A stub asserting
#              any of these would be inventing the answer. They are PLAN.md 1.4, on hardware.
#   PROCEDURE  does 1-of-3 fail and 2-of-3 succeed? does a revoked custodian stop counting? does
#              each SITE need its own quorum? what happens at 3am with one custodian unreachable?
#              -> fully modellable, and this is where the operational mistakes live.
#
# This suite covers the second kind only, and says so. It pins the SHAPE the hardware must satisfy,
# so a hardware result that contradicts it is caught rather than absorbed.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT

# ---- model -------------------------------------------------------------------------------------
# A device has: a set of ENROLLED custodian keys, a threshold, and a live AUTHENTICATED set that is
# emptied on power-off. Authenticating requires the presenting key to be enrolled.
dev_init(){ # $1=dev $2=threshold $3..=enrolled keys
  local d="$ROOT/$1"; mkdir -p "$d"; printf '%s' "$2" > "$d/threshold"; : > "$d/enrolled"; : > "$d/auth"
  shift 2; for k in "$@"; do printf '%s\n' "$k" >> "$d/enrolled"; done
}
dev_enrolled(){ grep -qxF "$2" "$ROOT/$1/enrolled" 2>/dev/null; }
# THERE IS NO SELECTIVE REVOCATION. Verified against the OpenSC source: --register-public-key works
# only while FEWER than N keys are registered, and NOTHING removes an enrolled PKA key. So "revoke
# alice" is not an operation this hardware offers — the only route is INITIALIZE DEVICE (which
# destroys every key, certificate and enrolment) followed by re-provisioning from the seed and
# re-enrolling the survivors plus the replacement.
#
# The model says so by CONSTRUCTION rather than by comment: there is no dev_revoke(). An earlier
# version of this file had one, and it was modelling a capability the cards do not have — the same
# defect class as the A7 model that pinned a retired design. A model that offers an impossible
# operation teaches an operator to expect it.
dev_reinit_and_reenrol(){ # $1=dev  $2..=the NEW full custodian set
  local name="$1" d="$ROOT/$1" thr; thr="$(cat "$d/threshold")"
  shift                                    # capture the name BEFORE shifting past it
  rm -rf "$d"                              # INITIALIZE DEVICE — everything goes
  dev_init "$name" "$thr" "$@"             # …then re-enrol from scratch
}
dev_auth(){ # present custodian key $2 to device $1
  dev_enrolled "$1" "$2" || return 1
  grep -qxF "$2" "$ROOT/$1/auth" 2>/dev/null || printf '%s\n' "$2" >> "$ROOT/$1/auth"; }
dev_authed(){ grep -c . "$ROOT/$1/auth" 2>/dev/null | tr -dc '0-9'; }
dev_can_sign(){ [ "$(dev_authed "$1")" -ge "$(cat "$ROOT/$1/threshold")" ]; }
dev_powercycle(){ : > "$ROOT/$1/auth"; }   # THE property D2 buys: auth dies with power

# =================================================================================================
hdr "2-of-3: one custodian is NOT enough"
dev_init sitea 2 alice bob carol
dev_auth sitea alice
dev_can_sign sitea && F "one custodian reached threshold — 2-of-3 is not enforced" \
                    || P "1 of 3 cannot sign (a single compromised token is not a quorum)"

hdr "…and two ARE"
dev_auth sitea bob
dev_can_sign sitea && P "2 of 3 can sign" || F "two custodians could not reach threshold"

hdr "THE PROPERTY D2 IS BOUGHT FOR: auth dies on power-off"
# This is simultaneously the control and the only tamper signal available on hardware with no
# on-device log — a token removed and returned is dead until a custodian re-authorises.
dev_powercycle sitea
dev_can_sign sitea && F "still signing after power-off — the tamper signal does not exist" \
                    || P "power-off cleared the authenticated set (removed-and-returned = dead)"
[ "$(dev_authed sitea)" = "0" ] && P "…and it cleared ALL of it, not just one key" \
                                 || F "power-off left $(dev_authed sitea) keys authenticated"

hdr "C5: rotating a custodian out means RE-INITIALISING — there is no selective revoke"
# The failure this prevents: one stale credential plus one current custodian IS a full quorum at
# 2-of-3, so a departed employee who kept their token can still sign. And the only way to remove
# them is to wipe the card — which is why C5 is a ceremony, not a command.
dev_init siteb 2 alice bob carol
dev_auth siteb alice; dev_auth siteb bob
dev_can_sign siteb || F "setup failed"

dev_reinit_and_reenrol siteb bob carol dave      # alice out, dave in
dev_enrolled siteb alice && F "alice survived the re-initialisation — the wipe is not a wipe" \
                         || P "re-initialisation removed the departing custodian entirely"
[ "$(dev_authed siteb)" = "0" ] \
  && P "…and cleared every authenticated session with it" \
  || F "authenticated sessions survived a device wipe"

hdr "…and the NEW set reaches quorum, while the old member cannot"
dev_auth siteb alice 2>/dev/null && F "the departed custodian still authenticates" \
                                 || P "the departed custodian cannot authenticate at all"
dev_auth siteb bob; dev_auth siteb dave
dev_can_sign siteb && P "bob + dave reach 2-of-3 on the re-enrolled set" \
                   || F "rotation left the site unable to sign — the outage just moved"

hdr "The model offers NO selective-revoke operation"
# Asserted structurally: if someone reintroduces one, this fails and they have to justify it
# against the OpenSC source rather than against convenience.
# Anchored to a DEFINITION at line start, not any mention — the comment above names it, and a
# check that matches its own documentation is a check that always fires.
MODEL_CODE="$(python3 "$HERE/source_lexing.py" shell "$0")" \
  || { echo "source lexer failed" >&2; exit 2; }
grep -qE '^dev_revoke\(\)' <<<"$MODEL_CODE" \
  && F "a selective revoke exists in the model — the hardware has none" \
  || P "no dev_revoke() — the model cannot teach an operation the cards lack"

hdr "Each SITE needs its OWN quorum — authenticating at one does not enable the other"
dev_init lis2 2 alice bob carol; dev_init por2 2 alice bob carol
dev_auth lis2 alice; dev_auth lis2 bob
dev_can_sign lis2 || F "setup failed"
dev_can_sign por2 && F "authenticating at SiteA enabled SiteB — the sites are not independent" \
                  || P "SiteB still cannot sign (custody is per-device, not fleet-wide)"

hdr "THE 3AM CASE — one custodian unreachable"
# The ratified answer: any two of three authenticate; if only one is reachable the site stays
# DEGRADED rather than custody being weakened. This asserts the second half, which is the one
# people are tempted to bargain away at 3am.
dev_init night 2 alice bob carol
dev_auth night alice          # bob asleep, carol on a plane
dev_can_sign night && F "a single reachable custodian brought the site up — the threshold was bargained away" \
                   || P "one reachable custodian leaves the site DOWN, not weakened"
dev_auth night carol
dev_can_sign night && P "…and the moment a second is reachable, it recovers" || F "two custodians could not recover the site"

hdr "NEGATIVE CONTROLS — this model must be able to fail"
dev_init ctrl 2 alice bob carol
dev_auth ctrl mallory 2>/dev/null && F "an UNENROLLED key authenticated — the model ignores enrolment" \
                                  || P "an unenrolled key cannot authenticate"
dev_auth ctrl alice; dev_auth ctrl alice
[ "$(dev_authed ctrl)" = "1" ] && P "authenticating twice with the SAME key counts once (no self-quorum)" \
                               || F "one custodian reached threshold by presenting twice"

hdr "WHAT THIS SUITE DOES NOT ESTABLISH"
printf '  \033[33mNOTE\033[0m These are PROCEDURAL properties of a model. It does NOT establish that the\n'
printf '        hardware behaves this way. Three firmware questions remain open and are PLAN.md 1.4:\n'
printf '          1. does the authenticated set REALLY clear on power-off?\n'
printf '          2. can an SO-PIN RESET override PKA? (if yes, B8 and B6 are a MANDATORY PAIR)\n'
printf '          3. does the user PIN stop working once custodians are enrolled? Measured\n'
printf '             2026-08-01 with ZERO enrolled: the PIN still logged in, so "PKA REPLACES the\n'
printf '             static PIN" is UNVERIFIED — and if it is false, D2 does not deliver what it\n'
printf '             claims (no credential on the colo host unlocks the key).\n'

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
