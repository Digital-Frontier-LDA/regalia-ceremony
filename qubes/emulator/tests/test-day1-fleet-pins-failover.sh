#!/usr/bin/env bash
# test-day1-fleet-pins-failover.sh — REQUIREMENTS A3, A5, A6, A7.
#
# The two-device properties. Every one of these is a claim the fleet design rests on and none of
# them had a test before now.
#
#   A3/A5  SiteA and SiteB independently import the SAME seed key and reach the SAME address,
#          each under its OWN DKEK. No shared DKEK domain is required.
#   A6     Custody is PER DEVICE. A PKA session opened at SiteA authenticates nothing at SiteB,
#          and failed authentication attempts burn a per-device budget: probing one site never
#          degrades the other. This is what stops geo-redundancy from doubling the
#          confidentiality exposure: a site compromise stays a site compromise.
#   A7     COLD STANDBY under PKA. The standby holds the key but NO live authentication session,
#          so it CANNOT sign — enforced by the hardware, not by a policy flag a bug could flip.
#          The PKA session *is* the active-signer token: exactly one site in the fleet holds a
#          usable quorum at a time, so split-brain is impossible without a deliberate human act.
#
# UPDATED 2026-08-02 — THIS SUITE NOW MODELS THE CURRENT DESIGN. Decision D2 / requirement B8
# (ratified 2026-08-01) replaced the static user PIN with 2-of-3 public-key authentication at
# both production sites. This file previously modelled the SUPERSEDED design — "the standby
# holds no PIN; a custodian activates it by entering its static PIN" — and kept passing while
# the real architecture went unmodelled here. The failover path below is the PKA one:
# activation is custodian RE-AUTHENTICATION at the standby site (2-of-3), not a PIN entry, and
# a session that dies on power-off is the D2 control that makes a removed-and-returned token
# dead until re-authorised.
#
# WHAT A STUB CAN AND CANNOT SETTLE. Same discipline as test-pka-threshold.sh, whose device
# model this file reuses: the FIRMWARE questions — does auth state really die on power-off, can
# an SO-PIN reset override PKA, does the PIN stop working once custodians are enrolled, does the
# hardware LOCK after N failed PKA challenges — are NOT modellable; they are PLAN.md 1.4, on
# hardware. The PROCEDURAL shape of the failover IS modellable, and that is where the
# operational mistakes live. Where the suite touches a firmware behaviour (power-off clearing
# auth), it pins the SHAPE the hardware must satisfy so a contradicting hardware result is
# caught, not absorbed.
set -uo pipefail

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
LIS="$ROOT/sitea"; POR="$ROOT/siteb"

SEED="$ROOT/seed.key"; printf 'the-authoritative-seed-derived-funding-key' > "$SEED"

# ---- device model --------------------------------------------------------------------------------
# A device has: the imported key material (the SAME seed at both sites — A3/A5), its OWN DKEK id,
# its OWN enrolled-custodian set (B8: 2-of-3 public-key auth), a live AUTHENTICATED set that is
# emptied on power-off, and a LOCAL count of failed authentication presentations (A6: the budget
# is per-device). The threshold is fixed at 2 because B8 ratified 2-of-3, not a parameter.
dev_init(){ # $1=state-dir $2=dkek-id $3..=enrolled custodian keys
  local S="$1"; mkdir -p "$S"; shift
  printf '2' > "$S/threshold"; : > "$S/enrolled"; : > "$S/auth"; printf '0' > "$S/fails"
  printf '%s' "$1" > "$S/dkek"; cp "$SEED" "$S/key_material"; shift
  for k in "$@"; do printf '%s\n' "$k" >> "$S/enrolled"; done
}
addr(){ [ -f "$1/key_material" ] || return 1; cksum < "$1/key_material" | awk '{printf "akash1%08x",$1}'; }

# Presenting a custodian key authenticates ONLY if it is enrolled on THIS device. A rejected
# presentation burns one of THIS device's failed-attempt budget — never the other site's.
dev_auth(){ # $1=state $2=presented custodian key
  local S="$1"
  if grep -qxF "$2" "$S/enrolled" 2>/dev/null; then
    grep -qxF "$2" "$S/auth" 2>/dev/null || printf '%s\n' "$2" >> "$S/auth"; return 0
  fi
  printf '%d' "$(( $(cat "$S/fails") + 1 ))" > "$S/fails"; return 1
}
fails(){ cat "$1/fails"; }
dev_authed(){ grep -c . "$1/auth" 2>/dev/null | tr -dc '0-9'; }

# Signing REQUIRES a live PKA quorum on the device. No authenticated custodians -> cannot sign,
# full stop. The credential is the session, not anything the colo host stores.
sign(){ [ "$(dev_authed "$1")" -ge "$(cat "$1/threshold")" ]; }
dev_powercycle(){ : > "$1/auth"; }   # THE property D2 buys: auth dies with power

# The handover is a deliberate human act with a hard precondition: the active site must be
# ACTUALLY down before the standby is activated. Activating while the active still signs is
# the split-brain this fleet exists to prevent, so the procedure refuses it outright.
handover(){ # $1=active-site $2=standby-site -> 0 allowed, 1 refused
  sign "$1" && return 1
  return 0
}

# =================================================================================================
hdr "A3/A5: two sites, two DKEKs, ONE address"
dev_init "$LIS" "dkek-sitea" alice bob carol
dev_init "$POR" "dkek-siteb"  alice bob carol
AL="$(addr "$LIS")"; AP="$(addr "$POR")"
[ "$AL" = "$AP" ] && [ -n "$AL" ] \
  && P "SiteA and SiteB reach the same address ($AL)" \
  || F "addresses differ: SiteA=$AL SiteB=$AP"
[ "$(cat "$LIS/dkek")" != "$(cat "$POR/dkek")" ] \
  && P "…while holding DIFFERENT DKEKs — no shared domain needed" \
  || F "the two sites share a DKEK; the test proves nothing about independence"

hdr "A6: a PKA session is PER DEVICE — authenticating at SiteA enables nothing at SiteB"
dev_auth "$LIS" alice; dev_auth "$LIS" bob
sign "$LIS" && P "a 2-of-3 quorum at SiteA lets SiteA sign" || F "setup failed: SiteA quorum did not enable signing"
if sign "$POR"; then
  F "SITEA'S SESSION ENABLED SITEB — custody would be fleet-wide, not per-device"
else
  P "SiteB still cannot sign: the session lives on the device, not in the fleet"
fi

hdr "A6: failed presentations burn a LOCAL budget — probing one site never degrades the other"
# Whether the hardware LOCKS after N failed PKA challenges is a firmware question (PLAN.md 1.4)
# and is deliberately NOT asserted. What is asserted: the budget is per-device state, so an
# attacker hammering SiteA's reader spends nothing of SiteB's.
dev_auth "$LIS" mallory >/dev/null 2>&1
dev_auth "$LIS" mallory >/dev/null 2>&1
dev_auth "$LIS" nobody  >/dev/null 2>&1
[ "$(fails "$LIS")" = "3" ] && P "three rejected presentations counted against SITEA" \
                            || F "failed-attempt budget not counted (got $(fails "$LIS"))"
[ "$(fails "$POR")" = "0" ] \
  && P "…and SiteB's budget is UNTOUCHED — the budgets are independent" \
  || F "SiteB's budget moved; the fleet shares one guess budget"
sign "$LIS" && P "SiteA still signs on its real quorum — failed guesses do not weaken a site" \
            || F "rejected presentations broke SiteA's live quorum"

hdr "A7: COLD STANDBY — the standby holds the key but cannot sign, structurally"
[ -f "$POR/key_material" ] && P "standby holds the key (so it CAN take over)" || F "standby has no key"
if sign "$POR"; then
  F "STANDBY SIGNED WITH NO SESSION — split-brain is possible"
else
  P "standby cannot sign: no live PKA session (hardware-enforced, not a policy flag)"
fi

hdr "A7: activation is a deliberate QUORUM act — no single person can light up the standby"
# Under the superseded PIN design the fail-closed case was "the wrong site's PIN". Under PKA the
# equivalent is stronger: an UNENROLLED key authenticates nowhere, and even a legitimate
# custodian acting alone — the mistaken or coerced single operator — cannot reach threshold.
dev_auth "$POR" mallory >/dev/null 2>&1 \
  && F "an UNENROLLED key authenticated at the standby — enrolment is not checked" \
  || P "an unenrolled key fails closed at the standby"
dev_auth "$POR" alice
if sign "$POR"; then
  F "ONE custodian activated the standby — a lone operator can cause split-brain"
else
  P "one custodian alone cannot activate the standby (2-of-3 fails closed for a single actor)"
fi

hdr "A7: the handover REFUSES while the active site still signs"
if handover "$LIS" "$POR"; then
  F "handover allowed with SiteA live — a partition would produce two signers"
else
  P "refused: SiteA still holds a usable quorum (confirm it is ACTUALLY down first)"
fi
# SiteA dies — a grid fault takes the site (both datacenters share the Portuguese grid), and
# D2's control means the session dies with the power. The site does not come back signing.
dev_powercycle "$LIS"
sign "$LIS" && F "SiteA still signs after power loss — the D2 tamper signal does not exist" \
            || P "power loss killed SiteA's session — a removed/failed token is dead"
handover "$LIS" "$POR" && P "handover allowed once SiteA is confirmed down" \
                       || F "handover still refused after SiteA died — failover is impossible"

hdr "A7: failover completes by custodian RE-AUTHENTICATION at the standby (RTO is human-speed)"
# The RTO is bounded by reaching a second custodian, not by any technical step — stated, not
# implied, and deliberately unnamed until PLAN.md 1.4 measures the re-auth timing. The 3am
# case: with only one custodian reachable the site stays DOWN, not weakened.
sign "$POR" && F "setup failed: standby already signing" || P "standby still dark with one custodian authenticated (3am: down, not weakened)"
dev_auth "$POR" carol    # bob is unreachable; any second custodian completes the quorum
sign "$POR" && P "standby signs the moment a SECOND custodian re-authenticates" \
            || F "two custodians could not activate the standby"
[ "$(addr "$POR")" = "$AL" ] \
  && P "…and it signs for the SAME address — the fleet survives the handover" \
  || F "standby address differs after failover"

hdr "A7: exactly ONE active signer in the fleet, before AND after the failover"
# The invariant that makes the PKA session the active-signer token. And the recovery case: when
# SiteA's power returns it must NOT resume signing — its session is gone, so the standby
# activation does not become a split-brain when the failed site revives.
active=0; for d in "$LIS" "$POR"; do sign "$d" && active=$((active+1)); done
[ "$active" = "1" ] && P "exactly one site can sign after the handover" \
                    || F "$active sites can sign after the handover — the invariant is broken"
sign "$LIS" && F "SiteA resumed signing when power returned — the failover created a split-brain" \
            || P "a revived SiteA comes back DARK — re-activation needs a fresh quorum, so recovery is not a split-brain"

hdr "WHAT THIS SUITE DOES NOT ESTABLISH"
printf '  \033[33mNOTE\033[0m These are PROCEDURAL properties of a model. It does NOT establish that the\n'
printf '        hardware behaves this way. The open firmware questions — auth really dying on\n'
printf '        power-off, an SO-PIN reset overriding PKA, the PIN still working once custodians\n'
printf '        are enrolled — are PLAN.md 1.4 and are tracked in test-pka-threshold.sh.\n'

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
