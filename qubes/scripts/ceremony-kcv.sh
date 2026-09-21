#!/usr/bin/env bash
# ceremony-kcv.sh — kcv_of(): the DKEK key check value, parsed from sc-hsm-tool output.
#
# ONE DEFINITION, TWO CALLERS. ceremony.sh and hsm-recovery-drill.sh both decide whether two cards
# hold the same DKEK by string-comparing this value, and a drift between two copies of the parse
# would make the same key read as a mismatch (or, far worse, two unrelated cards read as equal).
# Sourced by both; there is no second copy.
# Extract the DKEK key check value from captured sc-hsm-tool output. OpenSC prints
# "DKEK key check value : <hex>"; the emulator model prints "KCV <hex>". Accept either.
kcv_of() {
  [ -s "${1:-}" ] || return 1
  local kcv
  # Normalise to LOWERCASE. The KCV is later compared with a string equality test to decide
  # whether two devices share a DKEK domain, and different producers print different case
  # (the emulator model uppercases, OpenSC lowercases). Without folding, the SAME key check
  # value reads as a mismatch and aborts the clone path on a correctly-cloned pair.
  kcv="$(grep -oiE '(key check value|kcv)[[:space:]:.=]*[0-9a-f]{6,}' "$1" | tail -1 \
    | grep -oiE '[0-9a-f]{6,}$' | tr 'A-F' 'a-f')"
  [ -n "$kcv" ] || return 1
  # An ALL-ZERO KCV is not a key check value, it is the absence of one. Measured 2026-07-29: a
  # Pico HSM (firmware 6.6) reports "DKEK key check value : 0000000000000000" even for a domain
  # populated with a random share whose correctly-derived KCV was DA4BF33D408C5C57 — it simply
  # does not compute the field. Returning it would make two UNRELATED devices compare EQUAL and
  # print "same domain confirmed", which is a false assurance drawn from no evidence. Fail the
  # parse instead, so the caller takes its existing "could not parse → warn, do not block" path
  # and the unwrap + restored-pubkey byte-compare stays the real gate.
  case "$kcv" in
    *[!0]*) printf '%s' "$kcv" ;;
    *) return 1 ;;
  esac
}
