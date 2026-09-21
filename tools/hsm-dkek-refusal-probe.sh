#!/usr/bin/env bash
# hsm-dkek-refusal-probe.sh — how often does `sc-hsm-tool --import-dkek-share` accept a WRONG
# password reconstructed from corrupted shares? Answers regalia#460 step 3, host-side.
#
# THE QUESTION. On 2026-09-14 the recovery drill's negative control — four password shares with
# share 1 replaced by 00:00:00:00:00:00:00:00, which must be REFUSED — was ACCEPTED in 2 of 30
# runs. Two explanations fit and the drill's output was discarded, so neither could be told from
# the other:
#
#   chance      sc-hsm-tool rebuilds a password from the shares and decrypts dkek.pbe (AES-CBC).
#               A wrong password leaves valid PKCS#7 padding about 1 time in 256, so an acceptance
#               is expected at p ~ 0.4%. Two or more in 30 runs has probability ~0.6% under that
#               model: unlikely, not excluded.
#   systematic  a parse fallback on the malformed 8-byte share value, or a password-prompt
#               fallback when reconstruction fails. Then the rate is far above 1/256 and the
#               refusal is not a control at all.
#
# 30 samples cannot separate 0.4% from 7%. This does, by taking many more of them — and it is the
# same host-side path the drill exercises, driven the same way, so the answer transfers.
#
# WHY IT STILL NEEDS A CARD. sc-hsm-tool resolves the reader BEFORE it decrypts: with `--reader 9`
# it exits at "Reader not found" without ever deriving a key, so a card-free run measures nothing.
# It is pointed at a scratch card and never gets past the decrypt on a refusal. An ACCEPTANCE does
# reach the card, which is why this refuses to run against anything the staging registry does not
# call `staging`.
#
#   HSM_PROBE_READER=1 ./tools/hsm-dkek-refusal-probe.sh [samples]     # default 60
#
# Each sample costs ~23s, almost all of it the PBKDF: budget 20 samples per 8 minutes.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
READER="${HSM_PROBE_READER:-}"
SAMPLES="${1:-60}"
OUT="${HSM_PROBE_DIR:-${TMPDIR:-/tmp}/dkek-refusal-probe-$(date +%Y%m%d-%H%M%S)}"

die(){ printf 'dkek-refusal-probe: %s\n' "$*" >&2; exit 2; }
say(){ printf '  %s\n' "$*"; }

[ -n "$READER" ] || die "set HSM_PROBE_READER to the PC/SC reader holding a SCRATCH card"
command -v sc-hsm-tool >/dev/null || die "sc-hsm-tool not found (install opensc)"
case "$SAMPLES" in *[!0-9]*|"") die "samples must be a whole number, got '$SAMPLES'";; esac
[ "$SAMPLES" -ge 1 ] || die "samples must be at least 1"

# THE CARD THIS AIMS AT MUST BE ONE THAT MAY BE TOUCHED. A refusal never reaches the card, but an
# acceptance sends IMPORT DKEK SHARE to it — which is the outcome under investigation, so it is
# exactly the run that must not land on a card nobody registered.
# shellcheck source=hsm-reader-select.sh
. "$REPO/tools/hsm-reader-select.sh"
_probe_serial="$(hsm_serial_at_reader "$READER" 2>/dev/null)" || _probe_serial=""
[ -n "$_probe_serial" ] || die "reader $READER did not answer with a serial — refusing to probe an unidentified card"
if command -v hsm_assert_staging_card >/dev/null 2>&1; then
  hsm_assert_staging_card "$_probe_serial" || exit 1
else
  die "hsm_assert_staging_card is unavailable; this probe can reach the card and will not run without the gate"
fi

mkdir -p "$OUT"; chmod 700 "$OUT"
say "probing $_probe_serial at reader $READER, $SAMPLES samples"
say "artifacts: $OUT"

# feed_shares, the drill's own helper, so this feeds the prompts exactly as the control does.
# `wrong` replaces share $CORRUPT_AT's value; CORRUPT_VALUE defaults to the drill's all-zero one.
feed_shares(){
  local f="$1" n="$2" wrong="${3:-}" first="${4:-1}" prime ids vals i id val
  prime="$(grep -m1 -oE 'Prime *: *[0-9a-fA-F:]+' "$f" | grep -oE '[0-9a-fA-F:]+$')"
  ids="$(grep -oE 'Share ID *: *[0-9]+' "$f" | grep -oE '[0-9]+$')"
  vals="$(grep -oE 'Share value *: *[0-9a-fA-F:]+' "$f" | grep -oE '[0-9a-fA-F:]+$')"
  [ -n "$prime" ] && [ -n "$ids" ] && [ -n "$vals" ] || return 1
  printf '%s\n' "$prime"
  i=0
  while [ "$i" -lt "$n" ]; do
    i=$((i+1))
    id="$(printf '%s\n' "$ids" | sed -n "$((first + i - 1))p")"
    val="$(printf '%s\n' "$vals" | sed -n "$((first + i - 1))p")"
    [ -n "$id" ] && [ -n "$val" ] || return 1
    [ "$wrong" = "wrong" ] && [ "$i" = "${CORRUPT_AT:-1}" ] && val="${CORRUPT_VALUE:-00:00:00:00:00:00:00:00}"
    printf '\n%s\n%s\n' "$id" "$val"
  done
}

mint(){   # one fresh 4-of-6 share set; the password is random per mint
  perl -e 'alarm 200; exec @ARGV' -- sc-hsm-tool --reader "$READER" --create-dkek-share "$1" \
      --pwd-shares-threshold 4 --pwd-shares-total 6 < /dev/null > "$2" 2>&1 && [ -s "$1" ]
}

say "minting the share set (one PBKDF, ~25s)"
mint "$OUT/dkek.pbe" "$OUT/shares.txt" || die "could not create the share set"
chmod 600 "$OUT/dkek.pbe" "$OUT/shares.txt"

refused=0; accepted=0; other=0; i=0
printf 'sample\tcorrupt_at\tcorrupt_value\tverdict\n' > "$OUT/ledger.tsv"
while [ "$i" -lt "$SAMPLES" ]; do
  i=$((i+1))
  # VARY THE WRONG PASSWORD, not just repeat one. A fixed corrupted set reconstructs the SAME wrong
  # password every time, so N samples of it answer whether that one password happens to decrypt —
  # not how often a wrong one does. The corrupted position moves through the four fed shares, and
  # from sample 5 the value is random rather than the drill's zeros, which also separates "the
  # zeros are special" from "any wrong password does this".
  CORRUPT_AT=$(( (i - 1) % 4 + 1 ))
  if [ "$i" -le 4 ]; then
    CORRUPT_VALUE="00:00:00:00:00:00:00:00"
  else
    CORRUPT_VALUE="$(od -An -N8 -tx1 /dev/urandom | tr -s ' ' | sed 's/^ //; s/ /:/g')"
  fi
  export CORRUPT_AT CORRUPT_VALUE
  out="$(feed_shares "$OUT/shares.txt" 4 wrong | perl -e 'alarm 200; exec @ARGV' -- \
         sc-hsm-tool --reader "$READER" --import-dkek-share "$OUT/dkek.pbe" --pwd-shares-total 4 2>&1)"
  if grep -qi 'Error decrypting DKEK share' <<< "$out"; then
    verdict=refused; refused=$((refused+1))
  elif grep -qiE 'DKEK share imported|shares? still missing|Not allowed|Condition of use' <<< "$out"; then
    # The decrypt SUCCEEDED and the tool went on to the card. That is the finding, whatever the
    # card then said — the control is the refusal, and there was none.
    verdict=ACCEPTED; accepted=$((accepted+1))
    printf '%s\n' "$out" | sed 's/[0-9A-Fa-f]\{2\}\(:[0-9A-Fa-f]\{2\}\)\{3,\}/<hex elided>/g' \
      > "$OUT/accepted-$i.log"
  else
    verdict=other; other=$((other+1))
    printf '%s\n' "$out" | sed 's/[0-9A-Fa-f]\{2\}\(:[0-9A-Fa-f]\{2\}\)\{3,\}/<hex elided>/g' \
      > "$OUT/other-$i.log"
  fi
  printf '%s\t%s\t%s\t%s\n' "$i" "$CORRUPT_AT" "$CORRUPT_VALUE" "$verdict" >> "$OUT/ledger.tsv"
  printf '  %3d/%s  %s\n' "$i" "$SAMPLES" "$verdict"
done

printf '\n'
say "RESULT over $SAMPLES samples: refused=$refused ACCEPTED=$accepted other=$other"
say "ledger: $OUT/ledger.tsv"
if [ "$accepted" -gt 0 ]; then
  say "an acceptance is recorded in $OUT/accepted-*.log (hex elided) — read what the tool printed"
fi
# The probe's own verdict is the RATE, not a pass/fail: it exists to measure, and a run with zero
# acceptances is as much an answer as one with many. Exit 0 unless the probe itself broke.
[ "$((refused + accepted + other))" = "$SAMPLES" ] || die "sample accounting is inconsistent"
