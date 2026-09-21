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

# HSM_PROBE_REPO lets a frozen copy of this script (one run from outside the tree, so that editing
# the original mid-run cannot corrupt the running instance) still find the resolver it sources.
REPO="${HSM_PROBE_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[ -r "$REPO/tools/hsm-reader-select.sh" ] \
  || { printf 'dkek-refusal-probe: no resolver at %s/tools/hsm-reader-select.sh — set HSM_PROBE_REPO to the repository root\n' "$REPO" >&2; exit 2; }
READER="${HSM_PROBE_READER:-}"
DRILL_FAITHFUL=0
SAMPLES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --drill-faithful) DRILL_FAITHFUL=1; shift;;
    -h|--help) sed -n '2,32p' "$0"; exit 0;;
    *) SAMPLES="$1"; shift;;
  esac
done
SAMPLES="${SAMPLES:-60}"
OUT="${HSM_PROBE_DIR:-}"

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

# CREATED EXCLUSIVELY, NOT JUST CHMODDED. A predictable name under /tmp can be pre-created by
# another local user; `mkdir -p` accepts their directory and a failed chmod does not stop the run,
# so the DKEK share this writes would land somewhere readable. mktemp -d creates 0700 or fails, and
# an explicit HSM_PROBE_DIR must not already exist.
if [ -n "$OUT" ]; then
  mkdir "$OUT" 2>/dev/null || die "$OUT already exists (or cannot be created) — refusing to write DKEK material into a directory this run did not create"
  chmod 700 "$OUT" || die "could not restrict $OUT to this user"
else
  OUT="$(mktemp -d "${TMPDIR:-/tmp}/dkek-refusal-probe.XXXXXXXX")" || die "could not create a private working directory"
fi
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

# --drill-faithful REPRODUCES THE DRILL'S CONDITIONS, not just its command.
#
# The default mode reuses one share set and varies WHICH wrong password is reconstructed, which is
# the efficient way to sample the host-side decrypt. But the two acceptances of 2026-09-14 happened
# inside a loop that also WIPED AND RE-INITIALISED the card between runs and minted a fresh share
# set each time — so the card met each import with a PENDING DKEK domain, not a complete one, and
# the password was new every time. If the acceptance depends on either, the efficient mode cannot
# see it. This mode pays ~50s per sample to hold nothing constant.
if [ "$DRILL_FAITHFUL" = 1 ]; then
  [ -n "${HSM_SO_PIN:-}" ] && [ -n "${HSM_USER_PIN:-}" ] \
    || die "--drill-faithful re-initialises the card between samples: HSM_SO_PIN and HSM_USER_PIN are required"
  INIT_SH="${HSM_INIT_HARDENED_SH:-$REPO/qubes/scripts/hsm-init-hardened.sh}"
  [ -r "$INIT_SH" ] || die "--drill-faithful needs $INIT_SH"
  say "mode: drill-faithful — re-initialising the card and minting a fresh share set per sample"
else
  say "minting the share set (one PBKDF, ~25s)"
  mint "$OUT/dkek.pbe" "$OUT/shares.txt" || die "could not create the share set"
  chmod 600 "$OUT/dkek.pbe" "$OUT/shares.txt"
fi

refused=0; accepted=0; other=0; i=0
printf 'sample\tcorrupt_at\tcorrupt_value\tverdict\texit\n' > "$OUT/ledger.tsv"
while [ "$i" -lt "$SAMPLES" ]; do
  i=$((i+1))
  # VARY THE WRONG PASSWORD, not just repeat one. A fixed corrupted set reconstructs the SAME wrong
  # password every time, so N samples of it answer whether that one password happens to decrypt —
  # not how often a wrong one does. The corrupted position moves through the four fed shares, and
  # from sample 5 the value is random rather than the drill's zeros, which also separates "the
  # zeros are special" from "any wrong password does this".
  if [ "$DRILL_FAITHFUL" = 1 ]; then
    # Exactly the drill: a wiped card with one DKEK share outstanding, a freshly minted set, and
    # share 1 replaced by zeros.
    HSM_SO_PIN="$HSM_SO_PIN" HSM_USER_PIN="$HSM_USER_PIN" \
      perl -e 'alarm 200; exec @ARGV' -- bash "$INIT_SH" --reader "$READER" \
        --expect-serial "$_probe_serial" --rrc off --dkek-shares 1 --retries 3 \
        --label probe > "$OUT/init-$i.log" 2>&1 \
      || die "sample $i: the initializer failed (see $OUT/init-$i.log). Continuing would mint and
  import into a card nobody confirmed was freshly initialised, and record the result as a
  drill-faithful sample — a rate computed from runs that did not meet their own conditions."
    mint "$OUT/dkek.pbe" "$OUT/shares.txt" || die "sample $i: could not mint a share set"
    chmod 600 "$OUT/dkek.pbe" "$OUT/shares.txt"
    CORRUPT_AT=1
    CORRUPT_VALUE="00:00:00:00:00:00:00:00"
  else
    CORRUPT_AT=$(( (i - 1) % 4 + 1 ))
    if [ "$i" -le 4 ]; then
      CORRUPT_VALUE="00:00:00:00:00:00:00:00"
    else
      CORRUPT_VALUE="$(od -An -N8 -tx1 /dev/urandom | tr -s ' ' | sed 's/^ //; s/ /:/g')"
    fi
  fi
  export CORRUPT_AT CORRUPT_VALUE
  out="$(feed_shares "$OUT/shares.txt" 4 wrong | perl -e 'alarm 200; exec @ARGV' -- \
         sc-hsm-tool --reader "$READER" --import-dkek-share "$OUT/dkek.pbe" --pwd-shares-total 4 2>&1)"; rc=$?
  # THE STATUS AND THE TEXT TOGETHER. Classifying on output alone counts a command that died for an
  # unrelated reason — a reader that went away mid-run, a timeout — as a refusal or an acceptance,
  # and the whole point of this probe is a RATE. A refusal is the tool exiting non-zero AND saying
  # it could not decrypt; an acceptance is it exiting zero after getting past the decrypt.
  if [ "$rc" -ne 0 ] && grep -qi 'Error decrypting DKEK share' <<< "$out"; then
    verdict=refused; refused=$((refused+1))
  elif [ "$rc" -eq 0 ] && grep -qiE 'DKEK share imported|shares? still missing|Not allowed|Condition of use' <<< "$out"; then
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
  printf '%s\t%s\t%s\t%s\trc=%s\n' "$i" "$CORRUPT_AT" "$CORRUPT_VALUE" "$verdict" "$rc" >> "$OUT/ledger.tsv"
  printf '  %3d/%s  %s\n' "$i" "$SAMPLES" "$verdict"
done

printf '\n'
say "RESULT over $SAMPLES samples: refused=$refused ACCEPTED=$accepted other=$other"
# `other` is not noise to be rounded away: it is every run that neither refused cleanly nor got
# past the decrypt, and a probe reporting a RATE has to say how much of its sample it could not
# classify.
[ "$other" -eq 0 ] || say "NOTE $other sample(s) were neither: read $OUT/other-*.log before quoting a rate"
say "ledger: $OUT/ledger.tsv"
if [ "$accepted" -gt 0 ]; then
  say "an acceptance is recorded in $OUT/accepted-*.log (hex elided) — read what the tool printed"
fi
# The probe's own verdict is the RATE, not a pass/fail: it exists to measure, and a run with zero
# acceptances is as much an answer as one with many. Exit 0 unless the probe itself broke.
[ "$((refused + accepted + other))" = "$SAMPLES" ] || die "sample accounting is inconsistent"
