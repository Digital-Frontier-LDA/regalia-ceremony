#!/usr/bin/env bash
# test-transcript-redact.sh — the write-time redactor's own contract (#185).
#
# test-hsm-staging-ci.sh proves the redactor is WIRED into every uploaded surface; this file
# proves the FILTER ITSELF keeps the promises its header makes — the classes of secret it reads,
# the marker it leaves, the boundaries it states. The two are separate because a wiring test
# cannot observe a value the battery never prints (the SO-PIN), and a filter test cannot observe
# a pipeline the filter is not in.
#
# FALSIFIABILITY. Every value pushed through the filter here is generated at runtime from
# /dev/urandom: high-entropy (a low-entropy fixture reads as "no finding" to both the secret
# scanner and to any future entropy gate), and never a repo literal. A filter that had the value
# baked in could not pass, and a filter that silently passes values through fails below by name.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REDACT="$HERE/../../../tools/hsm-transcript-redact.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -r "$REDACT" ] || { echo "  (skipping: redactor not found at $REDACT)"; exit 0; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

PIN="ci$(od -An -N10 -tx1 /dev/urandom | tr -d ' \n')"
SO="so$(od -An -N10 -tx1 /dev/urandom | tr -d ' \n')"
EX1="dk$(od -An -N10 -tx1 /dev/urandom | tr -d ' \n')"
EX2="d2$(od -An -N10 -tx1 /dev/urandom | tr -d ' \n')"
# regex metacharacters: index()/substr() replacement must not parse the value as a pattern
META="m$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n').*[x]+\${}"

run(){ # $1=env-prefix string, stdin in, stdout out — one place so every case uses the real binary
  eval "env HSM_USER_PIN=\"\$PIN\" HSM_SO_PIN=\"\$SO\" HSM_CI_REDACT_EXTRA=\"\$EX1:\$EX2\" $1 \"$REDACT\""
}

# =================================================================================================
hdr "EVERY NAMED CLASS IS REPLACED, AND THE MARKER SAYS WHICH"
out="$(printf 'login --pin %s; so-pin %s; dkek %s and %s\n' "$PIN" "$SO" "$EX1" "$EX2" | run '')"
for pair in "$PIN:[redacted:user-pin]" "$SO:[redacted:so-pin]" "$EX1:[redacted:extra]" "$EX2:[redacted:extra]"; do
  v="${pair%%:*}"; m="${pair#*:}"
  case "$out" in *"$v"*) F "the $m value survived the filter";; *"$m"*) P "$m replaced its value";; *) F "neither the $m value nor its marker appeared";; esac
done

hdr "A VALUE WITH REGEX METACHARACTERS IS REPLACED LITERALLY"
out="$(printf 'pin %s end\n' "$META" | env HSM_CI_REDACT_EXTRA="$META" "$REDACT")"
case "$out" in *"$META"*) F "a metacharacter-bearing secret survived — the filter is parsing values as patterns";;
  *'[redacted:extra]'*) P "a metacharacter-bearing secret is replaced literally, not parsed";;
  *) F "metacharacter case produced neither the value nor the marker";; esac

hdr "EVERY OCCURRENCE, NOT JUST THE FIRST"
out="$(printf '%s %s %s\n' "$PIN" "$PIN" "$PIN" | run '')"
n="$(grep -o '\[redacted:user-pin\]' <<< "$out" | wc -l | tr -d ' ')"
[ "$n" = 3 ] && P "all three occurrences on a line are replaced" \
            || F "got $n markers for 3 occurrences — replacement stops at the first"

hdr "STATED BOUNDARIES HOLD: SHORT VALUES SKIP, EVERYTHING ELSE PASSES THROUGH"
out="$(printf 'the pin ab on the card\nuntouched line\n' | env HSM_USER_PIN=ab "$REDACT")"
[ "$out" = "$(printf 'the pin ab on the card\nuntouched line\n')" ] \
  && P "a value shorter than 4 is skipped and ordinary prose is untouched" \
  || F "the short-value boundary or pass-through is broken: $out"
out="$(env -u HSM_USER_PIN -u HSM_SO_PIN -u HSM_CI_REDACT_EXTRA "$REDACT" <<< 'no secrets configured')"
[ "$out" = 'no secrets configured' ] && P "with no secrets configured the filter is an identity" \
                                       || F "no-secret mode altered the stream: $out"

hdr "-o MODE IS A TEE: SAME BYTES TO THE FILE AS TO STDOUT"
: > "$T/tee.log"
out="$(printf 'pin %s plus normal output\n' "$PIN" \
       | env HSM_USER_PIN="$PIN" HSM_SO_PIN="$SO" HSM_CI_REDACT_EXTRA="$EX1:$EX2" "$REDACT" -o "$T/tee.log")"
[ -f "$T/tee.log" ] && [ "$(cat "$T/tee.log")" = "$out" ] \
  && case "$out" in *"$PIN"*) F "the -o stream leaked the value";; *'[redacted:user-pin]'*) P "-o writes the same redacted bytes to the file and stdout";; *) F "-o wrote neither value nor marker";; esac \
  || F "-o mode did not write the file or wrote different bytes than stdout"

hdr "A SECRET EMBEDDED IN ANOTHER SECRET LEAVES NO REMAINDER"
# Found on #211 review: replacing in insertion order means a shorter secret that is a PREFIX of
# a longer one replaces only its own span first, stranding the longer value's suffix in the
# clear (pin=1234, extra=1234567890 -> "[redacted:user-pin]567890"). The filter must replace
# the longest span first.
TAIL="t1$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"   # the suffix that must NOT survive
EMBED="$PIN$TAIL"                                        # an extra token that embeds the PIN
out="$(printf 'token %s pin %s\n' "$EMBED" "$PIN" \
       | env HSM_USER_PIN="$PIN" HSM_CI_REDACT_EXTRA="$EMBED" "$REDACT")"
case "$out" in
  *"$TAIL"*) F "the longer secret's suffix survived — replacement ran short-value-first";;
  *"$PIN"*)  F "the embedded PIN survived inside the longer secret";;
  *'[redacted:extra]'*) P "the embedded value is replaced whole — no remainder, no stranding";;
  *)         F "neither the values nor the markers appeared";;
esac

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
