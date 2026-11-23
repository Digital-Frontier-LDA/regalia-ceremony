#!/usr/bin/env bash
# test-yubikey-policy-docs.sh — the YubiKey ops identity's default touch and PIN policy, as the
# ceremony APPLIES it, is the policy the written procedure states, and both override variables are
# named with exactly the values the ceremony accepts.
#
# SPEC. regalia:openspec/specs/ceremony-yubikey-identity/spec.md, all four scenarios:
#   ceremony-yubikey-identity/default-policy-is-stated-and-applied
#   ceremony-yubikey-identity/documented-touch-behavior-matches-the-default
#   ceremony-yubikey-identity/documented-pin-cadence-matches-the-default
#   ceremony-yubikey-identity/both-overrides-are-named
# The spec->test join key (regalia-kms tools/spectrace) scans Go tests in regalia-kms only, so it
# cannot see this file. Where that gate keeps an allow-list, these four keys belong on it with this
# test named as the coverage the gate cannot reach.
#
# WHAT IS PROVEN, AND WHAT IS NOT.
#  - The applied policy is read by RUNNING step_yubikey_ops with run() replaced by a recorder. The
#    flags are the ones the step would hand to age-plugin-yubikey, not a grep of the source, so a
#    default changed anywhere on the way (the variable, the case guard, the command line) shows here.
#  - The accepted values are found the same way: each candidate value is run through the step; a
#    value that reaches age-plugin-yubikey is accepted, one refused before it is not.
#  - qubes/README.md lives in this repo and is always checked.
#  - doc/SECRETS.md lives in the tracking repo (regalia), not here. Set REGALIA_SECRETS_MD to its
#    path to check it. Without it that half prints UNKNOWN and counts as neither pass nor fail: an
#    unread document is not a matching one.
#  - The document checks match the sentences the documents use today. A reworded document fails
#    here and this test is updated with it; a policy statement nobody re-checks is how the two
#    drifted apart in the first place.
#  - Only the touch=never wording is understood. If the applied default ever becomes another touch
#    policy, the touch-behaviour check FAILS and says so rather than guess what the doc should say.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
QUBES="$(cd "$HERE/../.." && pwd)"
CEREMONY="$QUBES/scripts/ceremony.sh"
README="$QUBES/README.md"
SECRETS="${REGALIA_SECRETS_MD:-}"

STUB="$(mktemp -d)"
trap 'rm -rf "$STUB"' EXIT
# step_yubikey_ops checks the plugin is installed before it builds the command. This stub is never
# executed: run() is replaced below, so reaching it would itself be a failure.
printf '#!/bin/sh\necho "age-plugin-yubikey stub was executed" >&2\nexit 99\n' > "$STUB/age-plugin-yubikey"
chmod +x "$STUB/age-plugin-yubikey"

pass=0; fail=0; unknown=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
U(){ printf '  \033[33mUNKNOWN\033[0m %s\n' "$1"; unknown=$((unknown+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# applied VAR=VALUE... — run the real step in a subshell with only the given overrides set, and
# print the age-plugin-yubikey --generate command it would run (empty when the step refused before
# reaching it). The step reads the token through ykman before it gets there, so the emulator's
# stand-ins come first on PATH, as under run-tests.sh, and no real card is reachable (#104). Only
# the plugin is replaced by the never-executed stub.
applied() {
  (
    unset CEREMONY_YUBI_PIN_POLICY CEREMONY_YUBI_TOUCH_POLICY CEREMONY_YUBIKEY_SET state_step0_done
    local a
    for a in "$@"; do export "${a?}"; done
    export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1
    export PCSCLITE_CSOCK_NAME=/nonexistent/regalia-no-pcscd.comm
    PATH="$STUB:$HERE/../bin:$PATH"
    # shellcheck disable=SC1090
    source "$CEREMONY"
    run(){ printf '%s\n' "$*" >&3; return 0; }
    ask(){ return 0; }
    pause(){ :; }
    step_yubikey_ops >/dev/null 2>&1
  ) 3>&1 | grep '^age-plugin-yubikey --generate ' || true
}
flag() { sed -n "s/.*--$1 \([^ ]*\).*/\1/p" <<<"$2"; }

# values_in LINE VAR — the policy words a document lists for VAR on LINE: the {…} set when the line
# uses braces, otherwise everything after VAR up to the next ';'. Only policy words are kept, so
# "(default)" and the surrounding prose drop out.
values_in() {
  local rest="${1#*"$2"}"
  case "$rest" in
    *'{'*) rest="${rest#*\{}"; rest="${rest%%\}*}" ;;
    *) rest="${rest%%;*}" ;;
  esac
  grep -oE '[a-z]+' <<<"$rest" | grep -xE 'never|always|cached|once' | sort -u | paste -sd' ' -
}

# ---------------------------------------------------------------------------------------------
hdr "The policy the ceremony applies with no override"
# spec: ceremony-yubikey-identity/default-policy-is-stated-and-applied
[ -r "$CEREMONY" ] || { F "cannot read $CEREMONY — nothing below can be evaluated"; printf '  %d passed, %d failed\n' "$pass" "$fail"; exit 1; }
cmd="$(applied)"
case "$cmd" in
  "age-plugin-yubikey --generate "*) P "with both variables unset the step runs: $cmd" ;;
  *) F "with both variables unset the step ran no age-plugin-yubikey --generate (got: '${cmd:-nothing}')" ;;
esac
DEF_PIN="$(flag pin-policy "$cmd")"; DEF_TOUCH="$(flag touch-policy "$cmd")"
[ "$DEF_PIN" = once ] && P "applied PIN policy is once (the spec's default)" \
  || F "applied PIN policy is '${DEF_PIN:-none}', the spec's default is once"
[ "$DEF_TOUCH" = never ] && P "applied touch policy is never (the spec's default)" \
  || F "applied touch policy is '${DEF_TOUCH:-none}', the spec's default is never"

hdr "The values each override variable accepts"
accepted() {  # accepted VAR — the candidates the step lets through for VAR
  local v out=""
  for v in never always cached once sometimes; do
    [ -n "$(applied "$1=$v")" ] && out="$out $v"
  done
  printf '%s\n' "${out# }"
}
ACC_TOUCH="$(accepted CEREMONY_YUBI_TOUCH_POLICY | tr ' ' '\n' | sort -u | paste -sd' ' -)"
ACC_PIN="$(accepted CEREMONY_YUBI_PIN_POLICY | tr ' ' '\n' | sort -u | paste -sd' ' -)"
# A set that is empty, or that lets a made-up value through, means the probe is not measuring the
# guard: stop trusting the comparison below.
case " $ACC_TOUCH $ACC_PIN " in *" sometimes "*) F "a made-up policy value reached age-plugin-yubikey — the guard is not refusing" ;; esac
[ -n "$ACC_TOUCH" ] && P "CEREMONY_YUBI_TOUCH_POLICY accepts: $ACC_TOUCH" || F "no touch value was accepted — the probe cannot see the step"
[ -n "$ACC_PIN" ] && P "CEREMONY_YUBI_PIN_POLICY accepts: $ACC_PIN" || F "no PIN value was accepted — the probe cannot see the step"
for v in $ACC_TOUCH; do
  [ "$(flag touch-policy "$(applied "CEREMONY_YUBI_TOUCH_POLICY=$v")")" = "$v" ] \
    || F "CEREMONY_YUBI_TOUCH_POLICY=$v is accepted but not what reaches --touch-policy"
done
for v in $ACC_PIN; do
  [ "$(flag pin-policy "$(applied "CEREMONY_YUBI_PIN_POLICY=$v")")" = "$v" ] \
    || F "CEREMONY_YUBI_PIN_POLICY=$v is accepted but not what reaches --pin-policy"
done

# ---------------------------------------------------------------------------------------------
# check_doc NAME FILE DEFAULT_RE TOUCH_RE PIN_RE — one document against the applied policy.
check_doc() {
  local name="$1" file="$2" def_re="$3" touch_re="$4" pin_re="$5" line var want got n

  hdr "$name states the applied default"
  # spec: ceremony-yubikey-identity/default-policy-is-stated-and-applied
  grep -qE "$def_re" "$file" && P "$name states the default as the applied pin=$DEF_PIN, touch=$DEF_TOUCH" \
    || F "$name does not state the applied default pin=$DEF_PIN, touch=$DEF_TOUCH"

  hdr "$name: touch behaviour during decryption matches the default"
  # spec: ceremony-yubikey-identity/documented-touch-behavior-matches-the-default
  if [ "$DEF_TOUCH" != never ]; then
    F "the applied touch default is '$DEF_TOUCH'; this test only reads the touch=never wording — extend it"
  else
    grep -qE "$touch_re" "$file" && P "$name says the default needs no physical touch" \
      || F "$name does not say the default needs no physical touch"
    # The requirement's negative half: no document describes a physical check the default does
    # not perform. These are the phrasings that would claim a touch. The 'no touch prompt' and
    # 'no physical touch' forms are allowed, and only those words are removed before matching: a
    # touch claim sharing a line with an allowed phrase is still caught (dropping the whole line
    # let one through).
    n="$(grep -n '' "$file" | perl -ne '($l = $_) =~ s/\bno (?:physical )?touch(?: prompt)?//gi;
          print if $l =~ /touch-decrypt|touch prompt|tap the|touch the (?:yubikey|token|key)|requires? a touch|touch to (?:decrypt|confirm)/i')"
    [ -z "$n" ] && P "$name describes no touch the default does not perform" \
      || F "$name describes a touch the default (touch=never) does not perform: $n"
  fi

  hdr "$name: PIN cadence matches the default"
  # spec: ceremony-yubikey-identity/documented-pin-cadence-matches-the-default
  if [ -z "$pin_re" ]; then
    U "$name states the PIN policy value only; it makes no per-session/per-operation statement to compare"
  else
    grep -qE "$pin_re" "$file" && P "$name states the PIN cadence of pin=$DEF_PIN" \
      || F "$name does not state the PIN cadence of pin=$DEF_PIN"
  fi

  hdr "$name names both overrides with the accepted values"
  # spec: ceremony-yubikey-identity/both-overrides-are-named
  for var in CEREMONY_YUBI_TOUCH_POLICY CEREMONY_YUBI_PIN_POLICY; do
    if [ "$var" = CEREMONY_YUBI_TOUCH_POLICY ]; then want="$ACC_TOUCH"; else want="$ACC_PIN"; fi
    n=0
    while IFS= read -r line; do
      # Only lines that list values for the variable: a ∈ or a { after it.
      case "${line#*"$var"}" in *'∈'*|*'{'*) ;; *) continue ;; esac
      n=$((n+1))
      got="$(values_in "$line" "$var")"
      [ "$got" = "$want" ] && P "$name lists $var ∈ {$got}" \
        || F "$name lists $var ∈ {${got:-nothing}}, the ceremony accepts {$want}"
    done < <(grep -F "$var" "$file")
    [ "$n" -gt 0 ] || F "$name never lists the values of $var"
  done
}

# The default statements as each document writes them today, built from the APPLIED values so a
# changed default fails here instead of matching stale text.
pin_cadence=""
[ "$DEF_PIN" = once ] && pin_cadence='PIN is entered once per plugin session'
[ -n "$pin_cadence" ] || F "the applied PIN default is '$DEF_PIN'; this test only reads the pin=once wording — extend it"
check_doc "qubes/README.md" "$README" \
  "applies \`pin=$DEF_PIN, touch=$DEF_TOUCH\` by default" \
  'no physical touch' \
  "${pin_cadence:-a-cadence-this-test-cannot-read}"
# README marks the default value inside each override list as well.
grep -qF "\`CEREMONY_YUBI_TOUCH_POLICY\` ∈ \`$DEF_TOUCH\` (default" "$README" \
  && P "qubes/README.md marks $DEF_TOUCH as the touch default in the override list" \
  || F "qubes/README.md does not mark $DEF_TOUCH as the touch default in the override list"
grep -qF "\`CEREMONY_YUBI_PIN_POLICY\` ∈ \`$DEF_PIN\` (default" "$README" \
  && P "qubes/README.md marks $DEF_PIN as the PIN default in the override list" \
  || F "qubes/README.md does not mark $DEF_PIN as the PIN default in the override list"

if [ -z "$SECRETS" ]; then
  hdr "regalia:doc/SECRETS.md"
  U "REGALIA_SECRETS_MD is not set — doc/SECRETS.md (tracking repo) was not read, so it is not proven"
elif [ ! -r "$SECRETS" ]; then
  hdr "regalia:doc/SECRETS.md"
  F "REGALIA_SECRETS_MD=$SECRETS is not readable — the check was asked for and could not run"
else
  check_doc "doc/SECRETS.md" "$SECRETS" \
    "\`touch=$DEF_TOUCH, pin=$DEF_PIN\` by default" \
    'requires no physical touch' \
    "${pin_cadence:-a-cadence-this-test-cannot-read}"
fi

printf '\n  %d passed, %d failed, %d unknown\n' "$pass" "$fail" "$unknown"
[ "$fail" -eq 0 ]
