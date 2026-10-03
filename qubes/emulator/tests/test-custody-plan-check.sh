#!/usr/bin/env bash
# test-custody-plan-check.sh — custody-plan-check.py enforces the public site rules (CUSTODY-SITES.md)
# for any k-of-n: one site per share, at most n-k per region or zone, nobody reaches k alone, the
# directory holders reach nothing, pairs that reach k are reported (owner, 2026-09-30: the places
# stay private, the checklist for choosing them is public).
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CK="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/custody-plan-check.py"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
run(){ python3 "$CK" "$1" 2>&1 | sed $'s/\033\\[[0-9;]*m//g'; }
rc(){ python3 "$CK" "$1" >/dev/null 2>&1; echo $?; }
# site <id> <region> <reach...> -> a [[site]] table; zones via ZONES env
site(){ local id="$1" region="$2"; shift 2; local r; r="$(printf '"%s", ' "$@")"
  printf '[[site]]\nid = %s\nregion = "%s"\nreach = [%s]\n%s\n' "$id" "$region" "${r%, }" "${ZONES:+zones = [$ZONES]}"; }

hdr "the fictional example passes"
python3 "$CK" --example > "$T/ex.toml"
out="$(run "$T/ex.toml")"
[ "$(rc "$T/ex.toml")" = 0 ] && grep -q '^PLAN OK' <<< "$out" && P "example: PLAN OK, exit 0" || F "example did not pass: $out"
bad="$(grep -E '^  [A-Z]+ ' <<< "$out" | grep -vE '^  (OK  |WARN|FAIL) ' || true)"
[ -z "$bad" ] && P "every line reads OK, WARN or FAIL" || F "other markers: $bad"

hdr "rule 2: n-k per region, for 4-of-6, 3-of-5 and 2-of-3"
{ echo 'scheme = "shamir-4-of-6"'; echo 'directory_holders = ["executor"]'
  site 1 capital a; site 2 capital b; site 3 capital c; site 4 north d; site 5 north e; site 6 centre f; } > "$T/r1.toml"
out="$(run "$T/r1.toml")"
grep -q 'FAIL capital holds 3 sites (1, 2, 3): losing it leaves 3, fewer than 4' <<< "$out" && [ "$(rc "$T/r1.toml")" = 1 ] \
  && P "4-of-6: three sites in one region is a FAIL" || F "three in one region not refused: $out"
{ echo 'scheme = "shamir-3-of-5"'; echo 'directory_holders = ["executor"]'
  site 1 capital a; site 2 capital b; site 3 north c; site 4 north d; site 5 centre e; } > "$T/r2.toml"
[ "$(rc "$T/r2.toml")" = 0 ] && P "3-of-5 with two per region passes" || F "3-of-5 two per region refused: $(run "$T/r2.toml")"
{ echo 'scheme = "shamir-2-of-3"'; echo 'directory_holders = ["executor"]'
  site 1 capital a; site 2 capital b; site 3 north c; } > "$T/r3.toml"
grep -q 'FAIL capital holds 2 sites' <<< "$(run "$T/r3.toml")" && P "2-of-3: two in one region is a FAIL (n-k = 1)" || F "2-of-3 limit not applied"
{ echo 'scheme = "shamir-4-of-6"'; echo 'directory_holders = ["executor"]'
  ZONES='"fault"' site 1 capital a; ZONES='"fault"' site 2 north b; ZONES='"fault"' site 3 centre c
  site 4 north d; site 5 centre e; site 6 west f; } > "$T/r4.toml"
grep -q 'FAIL fault holds 3 sites (1, 2, 3)' <<< "$(run "$T/r4.toml")" && P "a hazard zone across regions counts like a region" || F "zones not counted: $(run "$T/r4.toml")"

hdr "rule 3: nobody reaches k alone"
{ echo 'scheme = "shamir-4-of-6"'; echo 'directory_holders = ["executor"]'
  site 1 capital tech; site 2 capital tech; site 3 north tech; site 4 north tech; site 5 centre e; site 6 centre f; } > "$T/a1.toml"
grep -q 'FAIL tech alone reaches 4 sites (1, 2, 3, 4): k is 4' <<< "$(run "$T/a1.toml")" && P "one actor reaching k is a FAIL" || F "actor reaching k not refused"
{ echo 'scheme = "shamir-4-of-6"'; echo 'directory_holders = ["executor"]'
  site 1 capital a; site 2 capital; site 3 north c; site 4 north d; site 5 centre e; site 6 centre f; } > "$T/a2.toml"
grep -q 'FAIL site 2 lists nobody in reach' <<< "$(run "$T/a2.toml")" && P "a site with nobody in reach is a FAIL" || F "empty reach accepted"

hdr "rule 3: the principal may reach k or more (WARN naming the defence), nobody else"
{ echo 'scheme = "shamir-4-of-6"'; echo 'principal = "boss"'; echo 'directory_holders = ["executor"]'
  site 1 capital boss; site 2 capital boss tech; site 3 north boss tech; site 4 north boss; site 5 centre boss; site 6 centre boss rel; } > "$T/pr1.toml"
out="$(run "$T/pr1.toml")"
grep -q 'WARN boss (the principal) reaches 6 sites (1, 2, 3, 4, 5, 6), k or more by design' <<< "$out" && P "the principal reaching all six is a WARN" || F "principal not a WARN: $out"
grep -q 'in-person rule' <<< "$out" && P "the WARN names the defence" || F "defence not named"
[ "$(rc "$T/pr1.toml")" = 0 ] && P "PLAN OK with the principal reaching every site" || F "principal reaching every site failed the plan"
sed 's/principal = "boss"/principal = "someone-else"/' "$T/pr1.toml" > "$T/pr2.toml"
grep -q 'FAIL boss alone reaches 6 sites' <<< "$(run "$T/pr2.toml")" && P "the same reach by a non-principal is still a FAIL" || F "non-principal reaching k accepted"
sed 's/directory_holders = \["executor"\]/directory_holders = ["boss"]/' "$T/pr1.toml" > "$T/pr3.toml"
grep -q 'FAIL boss holds the directory AND reaches' <<< "$(run "$T/pr3.toml")" && P "the principal holding the directory is still a FAIL (D18)" || F "principal + directory accepted"

hdr "rule 6: traces — logged sites (banks, datacenters) mean no silent recovery"
logged(){ sed "/^\[\[site\]\]/,+1{/^id = \($1\)$/a logged = true
}" "$2"; }
{ echo 'scheme = "shamir-4-of-6"'; echo 'directory_holders = ["executor"]'
  site 1 capital a; site 2 capital b; site 3 north c; site 4 north d; site 5 centre e; site 6 centre f; } > "$T/l0.toml"
grep -q 'WARN 6 sites keep no access log (1, 2, 3, 4, 5, 6): k of them could be opened without a trace' <<< "$(run "$T/l0.toml")" \
  && P "no logged site: a silent recovery is a WARN" || F "silent recovery not reported: $(run "$T/l0.toml")"
logged '2\|3\|4\|5' "$T/l0.toml" > "$T/l1.toml"
grep -q 'OK   any recovery touches at least 2 logged site(s): only 2 site(s) (1, 6) open without a trace' <<< "$(run "$T/l1.toml")" \
  && P "four logged of six: every recovery leaves at least 2 traces" || F "trace count wrong: $(run "$T/l1.toml" | grep -i trace)"
logged '2\|3' "$T/l0.toml" > "$T/l2.toml"
grep -q 'WARN 4 sites keep no access log (1, 4, 5, 6)' <<< "$(run "$T/l2.toml")" && P "two logged of six (k=4): still a WARN" || F "two logged not reported: $(run "$T/l2.toml" | grep -i log)"
[ "$(rc "$T/l0.toml")" = 0 ] && P "a trace WARN alone keeps PLAN OK" || F "trace WARN failed the plan"

hdr "rule 4: the directory holder reaches no site"
{ echo 'scheme = "shamir-4-of-6"'; echo 'directory_holders = ["lawyer"]'
  site 1 capital a; site 2 capital lawyer; site 3 north c; site 4 north d; site 5 centre e; site 6 centre f; } > "$T/d1.toml"
grep -q 'FAIL lawyer holds the directory AND reaches site(s) 2' <<< "$(run "$T/d1.toml")" && P "directory + a share is a FAIL" || F "directory holder with a share accepted"
{ echo 'scheme = "shamir-4-of-6"'
  site 1 capital a; site 2 capital b; site 3 north c; site 4 north d; site 5 centre e; site 6 centre f; } > "$T/d2.toml"
grep -q 'WARN no directory_holders listed' <<< "$(run "$T/d2.toml")" && P "no directory holder is a WARN" || F "missing directory holder not reported"

hdr "rule 5: pairs reaching k are WARN, pairs with the principal are not listed"
{ echo 'scheme = "shamir-4-of-6"'; echo 'principal = "boss"'; echo 'directory_holders = ["executor"]'
  site 1 capital x boss; site 2 capital x; site 3 north y boss; site 4 north y; site 5 centre boss; site 6 centre f; } > "$T/p1.toml"
out="$(run "$T/p1.toml")"
grep -q 'WARN x and y together reach 4 sites (1, 2, 3, 4)' <<< "$out" && P "a pair reaching k is a WARN" || F "pair not reported: $out"
grep -qE 'WARN (boss and|.* and boss)' <<< "$out" && F "a pair with the principal was listed" || P "pairs with the principal are not listed"
[ "$(rc "$T/p1.toml")" = 0 ] && P "WARN alone keeps PLAN OK" || F "a WARN failed the plan"

hdr "rule 1 and input errors"
{ echo 'scheme = "shamir-4-of-6"'; echo 'directory_holders = ["executor"]'
  site 1 capital a; site 2 north b; site 3 centre c; site 4 west d; site 5 east e; } > "$T/n1.toml"
grep -q 'FAIL 5 sites for 6 shares' <<< "$(run "$T/n1.toml")" && P "too few sites is a FAIL" || F "site count not checked"
for sch in "shamir-1-of-3" "shamir-5-of-4" "shamir-4-of-17" "4-of-6" "shamir-04-of-6x"; do
  printf 'scheme = "%s"\n' "$sch" > "$T/s.toml"
  grep -q 'FAIL scheme must be' <<< "$(run "$T/s.toml")" && P "scheme '$sch' refused" || F "scheme '$sch' accepted"
done
printf 'scheme = [broken\n' > "$T/bad.toml"
[ "$(rc "$T/bad.toml")" = 2 ] && P "unreadable TOML exits 2" || F "bad TOML exit $(rc "$T/bad.toml")"

hdr "guided --new: asks, checks as it goes, writes a private file that re-checks"
ans='4\n6\n\nexecutor\nsafe\ncapital\n\nprincipal\nn\n\nbox\ncapital\n\ntech\ny\n\nbox\ncapital\n\ntech\ny\n\nbank\nnorth\n\nprincipal, bank\ny\n\nbank\ncentre\n\nbank2\ny\n\nrelative\ncentre\n\nrelative\nn\nCoimbra\n'
out="$(printf "$ans" | python3 "$CK" --new "$T/new.toml" 2>&1 | sed $'s/\033\\[[0-9;]*m//g')"
grep -q 'FAIL capital now holds 3 sites' <<< "$out" && P "warns the moment a region goes over n-k" || F "no live region warning: $out"
grep -q '^PLAN FAILED' <<< "$out" && P "ends in the full check (PLAN FAILED here)" || F "no final check"
[ -f "$T/new.toml" ] && [ "$(stat -c %a "$T/new.toml")" = 600 ] && P "writes the plan, mode 0600" || F "plan not written 0600"
[ "$(rc "$T/new.toml")" = 1 ] && P "the written plan re-checks the same (exit 1)" || F "written plan re-check differs"
grep -q 'station = "Coimbra"' "$T/new.toml" && P "the station is recorded" || F "station missing"
[ "$(grep -c '^logged = true' "$T/new.toml")" = 4 ] && P "the four logged answers are recorded" || F "logged flags: $(grep '^logged' "$T/new.toml" | tr '\n' ' ')"
printf '4\n6\n' | python3 "$CK" --new "$T/new.toml" >/dev/null 2>&1; [ $? = 2 ] && P "refuses to overwrite an existing plan" || F "overwrote a plan"
printf '4\n6\n' | python3 "$CK" --new "$T/short.toml" >/dev/null 2>&1; e=$?
[ "$e" = 2 ] && [ ! -e "$T/short.toml" ] && P "input ending early writes nothing (exit 2)" || F "partial input: exit $e, file $(ls "$T/short.toml" 2>&1)"

ln -s "$T/target" "$T/link.toml"
printf "$ans" | python3 "$CK" --new "$T/link.toml" >/dev/null 2>&1; e=$?
[ "$e" = 2 ] && [ ! -e "$T/target" ] && P "a symlink at the plan path is refused, not followed" || F "symlink followed: exit $e"
( umask 000; printf "$ans" | python3 "$CK" --new "$T/umask.toml" >/dev/null 2>&1 )
[ "$(stat -c %a "$T/umask.toml")" = 600 ] && P "0600 even with umask 000 (created with the mode, not chmod after)" || F "mode $(stat -c %a "$T/umask.toml") under umask 000"

echo; echo "custody-plan-check: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
