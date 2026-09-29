#!/usr/bin/env bash
# qubes/dom0/vault-tools-update.sh — the one-command template update run in dom0. dom0 tools are
# stand-ins here: qvm-run -p "downloads" a tarball built from this checkout, qubesctl prints a Salt
# summary, sudo runs the command, /srv/salt is a scratch directory.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
QUBES="$(cd "$HERE/../.." && pwd)"
UPD="$QUBES/dom0/vault-tools-update.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/salt" "$T/work" "$T/home"

# the release tarball, laid out as GitHub builds it: regalia-ceremony-<tag>/qubes/...
tar -C "$QUBES/.." -czf "$T/release.tgz" --transform 's,^qubes,regalia-ceremony-vt-test/qubes,' \
    --exclude='qubes/emulator' qubes
SHA="$(sha256sum "$T/release.tgz" | cut -d' ' -f1)"

for c in qvm-create qvm-kill qvm-remove; do printf '#!/bin/sh\necho "%s $*" >> "$CALLS"\nexit 0\n' "$c" > "$T/bin/$c"; done
cat > "$T/bin/qvm-run" <<'SH'
#!/bin/sh
echo "qvm-run $*" >> "$CALLS"
[ -n "${FAIL_DL:-}" ] && exit 1
cat "$RELEASE"
SH
cat > "$T/bin/qvm-shutdown" <<'SH'
#!/bin/sh
echo "qvm-shutdown $*" >> "$CALLS"
SH
cat > "$T/bin/qubesctl" <<'SH'
#!/bin/sh
echo "qubesctl $*" >> "$CALLS"
if [ -n "${SALT_FAIL:-}" ]; then printf 'Summary for vault-tools\nSucceeded: 16\nFailed:     2\n'; exit 1; fi
printf 'Summary for vault-tools\n------------\nSucceeded: 18 (changed=3)\nFailed:     0\n'
exit "${SALT_RC:-0}"
SH
# cp / mv that fail when an argument contains a chosen string, to exercise the staging and the rollback.
for c in cp mv; do
cat > "$T/bin/$c" <<SH
#!/bin/bash
v="FAIL_$(tr a-z A-Z <<< "$c")"; pat="\${!v:-}"
if [ -n "\$pat" ] && [[ "\$*" == *"\$pat"* ]]; then echo "$c: simulated failure" >&2; exit 1; fi
exec /bin/$c "\$@"
SH
done
printf '#!/bin/sh\nexec "$@"\n' > "$T/bin/sudo"
chmod +x "$T/bin"/*

run(){ PATH="$T/bin:$PATH" CALLS="$T/calls" RELEASE="$T/release.tgz" SALT_DIR="$T/salt" WORK="$T/work" \
       HOME="$T/home" bash "$UPD" "$@" 2>&1; }

hdr "a good tag and sha256: downloaded, verified, copied, applied, template shut down"
: > "$T/calls"
out="$(run vt-test "$SHA")"; rc=$?
[ "$rc" = 0 ] && grep -q "^DONE: vt-test applied" <<< "$out" && P "succeeds and says DONE" || F "did not succeed: $out"
[ -f "$T/salt/vault-tools.sls" ] && [ -f "$T/salt/vault-ceremony-scripts/ceremony.sh" ] && [ -f "$T/salt/vault-ceremony-requirements.txt" ] && [ -d "$T/salt/vault-ceremony-recovery" ] \
  && P "the recipe is in the Salt dir" || F "recipe missing from the Salt dir"
grep -q "Succeeded: 18, Failed: 0" <<< "$out" && P "reports the Salt summary" || F "no Salt summary"
grep -q "qvm-shutdown --wait vault-tools" "$T/calls" && P "shuts the template down" || F "template not shut down"
grep -q "qvm-remove -f vault-fetch-" "$T/calls" && P "removes the download disposable" || F "disposable not removed"
[ ! -e "$T/work/vault-tools-vt-test.tgz" ] && P "cleans up the download" || F "download left behind"

hdr "a second run over an existing copy does not nest scripts/ inside the old one"
out="$(run vt-test "$SHA")"
[ ! -e "$T/salt/vault-ceremony-scripts/scripts" ] && P "no nested scripts/scripts" || F "scripts nested inside the old copy"

hdr "the sha256 prefix does not match: nothing is changed"
echo "sentinel" > "$T/salt/vault-ceremony-scripts/ceremony.sh"; : > "$T/calls"
out="$(run vt-test 0000000000000000)"; rc=$?
[ "$rc" != 0 ] && grep -q "NOTHING was changed" <<< "$out" && P "refused" || F "a wrong sha256 was accepted"
[ "$(cat "$T/salt/vault-ceremony-scripts/ceremony.sh")" = sentinel ] && P "the Salt dir was not touched" || F "the Salt dir changed after a wrong sha256"
grep -q "qubesctl" "$T/calls" && F "Salt ran after a wrong sha256" || P "Salt did not run"
grep -q "qvm-remove -f vault-fetch-" "$T/calls" && P "the disposable is still removed" || F "disposable left running"

hdr "the download fails"
out="$(FAIL_DL=1 run vt-test "$SHA")"; rc=$?
[ "$rc" != 0 ] && grep -q "download failed" <<< "$out" && P "fails with a reason" || F "download failure not reported"

hdr "Salt reports failures: the run FAILS and says how to find them"
out="$(SALT_FAIL=1 run vt-test "$SHA")"; rc=$?
[ "$rc" != 0 ] && grep -q "Failed: 2" <<< "$out" && grep -q "Result: False" <<< "$out" && P "fails, names the count and where to look" || F "a failed apply passed: $out"

hdr "qubesctl exits non-zero although the summary says Failed: 0: the run FAILS"
: > "$T/calls"
out="$(SALT_RC=3 run vt-test "$SHA")"; rc=$?
[ "$rc" != 0 ] && grep -q "qubesctl exited 3" <<< "$out" && ! grep -q "^DONE" <<< "$out" && P "fails" || F "a non-zero qubesctl passed: $out"
grep -q "qvm-shutdown" "$T/calls" && F "template shut down after a failed apply" || P "template not shut down"

hdr "a copy into staging fails: the installed files are NOT touched"
echo "sentinel" > "$T/salt/vault-ceremony-scripts/ceremony.sh"; echo keep > "$T/salt/other.sls"
out="$(FAIL_CP=vault-ceremony-recovery run vt-test "$SHA")"; rc=$?
[ "$rc" != 0 ] && grep -q "NOT changed" <<< "$out" && P "fails, says nothing changed" || F "staging failure not reported: $out"
[ "$(cat "$T/salt/vault-ceremony-scripts/ceremony.sh")" = sentinel ] && [ -d "$T/salt/vault-ceremony-recovery" ] && P "previous files intact" || F "previous files damaged"
[ ! -e "$T/salt/.vault-tools-stage" ] && [ ! -e "$T/work/vault-tools-vt-test.tgz" ] && [ ! -e "$T/work/vault-tools-vt-test" ] && P "staging and download removed on failure" || F "temporary files left behind"

hdr "a move during the swap fails: the previous files are put back"
out="$(FAIL_MV=.vault-tools-stage/vault-ceremony-recovery run vt-test "$SHA")"; rc=$?
[ "$rc" != 0 ] && grep -q "previous files restored" <<< "$out" && P "fails, says restored" || F "swap failure not reported: $out"
[ "$(cat "$T/salt/vault-ceremony-scripts/ceremony.sh")" = sentinel ] && [ -d "$T/salt/vault-ceremony-recovery" ] && [ -f "$T/salt/vault-tools.sls" ] && P "previous files restored" || F "rollback incomplete: $(ls -A "$T/salt")"
[ "$(cat "$T/salt/other.sls")" = keep ] && P "unrelated Salt files untouched" || F "an unrelated Salt file changed"

hdr "bad input is refused before anything runs"
: > "$T/calls"
out="$(run 'vt;rm -rf /' "$SHA")"; rc=$?
[ "$rc" != 0 ] && [ ! -s "$T/calls" ] && P "a tag with shell characters is refused" || F "bad tag accepted"
out="$(run vt-test abc123)"; rc=$?
[ "$rc" != 0 ] && grep -q "16 to 64 hex" <<< "$out" && P "a sha256 shorter than 16 characters is refused" || F "short sha256 accepted"
out="$(run vt-test "$(tr 'a-f' 'A-F' <<< "${SHA:0:20}")")"; rc=$?
[ "$rc" = 0 ] && P "an upper-case sha256 prefix is accepted" || F "upper-case sha256 refused"

hdr "--install copies the verified script to ~/bin"
out="$(run --install vt-test "$SHA")"; rc=$?
[ "$rc" = 0 ] && [ -x "$T/home/bin/vault-tools-update" ] && cmp -s "$T/home/bin/vault-tools-update" "$UPD" && P "installed, identical to the tag's copy" || F "not installed: $out"

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
