#!/bin/bash
# vault-tools-update.sh — update the vault-tools template from a release tag, in dom0, in one command.
#
#   vault-tools-update.sh <tag> <sha256>            e.g. vault-tools-update.sh vt-0929 d500b9a46416...
#   vault-tools-update.sh --install <tag> <sha256>  the same, then copy this script to ~/bin
#
# Does exactly the README "Build" steps 0 and 2, so none of them can be mistyped:
#   1. download the tag's tarball from GitHub in a throwaway disposable (dom0 has no network);
#   2. REFUSE to go on unless its sha256 starts with the value given (at least 16 hex characters —
#      take it from the release note; the full 64 is better);
#   3. unpack only qubes/ and replace the Salt files in /srv/salt (removing the old copies first:
#      `cp -r dir existing-dir` would nest the new one inside the old one);
#   4. qubesctl state.apply vault-tools, and FAIL unless the summary says "Failed: 0";
#   5. shut the template down (a disposable started earlier keeps the old template).
# Every step prints one OK/FAIL line, so nothing needs to be copied out of dom0.
#
# Environment (normally left alone): FETCH_DVM (default default-dvm), TEMPLATE (default
# vault-tools), REPO (default Digital-Frontier-LDA/regalia-ceremony), SALT_DIR (default /srv/salt),
# WORK (default /tmp).
set -uo pipefail

FETCH_DVM="${FETCH_DVM:-default-dvm}"
TEMPLATE="${TEMPLATE:-vault-tools}"
REPO="${REPO:-Digital-Frontier-LDA/regalia-ceremony}"
SALT_DIR="${SALT_DIR:-/srv/salt}"
WORK="${WORK:-/tmp}"
FETCH_QUBE="vault-fetch-$$"

ok()   { printf '  OK    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; exit 1; }
step() { printf '\n== %s\n' "$*"; }

install=0
if [ "${1:-}" = "--install" ]; then install=1; shift; fi
TAG="${1:-}"; WANT="${2:-}"
[ -n "$TAG" ] && [ -n "$WANT" ] || { sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
# The tag goes into a URL and a path: letters, digits, dot, dash, underscore only.
[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || fail "tag '$TAG' has characters a release tag never has"
WANT="$(tr 'A-F' 'a-f' <<< "$WANT")"
[[ "$WANT" =~ ^[0-9a-f]{16,64}$ ]] || fail "the sha256 must be 16 to 64 hex characters (got ${#WANT})"

command -v qvm-run >/dev/null || fail "this runs in dom0 (qvm-run not found)"
TGZ="$WORK/vault-tools-$TAG.tgz"
SRC="$WORK/vault-tools-$TAG"
URL="https://github.com/$REPO/archive/$TAG.tar.gz"

cleanup() { qvm-kill "$FETCH_QUBE" >/dev/null 2>&1; qvm-remove -f "$FETCH_QUBE" >/dev/null 2>&1; }
trap cleanup EXIT

step "1. download $TAG in a throwaway disposable ($FETCH_DVM)"
qvm-create --class DispVM --template "$FETCH_DVM" --label red "$FETCH_QUBE" >/dev/null \
  || fail "could not create the disposable $FETCH_QUBE from $FETCH_DVM"
rm -f "$TGZ"
qvm-run -p "$FETCH_QUBE" "curl -fsSL --max-time 300 '$URL'" > "$TGZ" \
  || fail "download failed (is $FETCH_DVM networked? does tag $TAG exist?)"
cleanup
[ -s "$TGZ" ] || fail "downloaded file is empty"
ok "downloaded $(wc -c < "$TGZ") bytes; disposable removed"

step "2. check the sha256"
GOT="$(sha256sum "$TGZ" | cut -d' ' -f1)"
if [ "${GOT:0:${#WANT}}" != "$WANT" ]; then
  rm -f "$TGZ"
  fail "sha256 is ${GOT:0:16}…, expected ${WANT:0:16}… — NOTHING was changed; the download is deleted"
fi
ok "sha256 ${GOT:0:16}… matches"

step "3. unpack and replace the Salt files in $SALT_DIR"
rm -rf "$SRC" && mkdir -p "$SRC" || fail "cannot create $SRC"
tar -xzf "$TGZ" -C "$SRC" --strip-components=1 "regalia-ceremony-$TAG/qubes" \
  || fail "the tarball does not contain regalia-ceremony-$TAG/qubes"
Q="$SRC/qubes"
for f in salt/vault-tools.sls scripts/ceremony.sh requirements.txt recovery; do
  [ -e "$Q/$f" ] || fail "the tarball lacks qubes/$f"
done
sudo rm -rf "$SALT_DIR/vault-ceremony-scripts" "$SALT_DIR/vault-ceremony-recovery" || fail "cannot clear the old copies"
sudo cp -r "$Q/salt/." "$SALT_DIR/" \
  && sudo cp -r "$Q/scripts" "$SALT_DIR/vault-ceremony-scripts" \
  && sudo cp "$Q/requirements.txt" "$SALT_DIR/vault-ceremony-requirements.txt" \
  && sudo cp -r "$Q/recovery" "$SALT_DIR/vault-ceremony-recovery" \
  || fail "copying the recipe into $SALT_DIR failed"
cmp -s "$Q/scripts/ceremony.sh" "$SALT_DIR/vault-ceremony-scripts/ceremony.sh" \
  || fail "$SALT_DIR does not hold this tag's ceremony.sh after the copy"
ok "recipe from $TAG is in $SALT_DIR"

step "4. apply it to $TEMPLATE (a few minutes)"
LOG="$WORK/vault-tools-$TAG-apply.log"
# shellcheck disable=SC2024  # the log is written as the user on purpose: readable without sudo
sudo qubesctl --show-output --skip-dom0 --targets="$TEMPLATE" state.apply vault-tools > "$LOG" 2>&1
SUCC="$(grep -oE 'Succeeded: *[0-9]+' "$LOG" | tail -1 | grep -oE '[0-9]+')"
FAILED="$(grep -oE 'Failed: *[0-9]+' "$LOG" | tail -1 | grep -oE '[0-9]+')"
[ -n "$FAILED" ] || fail "no Salt summary in $LOG — look at its end: tail -40 $LOG"
[ "$FAILED" = 0 ] || fail "Salt reports Failed: $FAILED (Succeeded: ${SUCC:-?}) — the failing states: grep -B2 -A8 'Result: False' $LOG"
ok "Succeeded: $SUCC, Failed: 0"

step "5. shut $TEMPLATE down"
qvm-shutdown --wait "$TEMPLATE" >/dev/null 2>&1 || fail "could not shut $TEMPLATE down"
ok "$TEMPLATE is off; the next disposable starts from the updated template"

if [ "$install" = 1 ]; then
  mkdir -p "$HOME/bin" && install -m 0755 "$Q/dom0/vault-tools-update.sh" "$HOME/bin/vault-tools-update" \
    && ok "installed as ~/bin/vault-tools-update (from the verified $TAG)" \
    || fail "could not install into ~/bin"
fi
rm -rf "$TGZ" "$SRC"
printf '\nDONE: %s applied. Open a NEW disposable: qvm-run --dispvm=ceremony-vault xterm &\n' "$TAG"
