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
#   3. unpack only qubes/, copy the new Salt files into a staging directory inside /srv/salt, check
#      them, then swap them in; if any move fails the previous files are put back;
#   4. qubesctl state.apply vault-tools, and FAIL unless it exits 0 and the summary says "Failed: 0";
#   5. shut the template down (a disposable started earlier keeps the old template).
# Every step prints one OK/FAIL line, so nothing needs to be copied out of dom0.
#
# Environment (normally left alone): FETCH_DVM (default default-dvm), TEMPLATE (default
# vault-tools), REPO (default Digital-Frontier-LDA/regalia-ceremony), SALT_DIR (default /srv/salt),
# WORK (default /tmp).
set -uo pipefail
# ASCII RANGES. A check here that says [0-9] means ten digits, and [a-z] twenty-six letters. In a
# UTF-8 locale bash matches a bracket range by the locale's collation instead: [0-9] also takes
# full-width and Arabic-Indic digits, [a-z0-9] takes accented letters, and a negated range such as
# *[!0-9]* no longer catches them (measured: bash 5.2, glibc 2.41, en_US.UTF-8). Only the collation is
# pinned, so text stays UTF-8 and lengths are still counted in characters. LC_ALL overrides
# LC_COLLATE, so it is moved away first, into every other category it was deciding.
if [ -n "${LC_ALL:-}" ]; then
  for _lc in LANG LC_CTYPE LC_NUMERIC LC_TIME LC_MONETARY LC_MESSAGES LC_PAPER LC_NAME LC_ADDRESS \
             LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION; do export "$_lc=$LC_ALL"; done
  unset LC_ALL _lc
fi
export LC_COLLATE=C

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

STAGE="$SALT_DIR/.vault-tools-stage"; PREV="$SALT_DIR/.vault-tools-prev"
# What this script owns in $SALT_DIR; nothing else there is touched.
ITEMS=(vault-tools.sls vault-tools.top vault-ceremony-scripts vault-ceremony-requirements.txt vault-ceremony-recovery)

remove_fetch_qube() { qvm-kill "$FETCH_QUBE" >/dev/null 2>&1; qvm-remove -f "$FETCH_QUBE" >/dev/null 2>&1; }
cleanup() { remove_fetch_qube; rm -rf "$TGZ" "$SRC"; sudo rm -rf "$STAGE"; }
trap cleanup EXIT

step "1. download $TAG in a throwaway disposable ($FETCH_DVM)"
qvm-create --class DispVM --template "$FETCH_DVM" --label red "$FETCH_QUBE" >/dev/null \
  || fail "could not create the disposable $FETCH_QUBE from $FETCH_DVM"
rm -f "$TGZ"
qvm-run -p "$FETCH_QUBE" "curl -fsSL --max-time 300 '$URL'" > "$TGZ" \
  || fail "download failed (is $FETCH_DVM networked? does tag $TAG exist?)"
remove_fetch_qube
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
# /srv/salt is root-only in dom0: every look inside it (test, cmp) goes through sudo, like the writes.
# Stage first (same filesystem as $SALT_DIR, so the swap below is a set of renames). A failed copy
# here leaves the installed files untouched.
sudo rm -rf "$STAGE" "$PREV" && sudo mkdir -p "$STAGE" "$PREV" || fail "cannot create $STAGE"
sudo cp "$Q/salt/vault-tools.sls" "$Q/salt/vault-tools.top" "$STAGE/" \
  && sudo cp -r "$Q/scripts" "$STAGE/vault-ceremony-scripts" \
  && sudo cp "$Q/requirements.txt" "$STAGE/vault-ceremony-requirements.txt" \
  && sudo cp -r "$Q/recovery" "$STAGE/vault-ceremony-recovery" \
  || fail "copying the recipe into $STAGE failed — the installed files were NOT changed"
for i in "${ITEMS[@]}"; do sudo test -e "$STAGE/$i" || fail "staging lacks $i — the installed files were NOT changed"; done
sudo cmp -s "$Q/scripts/ceremony.sh" "$STAGE/vault-ceremony-scripts/ceremony.sh" \
  || fail "the staged ceremony.sh differs from the tag's — the installed files were NOT changed"
# Swap: old item -> $PREV, staged item -> $SALT_DIR. On any failure, undo what was moved.
rollback() {   # $1 = what went wrong
  local bad=0
  for i in "${ITEMS[@]}"; do
    if sudo test -e "$PREV/$i"; then
      sudo rm -rf "${SALT_DIR:?}/$i"; sudo mv "$PREV/$i" "$SALT_DIR/$i" || bad=1
    fi
  done
  [ "$bad" = 0 ] && fail "$1 — previous files restored"
  fail "$1 — AND restoring failed: the previous files are in $PREV; move them back by hand"
}
for i in "${ITEMS[@]}"; do
  if sudo test -e "$SALT_DIR/$i"; then sudo mv "$SALT_DIR/$i" "$PREV/$i" || rollback "could not move the old $i aside"; fi
  sudo mv "$STAGE/$i" "$SALT_DIR/$i" || rollback "could not move the new $i in"
done
sudo rm -rf "$PREV" "$STAGE"
sudo cmp -s "$Q/scripts/ceremony.sh" "$SALT_DIR/vault-ceremony-scripts/ceremony.sh" \
  || fail "$SALT_DIR does not hold this tag's ceremony.sh after the swap"
ok "recipe from $TAG is in $SALT_DIR"

step "4. apply it to $TEMPLATE (a few minutes)"
LOG="$WORK/vault-tools-$TAG-apply.log"
# shellcheck disable=SC2024  # the log is written as the user on purpose: readable without sudo
sudo qubesctl --show-output --skip-dom0 --targets="$TEMPLATE" state.apply vault-tools > "$LOG" 2>&1
RC=$?
SUCC="$(grep -oE 'Succeeded: *[0-9]+' "$LOG" | tail -1 | grep -oE '[0-9]+')"
FAILED="$(grep -oE 'Failed: *[0-9]+' "$LOG" | tail -1 | grep -oE '[0-9]+')"
[ -n "$FAILED" ] || fail "no Salt summary in $LOG — look at its end: tail -40 $LOG"
[ "$FAILED" = 0 ] || fail "Salt reports Failed: $FAILED (Succeeded: ${SUCC:-?}) — the failing states: grep -B2 -A8 'Result: False' $LOG"
[ "$RC" = 0 ] || fail "qubesctl exited $RC although Salt says Failed: 0 — look at the end of $LOG: tail -40 $LOG"
ok "Succeeded: $SUCC, Failed: 0"

step "5. shut $TEMPLATE down"
qvm-shutdown --wait "$TEMPLATE" >/dev/null 2>&1 || fail "could not shut $TEMPLATE down"
ok "$TEMPLATE is off; the next disposable starts from the updated template"

if [ "$install" = 1 ]; then
  mkdir -p "$HOME/bin" && install -m 0755 "$Q/dom0/vault-tools-update.sh" "$HOME/bin/vault-tools-update" \
    && ok "installed as ~/bin/vault-tools-update (from the verified $TAG)" \
    || fail "could not install into ~/bin"
fi
printf '\nDONE: %s applied. Open a NEW disposable: qvm-run --dispvm=ceremony-vault xterm & disown\n' "$TAG"
printf '  (disown: closing this dom0 terminal then cannot kill the disposable; end it with exit in its xterm)\n\n'

