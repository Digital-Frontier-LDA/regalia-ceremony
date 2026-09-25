#!/usr/bin/env bash
# ceremony.sh — interactive guide for the custodial-wallet key ceremonies.
# Baked into the vault-tools template at /opt/vault-ceremony/ceremony.sh.
# Run on the AIR-GAPPED Qubes vault qube (see ../README.md).
#
#   /opt/vault-ceremony/ceremony.sh
#
# DESIGN / SAFETY:
#   * Every step EXPLAINS itself, shows the exact command, and waits for you to
#     confirm before running. Nothing irreversible happens without a yes.
#   * Secrets are handled in a tmpfs workdir under /dev/shm (RAM only) and shredded
#     on exit. Secret VALUES are never echoed to the terminal — they flow
#     file -> tool -> (qrencode | printer) without printing.
#   * This orchestrates STANDARD tools (age-plugin-yubikey, sc-hsm-tool, ssss,
#     shamir, qrencode, lp). Review it before trusting it with real keys.
#   * The hardware + printer paths cannot be unit-tested; treat the first run as a
#     DRY RUN with throwaway keys.

set -uo pipefail
# The vault-tools image keeps its pinned tools in /opt/vault-bin (sops, shamir, sle4442-manager)
# and the hash-pinned Python packages in the /opt/vault-ceremony/venv interpreter. /etc/profile.d
# puts both on PATH for LOGIN shells only; the xterm a disposable opens is not one, so add them here.
for _d in /opt/vault-bin /opt/vault-ceremony/venv/bin; do
  case ":$PATH:" in *":$_d:"*) ;; *) [ -d "$_d" ] && PATH="$_d:$PATH" ;; esac
done
unset _d

# Resolve sibling scripts relative to THIS file, not $0. $0 breaks when the wizard is
# symlinked, run through a wrapper, or sourced by a test harness — and a wizard that can't
# find derive-akash-address.py / slip39-mint.py mid-ceremony is exactly the kind of stall
# you cannot afford on the air-gapped day.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- process hygiene (no history, no core dumps, tight umask) ----------------
# Keep secrets out of shell history and crash dumps; default new files to 0600-ish.
unset HISTFILE 2>/dev/null || true
set +o history 2>/dev/null || true
ulimit -c 0 2>/dev/null || true
umask 077

# ---- ui helpers --------------------------------------------------------------
b()    { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
info() { printf '   %s\n' "$1"; }
warn() { printf '   \033[33m! %s\033[0m\n' "$1"; }
err()  { printf '   \033[31mFAIL %s\033[0m\n' "$1"; }
ask()  { local a; read -r -p "   $1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ]; }
pause(){ read -r -p "   press Enter to continue… " _; }
show() { printf '   \033[36m$ %s\033[0m\n' "$1"; }   # display a command, not run it
# eval IS LOAD-BEARING HERE, and shellcheck's SC2294 does not apply. Callers pass a whole shell
# COMMAND as one string, including pipelines, redirections, subshells and && chains — see the
# feed_dkek_shares | sc-hsm-tool pipelines, `ssss-split … < '$f' > '$WORK/shares.txt'`, and the
# `( cd … && find … | xargs … )` manifest line. Dropping eval would run those words as a command
# name and its arguments. The string is also what show() prints, so the operator approves exactly
# what runs.
# shellcheck disable=SC2294
run()  { show "$*"; ask "run it?" && { eval "$@"; return $?; } || { warn "skipped"; return 100; }; }
# Like run(), but ALSO tees the tool's output to $1 so a later step can parse it (the DKEK
# key check value) without hiding anything from the operator. Returns the eval's own status,
# not tee's, so a failing tool still aborts the step under `pipefail`.
run_tee() {
  local out="$1"; shift
  show "$*"
  # shellcheck disable=SC2294  # same as run(): the argument is a shell command string, not argv
  if ask "run it?"; then eval "$@" 2>&1 | tee "$out"; return "${PIPESTATUS[0]}"; fi
  warn "skipped"; return 100
}

# kcv_of() lives in ceremony-kcv.sh, sourced here, because hsm-recovery-drill.sh needs the same
# parse and a second copy of it would be free to drift.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ceremony-kcv.sh"

# THE CEREMONY'S INTERPRETER, RESOLVED ONCE — and by preflight.sh too, or the two disagree.
#
# Every python step here runs bare `python3`, so the interpreter is whatever PATH happens to give.
# preflight.sh proves `import mnemonic` and `import shamir_mnemonic` resolve BEFORE keys are in
# RAM, precisely so step 3c cannot fail mid-ceremony with the money exposed — but it proved it for
# ITS python3, which is not necessarily this one. On the air-gapped image they coincide because
# the wheels are installed system-wide. Anywhere the dependencies live in a venv they do not, and
# then preflight either green-lights a ceremony whose python cannot import the module, or refuses
# one that would have worked. A readiness check about a different interpreter than the one that
# runs is not a readiness check.
#
# prefer, not require: this script does far more than the python steps, and the preflight check is
# where a genuinely missing module must stop things.
_cp="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/ceremony-python.sh"
if [ -r "$_cp" ]; then
  # shellcheck source=/dev/null
  . "$_cp"
  ceremony_python_prefer mnemonic shamir_mnemonic
fi
unset _cp


# Feed captured --create-dkek-share output to `sc-hsm-tool --import-dkek-share … --pwd-shares-total N`
# in the order OpenSC 0.27.1 reads it: the prime once, then for each share one blank line (its
# "Press <enter>"), the share ID and the share value. The same protocol hsm-recovery-drill.sh's
# feed_shares speaks. $1 = the captured output; $2… = which shares, by position. Values go down
# the pipe only, never to the screen. A share missing from the capture stops the feed, so the
# import reads EOF and refuses rather than importing from fewer shares than it was told.
feed_dkek_shares() {
  local f="$1" prime ids vals i id val; shift
  prime="$(grep -m1 -oE 'Prime *: *[0-9a-fA-F:]+' "$f" | grep -oE '[0-9a-fA-F:]+$')"
  ids="$(grep -oE 'Share ID *: *[0-9]+' "$f" | grep -oE '[0-9]+$')"
  vals="$(grep -oE 'Share value *: *[0-9a-fA-F:]+' "$f" | grep -oE '[0-9a-fA-F:]+$')"
  [ -n "$prime" ] && [ -n "$ids" ] && [ -n "$vals" ] || return 1
  printf '%s\n' "$prime"
  for i in "$@"; do
    id="$(printf '%s\n' "$ids" | sed -n "${i}p")"
    val="$(printf '%s\n' "$vals" | sed -n "${i}p")"
    [ -n "$id" ] && [ -n "$val" ] || return 1
    printf '\n%s\n%s\n' "$id" "$val"
  done
}

# Refuse to --initialize a card that already carries a funding key, and FAIL CLOSED when the
# card cannot be enumerated at all. A transient PKCS#11 read error (token not re-attached
# after qvm-usb, pcscd not ready, a CCID glitch) makes list-objects print nothing and exit
# non-zero; treating that as "blank" would let a re-init WIPE a non-exportable key that has
# no plaintext copy. Only a SUCCESSFUL listing showing no 'akash-funding' object proves the
# card is safe to erase. $1 = label for messages, $2 = the FULL pkcs11-tool invocation for the
# device under test (env prefix + binary + selector), so the probe always targets the card that
# is about to be wiped — never the default reader.
# Confirm the reader is showing the device the operator MEANT, before anything destructive.
#
# WHY AN ATR AND NOT A READER INDEX: reader numbering is assigned by the OS in attach order, so
# it silently changes when a device is re-plugged, when a hub enumerates differently, or when a
# second token is added. Every destructive step here (--initialize, the SCSH import hand-off)
# would then target the wrong card. Once a Pico HSM lives permanently on the same machine as a
# real Nitrokey — the test device and the custody device side by side — an index is not evidence
# of anything. The ATR narrows it down but is NOT a per-model fingerprint: a genuine
# SmartCard-HSM carries the ASCII string 'THSM1' — and a Pico HSM DOES TOO (measured 2026-07-29;
# correction in qubes/PICO-DRILL-RUNBOOK.md). The THSM1 default marker below therefore
# only confirms a SmartCard-HSM-PROTOCOL device; it cannot tell a Pico from a Nitrokey. Pin the
# EXACT full ATR with CEREMONY_EXPECT_ATR and cross-check the PKCS#11 token serial.
#
# $1 = human label. $2 = expected marker (default THSM1). Set CEREMONY_EXPECT_ATR to pin an
# EXACT full ATR when you want this device and not merely this model.
assert_expected_device() {
  # $3 = PC/SC reader index. WITHOUT IT THIS FINGERPRINTS THE WRONG CARD: `opensc-tool --atr` with
  # no -r reads whichever reader enumerated first, so on a bench with two tokens the guard could
  # approve device 0 while the step that follows writes to device 1. Callers that name a reader
  # must pass it here, or the check and the write are about different cards.
  local what="$1" marker="${2:-THSM1}" rdr="${3:-}" atr ascii tmo="" rsel=()
  [ -n "$rdr" ] && rsel=(-r "$rdr")
  command -v opensc-tool >/dev/null 2>&1 || { warn "opensc-tool missing — cannot fingerprint $what"; return 0; }
  # `timeout` is coreutils and is ABSENT on macOS. Calling it unconditionally made this guard
  # return an empty ATR on any non-Linux host, which — being fail-closed — aborted every step
  # that uses it. Use it when present (a wedged reader must not hang the ceremony) and fall
  # back to a plain call when not.
  command -v timeout >/dev/null 2>&1 && tmo="timeout 8"
  atr="$($tmo opensc-tool ${rsel[@]+"${rsel[@]}"} --atr 2>/dev/null | tr -d ' \n' | grep -oiE '[0-9a-f:]{20,}' | tr -d ':' | tr 'A-F' 'a-f')"
  if [ -z "$atr" ]; then
    err "no ATR from the reader — cannot confirm WHICH device is attached to $what."
    err "Refusing a destructive step against an unidentified card."
    return 1
  fi
  if [ -n "${CEREMONY_EXPECT_ATR:-}" ]; then
    if [ "$(printf '%s' "$atr" | tr 'A-F' 'a-f')" != "$(printf '%s' "$CEREMONY_EXPECT_ATR" | tr -d ': ' | tr 'A-F' 'a-f')" ]; then
      err "ATR MISMATCH for $what — this is NOT the device you pinned."
      err "  expected : $CEREMONY_EXPECT_ATR"
      err "  attached : $atr"
      err "Re-seat the intended device. Do NOT continue: the next step is destructive."
      return 1
    fi
    info "   ATR matches the pinned device ($what)."
    return 0
  fi
  ascii="$(printf '%s' "$atr" | python3 -c "
import sys
raw = bytes.fromhex(sys.stdin.read().strip())
print(''.join(chr(b) if 32 <= b < 127 else '.' for b in raw))
" 2>/dev/null || true)"
  if ! grep -q "$marker" <<< "$ascii"; then
    err "the card in the reader does NOT look like a SmartCard-HSM (expected '$marker' in its ATR)."
    err "  ATR   : $atr"
    err "  ASCII : $ascii"
    err "If this is a Pico HSM or another token, it is the WRONG device for $what."
    err "Refusing a destructive step against it."
    return 1
  fi
  info "   device fingerprint OK for $what (ATR carries '$marker')."
  return 0
}

assert_hsm_blank() {
  local what="$1" inv="$2" objs rc
  objs="$(eval "$inv" --list-objects --type pubkey 2>/dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    err "could NOT enumerate key objects on $what (pkcs11-tool exit $rc) — refusing to"
    err "--initialize. A read error must NOT be mistaken for a blank card, or a re-init could WIPE"
    err "a non-exportable funding key that has no plaintext copy. Re-seat the token and retry."
    return 1
  fi
  if grep -qi 'akash-funding' <<< "$objs"; then
    err "a funding key labelled 'akash-funding' already exists on $what — --initialize"
    err "would DESTROY it. Use a fresh/blank HSM (or wrap-back the existing key first);"
    err "refusing to re-initialise over an existing funding key."
    return 1
  fi
  return 0
}

# ---- RAM (tmpfs) workdir, removed on exit ------------------------------------
WORK=""
RESIDUE_CANARY=""
MOUNT_BASELINE=""
cleanup() {
  # NOTE: on tmpfs `shred` is not a secure overwrite (pages aren't rewritten in place);
  # the real guarantee is that tmpfs is RAM-only and the DispVM wipes memory on shutdown.
  # We still rm the files; shred only helps on the non-tmpfs fallback path.
  [ -n "$WORK" ] && [ -d "$WORK" ] || return 0
  if [ "${CEREMONY_SIMULATE:-}" != 1 ] && [ -x "$HERE/ceremony-teardown.py" ] \
     && [ -s "$RESIDUE_CANARY" ] && [ -s "$MOUNT_BASELINE" ]; then
    local report_args=()
    if [ -n "${CEREMONY_EVIDENCE_DIR:-}" ]; then
      report_args=(--report "$CEREMONY_EVIDENCE_DIR/teardown-$(date -u +%Y%m%dT%H%M%SZ)-$$.json")
    fi
    if ! "$HERE/ceremony-teardown.py" --workdir "$WORK" --canary "$RESIDUE_CANARY" \
      --mount-baseline "$MOUNT_BASELINE" --scan-root "${HOME:?}" --scan-root /tmp \
      --scan-root /var/tmp --scan-root /var/spool/cups "${report_args[@]}"; then
      err "teardown evidence FAILED — retain the report, power off, and treat the environment as contaminated"
      trap - EXIT INT TERM
      exit 1
    fi
  elif [ "${CEREMONY_SIMULATE:-}" = 1 ]; then
    # Simulation harnesses retain their historical cleanup behavior. On tmpfs,
    # unlink/removal is the control; shred is not claimed as physical erasure.
    find "$WORK" -type f -exec shred -u {} + 2>/dev/null
    rm -rf "$WORK"
  else
    rm -rf "$WORK"
    err "teardown prerequisites missing — cleanup is unverified; treat the environment as contaminated"
    trap - EXIT INT TERM
    exit 1
  fi
}
trap cleanup EXIT
trap 'trap - INT TERM; exit 130' INT TERM
init_work() {
  local base=""
  if [ -d /dev/shm ] && grep -qs "[[:space:]]/dev/shm[[:space:]]tmpfs[[:space:]]" /proc/mounts; then
    base=/dev/shm                                   # tmpfs (RAM) — the intended path
  elif [ "${CEREMONY_ALLOW_NONTMPFS:-}" = 1 ]; then
    base="${TMPDIR:-/tmp}"                           # off-Linux test/sim only (harnesses set this)
    warn "no tmpfs /dev/shm — using $base (NOT RAM-backed). Test/sim only."
  else
    err "/dev/shm is not a tmpfs mount — refusing to write secrets to disk."
    err "On the Qubes vault qube /dev/shm is tmpfs; run there. (Tests set CEREMONY_ALLOW_NONTMPFS=1.)"
    exit 1
  fi
  # FAIL CLOSED: if mktemp -d fails (base momentarily full/unwritable), WORK must NOT be left
  # empty. An empty WORK would make every step write '$WORK/dkek.pbe' etc. to '/dkek.pbe' on the
  # persistent on-disk ROOT FS, and cleanup()'s `[ -n "$WORK" ]` guard would then skip all
  # shredding — silently breaking both the RAM-only-workdir and shred-on-exit guarantees. There
  # is no `set -e`, so guard the assignment explicitly and refuse to run without a real workdir.
  WORK=$(mktemp -d "$base/ceremony.XXXXXX") \
    || { err "could not create RAM workdir under $base — refusing to run"; exit 1; }
  [ -n "$WORK" ] && [ -d "$WORK" ] \
    || { err "RAM workdir was not created under $base — refusing to run"; exit 1; }
  chmod 700 "$WORK"
  RESIDUE_CANARY="$WORK/.residue-canary"
  MOUNT_BASELINE="$WORK/.mount-baseline"
  if [ "${CEREMONY_SIMULATE:-}" != 1 ]; then
    head -c 32 /dev/urandom > "$RESIDUE_CANARY" \
      || { err "could not create the RAM-only residue canary"; exit 1; }
    findmnt -rn -o TARGET > "$MOUNT_BASELINE" \
      || { err "could not establish the teardown mount baseline"; exit 1; }
  fi
  info "workdir (RAM, removed on exit): $WORK"
}

# ---- stub-shadow guard -------------------------------------------------------
# The test/sim harnesses prepend a fake-bin dir of stubbed tools to PATH. If a hardware
# tool resolves to a temp dir during a REAL ceremony, that's a stub shadowing the real
# tool — abort. Harnesses/simulator set CEREMONY_SIMULATE=1 to acknowledge the stubs.
guard_no_stubs() {
  [ "${CEREMONY_SIMULATE:-}" = 1 ] && return 0
  local t p
  for t in age-plugin-yubikey sc-hsm-tool pkcs11-tool ip lp; do
    p="$(command -v "$t" 2>/dev/null)" || continue
    case "$p" in
      /tmp/*|/private/tmp/*|/var/folders/*|*/.cache/*|*/T/tmp.*)
        err "'$t' resolves to $p — looks like a test STUB shadowing the real tool."
        err "Refusing a real ceremony with stubbed tools. (Harnesses set CEREMONY_SIMULATE=1.)"
        exit 1;;
    esac
  done
}

# ---- preflight gate ----------------------------------------------------------
require_airgap_and_tools() {
  b "Preflight"
  guard_no_stubs
  if [ -x "$HERE/preflight.sh" ]; then
    "$HERE/preflight.sh" || { err "preflight failed — fix before continuing"; exit 1; }
  else
    err "preflight.sh not found next to this script — refusing to expose secrets without the environment gate"
    exit 1
  fi
}

# ---- printer (a USB laser via CUPS) -------------------------------------------
PRINTER=""
pick_printer() {
  b "Printer"
  warn "Print ONLY to a USB-attached printer with NO network and NO internal storage."
  warn "After printing, power-cycle the printer to clear its page memory. The CUPS"
  warn "spool lives in this disposable qube and dies when you power it off."
  if ! command -v lpstat >/dev/null 2>&1; then warn "CUPS (lp/lpstat) not installed; skipping print steps"; return 1; fi
  info "Detected print queues:"; lpstat -p 2>/dev/null | sed 's/^/     /' || true
  read -r -p "   printer queue name (blank = skip printing): " PRINTER
  [ -n "$PRINTER" ] || { warn "no printer chosen; paper steps will only write files for you to print manually"; return 1; }
  # the queue name is later embedded in an lp command; restrict it to CUPS-legal
  # characters so it can't inject shell metacharacters.
  if ! grep -qE '^[A-Za-z0-9_-]+$' <<< "$PRINTER"; then
    warn "invalid queue name (allowed: letters, digits, _ , -); skipping printing"; PRINTER=""; return 1
  fi
  # USB-only: a network printer (socket/ipp/lpd) would send the plaintext share over the
  # wire. Require the queue's device-uri to be usb:// (or a local file/pipe for testing).
  # Anchor the parse to the "device for <queue>: " label colon, NOT the last colon on the
  # line. A greedy `s/.*: *//` strips the URI's own scheme colon too, turning
  # smb://host/path into //host/path, which the `/*` case arm below would wave through as a
  # local absolute-path device — sending the plaintext share over the wire. Matching the
  # anchored label like preflight.sh / go-nogo.sh do preserves smb://, ipp://, usb://, etc.
  local uri; uri="$(lpstat -v "$PRINTER" 2>/dev/null | sed -E 's/^device for [^:]+: *//')"
  case "${uri:-}" in
    usb://*|""|file:*|/*|cups-pdf:*) : ;;   # usb (or local/unknown in tests) — allow
    *) warn "printer '$PRINTER' device-uri is '$uri' — NOT usb://; refusing (no network printers)."; PRINTER=""; return 1;;
  esac
  info "using printer: $PRINTER ${uri:+($uri)}"
  warn "CUPS spool advice: keep /var/spool/cups on tmpfs (DispVM does); jobs are purged after each print."
}

# ---- scan-back (webcam) ------------------------------------------------------
# Decoding the PRINTED symbol is the only proof that paper is a backup: every earlier check is on
# files that are shredded on exit. A webcam attached with `qvm-usb attach` shows up as /dev/video*.
# Returns 0 when verified, 1 when it failed, 2 when the operator skipped (no camera, or declined).
SCAN_DEVICE="${CEREMONY_SCAN_DEVICE:-/dev/video0}"
scan_back_payload() {
  local enc="$1"
  if ! command -v zbarcam >/dev/null 2>&1 || [ ! -e "$SCAN_DEVICE" ]; then
    warn "no camera at $SCAN_DEVICE — scan the printed sheet back later:"
    warn "  photograph it, then: zbarimg --raw -q photo.jpg | payload-qr.py --verify-scan payload.age --scans -"
    return 2
  fi
  ask "scan the PRINTED QR sheet back with the camera now (strongly recommended)?" || return 2
  python3 "$HERE/payload-qr.py" --verify-scan "$enc" --device "$SCAN_DEVICE"
}

# Scan ONE printed share symbol back and compare it with the file it was printed from, without
# echoing either: zbarcam's output goes into a variable in this RAM-only shell, never the terminal.
scan_back_share() {
  local label="$1" secret_file="$2" got want
  command -v zbarcam >/dev/null 2>&1 && [ -e "$SCAN_DEVICE" ] || return 2
  ask "scan the PRINTED '$label' QR back with the camera now?" || return 2
  info "hold the printed '$label' QR to the camera; the window closes on the first QR read."
  got="$(timeout "${CEREMONY_SCAN_TIMEOUT:-180}" zbarcam --raw -q -1 -Sdisable -Sqrcode.enable "$SCAN_DEVICE" 2>/dev/null)" || true
  want="$(cat "$secret_file")"
  if [ -n "$got" ] && [ "$got" = "$want" ]; then
    got=""; want=""; info "   SCAN-BACK OK — the printed '$label' QR decodes to exactly the share."; return 0
  fi
  got=""; want=""
  err "SCAN-BACK FAILED for '$label' — the printed QR did not decode to the share (or nothing was read)."
  return 1
}

# print a single labelled artifact (text words + a QR PNG of the same string).
# arg1 = human label, arg2 = path to a file holding the secret string (one line).
print_share() {
  local label="$1" secret_file="$2"
  # Declared and assigned separately: `local x="$(…)"` makes the exit status that of `local`,
  # which always succeeds, so a failing substitution would be invisible here (SC2155).
  local slug png txt
  slug="$(printf '%s' "$label" | tr ' /' '__')"
  png="$WORK/$slug.png"
  txt="$WORK/$slug.txt"
  # -l H = 30% Reed-Solomon error correction, the HIGHEST of qrencode's four levels. qrencode
  # DEFAULTS TO L (7%), which is the wrong trade for a backup meant to outlive its operator:
  # a crease through the symbol, a coffee ring, foxing, or flaked toner over ~8% of the modules
  # makes an L-level share unreadable, and this paper copy exists precisely for the day the
  # other media are gone. H survives roughly a third of the symbol being destroyed. A SLIP-39
  # share is a few hundred bytes, far inside even a mid-version H symbol, so the capacity cost
  # buys real damage tolerance and costs nothing we need.
  qrencode -o "$png" -r "$secret_file" -s 6 -m 4 -l H       # QR from the file (no echo)
  { printf '%s\n' "$label";
    printf 'Generated on the air-gapped vault qube. Store sealed. Tamper-evident.\n\n';
    printf 'TRANSCRIBE / VERIFY (canonical form):\n\n';
    cat "$secret_file"; printf '\n\n(QR on the following page encodes the exact same string.)\n';
  } > "$txt"
  info "rendered: $txt  +  $png"
  if [ -n "$PRINTER" ]; then
    if run "lp -d '$PRINTER' '$txt'" && run "lp -d '$PRINTER' '$png'"; then
      info "sent '$label' (text + QR) to $PRINTER — waiting for it to finish printing…"
    else
      # A failed `lp` here does NOT mean nothing spooled: the two jobs are queued in sequence, so
      # the plaintext words page (txt, spooled FIRST) can already be PENDING while the QR page
      # (png, e.g. never rendered because qrencode failed) is what fails the `&&`. We must still
      # drain the queue below before purging, or the pending plaintext page is deleted unprinted.
      warn "print skipped/failed for $label — checking the spool for any page that DID queue…"
    fi
    # WAIT for any page that DID spool to actually PRINT before purging. This MUST run on BOTH
    # branches above. `lp` returns as soon as a job is SPOOLED, not when the paper emerges — and an
    # idle USB laser is asleep/warming, so a queued job sits PENDING for a while. Purging (cancel -x
    # below) before it prints would silently drop the paper/QR backup while $WORK is shredded on
    # exit — including the case where only ONE of the two jobs spooled. Poll lpstat -o until THIS
    # queue has no outstanding jobs (every page has printed), and only THEN purge. Bounded so a
    # stuck/offline printer can't hang the ceremony forever: after enough empty polls we re-prompt
    # instead of purging blind. When nothing spooled at all the queue is already empty and we fall
    # straight through to the purge (a harmless no-op).
    local _polls=0 _maxpolls="${CEREMONY_PRINT_MAXPOLLS:-150}" _poll="${CEREMONY_PRINT_POLL:-2}" _q
    # Capture lpstat into a var and test emptiness — do NOT pipe into `grep -q`. Under the
    # `set -o pipefail` at the top of this file, `grep -q` closes the pipe on its first match
    # and SIGPIPEs lpstat, so `lpstat | grep -q .` exits NON-ZERO and this loop would fall
    # straight through — purging the spool before the pages print, the very bug we're fixing.
    while _q="$(lpstat -o "$PRINTER" 2>/dev/null)"; [ -n "$_q" ]; do
      sleep "$_poll"
      _polls=$((_polls+1))
      if [ "$_polls" -ge "$_maxpolls" ]; then
        warn "printer '$PRINTER' still has queued jobs — wake/clear it and CONFIRM the '$label'"
        warn "pages printed. NOT purging the spool (plaintext) until the queue drains."
        pause; _polls=0
      fi
    done
    info "print queue drained for '$label'"
    local _sb=0; scan_back_share "$label" "$secret_file" || _sb=$?
    if [ "$_sb" = 1 ]; then
      warn "the '$label' page is NOT proven readable: reprint it before it is sealed."
      pause
    fi
    # PURGE the job DATA files from the CUPS spool so the plaintext share doesn't linger on disk.
    # Safe here: the queue has drained (all pages printed), so this deletes only COMPLETED job
    # data, never a still-pending page. `cancel -a` alone only cancels ACTIVE (queued) jobs; once
    # `lp` has finished the job is COMPLETE and CUPS keeps its rendered document
    # (/var/spool/cups/d<jobid>-NNN) under PreserveJobFiles (~1 day). Use -x to actually DELETE
    # the completed job's data — otherwise the plaintext words + QR stay readable in the spool.
    cancel -x -a "$PRINTER" 2>/dev/null || true
  else
    warn "no printer set — print these two files yourself, then shred the qube"
  fi
}

# =============================================================================
# Ceremony steps
# =============================================================================

step_yubikey_ops() {
  b "YubiKey — hardware 'ops' age/SOPS identity (PIV / P-256)"
  info "Generates an age identity ON the YubiKey; the private key never leaves it,"
  local pin_policy="${CEREMONY_YUBI_PIN_POLICY:-once}"
  local touch_policy="${CEREMONY_YUBI_TOUCH_POLICY:-never}"
  case "$pin_policy" in once|always) ;; *) err "CEREMONY_YUBI_PIN_POLICY must be once or always"; return 1 ;; esac
  case "$touch_policy" in never|always|cached) ;; *) err "CEREMONY_YUBI_TOUCH_POLICY must be never, always, or cached"; return 1 ;; esac
  info "and unattended decrypts use PIN policy $pin_policy with touch policy $touch_policy."
  info "The default is touch=never; set CEREMONY_YUBI_TOUCH_POLICY=always for an interactive ceremony."
  command -v age-plugin-yubikey >/dev/null || { err "age-plugin-yubikey missing"; return 1; }
  # Two things age-plugin-yubikey 0.5.0 does to a factory card, measured on YubiKey 5.7.4
  # (regalia doc/drills/2026-09-23-yubikey-multi-enrollment.md):
  #   - it REFUSES the firmware-5.7 default management key (AES192): "Custom unprotected non-TDES
  #     management keys are not supported". It needs a PIN-protected TDES key.
  #   - on the default PIN it forces a new PIN AND SETS THE PUK TO IT, merging two credentials the
  #     ceremony keeps apart (regalia#28). So the PIN and a distinct PUK are set here, first.
  # Only acted on when ykman reports a real card; a stub that prints no management-key line is left alone.
  local info rc
  info="$(ykman piv info 2>/dev/null || true)"
  # The card's PIN and PUK are set to the values step 0 loaded for ESCROW (pins.env →
  # yubikey_piv_pin / yubikey_piv_puk → the tier-0 payload), never to values typed at a prompt:
  # otherwise the payload can hold a PIN this card does not answer to, discovered on recovery day.
  # The commands are shown redacted and run directly, because run() would print the PIN.
  if grep -q "Using default PIN" <<< "$info" || grep -q "Using default PUK" <<< "$info"; then
    if [ -z "${yubikey_piv_pin:-}" ] || [ -z "${yubikey_piv_puk:-}" ]; then
      err "This YubiKey still has a factory PIN or PUK, and step 0 has not loaded yubikey_piv_pin and"
      err "yubikey_piv_puk. Run step 0 first: the values set on the card must be the ones escrowed."
      return 1
    fi
    [ "$yubikey_piv_pin" != "$yubikey_piv_puk" ] || { err "yubikey_piv_pin and yubikey_piv_puk are equal; the ceremony keeps them apart"; return 1; }
    if grep -q "Using default PIN" <<< "$info"; then
      # Step 0 holds ONE yubikey_piv_pin. A second factory token in the same run would get the same
      # PIN, and the fleet needs distinct PINs per token (regalia#17). The second token gets its own
      # run, with its own pins.env.
      if [ "${yubikey_pins_set_this_run:-0}" -ge 1 ]; then
        err "This run already set the escrowed yubikey_piv_pin on a YubiKey. Two tokens must not share a"
        err "PIN: provision this one in a separate run with its own pins.env (qubes/CREDENTIAL-SEPARATION.md)."
        return 1
      fi
      show "ykman piv access change-pin -P <factory PIN> -n <yubikey_piv_pin from step 0>"
      ask "set the card's PIN to the escrowed value?" || { err "the factory PIN was kept, so age-plugin-yubikey would replace it with an unescrowed one"; return 1; }
      ykman piv access change-pin -P 123456 -n "$yubikey_piv_pin" >/dev/null || { err "PIN change failed"; return 1; }
      yubikey_pins_set_this_run=$(( ${yubikey_pins_set_this_run:-0} + 1 ))
    fi
    if grep -q "Using default PUK" <<< "$info"; then
      show "ykman piv access change-puk -p <factory PUK> -n <yubikey_piv_puk from step 0>"
      ask "set the card's PUK to the escrowed value?" || { err "the factory PUK was kept"; return 1; }
      ykman piv access change-puk -p 12345678 -n "$yubikey_piv_puk" >/dev/null || { err "PUK change failed"; return 1; }
    fi
  fi
  # PIN-BINDING PROOF, as for the HSM in step_payload: present the escrowed PIN to the card now,
  # while both are known. Changing the PIN to itself verifies it; a wrong value costs one try here
  # instead of one on recovery day.
  if [ -n "${yubikey_piv_pin:-}" ] && grep -q "Management key algorithm" <<< "$info"; then
    ykman piv access change-pin -P "$yubikey_piv_pin" -n "$yubikey_piv_pin" >/dev/null 2>&1 \
      || { err "PIN BINDING FAILED: the escrowed yubikey_piv_pin does not open this YubiKey"; return 1; }
    info "   PIN BINDING PROVEN — the escrowed yubikey_piv_pin opens this YubiKey."
  else
    warn "yubikey_piv_pin not loaded (step 0), or no real card: the PIN-binding proof was SKIPPED, not passed."
  fi
  if grep -q "Management key algorithm" <<< "$info" && ! grep -q "protected by PIN" <<< "$info"; then
    warn "age-plugin-yubikey needs a PIN-protected TDES management key; this card's is not. It becomes a"
    warn "random key stored on the card behind the PIN, so the escrowed PIN also recovers it."
    run "ykman piv access change-management-key -a TDES --protect"; rc=$?
    [ "$rc" = 0 ] || { err "the management key was not changed, so age-plugin-yubikey would refuse this card"; return 1; }
  fi
  # A declined step (100) is the operator's choice; a FAILED generation is not a success.
  run "age-plugin-yubikey --generate --pin-policy $pin_policy --touch-policy $touch_policy"; rc=$?
  [ "$rc" = 100 ] && return 0
  [ "$rc" = 0 ] || { err "age-plugin-yubikey --generate failed (exit $rc): no identity was created"; return 1; }
  warn "Copy the printed  age1yubikey1…  recipient into every repo's .sops.yaml as the"
  warn "ops recipient, then on a NETWORKED admin box run:"
  show "git ls-files '*.sops.*' | grep -vE '(^|/)\\.sops\\.yaml\$' | while read -r f; do sops updatekeys -y \"\$f\"; done"
  warn "Keep the old laptop keys.txt recipient until you've proven a touch-decrypt, and"
  warn "register a SECOND YubiKey the same way before retiring it (loss resilience)."
}

# ---- custody manifest (regalia#28) --------------------------------------------
# OPTIONAL, AND INERT WHEN ABSENT. With CEREMONY_MANIFEST unset every function below returns at its
# first line and the menu is the one it always was. With it set, the ceremony is driven by the
# manifest at both ends:
#
#   start  `ceremony-manifest.py plan` — refuse, BEFORE any key exists, a manifest asking for
#          something this ceremony cannot honour, and print every planned provisioning step;
#   m)     generate each planned YubiKey PIV key with the policies the MANIFEST names (never typed
#          here), capture the device's own report of it as evidence, and prove the key signs with the
#          PIN (operation-proof.sh; Nitrokeys run the same script at the rack after commission-card.sh);
#   end    `ceremony-manifest.py record` — fill the bindings from the evidence and advance them to
#          qualified, or refuse by name and write nothing.
#
#   CEREMONY_MANIFEST               the custody manifest (regalia-kms format) — enables all of this
#   CEREMONY_MANIFEST_EVIDENCE_DIR  REQUIRED with it: where evidence is kept. On persistent storage,
#                                   NOT the RAM workdir, which is shredded on exit — the evidence is
#                                   public (serials, public-key digests, ykman reports) and it is the
#                                   record of the ceremony. commission-card.sh transcripts and the
#                                   Nitrokeys' operation-proof.sh records go here too.
#   CEREMONY_MANIFEST_OUT           where record writes (default: <evidence dir>/custody-manifest.qualified.json);
#                                   the input manifest is never rewritten by the wizard
#   CEREMONY_MANIFEST_SITE          restrict plan/record to one site
#   CEREMONY_MANIFEST_BACKEND       restrict plan/record to one backend, e.g. yubikey-piv when the
#                                   Nitrokeys are commissioned later at the rack
CEREMONY_MANIFEST="${CEREMONY_MANIFEST:-}"
manifest_tool(){ python3 "$HERE/ceremony-manifest.py" "$@"; }
manifest_scope() {
  MANIFEST_SCOPE=()
  [ -n "${CEREMONY_MANIFEST_SITE:-}" ] && MANIFEST_SCOPE+=(--site "$CEREMONY_MANIFEST_SITE")
  [ -n "${CEREMONY_MANIFEST_BACKEND:-}" ] && MANIFEST_SCOPE+=(--backend "$CEREMONY_MANIFEST_BACKEND")
  return 0
}
manifest_out(){ printf '%s' "${CEREMONY_MANIFEST_OUT:-$CEREMONY_MANIFEST_EVIDENCE_DIR/custody-manifest.qualified.json}"; }

manifest_plan() {
  [ -n "$CEREMONY_MANIFEST" ] || return 0
  b "Custody manifest — plan (regalia#28)"
  # Both preconditions are checked HERE, at the start, and not when record runs at the end: a
  # ceremony that learns only after generating keys that it has nowhere to put the proof of them has
  # already produced keys without a record.
  [ -r "$CEREMONY_MANIFEST" ] || { err "CEREMONY_MANIFEST=$CEREMONY_MANIFEST is not readable"; return 1; }
  if [ -z "${CEREMONY_MANIFEST_EVIDENCE_DIR:-}" ]; then
    err "CEREMONY_MANIFEST is set but CEREMONY_MANIFEST_EVIDENCE_DIR is not — refusing to generate keys"
    err "with nowhere to keep the evidence that proves them. Point it at persistent storage, not /dev/shm."
    return 1
  fi
  mkdir -p "$CEREMONY_MANIFEST_EVIDENCE_DIR" || { err "cannot create $CEREMONY_MANIFEST_EVIDENCE_DIR"; return 1; }
  manifest_scope
  if ! manifest_tool plan "$CEREMONY_MANIFEST" "${MANIFEST_SCOPE[@]}"; then
    err "the manifest asks for something this ceremony cannot honour (reason above) — refusing"
    err "before any key is generated. Fix the manifest, not the ceremony."
    return 1
  fi
  info "evidence for these steps goes to $CEREMONY_MANIFEST_EVIDENCE_DIR; record runs when you quit."
}

step_manifest_yubikey() {
  b "Manifest — generate a planned YubiKey PIV key and capture its evidence"
  info "The slot, algorithm, PIN policy and touch policy come from the manifest; you choose only"
  info "WHICH token this is. The key is GENERATED ON THE TOKEN and never imported (ADR-0002 D5)."
  info "Each key is then proven with the token's PIN (a signature, or a decrypt round trip for a KEK) —"
  info "you are asked for the PIN once per key."
  local device serial steps slot alg pin touch path proof ev op
  read -r -p "   manifest device_id of the token in the reader > " device || return 1
  # The id becomes part of evidence FILE NAMES below (and an rm), so it must be one safe path
  # component: a manifest id of "../x" would otherwise reach outside the evidence directory.
  if ! [[ "$device" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || [[ "$device" == *..* ]]; then
    err "manifest device_id must be one path component of letters, digits, '.', '_' or '-'"; return 1
  fi
  read -r -p "   its serial (ykman list --serials) > " serial || return 1
  case "$serial" in ''|*[!0-9]*) err "a YubiKey serial is digits only"; return 1 ;; esac
  steps="$(manifest_tool piv-steps "$CEREMONY_MANIFEST" --device-id "$device" \
            ${CEREMONY_MANIFEST_SITE:+--site "$CEREMONY_MANIFEST_SITE"})" || { err "nothing to do for $device (reason above)"; return 1; }
  # The step list is read on fd 9, NOT stdin: operation-proof.sh below asks for the PIN on stdin, and
  # inside a `while … done <<< "$steps"` loop stdin IS the step list — the PIN prompt would read the
  # next step's line (or EOF) instead of the operator's keyboard.
  # VALIDATE THE WHOLE STEP LIST BEFORE GENERATING ANYTHING. `piv keys generate` REPLACES whatever is
  # in the slot and cannot be undone, so a step that could never be proven must be refused before the
  # first key on this token is touched — not after it, and not after an earlier slot in the same list
  # was already regenerated (review of regalia-ceremony#39).
  while IFS=$'\t' read -r -u 9 slot alg pin touch path proof; do
    [ -n "$slot" ] || continue
    case "$proof" in sign|decrypt|key-agreement) ;;
      *) err "piv-steps named no proof operation for $path — nothing was generated on $serial"; return 1;; esac
  done 9<<< "$steps"
  while IFS=$'\t' read -r -u 9 slot alg pin touch path proof; do
    [ -n "$slot" ] || continue
    info "$path: slot $slot $alg pin=$pin touch=$touch on $device (serial $serial)"
    # Evidence from an EARLIER generation of this slot describes a key about to be replaced, so it is
    # removed in the SAME confirmed action as the generation: declining keeps both the old key and its
    # evidence, a failed removal generates nothing, and a failed generation leaves no stale proof.
    run "rm -f '$CEREMONY_MANIFEST_EVIDENCE_DIR/yubikey-$device-$slot.json' '$CEREMONY_MANIFEST_EVIDENCE_DIR/opproof-yubikey-$device-$slot.json' && ykman --device '$serial' piv keys generate --algorithm '$alg' --pin-policy '$pin' --touch-policy '$touch' '$slot' '$WORK/yk-$serial-$slot.pem'" \
      || { warn "not generated — no evidence captured for $path"; continue; }
    # Everything below is READ from the token, after generation: its report (info, keys info, the key)
    # AND Yubico's attestation of that key. `record` believes the report only where the attestation,
    # signed by a genuine YubiKey, says the same (serial, policies, the key itself).
    ykman --device "$serial" info > "$WORK/yk-$serial.info" \
      && ykman --device "$serial" piv keys info "$slot" > "$WORK/yk-$serial-$slot.keys" \
      && ykman --device "$serial" piv keys export "$slot" --format DER "$WORK/yk-$serial-$slot.der" \
      || { err "could not read the key back from $serial slot $slot — no evidence for $path"; return 1; }
    # A YubiKey attests ONLY keys generated on it. A refusal here is the device itself saying this key
    # was imported, which is stronger than its Origin line: it comes from the f9 key, not from a report.
    ykman --device "$serial" piv keys attest "$slot" "$WORK/yk-$serial-$slot.att.pem" \
      && ykman --device "$serial" piv certificates export f9 "$WORK/yk-$serial.f9.pem" \
      || { err "$serial would not attest slot $slot: a YubiKey attests only keys generated on it, so this key"; \
           err "was not (ADR-0002 D5) — $path is NOT provisioned as planned"; return 1; }
    ev="$CEREMONY_MANIFEST_EVIDENCE_DIR/yubikey-$device-$slot.json"
    manifest_tool yubikey-evidence --device-id "$device" --slot "$slot" --info "$WORK/yk-$serial.info" \
      --keys-info "$WORK/yk-$serial-$slot.keys" --public-key "$WORK/yk-$serial-$slot.der" \
      --attestation "$WORK/yk-$serial-$slot.att.pem" --f9 "$WORK/yk-$serial.f9.pem" --out "$ev" \
      || { err "the token's own report was refused (reason above) — $path is NOT provisioned as planned"; return 1; }
    # THE OPERATION PROOF (regalia#28 criterion 3), while the token is still in the reader. Everything
    # above is the token's REPORT of the key; this is the key WORKING, with the PIN the operator types
    # (into operation-proof.sh, echo off — the wizard never sees it). $proof is the operation the
    # manifest's proof class needs, from piv-steps: `sign` for a signing key (a signature record
    # re-verifies), `decrypt` for an RSA KEK (a live RSA-OAEP round trip, attested now and NOT
    # re-verifiable later — the ceiling for a decrypt key). record refuses the binding without it.
    # Not behind run(): typing the PIN is the operator's consent, and a skipped proof is not a choice
    # this step offers — it only leaves the binding unqualifiable.
    op="$CEREMONY_MANIFEST_EVIDENCE_DIR/opproof-yubikey-$device-$slot.json"
    show "operation-proof.sh --operation '$proof' --backend yubikey-piv --serial '$serial' --object-id '$slot' --device-id '$device' --out '$op'"
    "$HERE/operation-proof.sh" --operation "$proof" --backend yubikey-piv --serial "$serial" --object-id "$slot" \
        --device-id "$device" --out "$op" \
      || { err "no operation proof for $path (reason above) — record will refuse it. Re-run the command shown"; \
           err "once the cause is fixed — if it was a wrong PIN, that attempt already spent one of the token's retries."; return 1; }
  done 9<<< "$steps"
}

manifest_record() {
  [ -n "$CEREMONY_MANIFEST" ] || return 0
  b "Custody manifest — record (regalia#28)"
  local out f evidence=()
  out="$(manifest_out)"
  for f in "$CEREMONY_MANIFEST_EVIDENCE_DIR"/*.json "$CEREMONY_MANIFEST_EVIDENCE_DIR"/*.txt; do
    [ -f "$f" ] || continue
    [ "$(realpath "$f")" = "$(realpath -m "$out")" ] && continue
    evidence+=("$f")
  done
  if [ "${#evidence[@]}" -eq 0 ]; then
    err "no evidence in $CEREMONY_MANIFEST_EVIDENCE_DIR — nothing planned was proven; the manifest is unchanged"
    return 1
  fi
  manifest_scope
  if ! manifest_tool record "$CEREMONY_MANIFEST" --evidence "${evidence[@]}" "${MANIFEST_SCOPE[@]}" --out "$out"; then
    err "record REFUSED (reason above) — nothing was written. The evidence is kept in"
    err "$CEREMONY_MANIFEST_EVIDENCE_DIR; resolve the named binding and re-run ceremony-manifest.py record."
    return 1
  fi
  info "qualified manifest: $out — review it, then commit it to regalia-kms."
}

step_hsm_funding() {
  b "Nitrokey HSM 2 — cold funding wallet (secp256k1, DKEK threshold backup)"
  # ── UNSUPPORTED PATH — OFF BY DEFAULT ───────────────────────────────────────────────────
  # This generates the funding key INSIDE the HSM, non-exportable. That conflicts with the
  # custody principle this ceremony now follows: every secret must be reconstructible from the
  # 4-of-6 Shamir shares alone, with no dependency on any hardware or vendor. A born-in-HSM key
  # is recoverable ONLY via its DKEK-wrapped blob restored onto a COMPATIBLE SmartCard-HSM. If
  # SmartCard-HSMs stop being available — vendor exit, an import ban, a firmware line ending —
  # four correct shares reconstruct nothing.
  #
  # IMPORT IS NOT AVAILABLE — verified, do not go looking for it. The obvious alternative would
  # be to derive the key from the seed and import it, keeping the seed authoritative while the
  # HSM protects the key in operation. OpenSC cannot do that:
  #   * sc-hsm-tool has NO import flag at all — its only key-movement options are --wrap-key and
  #     --unwrap-key (run `sc-hsm-tool` with no args to see the full option list).
  #   * pkcs15init's sc_hsm_store_key() is a stub returning SC_ERROR_NOT_SUPPORTED
  #     (OpenSC 0.27.1 src/pkcs15init/pkcs15-sc-hsm.c:122-127), so `pkcs11-tool --write-object
  #     --type privkey` fails against this card.
  #   * --unwrap-key only consumes a blob whose inner format the CARD FIRMWARE defines; OpenSC
  #     passes it through opaquely (card-sc-hsm.c SC_CARDCTL_SC_HSM_UNWRAP_KEY), so a blob
  #     cannot be constructed offline from a seed-derived key with open tooling.
  # The CARD ITSELF, however, DOES accept an imported key — Nitrokey documents it: "You can
  # import existing keys onto the Nitrokey HSM … by converting keys from a PKCS#12 container to
  # a suitable, importable format." That format is the DKEK-wrapped blob --unwrap-key consumes;
  # what OpenSC lacks is the ability to BUILD one, not the ability to send it. CardContact's
  # Smart Card Shell (OpenSCDP) is the documented tool that does the conversion.
  #
  # UNVERIFIED, AND IT MATTERS: nobody here has yet confirmed that path works for secp256k1, nor
  # what it costs (Smart Card Shell is Java — a new dependency on the air-gapped vault image).
  # If it DOES work, the supported design becomes: mint the seed, split it 4-of-6, derive the
  # key, import it — the HSM protects the key in operation while the seed stays authoritative,
  # and losing every device costs an import rather than the funds. Until someone proves that on
  # real hardware, this gate stays shut, because a born-in-HSM key is NOT reconstructible from
  # the shares and that is the one property the custody model will not trade away.
  #
  # Kept, not deleted: two suites exercise this code and it remains correct for anyone who
  # deliberately wants never-in-plaintext signing and accepts that the ONLY recovery is a DKEK
  # blob plus a compatible SmartCard-HSM.
  if [ "${CEREMONY_ALLOW_BORN_IN_HSM:-0}" != 1 ]; then
    err "born-in-HSM key generation is UNSUPPORTED under the current custody model."
    err "A key generated in the HSM is NOT reconstructible from the 4-of-6 Shamir shares — its"
    err "only backup is the DKEK blob, which needs a compatible SmartCard-HSM to restore onto."
    err "Use step 3 option (c): mint the seed from mixed entropy and split it 4-of-6."
    err "NOTE: OpenSC cannot IMPORT a key into this card (sc_hsm_store_key returns"
    err "SC_ERROR_NOT_SUPPORTED; there is no import flag). The CARD does accept an imported key"
    err "as a DKEK-wrapped blob — Nitrokey documents converting a PKCS#12 key to that format —"
    err "but building the blob needs CardContact's Smart Card Shell, and nobody has yet proven"
    err "that path for secp256k1. Prove it and the seed-derived key can live in the HSM."
    err "To run this path anyway (you accept a hardware-dependent recovery): re-run with"
    err "CEREMONY_ALLOW_BORN_IN_HSM=1"
    return 1
  fi
  warn "RUNNING THE UNSUPPORTED born-in-HSM PATH (CEREMONY_ALLOW_BORN_IN_HSM=1)."
  warn "The key produced here is recoverable ONLY from its DKEK backup onto a compatible"
  warn "SmartCard-HSM — NOT from the 4-of-6 Shamir shares."
  warn "OPTION B (chosen): the funding seed's recovery is its Shamir/metal/DVD backup"
  warn "(step 3 option c), NOT this HSM. This step is the OPTIONAL hardware-signer path"
  warn "(born-in-HSM + DKEK). Losing/breaking the HSM is survivable from the seed backup."
  warn "Skip this step unless you specifically want never-in-plaintext HSM signing — and if"
  warn "you do, keep a spare SmartCard-HSM — a DKEK restore needs a compatible device, and this"
  warn "key has no other recovery. (Under the SUPPORTED seed-authoritative model no spare is"
  warn "needed for recovery at all: 4 shares rebuild the seed and new hardware can be bought"
  warn "whenever it arrives. Spares there are convenience, not custody.)"
  command -v sc-hsm-tool >/dev/null || { err "sc-hsm-tool (OpenSC) missing"; return 1; }
  command -v pkcs11-tool >/dev/null || { err "pkcs11-tool (OpenSC) missing"; return 1; }
  # Each step below is a PREREQUISITE for the next: the funding key is born non-exportable
  # INSIDE the HSM, so its ONLY recoverable backup is the DKEK-wrapped blob (step 5). If the
  # DKEK share / init / import is skipped or fails, we MUST abort BEFORE generating the key —
  # otherwise we'd create a key on the device that can never be backed up (wrap would fail,
  # but the key would already exist). `run` returns non-zero on failure and 100 on a skip,
  # so check every prerequisite and stop the whole sequence on the first one that didn't run.
  # THE 4-of-6 BELOW IS AN OPTION-A REQUIREMENT ONLY. It exists because a born-in-HSM key is
  # non-exportable, so its DKEK-wrapped blob is the ONLY backup and the DKEK password therefore
  # carries the same weight as a seed.
  #
  # Under OPTION B — the chosen, seed-authoritative model — none of that holds. The key is
  # imported FROM the seed, the seed is already 4-of-6 on metal, and the DKEK is nothing but a
  # transport wrapper for unwrapKey. PROVEN ON HARDWARE 2026-07-31: a card was wiped, given a
  # completely unrelated DKEK (kcv A18E58706FDF611C), re-imported from the same seed, and produced
  # the SAME address. Losing a DKEK under Option B costs nothing — re-initialise and re-import.
  # See emulator/tests/test-day2-replaceability.sh.
  #
  # So on Option B: do NOT escrow these shares and do NOT archive dkek.pbe. You would be taking
  # custody of key-equivalent material — PIN + DKEK exports every key on the token, see
  # doc/HSM-THREAT-MODEL.md — in exchange for nothing.
  info "1) Create a DKEK share whose password is split 4-of-6 (OPTION A ONLY — see above):"
  # Teed into the RAM-only workdir (umask 077) because step 2 feeds the shares straight back into
  # the import (#464). The capture holds all six shares, so it never leaves $WORK: the M-DISC
  # stage copies an allowlist and refuses any *share*.txt, and the workdir is shredded on exit.
  run_tee "$WORK/dkek-shares.txt" "sc-hsm-tool --create-dkek-share '$WORK/dkek.pbe' --pwd-shares-threshold 4 --pwd-shares-total 6" \
    || { rm -f "$WORK/dkek-shares.txt"; \
         err "DKEK share creation was skipped or failed — aborting the HSM step."; \
         err "A born-in-HSM funding key has NO recoverable backup without a DKEK."; return 1; }
  if [ "$(grep -cE 'Share ID *: *[0-9]+' "$WORK/dkek-shares.txt" 2>/dev/null)" != 6 ]; then
    err "the six DKEK password shares were not captured, so step 2 cannot test them. Nothing is on"
    err "the card yet. Do not hand out these shares; re-run this step."
    rm -f "$WORK/dkek.pbe" "$WORK/dkek-shares.txt"
    return 1
  fi
  warn "OPTION A: record each password share with a custodian; dkek.pbe is password-protected,"
  warn "so copy it to archival media (M-DISC) freely."
  warn "OPTION B: do NEITHER. Destroy dkek.pbe with the rest of the ceremony scratch — the seed"
  warn "is the backup, and a DKEK that no longer exists can never end up beside a PIN."
  info "2) Initialise the HSM with one DKEK share and import it (DESTROYS existing keys):"
  # GUARD: --initialize WIPES the device. If a funding key already lives on this HSM (e.g. you
  # re-selected this step from the menu), re-initialising would DESTROY a non-exportable key
  # that has no plaintext copy. assert_hsm_blank probes for the public-key object (listable
  # without a PIN) and fails CLOSED on an unreadable card — see its definition above.
  assert_expected_device "the funding HSM" || return 1
  assert_hsm_blank "this device" "pkcs11-tool" || return 1
  run "sc-hsm-tool --initialize --dkek-shares 1 --label 'akash-funding'" \
    || { err "HSM --initialize was skipped or failed — aborting before key generation."; \
         err "No DKEK domain means the funding key would have no recoverable backup."; return 1; }
  # THE SHARE ROUND TRIP (#464). Import through the share path, exactly as a recovery does:
  # shares 1-4 from the capture, fed to --pwd-shares-total 4. Without that flag OpenSC asks for a
  # typed password instead, and the generated password is never shown to anyone.
  #
  # This import is also the ceremony-day test of the shares. OpenSC 0.27.1 rebuilds the password
  # as BN_bn2bin(secret), which drops a leading zero byte, so 1 share file in 128 can never be
  # opened from its own correct shares (#460). Found at a recovery, that is the DKEK lost. Found
  # here, it is a re-mint, and no key has been generated yet.
  #
  # There is no creation-time KCV to hold this against: --create-dkek-share prints none, and the
  # only way to get one would be --print-dkek-share, which puts the raw share on the screen. So
  # the REFUSAL is the gate. The KCV check that remains is step 6's card A against card B, and a
  # Pico reports an all-zero KCV that kcv_of rejects, so on a Pico bench the refusal is the only
  # half of this round trip that can be proven.
  #
  # Tee this import too: its key check value identifies the DKEK domain for step 6.
  local import_rc=0
  run_tee "$WORK/kcv-a.log" "feed_dkek_shares '$WORK/dkek-shares.txt' 1 2 3 4 | sc-hsm-tool --import-dkek-share '$WORK/dkek.pbe' --pwd-shares-total 4" \
    || import_rc=$?
  if [ "$import_rc" = 100 ]; then
    err "DKEK import was skipped — aborting before key generation."
    err "Generating the funding key now would leave it with NO recoverable DKEK backup."
    return 1
  elif [ "$import_rc" != 0 ]; then
    err "DKEK SHARE ROUND TRIP FAILED — dkek.pbe did not import from its own shares 1-4."
    err "If the output above says 'Error decrypting DKEK share', this share file cannot be opened"
    err "from its correct shares, today or at any recovery: OpenSC drops a leading zero byte from"
    err "the rebuilt password, which happens to 1 share file in 128 (#460)."
    err "No key has been generated. RE-MINT NOW, before anyone leaves the room:"
    err "  * every custodian destroys the share they just wrote down — it opens nothing;"
    err "  * re-run this step from 1): a new share file, six new shares, the card re-initialised."
    rm -f "$WORK/dkek.pbe" "$WORK/dkek-shares.txt"
    return 1
  fi
  info "3) Generate the funding key ON the device (non-exportable), secp256k1:"
  run "pkcs11-tool --login --keypairgen --key-type EC:secp256k1 --label akash-funding --id 01" \
    || { err "funding key generation was skipped or failed — aborting the HSM step."; return 1; }
  info "4) Export the PUBLIC key (safe) and derive the akash funding address:"
  run "pkcs11-tool --read-object --type pubkey --id 01 -o '$WORK/funding-pub.der'" \
    || { err "public-key export was skipped or failed — cannot prove key control; aborting."; return 1; }
  if [ ! -s "$WORK/funding-pub.der" ]; then
    err "no public key exported — cannot derive or prove the funding address; aborting."; return 1
  fi
  # PROOF OF CONTROL — do NOT trust the exported pubkey on its own. An exported public key is
  # NOT evidence the device holds the matching PRIVATE key: a faulty keygen, the WRONG --id
  # object, or hostile firmware can hand back a pubkey whose private key the HSM does not have.
  # Deriving + funding that address loses the money forever (unspendable). So sign a FRESH
  # random digest on the HSM with the funding key and verify it against the EXPORTED pubkey.
  # Only the holder of the matching private key can produce a signature that verifies.
  info "   proving the HSM controls the matching private key (sign a random digest, then verify)…"
  head -c 32 /dev/urandom > "$WORK/kat.digest" && chmod 600 "$WORK/kat.digest"
  local proven=0
  if run "pkcs11-tool --login --sign --id 01 -m ECDSA -i '$WORK/kat.digest' -o '$WORK/kat.sig'" \
     && [ -s "$WORK/kat.sig" ] \
     && python3 "$HERE/verify-hsm-control.py" --der "$WORK/funding-pub.der" \
          --digest "$WORK/kat.digest" --sig "$WORK/kat.sig" >/dev/null 2>&1; then
    proven=1
  fi
  rm -f "$WORK/kat.digest" "$WORK/kat.sig" 2>/dev/null
  if [ "$proven" != 1 ]; then
    err "KEYPAIR-CONTROL PROOF FAILED — the HSM did not produce a signature over a random digest"
    err "that verifies against the exported pubkey (id 01). The exported public key may NOT match"
    err "a private key this device holds (faulty keygen / wrong object / bad firmware)."
    err "Refusing to record a funding address: money sent there could be UNSPENDABLE. Do NOT fund."
    return 1
  fi
  info "   keypair-control proof PASSED — the HSM holds the private key for this public key."
  local addr; addr=$(python3 "$HERE/derive-akash-address.py" --der "$WORK/funding-pub.der" 2>/dev/null || true)
  if [ -z "$addr" ]; then
    err "address derivation failed after a passing key-control proof — derive manually and DO NOT"
    err "fund until you have an address: derive-akash-address.py --der funding-pub.der"
    return 1
  fi
  # The ADDRESS is public and now provably signable by the HSM — but it is NOT yet safe to fund.
  # The key is born non-exportable, so its ONLY recoverable copy is the DKEK-wrapped backup we are
  # about to make. We do NOT declare the address fundable until that backup is WRAPPED *and* proven
  # to RESTORE (steps 5-6). A wrap that returns 0 but cannot be unwrapped = money lost when the
  # primary HSM later dies.
  info "Derived funding address (NOT yet fundable — pending backup wrap + restore-verify): $addr"
  info "5) Back up the (wrapped) private key for disaster recovery — encrypted under the DKEK:"
  run "sc-hsm-tool --wrap-key '$WORK/funding-wrapped.bin' --key-reference 1" \
    || { err "wrap-backup was skipped or failed — the funding key EXISTS on the HSM but has NO"; \
         err "recoverable backup yet. Do NOT fund this address until the DKEK wrap succeeds."; return 1; }
  if [ ! -s "$WORK/funding-wrapped.bin" ]; then
    err "the wrap produced an EMPTY backup blob — do NOT fund; the funding key has no usable backup."
    return 1
  fi
  warn "OPTION A: store funding-wrapped.bin + dkek.pbe on M-DISC; the 4-of-6 shares are the secret."
  warn "OPTION B: this blob is a convenience, not the backup — the seed is. Do not escrow the DKEK."
  # RESTORE-VERIFY — a wrapped blob you have never unwrapped is NOT a backup. `--wrap-key` can
  # return 0 yet leave an UNRESTORABLE blob (a truncated write, faulty EEPROM/firmware, a DKEK a
  # restore won't rebuild, or the wrong key-reference object). The funding key is non-exportable with
  # no plaintext copy, so if this ONE backup can't restore, the money is unrecoverable the day the
  # primary HSM dies. Every OTHER backup path (ssss, SLIP-39) reconstruct-verifies before it is
  # trusted; this catastrophic one must too. Prove it: unwrap the backup into a SCRATCH key slot
  # (key-reference 2) under the SAME DKEK that a restore uses (the one imported from dkek.pbe), read
  # the restored public key, and require it to byte-match funding-pub.der. Do this on a sealed SPARE
  # HSM if you have one inserted; otherwise the scratch slot on this card proves the blob + DKEK
  # reconstruct the exact funding key. Refuse to record the address as fundable until this passes.
  info "6) RESTORE-VERIFY the wrapped backup (mandatory before the address is fundable):"
  # TWO-DEVICE PATH. A same-card unwrap into a scratch slot proves the blob decrypts under a DKEK
  # that is ALREADY RESIDENT on this card — it cannot prove a genuine disaster recovery, where a
  # DIFFERENT device must rebuild the same DKEK from dkek.pbe before the blob means anything. When
  # a second blank SmartCard-HSM is present, do the restore-verify ON IT: that exercises the real
  # recovery path end-to-end AND leaves the second device provisioned as the off-site failover
  # clone in the same operation. Falls back to the same-card scratch slot when only one token is in.
  #
  # Device selection: on real hardware each token is its own PC/SC reader (sc-hsm-tool --reader N,
  # pkcs11-tool --slot N). Under the ceremony emulator a "device" is its own state directory, so the
  # harness sets HSM_B_ENV=EMU_SCHSM_STATE=… and addresses it that way; leave reader/slot off then.
  #
  # The clone path is EXPLICIT OPT-IN: the operator must name which reader/slot holds the blank
  # device (HSM_B_READER / HSM_B_SLOT, or HSM_B_ENV under the emulator). Defaulting to "reader 1"
  # and asking would risk pointing --initialize at the PRIMARY card and wiping the key we just
  # generated; making the operator state the target removes that whole class of mistake.
  # ---- SUPERSEDED BY THE RATIFIED PLAN (PLAN.md 3.2, decision D1) ------------------------------
  # This path rebuilds the SAME DKEK domain on device B from dkek.pbe. That was the right shape
  # under OPTION A (key born on-card, wrapped blob the only backup). Two ratified decisions have
  # since made it the wrong one for production:
  #
  #   OPTION B (seed-authoritative)  each device imports FROM THE SEED under its OWN local DKEK and
  #                                  reaches the same address — PROVEN on hardware 2026-07-31. No
  #                                  shared domain is needed, so nothing has to travel.
  #   DECISION D1 (ship keyless)     the device leaves the ceremony with its DKEK and NO KEY; the
  #                                  wrapped blob follows over the network.
  #
  # Cloning moves a DKEK SHARE between two datacenters, and PIN + DKEK together export every key on
  # a token. It trades away the exact property the custody model is built on, for a convenience that
  # Option B does not need.
  #
  # KEPT, NOT DELETED, because it remains the correct procedure for an Option-A fleet and this
  # toolkit is meant to serve both. It is gated: production use requires an explicit acknowledgement.
  if [ -n "${HSM_B_READER:-}${HSM_B_SLOT:-}${HSM_B_ENV:-}" ] \
     && [ "${CEREMONY_MODE:-dev}" = "prod" ] && [ "${CEREMONY_ALLOW_CLONE_PATH:-0}" != 1 ]; then
    err "The two-device CLONE path is superseded for this fleet (PLAN.md 3.2 / decision D1)."
    err "It rebuilds the SAME DKEK domain on device B, which means a DKEK share travels between"
    err "sites — and PIN + DKEK together export every key on a token."
    err "Under Option B each device imports from the SEED under its OWN DKEK and reaches the same"
    err "address, so nothing needs to travel. Provision the second device independently instead."
    err "If you are deliberately running an OPTION A fleet, re-run with CEREMONY_ALLOW_CLONE_PATH=1."
    return 1
  fi

  local b_env="${HSM_B_ENV:-}" b_sc="" b_p11="" kcv_a kcv_b cloned=0
  # VALIDATE BEFORE USE. All three of these are interpolated into command strings that run()
  # and assert_hsm_blank() execute with eval, and this step --initialize's (WIPES) whichever
  # device they select. A stray quote, space or metacharacter from a mis-paste could retarget
  # the command or inject one, so constrain each to the shape it is actually allowed to have:
  # reader/slot are numeric selectors, and HSM_B_ENV is a single NAME=VALUE env assignment.
  case "${HSM_B_READER:-}" in
    ""|*[!0-9]*) [ -z "${HSM_B_READER:-}" ] || {
        err "HSM_B_READER must be a number (got: '${HSM_B_READER}'). Refusing — this value"
        err "selects which device gets WIPED."; return 1; };;
  esac
  case "${HSM_B_SLOT:-}" in
    ""|*[!0-9]*) [ -z "${HSM_B_SLOT:-}" ] || {
        err "HSM_B_SLOT must be a number (got: '${HSM_B_SLOT}'). Refusing — this value"
        err "selects which device gets WIPED."; return 1; };;
  esac
  if [ -n "$b_env" ]; then
    case "$b_env" in
      *[!A-Za-z0-9_=/.:-]*|*' '*|!*|'='*)
        err "HSM_B_ENV must be a single NAME=VALUE assignment using [A-Za-z0-9_=/.:-]"
        err "(got: '$b_env'). Refusing: it is executed inside a command string, and this step"
        err "WIPES the device it selects."; return 1;;
      *=*) : ;;
      *) err "HSM_B_ENV must contain '=' (a NAME=VALUE assignment); got: '$b_env'"; return 1;;
    esac
  fi
  [ -n "${HSM_B_READER:-}" ] && b_sc="--reader $HSM_B_READER"
  [ -n "${HSM_B_SLOT:-}" ]   && b_p11="--slot $HSM_B_SLOT"
  if [ -z "$b_env$b_sc$b_p11" ]; then
    info "   (to clone onto a second device instead, re-run with HSM_B_READER=<n> HSM_B_SLOT=<n>"
    info "    set to the blank token's reader/slot — that proves the real cross-device restore.)"
  fi
  if [ -n "$b_env$b_sc$b_p11" ] && ask "clone onto the SECOND, BLANK SmartCard-HSM at ${b_sc:-$b_env}?"; then
    warn "The second device will be INITIALISED (wiped), given the SAME DKEK domain, and the"
    warn "wrapped backup unwrapped INTO it. It becomes a full working clone that signs on its"
    warn "OWN PIN — seal it at a DIFFERENT site than the primary (e.g. SiteB vs SiteA)."
    # SAFETY: never --initialize a device that already holds a funding key. If the reader/slot
    # selector is wrong this would otherwise WIPE the primary card we just generated the key on.
    assert_hsm_blank "the SECOND HSM (${b_sc:-$b_env})" "$b_env pkcs11-tool $b_p11" || return 1
    run "$b_env sc-hsm-tool $b_sc --initialize --dkek-shares 1 --label 'akash-funding'" \
      || { err "second-HSM --initialize was skipped or failed — no clone was made. The primary key"; \
           err "and its wrapped backup are untouched; re-run this step with the spare inserted."; return 1; }
    # Shares 3-6, not 1-4: the clone is rebuilt by a second custodian quorum, from the same
    # capture, through the same --pwd-shares-total path a recovery uses.
    run_tee "$WORK/kcv-b.log" "feed_dkek_shares '$WORK/dkek-shares.txt' 3 4 5 6 | $b_env sc-hsm-tool $b_sc --import-dkek-share '$WORK/dkek.pbe' --pwd-shares-total 4" \
      || { err "DKEK import onto the second HSM was skipped or failed — it cannot receive the"; \
           err "clone. Do NOT treat it as a backup device."; return 1; }
    # KCV EQUALITY — two SmartCard-HSMs hold the same DKEK iff their key check values match.
    # This is an EARLY, unambiguous check; the unwrap + pubkey byte-compare below is the real
    # gate (a wrong DKEK cannot unwrap at all), so a KCV we cannot parse warns rather than blocks.
    kcv_a="$(kcv_of "$WORK/kcv-a.log" || true)"
    kcv_b="$(kcv_of "$WORK/kcv-b.log" || true)"
    if [ -n "$kcv_a" ] && [ -n "$kcv_b" ]; then
      if [ "$kcv_a" != "$kcv_b" ]; then
        err "DKEK MISMATCH — the two devices do NOT share a DKEK domain (key check values"
        err "$kcv_a vs $kcv_b). The second card could never restore this backup. Do NOT fund"
        err "$addr; re-initialise the second device from the SAME dkek.pbe and retry."
        return 1
      fi
      info "   DKEK key check values match on both devices ($kcv_a) — same domain confirmed."
    else
      warn "could not parse a DKEK key check value from both devices — skipping the early"
      warn "domain check. The unwrap + restored-pubkey comparison below still gates funding."
    fi
    run "$b_env sc-hsm-tool $b_sc --unwrap-key '$WORK/funding-wrapped.bin' --key-reference 1" \
      || { err "RESTORE-VERIFY FAILED — the second HSM could NOT unwrap the backup under its DKEK."; \
           err "The backup is UNRESTORABLE on a fresh device (corrupt blob, or a DKEK a restore"; \
           err "cannot rebuild). Do NOT fund $addr; REDO the backup before funding."; return 1; }
    run "$b_env pkcs11-tool $b_p11 --read-object --type pubkey --id 01 -o '$WORK/funding-restored-pub.der'" \
      || { err "RESTORE-VERIFY FAILED — could not read the restored public key from the SECOND"; \
           err "HSM. The clone is unproven; do NOT fund $addr."; return 1; }
    cloned=1
  else
    warn "no second device — falling back to a SAME-CARD scratch unwrap. This proves the blob"
    warn "decrypts under the DKEK already on this card; it does NOT prove a fresh device can"
    warn "rebuild that DKEK from dkek.pbe. Re-run with a spare inserted before funding for real."
    run "sc-hsm-tool --unwrap-key '$WORK/funding-wrapped.bin' --key-reference 2" \
      || { err "RESTORE-VERIFY FAILED — the wrapped backup could NOT be unwrapped under the DKEK. It is"; \
           err "UNRESTORABLE (truncated/corrupt blob, or a DKEK a restore cannot rebuild). Do NOT fund"; \
           err "$addr. Investigate the DKEK/wrap and REDO the backup before funding."; return 1; }
    run "pkcs11-tool --read-object --type pubkey --id 02 -o '$WORK/funding-restored-pub.der'" \
      || { err "RESTORE-VERIFY FAILED — could not read the restored public key from the unwrapped"; \
           err "backup. The restore is unproven; do NOT fund $addr."; return 1; }
  fi
  if [ ! -s "$WORK/funding-restored-pub.der" ] || ! cmp -s "$WORK/funding-pub.der" "$WORK/funding-restored-pub.der"; then
    err "RESTORE-VERIFY FAILED — the public key restored from the wrapped backup does NOT byte-match"
    err "the funding pubkey. The backup would NOT reconstruct the funding key (wrong key-reference"
    err "object, or a mismatched DKEK). Do NOT fund $addr; redo the born-in-HSM key + backup."
    rm -f "$WORK/funding-restored-pub.der" 2>/dev/null
    return 1
  fi
  rm -f "$WORK/funding-restored-pub.der" 2>/dev/null
  # Both imports are done; the shares are on paper now and nothing reads the capture again.
  rm -f "$WORK/dkek-shares.txt"
  info "   restore-verify OK — the wrapped backup unwraps to the EXACT funding key under the DKEK."
  if [ "$cloned" = 1 ]; then
    info "   CLONE PROVEN on the second device — it holds the same funding key at key-reference 1."
    warn "You now have TWO independently usable devices: either one can sign alone, under its OWN"
    warn "PIN. Set a DIFFERENT User PIN on each and seal them at different sites — separate PINs are"
    warn "the only dual-control this token gives you (OpenSC cannot drive its m-of-n public-key auth)."
    warn "Do NOT pre-initialise the remaining SPARE. A blank spare forces a real restore (dkek.pbe +"
    warn "4-of-6 custodian shares); a spare already holding the DKEK lets anyone with it and the"
    warn "wrapped blob rebuild the key with NO custodian threshold involved."
  else
    warn "The restore-verify left a scratch copy of the key at key-reference 2 on this card; delete it"
    warn "before sealing:  pkcs11-tool --login --delete-object --type privkey --id 02"
  fi
  warn "Real restore = fresh HSM, then: sc-hsm-tool --import-dkek-share dkek.pbe --pwd-shares-total 4"
  warn "(without --pwd-shares-total OpenSC never enters the share prompt path; it asks prime +"
  warn "share-ID + share-value per share, 4 of 6 custodians), then sc-hsm-tool --unwrap-key. The key"
  warn "is rebuilt INSIDE the HSM and never appears in host RAM."
  info "7) Backup PROVEN to restore. The funding address is now safe to record and fund:"
  info "FUNDING ADDRESS (public, key-control PROVEN + backup RESTORE-VERIFIED — record + fund): $addr"
}

# Slot index of the first attached SmartCard-HSM token (Nitrokey HSM 2 / Pico HSM), for its RNG.
hsm_rng_slot() {
  timeout 60 pkcs11-tool -L 2>/dev/null | awk '
    /^Slot [0-9]+ / { idx=$2; name=$0; sub(/^Slot [0-9]+ \([^)]*\): /, "", name) }
    /token manufacturer/ && /CardContact/ && !found { print idx; found=1 }'
}

step_entropy_seed() {
  b "Generate a NEW wallet seed from dice + Nitrokey HSM + OS randomness"
  info "Three independent sources are mixed (XOR): your DICE, the Nitrokey HSM's hardware RNG and"
  info "/dev/urandom. The result is at least as unpredictable as the best of them, so no single"
  info "flawed or backdoored source decides the seed. Dice are always required on top of the HSM."
  local f="$WORK/secret.in"
  if [ -s "$f" ]; then
    warn "$f already holds a secret."
    ask "REPLACE it with a newly generated seed?" || return 0
  fi
  local d="$WORK/dice.hex" h="$WORK/hsm.bin" o="$WORK/os.bin" m="$WORK/mixed.hex"
  # shellcheck disable=SC2064
  trap "rm -f '$d' '$h' '$o' '$m' '$WORK/seed.err'" RETURN

  info "1/3  DICE — at least 100 rolls of a fair six-sided die (100 x 2.585 = 258 bits)."
  info "     Roll, type the digits you see (spaces are fine), press Enter; repeat until the counter"
  info "     reaches 100. Typing is hidden. A mistyped line is discarded whole — just retype it."
  python3 "$HERE/dice-entropy.py" --out "$d" || { err "dice entropy not collected — no seed generated."; return 1; }

  info "2/3  NITROKEY HSM — 32 bytes from its hardware random number generator (no PIN needed)."
  local slot; slot="$(hsm_rng_slot)"
  if [ -z "$slot" ]; then
    err "no Nitrokey HSM / Pico HSM found — attach it with 'qvm-usb attach' and run this step again."
    err "The seed is never generated without the HSM's randomness (dice + HSM, both required)."
    return 1
  fi
  if ! timeout 60 pkcs11-tool --slot-index "$slot" --generate-random 32 --output-file "$h" >/dev/null 2>&1 \
     || [ "$(wc -c < "$h" 2>/dev/null)" != 32 ]; then
    err "the HSM did not return 32 random bytes — no seed generated."; return 1
  fi
  info "     32 bytes read from the HSM in slot $slot."

  info "3/3  OPERATING SYSTEM — 32 bytes from /dev/urandom."
  head -c 32 /dev/urandom > "$o" && chmod 600 "$o"

  python3 "$HERE/entropy-mix.py" --out "$m" "$d" "$h" "$o" \
    || { err "mixing refused the sources (identical or empty) — no seed generated."; return 1; }
  if ! python3 "$HERE/bip39-slip39-backup.py" --from-entropy --in "$m" --out "$f" 2>"$WORK/seed.err"; then
    sed 's/^/     /' "$WORK/seed.err" >&2; err "could not encode the mixed entropy as a mnemonic."; rm -f "$f"; return 1
  fi
  chmod 600 "$f"
  info "NEW 24-word wallet seed written to $f (RAM only; never shown). Fingerprint:"
  info "     $(sha256sum < "$f" | cut -c1-16)"
  info "Next: step 3, option c — split it into 4-of-6 SLIP-39 shares and record its funding address."
}

step_shamir() {
  b "Shamir split a recovery root (4-of-6)"
  # DETERMINISTIC MINT: neutralize any ambient SLIP-39 passphrase (a dry-run leftover, or one set
  # in the vault-qube profile) BEFORE minting. slip39-mint.py / bip39-slip39-backup.py resolve
  # SLIP39_PASSPHRASE from env with highest priority; an unnoticed value would silently bind the
  # funding-seed shares to an UNRECORDED passphrase (reconstruct-verify still passes — it uses the
  # same pw). At clean-shell disaster recovery the empty default yields a DIFFERENT seed -> address
  # != the recorded anchor -> STOP, and the sole Option-B backup is unrecoverable. A set-once
  # custodial backup must use the empty default; unset it so the ceremony is reproducible.
  unset SLIP39_PASSPHRASE 2>/dev/null || true
  # DETERMINISTIC ANCHOR: neutralize any ambient BIP39_PASSPHRASE (25th-word) the same way.
  # Option c splits the raw mnemonic (bip39-slip39-backup.py ignores BIP39 passphrases), but
  # the recovery anchor below runs derive-akash-address.py, which reads BIP39_PASSPHRASE with
  # highest priority. A stray value would record the seed+passphrase address instead of the
  # real empty-passphrase funding address -> at clean-shell recovery the good shares derive the
  # TRUE address != the recorded anchor -> the operator STOPs and distrusts a valid backup.
  unset BIP39_PASSPHRASE 2>/dev/null || true
  info "Use this for the BREAKGLASS age key (ASCII) or the DERIVATION root mnemonic."
  info "Put the secret in a file FIRST (don't type it at a prompt). It must already exist"
  info "in this RAM workdir — e.g. you exported the breakglass age key into $WORK/secret.in"
  local f="$WORK/secret.in"
  if [ ! -s "$f" ]; then
    warn "no $WORK/secret.in found."
    info "For a quick DRY RUN with a throwaway value:"
    show "printf 'TEST-do-not-use' > '$f'"
    ask "create a throwaway test secret now?" && printf 'TEST-do-not-use-%s' "$RANDOM" > "$f"
    [ -s "$f" ] || { warn "no secret to split"; return 0; }
  fi
  echo
  info "a) ssss  — best for an ASCII age key string (AGE-SECRET-KEY-1…)"
  info "b) SLIP-0039 shamir — MINT a fresh master secret + 5 word shares"
  info "c) BIP39 WALLET mnemonic -> SLIP-39 shares  (the funding / derivation seed;"
  info "   Option B — exact round-trip, recoverable with NO HSM; shares -> metal plates)"
  read -r -p "   choose a, b or c: " which
  case "$which" in
    a)
      # ssss splits a SINGLE line up to ~128 bytes. A multi-line or oversized secret would be
      # SILENTLY truncated — you'd distribute shares of the wrong thing. Refuse and redirect.
      local nbytes nlines; nbytes=$(wc -c < "$f" | tr -d ' '); nlines=$(grep -c '' "$f")
      if [ "$nlines" -gt 1 ]; then
        err "secret in secret.in is multi-line; ssss splits a single line only."
        err "Use option c (SLIP-39) for a seed/mnemonic or any multi-line secret."; return 0
      fi
      if [ "$nbytes" -gt 128 ]; then
        err "secret is ${nbytes} bytes; ssss handles ~128 max. Use option c (SLIP-39)."; return 0
      fi
      run "ssss-split -t 4 -n 6 -q < '$f' > '$WORK/shares.txt'" || return 0
      # RECONSTRUCT-VERIFY *before* distributing — an unverified split is not a backup. Recover
      # from a 4-subset and compare in-shell (no value is ever printed; ssss-combine emits the
      # secret on stderr and appends a newline, which $(...) strips).
      if [ "$(sed -n '1p;3p;4p;6p' "$WORK/shares.txt" | ssss-combine -t 4 -q 2>&1)" = "$(cat "$f")" ]; then
        info "reconstruct-verify OK: any 4 of the 6 shares rebuild the EXACT secret."
      else
        err "RECONSTRUCT-VERIFY FAILED — 4 shares did NOT rebuild the secret; refusing to distribute."
        err "(A trailing newline in secret.in is dropped by ssss — recreate it with no trailing newline.)"
        rm -f "$WORK/shares.txt"; return 1
      fi
      info "6 shares written + verified. Printing each on its own sealed page:"
      local i=0; while IFS= read -r line; do i=$((i+1)); printf '%s' "$line" > "$WORK/sh$i"; print_share "Breakglass age key — Shamir share $i of 6 (need 4)" "$WORK/sh$i"; done < "$WORK/shares.txt"
      ;;
    b)
      warn "MINTS a NEW master secret (recoverable ONLY from these shares; verify + distribute)."
      # Use slip39-mint.py, NOT 'shamir create': the CLI prints the master secret to stdout
      # (it would land in the shares file) and does no reconstruct-verify. The minter never
      # emits the master secret and proves every 4-of-6 subset recovers before writing.
      show "slip39-mint.py --threshold 4 --shares 6 --out slip39.txt"
      if python3 "$HERE/slip39-mint.py" --threshold 4 --shares 6 --out "$WORK/slip39.txt" 2>"$WORK/mint.err"; then
        info "Minted + reconstruct-verified (every 4-of-6 subset recovers). Printing shares:"
      else
        err "mint/verify FAILED — refusing to distribute:"; sed 's/^/     /' "$WORK/mint.err" >&2; rm -f "$WORK/slip39.txt"; return 1
      fi
      # A SLIP-39 share is a line of >=16 space-separated lowercase words (header has #/digits).
      local n=0; while IFS= read -r line; do
        if [[ "$line" =~ ^[a-z]+([[:space:]][a-z]+){15,}$ ]]; then
          n=$((n+1)); printf '%s' "$line" > "$WORK/w$n"; print_share "SLIP-0039 share $n of 6 (need 4)" "$WORK/w$n"
        fi
      done < "$WORK/slip39.txt"
      ;;
    c)
      # Option B: back up an EXISTING BIP39 wallet mnemonic (funding/derivation) as SLIP-39
      # word-shares. Exact round-trip; recover with NO HSM. secret.in must hold the mnemonic.
      show "bip39-slip39-backup.py --in secret.in --threshold 4 --shares 6 -> SLIP-39 shares"
      # Surface the tool's stderr to the operator (do NOT swallow it): if a passphrase is somehow
      # still in effect it WARNS that recovery requires the EXACT passphrase — that safeguard must
      # reach the operator, not vanish into /dev/null. Mirror option b (capture then echo).
      if python3 "$HERE/bip39-slip39-backup.py" --in "$f" --threshold 4 --shares 6 --out "$WORK/slip39.txt" 2>"$WORK/bkp.err"; then
        [ -s "$WORK/bkp.err" ] && sed 's/^/     /' "$WORK/bkp.err" >&2
        info "BIP39 mnemonic split into 6 SLIP-39 word-shares (any 4 recover the EXACT mnemonic)."
        local n=0; while IFS= read -r line; do
          if [[ "$line" =~ ^[a-z]+([[:space:]][a-z]+){15,}$ ]]; then
            n=$((n+1)); printf '%s' "$line" > "$WORK/w$n"; print_share "Wallet seed — SLIP-0039 share $n of 6 (need 4)" "$WORK/w$n"
          fi
        done < "$WORK/slip39.txt"
        info "Stamp each share to metal: metal-stamp-worksheet.py --in <share>. Recover the"
        info "mnemonic with: bip39-slip39-backup.py --recover  (then sops edit the vault / re-import to HSM)."
        # RECORD THE RECOVERY ANCHOR. The shares back up the seed, but recovery integrity
        # (RECOVERY-TECHNICAL.md Step 4 / recovery-card step 6: "recovered addr == funding addr on
        # the sealed sheet, else STOP") needs the funding ADDRESS recorded NOW. Without it a
        # wrong-share / wrong-passphrase / tampered recovery cannot be caught before funds move.
        # The address is PUBLIC; derive it from the source mnemonic file (never printed) and show it.
        local caddr; caddr=$(python3 "$HERE/derive-akash-address.py" --mnemonic-file "$f" 2>/dev/null || true)
        if [ -n "$caddr" ]; then
          info "FUNDING ADDRESS (public; derived from this seed at m/44'/118'/0'/0/0): $caddr"
          warn "RECORD this address on the sealed custodian-contact sheet / seal registry NOW. It is"
          warn "the recovery integrity anchor: at recovery, derive-akash-address.py must reproduce THIS"
          warn "address or you STOP (wrong shares/passphrase/tamper) before moving any funds."
        else
          warn "could not auto-derive the funding address (need python3). Before sealing, run"
          warn "derive-akash-address.py --mnemonic-file <seed> and RECORD the akash1… address on the"
          warn "sealed sheet — recovery has no integrity anchor without it."
        fi
      else
        [ -s "$WORK/bkp.err" ] && sed 's/^/     /' "$WORK/bkp.err" >&2
        warn "split failed — secret.in must be a valid BIP39 mnemonic; need python3 + mnemonic + shamir-mnemonic."
      fi
      ;;
    *) warn "no choice made";;
  esac
  warn "Distribute the 6 shares across media × geography × people. No single share leaks;"
  warn "any 4 reconstruct; you may lose up to 2."
}

# ── Dev default PIN guard ───────────────────────────────────────────────────────
# The Pico HSM ships FROM THE FACTORY as a blank device — there is no "default" PIN baked in
# by the firmware. The values shipped in the tier-0 payload template are dev fixtures the pico-
# hsm-tool docs use as the *example* for --initialize. They are NOT security. They are a
# footgun: a real operator who forgets to change them ships the docs' example PIN to a token that
# holds real funds, and that happens because the wizard's template made those strings the obvious
# "fill in to continue" values.
#
# Two-mode design. CEREMONY_MODE=prod (default) REFUSES to start the tier-0 payload step while
# any of the seven HSM PIN fields still holds a recognised dev default. CEREMONY_MODE=dev (only for
# the Pico HSM devops path) opts OUT of the guard and warns loudly. The mode is itself logged
# and the wizard's first prompt asks the operator to type the mode explicitly, so the answer is
# not "whatever the env happened to be".
#
# Recognised dev defaults that trip the guard in PROD:
#   648219                          — pico-hsm-tool --pin example value
#   3537363231383830                — pico-hsm-tool --so-pin example value
#   the literal strings "CHANGEME" / "TODO" / "FILL_IN"  — common placeholder escapes
#   empty string                                          — silent failure mode
# Note: the regex matches the literals only; the empty case is checked separately, because
# putting "|" with an empty alternation at the end is POSIX-correct but breaks under legacy
# grep implementations (macOS Homebrew's grep is ugrep, which rejects it).
# The YubiKey factory PIN, PUK and management key are defaults too: step_yubikey_ops changes a card TO
# the escrowed value, so an escrowed factory value leaves the factory credential on the card.
DEV_DEFAULT_PINS_REGEX='^(648219|3537363231383830|123456|12345678|010203040506070801020304050607080102030405060708|CHANGEME|TODO|FILL_IN)$'

# Source the mode. main() asks the operator to confirm it interactively, so the env value is a
# default, not a bypass. Record whether it arrived FROM THE ENVIRONMENT before the default is
# applied: once the default lands, CEREMONY_MODE is always non-empty and the distinction is
# unrecoverable. main() uses this to decide whether prompting is appropriate at all.
CEREMONY_MODE_EXPLICIT=0
[ -n "${CEREMONY_MODE:-}" ] && CEREMONY_MODE_EXPLICIT=1
CEREMONY_MODE="${CEREMONY_MODE:-prod}"

# Fail-closed: any tier-0 payload step using a default PIN aborts with a named error. This is
# the production-mode guard. Dev mode (CEREMONY_MODE=dev) opts out, but the wizard still warns
# on every step so the operator must consciously type past the warning.
fail_ceremony_default_pin() {
  local what="$1" value="$2"
  if [ "$CEREMONY_MODE" = "dev" ]; then
    # Only a value that IS a dev default is worth the warning, and the value itself is never
    # printed: this used to echo every field, real PINs included, into the terminal and the capture.
    if [ -z "$value" ] || grep -qE "$DEV_DEFAULT_PINS_REGEX" <<< "$value"; then
      warn "DEV MODE — $what is unset or holds a dev default. Confirm this is a SCRATCH device."
    fi
    return 0
  fi
  if [ -z "$value" ] || grep -qE "$DEV_DEFAULT_PINS_REGEX" <<< "$value"; then
    err "PROD GUARD: $what is unset or holds a recognised dev default."
    err "Refusing to produce a tier-0 payload while a PIN could be the docs' example."
    err "Edit the file, set a real value you have written down elsewhere, and re-run."
    err "If you are intentionally on a SCRATCH device, set CEREMONY_MODE=dev and re-run."
    return 1
  fi
  return 0
}

# =============================================================================
# Step 0 — set HSM PINs from a file BEFORE any HSM-credentialed step runs.
#
# Why this is step 0: the worst footgun in the ceremony isn't the ceremony itself — it's the
# transition from "demo on the Pico" to "real on the Nitrokey", where the operator forgets to
# change the dev defaults. Forcing PIN setup as step 0 makes the operator pass through the
# defaults ONCE, on a fresh screen, before any other step can run. The wizard refuses step 7
# (step_payload) if this step has not been completed.
# =============================================================================
# CREDENTIAL SEPARATION (regalia#28 criterion 1; the rules are qubes/CREDENTIAL-SEPARATION.md).
# The dev-default guard above catches a docs example. It says nothing about two fields holding the
# SAME value — card A's user PIN reused on card B, a user PIN equal to its own SO PIN, a YubiKey PIN
# equal to its PUK. Each of those turns one disclosure into two, and the payload would engrave it on
# metal. So every credential step 0 loads must be distinct, and each must have the shape its device
# accepts: a value the card will refuse at initialisation is found here, before anything is written.
# PROD refuses; DEV warns, because the dev fixtures repeat on purpose. Values are never printed.
check_credential_separation() {
  # Byte semantics: a YubiKey takes at most 8 BYTES, and in a UTF-8 locale [[:print:]]{6,8} counts
  # characters. Under C, multibyte input is not [[:print:]] at all, so it is refused outright.
  local LC_ALL=C
  local problems="" k v other ov
  local fields="hsm_a_user_pin hsm_a_so_pin hsm_b_user_pin hsm_b_so_pin yubikey_piv_pin yubikey_piv_puk yubikey_mgmt_key"
  for k in $fields; do
    # A field the file omits is a problem, not a skip: a file of comments would otherwise pass.
    v="${!k:-}"; [ -n "$v" ] || { problems="$problems|$k: missing from the PIN file"; continue; }
    case "$k" in
      hsm_?_user_pin)  [[ "$v" =~ ^[[:print:]]{6,15}$ ]] || problems="$problems|$k: a SmartCard-HSM user PIN is 6-15 printable characters" ;;
      hsm_?_so_pin)    [[ "$v" =~ ^[0-9A-Fa-f]{16}$ ]] || problems="$problems|$k: a SmartCard-HSM SO PIN is exactly 16 hex digits" ;;
      yubikey_piv_pin|yubikey_piv_puk) [[ "$v" =~ ^[[:print:]]{6,8}$ ]] || problems="$problems|$k: a YubiKey PIV PIN or PUK is 6-8 characters" ;;
      yubikey_mgmt_key) [[ "$v" =~ ^[0-9A-Fa-f]{48}$|^[0-9A-Fa-f]{32}$|^[0-9A-Fa-f]{64}$ ]] || problems="$problems|$k: a PIV management key is 32, 48 or 64 hex digits" ;;
    esac
    for other in $fields; do
      [[ "$other" > "$k" ]] || continue
      ov="${!other:-}"
      [ -n "$ov" ] && [ "${v,,}" = "${ov,,}" ] && problems="$problems|$k and $other hold the same value"
    done
  done
  [ -z "$problems" ] && { info "Credential separation: every loaded credential is distinct and well-formed."; return 0; }
  local line
  if [ "$CEREMONY_MODE" = "dev" ]; then
    warn "DEV MODE — credential separation would REFUSE this file in PROD:"
    while IFS= read -r line; do [ -n "$line" ] && warn "  - $line"; done <<< "${problems//|/$'\n'}"
    return 0
  fi
  err "CREDENTIAL SEPARATION: refusing the PIN file (values not shown):"
  while IFS= read -r line; do [ -n "$line" ] && err "  - $line"; done <<< "${problems//|/$'\n'}"
  err "Every PIN, SO PIN, PUK and management key must be its own value (qubes/CREDENTIAL-SEPARATION.md)."
  return 1
}

step_set_pins() {
  b "Step 0 — set HSM PIN defaults from a file"
  info "Mode: $CEREMONY_MODE"
  info "Tier-0 payload has seven HSM PIN fields. In DEV mode they hold the pico-hsm-tool docs'"
  info "example values. In PROD mode the ceremony refuses to start the tier-0 payload step while"
  info "any of them still holds a recognised dev default, so this step loads fresh values from a"
  info "file. The file is RAM-only (workdir on tmpfs); no PIN is read from disk after the wizard"
  info "exits. The mode is logged, and the gate below is the production version of the guard."
  local pfile="$WORK/pins.env"
  if [ ! -s "$pfile" ]; then
    cat > "$pfile" <<'EOF'
# HSM PIN defaults — one line per field, format: KEY=value
# Pin file is read once at step 0; the wizard consumes it and never echoes the values.
# Pin fields the tier-0 payload step reads:
#   hsm_a_user_pin, hsm_a_so_pin, hsm_b_user_pin, hsm_b_so_pin,
#   yubikey_piv_pin, yubikey_piv_puk, yubikey_mgmt_key
  #
  # DEVICE C (the staging Pico) IS DELIBERATELY ABSENT. Its PINs were collected here,
  # dev-default-guarded, and written into the tier-0 payload — then never used to provision
  # anything. Two things were wrong. Staging holds only throwaway keys, so its PINs do not need
  # 4-of-6 metal custody; and their presence in the PRODUCTION payload implied the Pico was part
  # of the production ceremony, when the standing rule is that a Pico NEVER holds a real key.
  # Provision the staging device in its own run with a throwaway seed. (PLAN.md 3.4)
# Edit in place. The wizard reads it but never echoes the values.
EOF
    chmod 600 "$pfile"
    show "\${EDITOR:-nano} '$pfile'"
    ask "open the editor?" && "${EDITOR:-nano}" "$pfile"
  fi
  [ -s "$pfile" ] || { err "PIN file is empty — aborting before any PIN-credentialed step."; return 1; }

  # Source the file into the workdir vars. The vars are local to this fn — they do not leak into
  # the app tier or any subprocess beyond the tier-0 payload step.
  failing_keys=""
  while IFS='=' read -r k v; do
    case "$k" in
      hsm_a_user_pin|hsm_a_so_pin|hsm_b_user_pin|hsm_b_so_pin|\
      yubikey_piv_pin|yubikey_piv_puk|yubikey_mgmt_key)
        fail_ceremony_default_pin "$k" "$v" || failing_keys="$failing_keys $k"
        eval "$k=\$v"
        ;;
    esac
  done < "$pfile"
  if [ -n "$failing_keys" ]; then
    err "One or more PIN fields failed the dev-default guard. Aborting:"
    for k in $failing_keys; do err "  - $k"; done
    return 1
  fi
  check_credential_separation || return 1
  # Mark steps 7 (and 9, which loads the keys into a serializer) as "needs step 0 first".
  state_step0_done=1
  info "PIN file loaded. Tier-0 payload steps will use these values, not the template."
  info "The file is removed when the workdir is shredded on exit."
}

step_payload() {
  # Step-0 gate — refuse to start the tier-0 payload unless the operator has loaded real PINs
  # via the menu's step 0. In PROD mode step 0's default-PIN guard already failed-fast on the
  # dev fixtures; this catches the DEV-mode case where the operator is intentionally running with
  # defaults but never actually filled a real values file. The same flag is set by step_set_pins
  # so either mode flips the gate.
  if [ "${state_step0_done:-0}" != 1 ]; then
    err "This step requires PIN defaults loaded from a file. Run step 0 (set HSM PINs) first."
    err "It is a fast, fail-closed step that produces zero secrets and only protects step 7 from"
    err "shipping the docs' example PINs to a token that holds real funds."
    return 1
  fi
  b "Tier-0 recovery payload — encrypt, then emit archival QR codes"
  # WHAT THIS IS FOR: the Shamir shares reconstruct ONE secret. The platform needs many, and
  # most of them ROTATE — vault.sops.yaml holds ~45 and the workflows ~59. Stamping those onto
  # metal and sealed discs would guarantee a stale archive that hands a future recoverer dead
  # credentials. So this payload carries ONLY the roots that never rotate, and everything else
  # is recovered THROUGH them: the breakglass age key decrypts vault.sops.yaml straight from
  # git, so those 45 stay current without ever being archived.
  #
  # NO NEW KEY, NO CIRCULARITY: the payload is encrypted TO the breakglass age RECIPIENT, whose
  # SECRET key step_shamir already splits 4-of-6. One threshold opens both the vault and this
  # payload. The payload therefore must NOT contain the breakglass secret key itself — that is
  # what the Shamir shares are for, and a copy in here would be a key locked inside its own box.
  info "Contents (non-rotating roots only — everything else recovers through the age key):"
  info "  both wallet mnemonics · ops age key · API_KEY_HASH_SECRET"
  info "  HSM User/SO PINs (per device) · SLE-4442 PSC · YubiKey PIV PIN/PUK/mgmt key"
  warn "Do NOT put the BREAKGLASS age secret key in here — it is the key that OPENS this file."
  warn "Do NOT put rotating credentials in here — they will be wrong within months and a"
  warn "recoverer cannot tell a stale value from a live one."

  local recip="${BREAKGLASS_RECIPIENT:-}"
  if [ -z "$recip" ]; then
    # The RECIPIENT is a public key — safe to read at the terminal, unlike anything else here.
    read -r -p "   breakglass age RECIPIENT (age1…): " recip
  fi
  # Validate STRICTLY, not just the prefix. $recip is interpolated into a command string that
  # run() executes with eval; a value containing a quote or shell metacharacter would break the
  # quoting and could inject. A real age recipient is bech32: age1 + [0-9a-z] only, so anything
  # outside that alphabet is either a paste accident or an attack, and both must stop here.
  # ORDER MATTERS: diagnose the most specific mistake first. A pasted SECRET key is the
  # dangerous, plausible slip and deserves its own explicit warning; falling through to the
  # generic bech32 message would technically still refuse, but would lose the one instruction
  # the operator most needs to see.
  case "$recip" in
    AGE-SECRET-KEY-1*|age-secret-key-1*)
       err "that is not an age recipient (must start with 'age1'). If you pasted a SECRET key"
       err "(AGE-SECRET-KEY-1…) STOP: encrypting to a secret key is not possible, and the secret"
       err "key must never be typed at a terminal that may be recorded."; return 1;;
    age1*[!0-9a-z]*|*[!0-9a-z]*)
       err "that is not an age recipient: it contains characters outside bech32 ([0-9a-z])."
       err "Refusing: this value is executed inside a quoted command string, so whitespace,"
       err "quotes or shell metacharacters could break quoting or inject a command."
       return 1;;
    age1*) : ;;
    *) err "that is not an age recipient (must start with 'age1'). If you pasted a SECRET key"
       err "(AGE-SECRET-KEY-1…) STOP: encrypting to a secret key is not possible, and the secret"
       err "key must never be typed at a terminal that may be recorded."; return 1;;
  esac

  local plain="$WORK/payload.txt" enc="$WORK/payload.age" qrdir="$WORK/payload-qr"
  if [ ! -s "$plain" ]; then
    # Template with EMPTY values: the operator fills it in the editor, inside the RAM workdir,
    # so no value ever reaches argv, the shell history, or this script's output. The seven HSM
    # PIN fields are PRE-FILLED from step 0 (the operator's PIN file) so the operator does NOT
    # edit those lines — they are the dev-default footgun, and shipping them to a real Nitrokey by
    # accident is the failure mode this whole step prevents. The operator edits only the four
    # recovery-root lines.
    cat > "$plain" <<TPL
# EXAMPLE SERVICE — TIER-0 RECOVERY ROOTS
# Fill in the four values below. Delete any line you are not using. NEVER add the breakglass
# age SECRET key (it is what decrypts this file) or any credential that rotates.
# The HSM PIN fields below are pre-populated from step 0; do NOT edit them.
derivation_wallet_mnemonic_v2:
funding_wallet_mnemonic_v2:
ops_age_key:
API_KEY_HASH_SECRET:
hsm_a_user_pin: ${hsm_a_user_pin-}
hsm_a_so_pin: ${hsm_a_so_pin-}
hsm_b_user_pin: ${hsm_b_user_pin-}
hsm_b_so_pin: ${hsm_b_so_pin-}
sle4442_psc:
yubikey_piv_pin: ${yubikey_piv_pin-}
yubikey_piv_puk: ${yubikey_piv_puk-}
yubikey_mgmt_key: ${yubikey_mgmt_key-}
TPL
    chmod 600 "$plain"
    info "Template written to $plain (RAM only). The seven HSM PIN fields are pre-populated"
    info "from step 0. Fill in the four recovery-root lines above the PIN block:"
    info "  derivation_wallet_mnemonic_v2, funding_wallet_mnemonic_v2, ops_age_key, API_KEY_HASH_SECRET"
    show "\${EDITOR:-nano} '$plain'"
    ask "open the editor?" && "${EDITOR:-nano}" "$plain"
  fi
  [ -s "$plain" ] || { err "payload is empty — nothing to archive."; return 1; }

  # FAIL CLOSED on an unfilled template. A payload of bare labels with no values encrypts and
  # prints perfectly, and the mistake only surfaces at recovery when it is far too late.
  if ! grep -qE '^[a-zA-Z_0-9]+:[[:space:]]*[^[:space:]]' "$plain"; then
    err "no filled-in values found in $plain — every line is still an empty label."
    err "Refusing to archive an empty payload that would look valid until recovery day."
    return 1
  fi
  # Refuse the one value that must never be in here. A breakglass secret key inside a file
  # encrypted TO that same key is unrecoverable by construction.
  if grep -q 'AGE-SECRET-KEY-1' "$plain" && [ "${PAYLOAD_ALLOW_AGE_SECRET:-0}" != 1 ]; then
    warn "an AGE-SECRET-KEY-1… value is present in the payload."
    warn "If that is the BREAKGLASS key, STOP — it would be locked inside the file it opens."
    warn "If it is the OPS key (a different key), that is intended and safe."
    ask "is it the OPS key (NOT breakglass)?" || { err "aborting — remove the breakglass key."; return 1; }
  fi

  run "age -a -r '$recip' -o '$enc' '$plain'" \
    || { err "encryption failed or was skipped — nothing was archived."; return 1; }
  [ -s "$enc" ] || { err "age produced an empty file — do NOT proceed."; return 1; }

  run "python3 '$HERE/payload-qr.py' --split '$enc' --outdir '$qrdir'" \
    || { err "QR emission failed — the payload has no paper copy."; return 1; }

  # ROUND-TRIP PROOF. An encrypted payload nobody has ever decrypted is not a backup. If the
  # operator has the breakglass identity to hand (dry run, or the reconstructed key during a
  # drill), prove the whole chain rebuilds the exact plaintext before anything is printed.
  if [ -s "$WORK/breakglass.key" ]; then
    info "Verifying the full chain: QR chunks -> payload.age -> decrypt -> original…"
    if python3 "$HERE/payload-qr.py" --join "$qrdir/chunks.txt" --out "$WORK/rebuilt.age" >/dev/null 2>&1 \
       && age -d -i "$WORK/breakglass.key" "$WORK/rebuilt.age" > "$WORK/rebuilt.txt" 2>/dev/null \
       && cmp -s "$plain" "$WORK/rebuilt.txt"; then
      info "   ROUND-TRIP PROVEN — the QR codes rebuild and decrypt to the exact payload."
      rm -f "$WORK/rebuilt.age" "$WORK/rebuilt.txt"
    else
      err "ROUND-TRIP FAILED — the emitted QR codes did NOT rebuild+decrypt to the payload."
      err "Do NOT print or distribute these sheets. Investigate before proceeding."
      rm -f "$WORK/rebuilt.age" "$WORK/rebuilt.txt"
      return 1
    fi
  else
    warn "no $WORK/breakglass.key present — emitted WITHOUT a decrypt round-trip proof."
    warn "Before trusting these sheets, prove one: reconstruct the key from 4 shares, then"
    warn "  payload-qr.py --join payload-qr/chunks.txt --out r.age && age -d -i key r.age"
  fi

  info "QR symbols + INSTRUCTIONS.txt are in $qrdir"
  warn "PRINT the symbols AND INSTRUCTIONS.txt on archival (cotton rag) stock with the LASER"
  warn "printer — toner is fused plastic, inkjet dye fades and runs. Store the sheets FLAT:"
  warn "toner cracks along a fold, and a fold through a symbol is the realistic failure mode."
  warn "The M-DISC gets payload.age itself (step 4); the chip cards get a SHARE, not this"
  warn "payload — an SLE-4442 holds 256 bytes and this file is several times that."
  if [ -n "$PRINTER" ] && ask "print the QR sheet (INSTRUCTIONS.txt + every symbol) to $PRINTER now?"; then
    run "lp -d '$PRINTER' '$qrdir/INSTRUCTIONS.txt' '$qrdir'/qr-*.png" \
      || warn "printing failed — print $qrdir/INSTRUCTIONS.txt and $qrdir/qr-*.png yourself"
  fi
  # SCAN-BACK: the checks above prove the PNG files; the sheet is what survives. A printer that
  # scales, crops or drops a page produces paper that looks right and rebuilds nothing.
  local _sb=0; scan_back_payload "$enc" || _sb=$?
  case "$_sb" in
    0) info "   the PRINTED sheet rebuilds payload.age byte-for-byte." ;;
    2) warn "the printed sheet was NOT scanned back; it is unproven until it is." ;;
    *) err "the printed sheet does NOT rebuild payload.age — reprint and scan again before relying on it."; return 1 ;;
  esac
  info "Payload archived. $enc will be shredded with the workdir on exit."
}

# Read the user-PIN retry counter from sc-hsm-tool's info block. Returns "?" when it cannot be
# determined — deliberately NOT 0 or 3, because a guessed counter in an error message is worse than
# an honest unknown. NOTE (PLAN.md 1.3): the true default is UNRECONCILED — Nitrokey's factsheet
# says the device locks after 15 attempts, OpenSC documents 3. This reads what the card reports.
hsm_pin_tries_left() {
  local out n
  out="$(perl -e 'alarm 20; exec @ARGV' -- sc-hsm-tool 2>/dev/null)" || { echo "?"; return 0; }
  n="$(printf '%s' "$out" | grep -oiE 'user PIN tries left[^0-9]*[0-9]+' | grep -oE '[0-9]+$' | head -1)"
  # The fallback lives HERE, not at the call sites: a caller that forgets `|| echo "?"` would
  # otherwise print an empty string into an error message, which reads as "0 tries left".
  [ -n "$n" ] && echo "$n" || echo "?"
}

# shellcheck disable=SC2120  # the parameter is OPTIONAL (the mnemonic file, defaulted to $WORK/funding.mnemonic); the menu calls this with none, which is the intended path
step_hsm_import() {
  b "Import the seed-derived funding key into the HSM (supported custody path)"
  # THE POINT: the key is derived FROM the seed that lives 4-of-6 on metal, so the HSM protects
  # it in operation without ever becoming part of the recovery path. Lose every device and the
  # cost is an import, not the funds — which is the property born-in-HSM cannot give.
  #
  # OpenSC CANNOT do this import (sc_hsm_store_key is a stub returning SC_ERROR_NOT_SUPPORTED,
  # and Nitrokey state pkcs15-init is unsupported on this card). The documented path is a
  # PKCS#12 container imported under a DKEK via CardContact's Smart Card Shell:
  #   docs.nitrokey.com/nitrokeys/features/hsm/import-keys-certs
  # So this step builds and verifies the container, then hands off to scsh. The card-side import
  # is driven by the operator; everything either side of it is checked here.
  #
  # PROVEN ON A PICO, NOT ON A NITROKEY — and the gate stays shut for that reason, not the old one.
  #
  # The previous text here said secp256k1 import was "not yet proven on hardware". That is no
  # longer true: it was proven on 2026-07-29 on a Pico HSM (firmware 6.6), and the long-standing
  # SW=6400 turned out to be a zero-valued DKEK in our own hsm-auto-import.js rather than a card or
  # curve limitation (#573). Leaving the old wording in place was actively harmful: an operator who
  # read "not proven on hardware", repeated the Pico drill, and saw it pass would reasonably
  # conclude the gate's condition was satisfied — and open it for REAL custody on the strength of a
  # different device's firmware.
  #
  # The Pico is an open-source reimplementation. The Nitrokey HSM 2 runs NXP firmware: a separate
  # implementation of the same spec, which is exactly the kind of difference that has already
  # bitten us once here (the ATR/THSM1 check we believed distinguished the two devices does not).
  # So the remaining condition is narrow and specific: repeat the drill on a SCRATCH Nitrokey.
  if [ "${CEREMONY_ALLOW_HSM_IMPORT:-0}" != 1 ]; then
    err "HSM key import is proven on a PICO (2026-07-29) but NOT on a Nitrokey — gate is shut."
    err "The Nitrokey runs different (NXP) firmware; a Pico pass does not carry over to it."
    err "Prove it on a SCRATCH Nitrokey with a THROWAWAY key (no funds): derive a scratch"
    err "mnemonic, build a container, import it via scsh, then confirm the card reports the SAME"
    err "address. When THAT passes, re-run with CEREMONY_ALLOW_HSM_IMPORT=1."
    return 1
  fi

  command -v openssl >/dev/null || { err "openssl missing — cannot build the PKCS#12 container"; return 1; }
  local mfile="${1:-$WORK/funding.mnemonic}"
  if [ ! -s "$mfile" ]; then
    err "no mnemonic at $mfile. Run step 3 option (c) first, or place the recovered mnemonic"
    err "there. It is read from a FILE, never argv — argv leaks to ps and shell history."
    return 1
  fi

  # Container password: random, generated here, never typed and never shown. It protects the
  # PKCS#12 only between this step and the import, and both live in the RAM workdir.
  local pwfile="$WORK/p12.pw" p12="$WORK/funding.p12"
  [ -s "$pwfile" ] || { head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$pwfile"; chmod 600 "$pwfile"; }

  local derived
  derived="$(python3 "$HERE/seed-to-pkcs12.py" --mnemonic-file "$mfile" \
               --password-file "$pwfile" --out "$p12" 2>&1 | tee /dev/stderr \
               | grep -oE 'akash1[a-z0-9]+' | head -1)"
  [ -s "$p12" ] || { err "no PKCS#12 container was produced — aborting."; return 1; }
  [ -n "$derived" ] || { err "could not determine the derived address — aborting before import."; return 1; }
  info "Derived funding address: $derived"

  # THE PROCEDURE IS DESTRUCTIVE. Nitrokey's documented import flow includes "Initialize device"
  # to establish the DKEK domain, and they state plainly that the target must be treated as
  # scratch because its contents are ERASED. An operator who points this step at an in-service
  # card — the off-site clone, say — destroys a working key by following the instructions. The
  # guard probes the device ABOUT to be wiped and fails closed if it cannot enumerate it, so an
  # unreadable card is never mistaken for an empty one.
  warn "The documented SCSH import procedure INITIALISES (ERASES) the target device — Nitrokey:"
  warn "\"ensure nothing on the used Nitrokey HSM 2 is needed, it will be erased during the"
  warn "procedure\". Use a SCRATCH device, never one already in service."
  # ONE LABEL AND ONE DEVICE, DECIDED HERE AND USED EVERYWHERE BELOW. The import, the blank
  # check, the ATR fingerprint, the read-back and the sign proof must all name the same key on the
  # same card. A custom HSM_KEY_LABEL that reached only the importer would import successfully and
  # then fail both proofs against the literal 'akash-funding'; a non-default HSM_SLOT that reached
  # only the importer would write to one card while the guards inspected another — which is the
  # hazard test-fleet-device-selection.sh exists for, arriving from the other direction.
  local klabel="${HSM_KEY_LABEL:-akash-funding}"
  local reader="${HSM_READER:-0}"
  local p11sel=()
  [ -n "${HSM_SLOT:-}" ] && p11sel=(--slot "$HSM_SLOT")
  assert_expected_device "the import target" THSM1 "$reader" || return 1
  assert_hsm_blank "the import target" "pkcs11-tool ${p11sel[*]}" || {
    err "Refusing to import: the target already holds a funding key and the procedure would ERASE it."
    return 1
  }
  warn "The device must hold a DKEK domain — the SmartCard-HSM supports ONLY encrypted import."
  warn "Under this custody model the DKEK is just transport: losing it costs a re-import from"
  warn "the seed, not the funds."

  # THE IMPORT IS DRIVEN HERE NOW, WITH NO JVM (regalia#486). This step used to print
  # "scsh3gui # Key Manager -> Import from PKCS#12" and hand the card-side work to an operator
  # driving a Java GUI — which is why the ceremony image was expected to carry a JRE and an
  # unsigned vendor zip on the machine that mints keys. hsm-import-key-nojvm.sh does the same two
  # APDUs directly (UNWRAP KEY, then the PKCS#15 description) and writes the certificate with
  # pkcs11-tool, so nothing Java-shaped is needed on this host at all.
  #
  # The DKEK's password is RECONSTRUCTED from the share file, never typed: --create-dkek-share
  # --pwd-shares-threshold/-total generates it, splits it, and prints only the shares. Verified on
  # DENK0404144 (2026-09-21): a password rebuilt from shares 2,4,5,6 produced the same key check
  # value the card reported after being fed shares 1,2,3,4 — EDE4B653C8280D28.
  # HSM_IMPORTER exists so the emulator suite can model the import the way it already models the
  # card, and — more to the point — so it can ASSERT the import was attempted. Before this step
  # drove the import, test-hsm-import-step.sh could not tell whether one had happened at all; it
  # placed a key on a modelled card out of band and checked the proofs. A seam that is only a
  # default is not a weakening: an operator who can set this variable can edit this file.
  local importer="${HSM_IMPORTER:-$HERE/hsm-import-key-nojvm.sh}"
  if [ ! -r "$importer" ]; then
    err "hsm-import-key-nojvm.sh is missing next to this script — cannot import without it."
    err "Do NOT fall back to Smart Card Shell here: this image is not built to carry a JRE."
    return 1
  fi
  local shares="$WORK/dkek-shares.txt" pbe="$WORK/dkek.pbe" pinf="$WORK/hsm-user.pin"
  for f in "$pbe" "$shares"; do
    [ -s "$f" ] || { err "no $f — run the DKEK step first; the import has nothing to wrap under."; return 1; }
  done
  # The user PIN reaches the importer as a FILE, never argv: argv leaks to ps and shell history.
  [ -s "$pinf" ] || { ( umask 077; printf '%s' "${HSM_USER_PIN:-}" > "$pinf" ); }
  [ -s "$pinf" ] || { err "no HSM user PIN available for the import (set HSM_USER_PIN)"; return 1; }
  info "Importing the container onto the card (no Smart Card Shell, no JRE)…"
  if ! "$importer" --p12 "$p12" --pw-file "$pwfile" --id "${HSM_KEY_ID:-1}" \
        --label "$klabel" \
        --dkek "$pbe" --dkek-shares "$shares" \
        ${HSM_DKEK_SHARES_USE:+--dkek-shares-use "$HSM_DKEK_SHARES_USE"} \
        --pin-file "$pinf" --reader "$reader" ${HSM_SLOT:+--slot "$HSM_SLOT"}; then
    err "the import failed — see the status words above. The card was NOT left with a usable key."
    return 1
  fi
  info "Nitrokey's own post-import check lists the object; this step then proves it cryptographically:"
  show "pkcs15-tool -D"

  # ADDRESS-MATCH PROOF — the whole reason this step exists. An import that lands a DIFFERENT
  # key produces a DIFFERENT address; funding that address loses the money to a key nobody can
  # reconstruct. The card's own public key is the authority, so read it back and compare.
  info "Verifying the CARD now holds the seed's key…"
  run "pkcs11-tool ${p11sel[*]} --read-object --type pubkey --label '$klabel' -o '$WORK/imported-pub.der'" \
    || { err "could not read the imported public key from the card — import unproven."; return 1; }
  [ -s "$WORK/imported-pub.der" ] || { err "empty public key read from the card — do NOT fund."; return 1; }
  local oncard
  oncard="$(python3 "$HERE/derive-akash-address.py" --der "$WORK/imported-pub.der" 2>/dev/null || true)"
  if [ -z "$oncard" ]; then
    err "could not derive an address from the card's public key — import unproven; do NOT fund."
    return 1
  fi
  if [ "$oncard" != "$derived" ]; then
    err "ADDRESS MISMATCH — the card holds a DIFFERENT key than the seed derives."
    err "  seed derives : $derived"
    err "  card reports : $oncard"
    err "Funding either address risks losing the money to a key you cannot reconstruct."
    err "Delete the imported object and investigate before doing anything else. Do NOT fund."
    return 1
  fi
  info "   ADDRESS MATCH — the card holds exactly the key the seed derives ($oncard)."

  # SIGN-AND-VERIFY — an address match proves the PUBLIC key arrived; it does not prove the card
  # can USE the private half. A faulty import can leave an object that reads back correctly and
  # cannot sign. Same reasoning as the born-in-HSM keypair-control proof.
  info "Proving the card can SIGN with the imported key…"
  head -c 32 /dev/urandom > "$WORK/imp.digest" && chmod 600 "$WORK/imp.digest"
  local proven=0
  if run "pkcs11-tool ${p11sel[*]} --login --sign --label '$klabel' -m ECDSA -i '$WORK/imp.digest' -o '$WORK/imp.sig'" \
     && [ -s "$WORK/imp.sig" ] \
     && python3 "$HERE/verify-hsm-control.py" --der "$WORK/imported-pub.der" \
          --digest "$WORK/imp.digest" --sig "$WORK/imp.sig" >/dev/null 2>&1; then
    proven=1
  fi
  rm -f "$WORK/imp.digest" "$WORK/imp.sig" 2>/dev/null
  if [ "$proven" != 1 ]; then
    err "SIGN PROOF FAILED — the card did not produce a verifiable signature with the imported"
    err "key. The object exists but is unusable; do NOT fund $derived until this passes."
    return 1
  fi
  info "   SIGN PROOF PASSED — the card controls the imported private key."

  # ---- PIN-BINDING PROOF (PLAN.md 3.1) --------------------------------------------------------
  # THE GAP THIS CLOSES. Two PIN values exist and NOTHING connected them:
  #   escrow: pins.env -> hsm_a_user_pin -> the tier-0 payload -> 4-of-6 metal shares
  #   card:   whatever the operator typed into Smart Card Shell during initialisation
  # fail_ceremony_default_pin() guards the ESCROW value only. So a ceremony could pass every guard,
  # engrave a strong PIN onto metal, and rack a card that answers to something else entirely.
  #
  # The failure is silent and DELAYED BY YEARS. A custodian recovers the payload, reads the PIN,
  # presents it to the card — and it is wrong. They now have two attempts left, no idea why, and no
  # way to derive the real value. The seed still recovers the KEY, but the deployed card is bricked
  # by its own escrow.
  #
  # So: present the escrowed PIN NOW, while the operator is standing here and both values are
  # known. This is a POSITIVE control — it proves the escrowed secret opens this card, which is a
  # different claim from "a PIN was written down".
  #
  # ON THE COST OF BEING WRONG: a failed attempt consumes one of the card's tries. That is the
  # point. Spending one attempt here, with the operator present and the correct value recoverable,
  # is strictly better than spending one years from now with no context. A SUCCESSFUL
  # authentication resets the counter, so the correct case costs nothing.
  if [ -n "${hsm_a_user_pin:-}" ]; then
    info "Proving the ESCROWED PIN actually opens this card…"
    local tries_before; tries_before="$(hsm_pin_tries_left 2>/dev/null || echo "?")"
    if pkcs11-tool --login --pin "$hsm_a_user_pin" --list-objects >/dev/null 2>&1; then
      info "   PIN BINDING PROVEN — the PIN going onto metal is the PIN this card answers to."
    else
      local tries_after; tries_after="$(hsm_pin_tries_left 2>/dev/null || echo "?")"
      err "PIN BINDING FAILED — the escrowed PIN does NOT open this card."
      err "  escrowed as : hsm_a_user_pin (already destined for the tier-0 payload and metal)"
      err "  card answers : something else — whatever was typed during scsh initialisation"
      err "  PIN tries    : $tries_before -> $tries_after (one attempt was consumed proving this)"
      err ""
      err "FIX IT NOW, while both values are still known. Either change the card PIN to the"
      err "escrowed value, or correct pins.env and re-run step 0 so the escrow matches the card."
      err "Do NOT proceed: engraving a PIN that does not open the card produces a device that is"
      err "bricked by its own backup, and nobody discovers it until recovery day."
      return 1
    fi
  else
    warn "hsm_a_user_pin is unset — the PIN-BINDING PROOF was SKIPPED, not passed."
    warn "Run step 0 first. Without it, nothing has checked that the PIN you are about to escrow"
    warn "is the PIN this card answers to, and that mismatch surfaces only at recovery."
  fi

  info "IMPORT COMPLETE AND PROVEN. Address: $derived"
  warn "Shred the container and its password now — they are a plaintext copy of the funding key:"
  show "shred -u '$p12' '$pwfile'"
  warn "(They are in the RAM workdir and go on exit, but do not leave them lying there mid-ceremony.)"
}

# shellcheck disable=SC2120  # the parameter is OPTIONAL (the share to write, defaulted to empty and prompted for); the menu calls this with none, which is the intended path
step_chipcard() {
  b "Write a SLIP-39 share to an SLE-4442 chip card"
  # WHY A SHARE AND NOT THE PAYLOAD: an SLE-4442 has 256 bytes of main memory. A realistic
  # encrypted Tier-0 payload is ~1.4 KB — it does not fit, by more than 5x. The card carries
  # ONE share (~140 bytes), the same thing the metal plate carries; the payload lives on the
  # M-DISC and the paper QR sheets. This is a hardware limit, not a preference.
  #
  # THE IRREVERSIBLE RISK: the PSC error counter allows THREE wrong attempts, then the card is
  # permanently locked and can never store or return anything. A write spends an attempt if the
  # PSC is wrong, so check how many are left BEFORE spending one — the same reasoning as the
  # HSM PIN-retry gate, for a card with no unblock path at all.
  command -v sle4442-manager >/dev/null || { err "sle4442-manager not on PATH"; return 1; }

  local share="${1:-}"
  if [ -z "$share" ]; then
    info "Available share files in the workdir:"
    ls -1 "$WORK"/w[0-9]* 2>/dev/null | sed 's/^/     /' || info "     (none — run step 3 first)"
    read -r -p "   path to the share file to store: " share
  fi
  [ -s "$share" ] || { err "share file '$share' is missing or empty"; return 1; }

  local nbytes; nbytes=$(wc -c < "$share" | tr -d ' ')
  # 224, not 256: bytes 0..31 are the card's factory area (its reset header and manufacturer
  # data, usually write-protected), so the share is stored from byte 32.
  if [ "$nbytes" -gt 224 ]; then
    err "that file is $nbytes bytes; an SLE-4442 holds 224 writable bytes (256 minus its 32-byte"
    err "factory area). A share fits (~140 B) — an encrypted payload does not. Put the payload on"
    err "the M-DISC and the QR sheets instead."
    return 1
  fi
  info "share is $nbytes bytes — fits in the card's 224 writable bytes (from byte 32)."

  # PSC off-argv, always: a PSC on the command line lands in ps, /proc/<pid>/cmdline and the
  # shell history, and it is the only thing standing between a found card and its share.
  local pscfile="$WORK/sle4442.psc"
  if [ ! -s "$pscfile" ]; then
    warn "No $pscfile found. Write the card's PSC there (no trailing newline), e.g.:"
    show "printf 'FFFFFF' > '$pscfile' && chmod 600 '$pscfile'"
    warn "The PSC guards WRITES only: an SLE-4442 can always be READ, so whoever holds this card"
    warn "holds the share, exactly like the paper and metal copies — its protection is the sealed"
    warn "case. FFFFFF is the FACTORY PSC: change it so the share cannot be overwritten or erased."
    ask "continue with the PSC file as-is?" || return 1
    [ -s "$pscfile" ] || { err "no PSC file — refusing to guess (a wrong guess burns one of three attempts)."; return 1; }
  fi

  # NEAR-LOCK GATE. `info` prints the error counter and deliberately does NOT print memory
  # contents, so it is safe to run and show. Two attempts left is already a warning; one means
  # a single slip destroys the card and whatever it holds.
  local infout attempts
  # On failure show the manager's own last line (which reader, mute card, no SLE-4442 found).
  # Safe to print: `info` never outputs card memory.
  infout="$(sle4442-manager info 2>&1)" || {
    err "could not read the card: $(printf '%s\n' "$infout" | tail -1)"
    err "Is it inserted chip-up and is pcscd running? With several readers attached, set"
    err "SLE4442_READER to a substring of the chip-card reader's name."
    return 1; }
  printf '%s\n' "$infout" | sed 's/^/     /'
  attempts="$(printf '%s\n' "$infout" | grep -oE '\(([0-9]+) PSC attempts left\)' | grep -oE '[0-9]+' | head -1)"
  case "${attempts:-}" in
    ''|*[!0-9]*) warn "could not read the PSC attempt counter — confirm it manually before writing.";;
    0) err "this card is LOCKED (0 PSC attempts left). It can never store or return data. Use another card."; return 1;;
    1) err "only ONE PSC attempt left — a single wrong PSC permanently destroys this card and any"
       err "share on it. Use a fresh card, or verify the PSC on a scratch card first."; return 1;;
    2) warn "only 2 PSC attempts left — enter carefully; 3 wrong in total locks the card forever.";;
    *) info "PSC attempts left: $attempts";;
  esac

  # `store` verify-reads the bytes back and compares INTERNALLY, failing loudly on a mismatch,
  # and never echoes the payload. Do NOT follow this with `sle4442-manager read` to "confirm" —
  # that subcommand PRINTS the stored bytes, which would put the share on the terminal.
  run "sle4442-manager store --addr 32 --text-file '$share' --psc-file '$pscfile'" \
    || { err "store failed or was skipped — the card does NOT hold the share."; \
         err "If the PSC was wrong, one of the three attempts has been spent."; return 1; }
  info "Share stored AND verify-read back by the card (a write that ACKs but does not persist"
  info "is caught there — the status word alone is never treated as success)."
  warn "Seal this card with its case. Do NOT run 'sle4442-manager read' to double-check: that"
  warn "prints the share to the terminal. The store already proved the bytes are on the card."
}

step_archive() {
  b "Archive to M-DISC (burn, then read every file back and checksum it)"
  info "One writer is enough (ADR-0002 D9): burn, push the tray shut, read the disc back and"
  info "check every file against the manifest. If a second drive is attached it is used for the"
  info "readback instead, which also catches a disc only the burning drive can read."
  warn "Confirm the drive is M-DISC capable (DVD M-DISC is written like DVD+R by most burners;"
  warn "check the M-DISC logo/firmware). DVD M-DISC ≈ 4.7 GB — far more than any key/shares need."
  warn "SD cards / USB flash are NOT archival (charge leaks over years) — use M-DISC + paper only."
  # Stage a DEDICATED burn directory so the disc carries ONLY non-secret / encrypted
  # artifacts — NEVER the plaintext Shamir shares (w*, slip39.txt, secret.in, shares.txt,
  # sh*) or their print_share() text/QR (*.txt / *.png) that step 3 leaves loose in $WORK.
  # Those shares live ONLY on paper/metal; burning $WORK wholesale would permanently commit
  # the plaintext secret to archival media. We copy an explicit allowlist into $burn and
  # burn $burn — not $WORK.
  local burn="$WORK/mdisc"; rm -rf "$burn"; mkdir -p "$burn"
  # Stage the SELF-CONTAINED recovery kit so each M-DISC carries the runbooks + toolkit
  # (a recoverer must not need the repo or a network). Best-effort across image/repo layouts.
  local sdir; sdir="$HERE"; local kit="$burn/recovery-kit"; mkdir -p "$kit"
  cp -r "$sdir/recovery" "$kit/" 2>/dev/null || cp -r "$sdir/../recovery" "$kit/" 2>/dev/null || true
  cp "$sdir"/*.py "$sdir"/*.sh "$kit/" 2>/dev/null || true
  # sle4442-manager has no extension, so the globs above miss it; a recoverer reading a share off
  # a chip card needs it as much as the rest of the toolkit.
  cp "$sdir/sle4442-manager" "$kit/" 2>/dev/null || true
  cp "$sdir/requirements.txt" "$kit/" 2>/dev/null || cp "$sdir/../requirements.txt" "$kit/" 2>/dev/null || true
  # Stage the HASH-PINNED wheels (shamir-mnemonic + mnemonic + their deps) so the
  # CLEAN-MACHINE / Tails recovery path RECOVERY-TECHNICAL.md endorses works with NO network:
  #   pip install --no-index --find-links wheels/ --require-hashes -r requirements.txt
  # The SLIP-39 tools `import shamir_mnemonic`/`mnemonic`, whose only documented install needs
  # PyPI — without these wheels on the disc, an air-gapped recoverer cannot reconstruct the
  # seeds, defeating the self-contained M-DISC claim. The wheels are baked into the vault-tools
  # image at build time (salt/vault-tools.sls). Best-effort across image/repo layouts; an
  # operator can override the source with CEREMONY_WHEELS_DIR. Wheels are non-secret.
  local wsrc
  for wsrc in "${CEREMONY_WHEELS_DIR:-}" "$sdir/wheels" "$sdir/../wheels" /opt/vault-ceremony/wheels; do
    [ -n "$wsrc" ] && [ -d "$wsrc" ] && ls "$wsrc"/*.whl >/dev/null 2>&1 \
      && { mkdir -p "$kit/wheels" && cp "$wsrc"/*.whl "$kit/wheels/" 2>/dev/null; break; }
  done
  if ls "$kit"/wheels/*.whl >/dev/null 2>&1; then
    info "Staged offline-recovery wheels for the M-DISC (pip install --no-index --find-links wheels/)."
  else
    warn "No wheels/ staged — the CLEAN-MACHINE (Tails) recovery path will need network for the"
    warn "shamir-mnemonic/mnemonic packages. Bake wheels into the image (vault-tools.sls) or set"
    warn "CEREMONY_WHEELS_DIR to a 'pip download --require-hashes -r requirements.txt -d <dir>' tree."
  fi
  # The ENCRYPTED / public artifacts that ARE meant for the disc: the password-protected
  # DKEK share, the DKEK-wrapped private key, and the public funding pubkey. Each is safe at
  # rest on its own (the 4-of-6 DKEK password — held by custodians — is the real secret).
  # payload.age is the Tier-0 recovery payload — ciphertext under the breakglass age recipient,
  # whose secret key is the 4-of-6 Shamir split. Safe at rest exactly like the DKEK artifacts.
  # Its QR symbols are deliberately NOT burned: those are the PAPER representation of the same
  # bytes, and the stray-artifact guard below refuses every *.png precisely so a plaintext share
  # QR can never reach archival media. The disc carries the payload itself; paper carries the
  # symbols. Nothing needs the guard relaxed.
  local art; for art in dkek.pbe funding-wrapped.bin funding-pub.der payload.age; do
    [ -e "$WORK/$art" ] && cp "$WORK/$art" "$burn/" 2>/dev/null || true
  done
  if [ -e "$kit/recovery" ] || ls "$kit"/*.py >/dev/null 2>&1; then
    info "Staged recovery kit for the M-DISC (RECOVERY-START-HERE.txt + RECOVERY-TECHNICAL.md + toolkit): $kit"
  else
    warn "recovery kit not found next to the script — manually add recovery/ + scripts to the M-DISC."
  fi
  # SAFETY NET: refuse to burn if any plaintext-share artifact slipped into the burn tree.
  # The allowlist copy above should never stage one; this catches a future regression before
  # it reaches irreversible media.
  # payload.txt is the PLAINTEXT Tier-0 payload — both wallet mnemonics and every hardware PIN
  # in one file, the single highest-value artifact the ceremony ever holds. The allowlist above
  # stages only payload.age, so it should never appear here; this catches the regression that
  # would otherwise commit it to write-once media.
  local stray; stray="$(find "$burn" -type f \( -name 'w[0-9]*' -o -name 'sh[0-9]*' \
      -o -name 'slip39*.txt' -o -name 'secret.in' -o -name 'shares.txt' \
      -o -name 'payload.txt' -o -name 'mixed.hex' -o -name 'dice*.hex' \
      -o -name '*share*.txt' -o -name '*.png' \) 2>/dev/null | head -1)"
  if [ -n "$stray" ]; then
    err "plaintext share artifact staged for the burn: $stray"
    err "Shares belong on paper/metal ONLY — refusing to commit a secret to archival media."
    return 1
  fi
  warn "Also burn the SEALED custodian-contact sheet's content is NOT on the disc — it is the"
  warn "printed sheet sealed in each case (your chosen model). Keep it sealed, not on the M-DISC."
  info "Typical (review paths/devices first):"
  # Burn and verify drives. Two USB drives are /dev/sr0 + /dev/sr1. With ONE USB writer and a
  # laptop's internal bay drive, the bay belongs to dom0 and reaches this qube read-only through
  # `qvm-block`, as /dev/xvdX: set CEREMONY_VERIFY_DEV to that node. It can read, never burn.
  local bdev="${CEREMONY_BURN_DEV:-/dev/sr0}" vdev="${CEREMONY_VERIFY_DEV:-}"
  if [ -z "$vdev" ]; then
    # Any other attached optical drive, else the burning drive itself (ADR-0002 D9).
    local d
    for d in /dev/sr[0-9]*; do
      if [ -b "$d" ] && [ "$d" != "$bdev" ]; then vdev="$d"; break; fi
    done
    vdev="${vdev:-$bdev}"
  fi
  # -dvd-compat CLOSES a DVD-R/DVD+R: an open (appendable) disc reads badly in some drives, and an
  # archive disc is written once. Proven on a Verbatim AZO DVD-R, 2026-09-25: status "complete".
  show "growisofs -dvd-compat -Z $bdev -R -J '$burn'     # burn on drive A ($bdev), and close the disc"
  info "A slim USB writer ejects its tray after the burn and cannot pull it back: push it shut"
  info "(or move the disc to drive B) and wait for the drive to settle before the readback."
  case "$vdev" in
    "$bdev") info "Readback on the same drive: push the tray shut and wait for it to settle first." ;;
    /dev/sr*) : ;;
    *) info "Verify drive $vdev is a block-attached drive. Move the disc into it, then in dom0:"
       show "qvm-block attach --ro <this-qube> dom0:sr0      # the internal bay drive, READ-ONLY"
       info "and check which node appeared here (lsblk) — it must be $vdev." ;;
  esac
  show "mount -o ro $vdev /mnt && ( cd /mnt && sha256sum -c manifest.sha256 )   # verify FROM the disc ($vdev), not the source tree"
  show "d=\$(mktemp -d) && xorriso -osirrox on -indev $vdev -extract / \"\$d\" && ( cd \"\$d\" && sha256sum -c manifest.sha256 )   # same check without a kernel mount"
  info "Generate a checksum manifest of what you burn first (recurses into recovery-kit/):"
  run "( cd '$burn' && find . -type f ! -name manifest.sha256 -print0 | xargs -0 sha256sum > manifest.sha256 ) && cat '$burn/manifest.sha256'"
}

step_drill() {
  b "Recovery drill (do this BEFORE relying on any share set)"
  info "Reconstruct from exactly k shares on THIS air-gapped qube, prove it works, re-seal."
  info "ssss:        feed any 4 of the 6 share lines to:   ssss-combine -t 4 -q"
  info "SLIP-0039:   shamir recover   (paste any 4 word-shares)"
  info "age/HSM:     decrypt a sops file to /dev/null with the recovered key, or unwrap into a"
  info "             spare HSM and sign a test message. Then shred this qube."
  warn "An untested share set is not a backup. Re-drill after any redistribution."
}

step_recovery_card() {
  b "Break-glass recovery instruction card (DVD-case sized — NO secrets)"
  info "Prints the recovery PROCEDURE (how to reconstruct from the shares + M-DISC)."
  info "Cut along the dashed line; it fits inside a DVD keep-case beside the M-DISC."
  local ps="$WORK/recovery-card.ps" cid serial hsm_flag=""
  read -r -p "   case id for this case (e.g. DF-BG-01, blank=none): " cid
  read -r -p "   holographic sticker serial on this case (blank=none): " serial
  # FUNDING CUSTODY MODEL — decides whether the card prints the DKEK/unwrap restore (funding key
  # born non-exportable in the Nitrokey HSM, backed up ONLY as the DKEK-wrapped blob + dkek.pbe +
  # 4-of-6 password shares, NO SLIP-39 funding shares) or the default SLIP-39 funding-seed recovery.
  #
  # DO NOT infer this from $WORK/funding-wrapped.bin alone: $WORK is per-session tmpfs that
  # cleanup() shreds on exit, so printing this card in a SEPARATE session from step_hsm_funding
  # (or after a crash) finds no artifact and would silently emit the SEED card — sending a
  # born-in-HSM recoverer to a nonexistent funding-shares.txt / funding.mnemonic instead of the
  # sc-hsm-tool --unwrap-key restore, stranding recovery of the real custodial funds. Ask the
  # operator EXPLICITLY; a detected artifact only pre-selects the default. When the model is
  # undetermined, REFUSE to guess rather than defaulting to the seed variant.
  local detected=""
  if [ -s "$WORK/funding-wrapped.bin" ]; then
    detected=hsm
    info "HSM funding artifact detected this session (funding-wrapped.bin)."
  fi
  local model=""
  while :; do
    local ans=""
    if [ -n "$detected" ]; then
      read -r -p "   Funding custody model — hsm=born-in-HSM DKEK-restore, seed=SLIP-39 recovery [hsm/seed, Enter=$detected]: " ans || true
      ans="${ans:-$detected}"
    elif ! read -r -p "   Funding custody model — was the funding key BORN IN THE HSM (DKEK-restore) or SEED-backed (SLIP-39)? [hsm/seed]: " ans; then
      warn "no funding-custody model given — refusing to guess (a wrong card strands recovery)."
      warn "Re-run step 6 and answer 'hsm' (born-in-HSM) or 'seed' (SLIP-39 funding seed)."
      return 0
    fi
    case "$ans" in
      hsm|HSM|h|H)   model=hsm;  hsm_flag="--hsm-funding"; break;;
      seed|SEED|s|S) model=seed; hsm_flag="";             break;;
      *) warn "answer 'hsm' (funding key born in the HSM) or 'seed' (SLIP-39 funding seed) — this selects the recovery procedure printed on the card.";;
    esac
  done
  if [ "$model" = hsm ]; then
    info "card will carry the DKEK-import / sc-hsm-tool --unwrap-key restore procedure."
  else
    info "card will carry the default SLIP-39 funding-seed recovery procedure."
  fi
  show "make-recovery-card.py -o recovery-card.ps --case-id '$cid' --seal-serial '$serial' $hsm_flag"
  if python3 "$HERE/make-recovery-card.py" -o "$ps" --date "$(date +%F)" --case-id "$cid" --seal-serial "$serial" $hsm_flag >/dev/null 2>&1; then
    info "card written: $ps"
  else
    warn "card generation failed (need python3 + make-recovery-card.py)"; return 0
  fi
  if [ -n "$PRINTER" ]; then
    run "lp -d '$PRINTER' '$ps'" && info "sent recovery card to $PRINTER (cut along the dashed line)" || warn "print skipped"
  else
    warn "no printer set — print it yourself: lp -d <queue> $ps"
  fi
}

# =============================================================================
main() {
  b "Custodial-wallet key ceremony — interactive guide"
  warn "Run this on the AIR-GAPPED vault qube only. Real keys = no undo. First run = dry run."
  # MODE — the operator must type it explicitly. Default is prod (safe); typing prod again is
  # the no-op confirmation; typing dev opts OUT of the dev-default PIN guard. The mode is logged
  # so the audit trail records which mode the ceremony ran in.
  # Ask for the mode ONLY when there is a human at a terminal and the mode was not already
  # decided in the environment.
  #
  # REGRESSION GUARD: this prompt originally ran unconditionally and called `read`. Anything
  # driving main() through a pipe — the dress rehearsal does exactly that, feeding the printer
  # name then menu choices — had its FIRST line eaten by this prompt, which then saw an invalid
  # mode and returned before the menu ever rendered. A prompt must never consume stdin that was
  # not meant for it.
  if [ "${CEREMONY_MODE_EXPLICIT:-0}" = 1 ]; then
    info "CEREMONY_MODE=$CEREMONY_MODE (set in the environment; not prompting)"
  elif [ ! -t 0 ]; then
    info "CEREMONY_MODE=$CEREMONY_MODE (stdin is not a terminal; not prompting)"
  else
    printf '\n  MODE — type prod (default, fail-closed on dev-default PINs) or dev (Pico HSM devops path)\n'
    read -r -p "   mode [prod]> " mode_choice
    case "$mode_choice" in
      ""|"prod"|"p") CEREMONY_MODE="prod" ;;
      "dev"|"d") CEREMONY_MODE="dev" ;;
      *) err "unknown mode '$mode_choice' — expected prod or dev"; return 1 ;;
    esac
  fi
  info "CEREMONY_MODE=$CEREMONY_MODE (this is logged)"
  require_airgap_and_tools
  init_work
  manifest_plan || return 1
  pick_printer || true
  while true; do
    b "Choose a step"
    cat <<MENU
   0) Set HSM PIN defaults from a file (PROD: required before step 7; DEV: optional, warns)
   1) YubiKey  — hardware ops age/SOPS identity
   2) Nitrokey HSM 2 — cold funding key + DKEK 4-of-6 backup
   e) Entropy: generate a NEW wallet seed from dice + Nitrokey HSM + OS randomness (then step 3 c)
   3) Shamir split a recovery root (breakglass age key / mnemonic) + print shares
   4) Archive to M-DISC (burn + readback verify)
   7) Tier-0 recovery payload -> encrypt + archival QR codes
   8) Write a SLIP-39 share to an SLE-4442 chip card
   9) Import the seed-derived funding key into the HSM (supported custody path)
   5) Recovery drill
   6) Print break-glass recovery instruction card (DVD-case sized)
MENU
    [ -n "$CEREMONY_MANIFEST" ] && printf '   m) Manifest: generate a planned YubiKey PIV key + capture its evidence and operation proof\n'
    printf '   q) quit (workdir is shredded)\n'
    # Break on EOF (Ctrl-D, or an exhausted piped stdin) so the menu never spins forever on
    # empty reads — a non-interactive run must terminate, not hang.
    read -r -p "   > " choice || break
    case "$choice" in
      0) step_set_pins;;
      1) step_yubikey_ops;;
      2) step_hsm_funding;;
      e|E) step_entropy_seed;;
      3) step_shamir;;
      4) step_archive;;
      5) step_drill;;
      6) step_recovery_card;;
      7) step_payload;;
      8) step_chipcard;;
      9) step_hsm_import;;
      m|M) if [ -n "$CEREMONY_MANIFEST" ]; then step_manifest_yubikey; else warn "pick 1-9 or q"; fi;;
      q|Q) break;;
      *) warn "pick 1-9 or q";;
    esac
    pause
  done
  manifest_record || return 1
  b "Done — workdir shredded on exit. Seal your media, clear the printer memory, power off the qube."
}

# Run the wizard only when executed directly; sourcing (e.g. the test harness)
# loads the functions without starting the interactive menu.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
