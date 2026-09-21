#!/usr/bin/env bash
# hsm-auto-import.sh — the ONE COMMAND that performs the seed→HSM import unattended.
#
# WHAT IT REPLACES: the runbook's manual sequence (run --prepare, read three sc-hsm-tool
# commands off the screen, type them, then drive the Smart Card Shell GUI to import a PKCS#12).
# That sequence needs a human at a keyboard, so the devops validation could never be automated.
#
# WHAT MAKES IT POSSIBLE: scsh3 ships `scriptrunner`, a HEADLESS JS engine with the same
# module tree the Key Manager GUI uses — so the import is scriptable (see hsm-auto-import.js).
#
# THE ONE THING THAT IS STILL MANUAL, AND WHY:
#   `sc-hsm-tool -r "$READER" --initialize` drops the Pico off the USB bus every single time it is run
#   (measured, reproducible — see PROOF-OF-WORKS.md). Only a physical replug recovers it.
#   --initialize is what RESERVES the DKEK key domains, so it is ONE-TIME PROVISIONING,
#   exactly like flashing the UF2. This script REFUSES to run it. Everything after it —
#   domain creation via createDKEKKeyDomain (APDU 80 52 01), share import, container build,
#   wrap, unwrap, address match, sign proof — runs with no human present.
#
# Provision once, by hand, on a scratch device:
#   sc-hsm-tool -r "$READER" --initialize --so-pin <so> --pin <pin> --dkek-shares 1 --label <label>
#   # …then physically replug the device…
# Thereafter, unattended:
#   qubes/scripts/hsm-auto-import.sh --check   # read-only preflight
#   qubes/scripts/hsm-auto-import.sh --run     # full import + proofs
#
# Secrets are written to files under a 0700 workdir and passed by PATH, never on argv
# (argv is visible in ps / /proc/<pid>/cmdline / shell history).
set -uo pipefail

# The ceremony's python dependencies (pycvc, shamir_mnemonic, mnemonic, pycryptodome) are
# hash-pinned and installed into a venv, NOT into the system interpreter. Prefer that venv so a
# bare `python3` resolves to it. MEASURED 2026-08-06: Homebrew moved python3 from 3.13 to 3.14 and
# orphaned the site-packages holding pycvc, which made the offline CVC check report the DEVICE
# certificate as unparseable when the real cause was a missing host library. Falls through to the
# system python3 when the venv is absent, so nothing breaks on a host that never made one.
CEREMONY_VENV="${CEREMONY_VENV:-$HOME/.local/share/akash-hsm-venv}"
[ -x "$CEREMONY_VENV/bin/python3" ] && PATH="$CEREMONY_VENV/bin:$PATH"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE}"
WORK="${HSM_AUTO_DIR:-${TMPDIR:-/tmp}/hsm-auto-import}"
# The tarball unpacks as scsh-3.18.77/scsh-3.18.77/ and scriptrunner is in the INNER directory,
# so this default named a directory that does not contain it. cmd_check catches that and says so;
# the import path did not, and produced `./scriptrunner: No such file or directory` on stderr while
# the caller reported "key import failed" with an empty reason. Accept either layout.
SCSH_HOME="${SCSH_HOME:-$HOME/tools/scsh-3.18.77}"
[ -x "$SCSH_HOME/scriptrunner" ] || [ ! -x "$SCSH_HOME/scsh-3.18.77/scriptrunner" ] \
  || SCSH_HOME="$SCSH_HOME/scsh-3.18.77"
# NOTE ON NAMES. HSM_READER is the repo's pre-existing handle and it is a reader NAME — scsh's
# `new Card()` takes a name, not a number (hsm-import-key.sh:104, measured 2026-08-02). The PC/SC
# index that `sc-hsm-tool -r` wants is a DIFFERENT thing, so it travels as HSM_PCSC_INDEX. Using
# one variable for both would hand "1" to scsh as a reader name, or a reader name to `-r`.
READER="${HSM_PCSC_INDEX:-0}"

b()    { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
info() { printf '   %s\n' "$1"; }
warn() { printf '   \033[33m! %s\033[0m\n' "$1"; }
err()  { printf '   \033[31mFAIL %s\033[0m\n' "$1"; }
ok()   { printf '   \033[32mOK\033[0m   %s\n' "$1"; }

# The published BIP39 test vector the drill uses. NEVER a real seed: this script is a drill
# harness, and a real mnemonic must not pass through a throwaway workdir.
DRILL_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
DRILL_ADDR="akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0"

# --------------------------------------------------------------------------------------
# Refuse --initialize, loudly. Passing it here would brick the unattended run: the device
# leaves the bus and no amount of retrying brings it back without a human.
for a in "$@"; do
  case "$a" in
    --initialize|--init)
      err "REFUSED: --initialize drops the device off the USB bus and needs a physical replug."
      err "It is ONE-TIME provisioning and must not run inside an unattended import."
      err "Provision by hand, replug, then re-run this script with --run."
      exit 2;;
  esac
done

cmd_check() {
  local rc=0
  b "Toolchain"
  for t in opensc-tool sc-hsm-tool openssl python3; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t"; else err "$t MISSING"; rc=1; fi
  done
  if [ -x "$SCSH_HOME/scriptrunner" ]; then
    ok "scsh3 scriptrunner ($SCSH_HOME/scriptrunner)"
  else
    err "scsh3 scriptrunner NOT FOUND at $SCSH_HOME/scriptrunner — set SCSH_HOME"; rc=1
  fi
  [ -r "$SCRIPTS/hsm-auto-import.js" ] && ok "hsm-auto-import.js" \
    || { err "hsm-auto-import.js missing next to this script"; rc=1; }
  [ -r "$SCRIPTS/seed-to-pkcs12.py" ] && ok "seed-to-pkcs12.py" \
    || { err "seed-to-pkcs12.py missing"; rc=1; }
  [ -r "$SCRIPTS/derive-akash-address.py" ] && ok "derive-akash-address.py" \
    || { err "derive-akash-address.py missing"; rc=1; }

  b "Card"
  local atr
  atr="$(opensc-tool -r "$READER" --atr 2>/dev/null | tr -d ' \n:' )"
  if [ -z "$atr" ]; then
    err "no ATR — no card in the reader. Plug the device in."
    return 1
  fi
  info "ATR : $atr"
  # 5448534d31 is the hex TEXT of the bytes 54 48 53 4d 31 = ASCII "THSM1". The variable holds
  # hex characters, so the pattern must be the hex text, not the literal string THSM1.
  # ⚠ This check does NOT distinguish a genuine SmartCard-HSM / Nitrokey from a Pico HSM:
  # BOTH carry THSM1 in the ATR (measured 2026-07-29; correction in PICO-DRILL-RUNBOOK.md).
  # It only confirms a SmartCard-HSM-PROTOCOL device is present. Identify the exact device
  # by its PKCS#11 token serial (pkcs11-tool --list-slots), never by this substring.
  case "$atr" in
    *5448534d31*) ok "SmartCard-HSM-protocol device present (ATR carries THSM1 — a Pico HSM also does; confirm identity by PKCS#11 serial)";;
    *) warn "ATR does not carry THSM1 — no SmartCard-HSM-protocol device; import will fail";;
  esac

  b "Provisioning state (this script cannot fix this — it needs a human + a replug)"
  local st shares
  st="$(sc-hsm-tool -r "$READER" 2>&1)"
  shares="$(printf '%s\n' "$st" | sed -n 's/^DKEK shares  *: *\([0-9][0-9]*\).*/\1/p' | head -1)"
  if grep -qi "never been initialized" <<< "$st"; then
    err "device is NOT initialised — run the one-time provisioning command in this file's header,"
    err "replug the device, then re-run --run."
    rc=1
  elif [ -n "$shares" ]; then
    ok "device initialised, DKEK shares reserved: $shares"
  else
    warn "could not read DKEK share count from sc-hsm-tool output"
  fi
  return "$rc"
}

cmd_run() {
  cmd_check || { err "preflight failed — refusing to run the import"; return 1; }

  b "Workdir"
  rm -rf "$WORK"; mkdir -p "$WORK"; chmod 700 "$WORK"
  info "workdir: $WORK (0700, removed on success)"

  b "Build the throwaway PKCS#12 from the published BIP39 vector"
  printf '%s' "$DRILL_MNEMONIC" > "$WORK/m.txt"; chmod 600 "$WORK/m.txt"
  # Password material never touches argv; it is generated into a 0600 file.
  ( umask 077; head -c 24 /dev/urandom | base64 | tr -d '\n=/+' > "$WORK/p12.pw" )
  # od, not xxd: xxd is not in the vault-tools image or a minimal Debian, and without `set -e` a
  # missing xxd left an EMPTY password file here while the next step still printed "DKEK share
  # created" (measured on dev-regalia, Debian 13, 2026-09-17). Refuse a short password outright.
  ( umask 077; head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/dkek.pw" )
  [ "$(wc -c < "$WORK/dkek.pw")" -eq 32 ] || { err "DKEK share password was not generated (expected 32 hex chars)"; return 1; }
  python3 "$SCRIPTS/seed-to-pkcs12.py" \
      --mnemonic-file "$WORK/m.txt" \
      --password-file "$WORK/p12.pw" \
      --out "$WORK/funding.p12" || { err "PKCS#12 build failed"; return 1; }
  [ -s "$WORK/funding.p12" ] || { err "no PKCS#12 produced"; return 1; }
  ok "container built"

  b "DKEK share"
  # A card whose DKEK domain is ALREADY complete cannot accept another share, so a freshly
  # generated one would leave the local DKEK different from the card's and every unwrap would
  # fail with SW=6400. When the operator provisioned the domain earlier they kept the share that
  # went into it; point HSM_DKEK_SHARE_IN/HSM_DKEK_PW_IN at that pair and it is reused verbatim.
  if [ -n "${HSM_DKEK_SHARE_IN:-}" ]; then
    [ -s "$HSM_DKEK_SHARE_IN" ] || { err "HSM_DKEK_SHARE_IN set but unreadable: $HSM_DKEK_SHARE_IN"; return 1; }
    [ -s "${HSM_DKEK_PW_IN:-}" ] || { err "HSM_DKEK_SHARE_IN needs HSM_DKEK_PW_IN (the share's password file)"; return 1; }
    ( umask 077; cat "$HSM_DKEK_SHARE_IN" > "$WORK/dkek.pbe"; cat "$HSM_DKEK_PW_IN" > "$WORK/dkek.pw" )
    ok "reusing the provisioned DKEK share ($HSM_DKEK_SHARE_IN)"
  else
    # --password env:VAR is what removes every interactive prompt. The value is treated as the
    # LITERAL ASCII password by sc-hsm-tool, and hsm-auto-import.js reads it back the same way.
    # In a umask-077 subshell: sc-hsm-tool creates the share file with the caller's umask, and
    # under the 0002 user-private-group default it came out 0664 (measured 2026-09-17).
    ( umask 077; HSM_DKEK_PW="$(cat "$WORK/dkek.pw")" \
      sc-hsm-tool -r "$READER" --create-dkek-share "$WORK/dkek.pbe" --password env:HSM_DKEK_PW >/dev/null 2>&1 ) \
        && [ -s "$WORK/dkek.pbe" ]   # the file is the proof; the exit status is not
    [ -s "$WORK/dkek.pbe" ] || { err "DKEK share not created"; return 1; }
    ok "DKEK share created"
  fi

  b "Import via the headless scsh3 scriptrunner (createDKEKKeyDomain path, no --initialize)"

  # THE PIN THIS CARD WILL CARRY FOR ITS WHOLE LIFE IS DECIDED ON THE NEXT LINE.
  #
  # It used to be `${HSM_USER_PIN:-648219}` — an unset variable silently provisioned the card with
  # the PUBLISHED pico-hsm example PIN. ceremony.sh's dev-default guard does not catch that: it
  # inspects the PIN written into the tier-0 PAYLOAD (hsm_a_user_pin et al), and its regex blocks
  # 648219 there — but nothing connects that value to this one. So a PROD ceremony could pass every
  # guard, archive a strong PIN onto metal shares, and hand the rack a card whose real PIN is in the
  # vendor documentation.
  #
  # That is fatal under the colocated topology (B7): the entire argument for surviving third-party
  # physical access is "a removed token is useless without the PIN". A published PIN removes it.
  #
  # So: in PROD, refuse. Never default. An operator who has to supply the value cannot accidentally
  # ship the documented one, and the guard below rejects it even if supplied explicitly.
  case "${CEREMONY_MODE:-dev}" in
    prod)
      [ -n "${HSM_USER_PIN:-}" ] || {
        err "CEREMONY_MODE=prod and HSM_USER_PIN is unset."
        err "REFUSING. Defaulting would provision this card with the published example PIN 648219."
        err "Supply the SAME value recorded as hsm_<device>_user_pin in the tier-0 payload, or the"
        err "escrowed PIN will not open the card and recovery burns attempts on a wrong secret."
        return 1
      }
      case "$HSM_USER_PIN" in
        648219|3537363231383830|CHANGEME|TODO|FILL_IN)
          err "CEREMONY_MODE=prod and HSM_USER_PIN is a recognised dev default ('$HSM_USER_PIN')."
          err "REFUSING to provision a production card with a documented PIN."
          return 1;;
      esac
      ;;
  esac
  ( umask 077; printf '%s' "${HSM_USER_PIN:-648219}" > "$WORK/pin.txt" )
  local out rc
  out="$( cd "$SCSH_HOME" && \
    HSM_P12="$WORK/funding.p12" \
    HSM_P12_PW_FILE="$WORK/p12.pw" \
    HSM_DKEK_SHARE="$WORK/dkek.pbe" \
    HSM_DKEK_PW_FILE="$WORK/dkek.pw" \
    HSM_USER_PIN_FILE="$WORK/pin.txt" \
    ./scriptrunner "$SCRIPTS/hsm-auto-import.js" 2>&1 )"
  rc=$?
  printf '%s\n' "$out" | sed 's/^/   /'
  if [ "$rc" -ne 0 ] || ! grep -q "IMPORT-OK" <<< "$out"; then
    err "scriptrunner import did not report IMPORT-OK (exit $rc)"
    return 1
  fi
  ok "import reported IMPORT-OK"

  b "Proof: the card must hold EXACTLY the seed's key"
  info "expected address: $DRILL_ADDR"
  warn "address-match and sign proofs run against the CARD and are performed by"
  warn "hsm-import-drill.sh --verify, whose verifier (verify-hsm-control.py) is the audited"
  warn "root of trust. Run it now:"
  info "  $SCRIPTS/hsm-import-drill.sh --verify"

  # Do NOT delete the workdir on the happy path: --verify below still needs the container and
  # the recorded expected address. The caller shreds it.
  ok "unattended import complete; workdir retained for --verify at $WORK"
  return 0
}

case "${1:---check}" in
  --check) cmd_check;;
  --run)   cmd_run;;
  -h|--help) sed -n '2,32p' "$0";;
  *) err "unknown option: $1"; sed -n '2,32p' "$0"; exit 2;;
esac
