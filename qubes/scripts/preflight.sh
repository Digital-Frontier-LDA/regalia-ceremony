#!/usr/bin/env bash
# preflight.sh — read-only readiness check for a wallet key ceremony.
# Baked into the vault-tools template at /opt/vault-ceremony/preflight.sh.
# Touches NO key material. Run it on the air-gapped vault qube before any ceremony.
#
#   /opt/vault-ceremony/preflight.sh
#
# Exits non-zero if anything that would make the ceremony unsafe is wrong
# (most importantly: if this qube can reach a network).

set -uo pipefail
# The vault-tools image keeps its pinned tools in /opt/vault-bin (sops, shamir, sle4442-manager)
# and the hash-pinned Python packages in the /opt/vault-ceremony/venv interpreter. /etc/profile.d
# puts both on PATH for LOGIN shells only; the xterm a disposable opens is not one, so add them here.
for _d in /opt/vault-bin /opt/vault-ceremony/venv/bin; do
  case ":$PATH:" in *":$_d:"*) ;; *) [ -d "$_d" ] && PATH="$_d:$PATH" ;; esac
done
unset _d

fail=0
ok()   { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }

echo "== Air-gap =="
# The vault qube must have NO network path. A default route means it is NOT air-gapped.
# Fail CLOSED: if the route tool itself is missing, the `ip ... 2>/dev/null` calls below
# would emit nothing and we'd wrongly conclude "air-gapped". Demand `ip` before trusting it.
if ! command -v ip >/dev/null 2>&1; then
  bad "iproute2/'ip' is missing — cannot verify the air-gap. Install iproute2 and retry."
elif [ -n "$(ip -4 route show default 2>/dev/null)" ]; then
  bad "a default route exists — this qube has network. Set netvm to none and retry."
elif [ -n "$(ip -6 route show default 2>/dev/null)" ]; then
  bad "an IPv6 default route exists — this qube has network."
else
  ok "no default route (air-gapped)."
fi
# A live non-loopback interface carrying a global-scope address IS a network path — peers on
# the directly-connected subnet are reachable even with NO default route pushed. For a set-once,
# real-money ceremony that must FAIL CLOSED, not merely WARN. (Loopback is scope host, so a
# genuinely air-gapped qube with only `lo` has no global-scope address and passes.)
if grep -q "inet " <<< "$(command -v ip >/dev/null 2>&1 && ip -4 addr show scope global 2>/dev/null)"; then
  bad "a global-scope IPv4 address is present on a live interface — this qube has a network path (a reachable subnet) even without a default route. Set netvm to none and retry."
elif grep -q "inet6 " <<< "$(command -v ip >/dev/null 2>&1 && ip -6 addr show scope global 2>/dev/null)"; then
  bad "a global-scope IPv6 address is present on a live interface — this qube has a network path even without a default route. Set netvm to none and retry."
fi

echo "== Leak controls =="
# Swap: anonymous (and tmpfs) pages can be paged to disk and survive. For real seeds the
# vault qube must have NO swap. We can only check from inside the qube.
# In SIMULATE mode (container/CI test) the swap seen is the host/VM's — a container cannot
# swapoff it. Downgrade to WARN so the emulator suites can run; on the REAL qube (no
# CEREMONY_SIMULATE) this stays a hard FAIL. CEREMONY_SIMULATE is already the acknowledged
# test flag (it also disables guard_no_stubs), and the real ceremony never sets it.
swap_bad() {
  if [ "${CEREMONY_SIMULATE:-}" = 1 ]; then
    warn "swap is ACTIVE — cannot swapoff a container/VM's host swap in SIMULATE mode (on the real vault qube this is a hard FAIL)."
  else
    bad "$1"
  fi
}
if [ -r /proc/swaps ]; then
  if [ "$(grep -c . /proc/swaps)" -gt 1 ]; then swap_bad "swap is ACTIVE — secrets could hit disk. Run: swapoff -a (and set the qube's swap off)."
  else ok "no active swap (/proc/swaps empty)."; fi
elif command -v swapon >/dev/null 2>&1; then
  if [ -n "$(swapon --noheadings --show=NAME 2>/dev/null)" ]; then swap_bad "swap is ACTIVE — run swapoff -a."; else ok "no active swap."; fi
else
  warn "cannot determine swap state here (no /proc/swaps, no swapon) — verify swap is off on the vault qube."
fi
# /dev/shm must be a tmpfs (the ceremony workdir lives there).
if grep -qs "[[:space:]]/dev/shm[[:space:]]tmpfs[[:space:]]" /proc/mounts 2>/dev/null; then ok "/dev/shm is tmpfs (RAM workdir)."
elif [ -r /proc/mounts ]; then bad "/dev/shm is not tmpfs — the RAM workdir guarantee fails."
else warn "cannot verify /dev/shm is tmpfs here (not Linux) — it is on the vault qube."; fi
# Shell history off
if [ -n "${HISTFILE:-}" ]; then
  if [ "${CEREMONY_SIMULATE:-}" = 1 ]; then warn "HISTFILE is set ($HISTFILE) — real ceremonies fail this control."
  else bad "HISTFILE is set ($HISTFILE) — unset it before the ceremony."; fi
else ok "HISTFILE unset."; fi
# Core dumps off
cl="$(ulimit -c 2>/dev/null || echo '?')"
if [ "$cl" = 0 ]; then ok "core dumps disabled (ulimit -c 0)."
elif [ "${CEREMONY_SIMULATE:-}" = 1 ]; then warn "core dump limit is '$cl' — real ceremonies fail this control."
else bad "core dump limit is '$cl' — run ulimit -c 0 before the ceremony."; fi

echo "== Execution profile =="
if [ "${CEREMONY_SIMULATE:-}" = 1 ]; then
  warn "execution-profile proof skipped in explicitly simulated test mode."
elif [ ! -x "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/preflight-environment.py" ]; then
  bad "preflight-environment.py is missing or not executable — cannot prove a supported disposable profile."
elif [ ! -x "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ceremony-teardown.py" ]; then
  bad "ceremony-teardown.py is missing or not executable — cannot prove cleanup after secret exposure."
elif ! profile_out="$("$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/preflight-environment.py" 2>&1)"; then
  bad "execution profile is unsafe or unsupported:"
  printf '%s\n' "$profile_out" | sed 's/^/       /'
else
  ok "$(printf '%s\n' "$profile_out" | head -1)"
  printf '%s\n' "$profile_out" | grep '^WARN ' | sed 's/^/       /' || true
fi

# THE SAME INTERPRETER THE CEREMONY WILL USE. ceremony.sh resolves the ceremony venv through
# tools/ceremony-python.sh; without doing the same here, this check reports on whichever python3
# happened to be on PATH when preflight ran — a different interpreter than the one that runs step
# 3c. It would then either green-light a ceremony whose python cannot import the module (the exact
# mid-ceremony failure this check exists to prevent, with the money already exposed) or refuse one
# that would have worked. Measured 2026-09-22: under `sudo`, secure_path drops the venv and this
# reported both modules missing on a host where the ceremony would have found them.
#
# prefer, not require: a host with no venv anywhere must still reach the import check below and
# fail THERE, with the message that says what to do about it.
_cp="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/ceremony-python.sh"
if [ -r "$_cp" ]; then
  # shellcheck source=/dev/null
  . "$_cp"
  ceremony_python_prefer mnemonic shamir_mnemonic
fi
unset _cp

echo "== Tools =="
for t in ip age sops age-plugin-yubikey pkcs11-tool sc-hsm-tool ykman ssss-split shamir qrencode zbarimg gpg sha256sum python3; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t"; else bad "$t not found (check the template build)"; fi
done
# `command -v python3` passing does NOT prove the seed backup will run. Ceremony step 3
# option c (bip39-slip39-backup.py — the FUNDING/derivation seed's only Option-B backup)
# does `from mnemonic import Mnemonic` + `import shamir_mnemonic` at RUNTIME. On the
# air-gapped qube there is no pip to recover a missing package, so prove the imports resolve
# HERE, before keys are in RAM — not mid-ceremony after the money is exposed.
if command -v python3 >/dev/null 2>&1; then
  for m in mnemonic shamir_mnemonic; do
    if python3 -c "import $m" >/dev/null 2>&1; then ok "python3 module '$m'"
    else bad "python3 cannot import '$m' — the BIP39<->SLIP-39 seed backup (step 3c) will fail; bake the wheel into the vault-tools image (no pip on the air-gapped qube)."; fi
  done
fi
# The M-DISC archive (step 4) burns with growisofs (or xorriso). Missing means no archival
# copy AND no way to install it on the air-gapped qube — catch it before the ceremony.
if command -v growisofs >/dev/null 2>&1 || command -v xorriso >/dev/null 2>&1; then ok "optical burner (growisofs/xorriso)"
else bad "no growisofs/xorriso — cannot burn the M-DISC archive; add it to the template build."; fi

echo "== Smartcard reader / tokens =="
if command -v opensc-tool >/dev/null 2>&1; then
  if grep -qi "reader" <<< "$(timeout 5 opensc-tool -l 2>/dev/null)"; then
    ok "a PC/SC reader is visible (opensc-tool -l)."
  else
    warn "no reader seen by opensc-tool — attach it with 'qvm-usb attach' from dom0."
  fi
else
  warn "opensc-tool not found — install opensc (reader check skipped)."
fi
if command -v ykman >/dev/null 2>&1; then
  if [ -n "$(timeout 5 ykman list 2>/dev/null)" ]; then ok "a YubiKey is present (ykman list)."
  else warn "no YubiKey seen — attach it if this ceremony needs one."; fi
fi

echo "== Printer (paper backup) =="
if command -v lpstat >/dev/null 2>&1; then
  if [ -n "$(lpstat -p 2>/dev/null)" ]; then
    ok "CUPS queue(s) present:"; lpstat -p 2>/dev/null | sed 's/^/       /'
    # ALLOWLIST (matches ceremony.sh pick_printer): only usb:// (or a local file:/cups-pdf:/
    # absolute-path/empty device-uri) is safe. A blocklist would miss smb://, bluetooth://, …
    # and send plaintext shares over the wire. Anything NOT on the allowlist is a network printer.
    # Anchor on the URI (text after the final ': '), not a colon-free queue name: CUPS
    # queue names may contain a colon, and [^:]+ would discard such a line, letting a
    # networked printer slip past. Names contain no spaces, so ': ' is only the boundary.
    net="$(lpstat -v 2>/dev/null | grep -E 'device for .+: ' | grep -vE 'device for .+: (usb://|file:|cups-pdf:|/|$)' || true)"
    if [ -n "$net" ]; then
      bad "a NETWORK printer queue exists — remove it; print only over usb://."
      printf '%s\n' "$net" | sed 's/^/       /'
    else ok "no network printer queues (usb/local only)."; fi
  else warn "no CUPS print queue — add the USB laser printer (no network, no internal storage) if you'll print paper shares."; fi
else warn "lp/lpstat not installed — paper steps will only write files."; fi

echo "== Optical drives (M-DISC archive) =="
drives=$(ls /dev/sr* 2>/dev/null | wc -l | tr -d ' ')
if [ "$drives" -ge 2 ]; then ok "$drives optical drives present — burn on one, read back on another (write capability: go-nogo.sh)."
elif [ "$drives" -eq 1 ]; then ok "1 optical drive present (its write capability is checked by go-nogo.sh --need drives); the burn is read back on it (ADR-0002 D9)."
else warn "no /dev/sr* optical drive seen — attach the internal/external DVD writer for M-DISC archive."; fi

echo "== Chip cards (SLE-4442) =="
# The chip-card step needs the manager AND pyscard; the manager exits at import without pyscard,
# which would surface only at the step, with a share already in RAM.
if command -v sle4442-manager >/dev/null 2>&1 && python3 -c "import smartcard" >/dev/null 2>&1; then
  ok "sle4442-manager + pyscard"
else bad "sle4442-manager or python3-pyscard missing — the SLE-4442 chip-card step cannot run; rebuild the template."; fi

echo "== Camera (scan the printed QR back) =="
if command -v zbarcam >/dev/null 2>&1; then
  if ls /dev/video* >/dev/null 2>&1; then ok "zbarcam + a camera ($(ls /dev/video* | head -1))"
  else warn "no /dev/video* — attach the webcam with 'qvm-usb attach' to scan the printed sheets back (or scan them with zbarimg from a photo)."; fi
else warn "zbarcam not installed — printed QR sheets cannot be scanned back here."; fi

echo "== Entropy =="
ent=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
if [ "$ent" -ge 256 ]; then ok "entropy_avail=$ent"
elif [ "${CEREMONY_SIMULATE:-}" = 1 ]; then warn "low entropy ($ent) — real ceremonies fail this control."
else bad "low entropy ($ent) — wait and re-run preflight before generating keys."; fi

echo
if [ "$fail" -eq 0 ]; then
  printf '\033[32mPREFLIGHT OK\033[0m — review the relevant SECRETS.md section, then run the ceremony steps by hand.\n'
else
  printf '\033[31mPREFLIGHT FAILED\033[0m — do NOT start the ceremony until the FAIL items are resolved.\n'
fi
exit "$fail"
