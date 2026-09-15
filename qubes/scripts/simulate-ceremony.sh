#!/usr/bin/env bash
# simulate-ceremony.sh — run the REAL ceremony wizard INTERACTIVELY on any machine,
# with hardware + printer tools stubbed and the real crypto tools doing real work.
# Lets you rehearse the exact sequence (menus, prompts, confirmations) before the
# real run on the air-gapped Qubes laptop. Throwaway data only — never real keys.
#
#   bash qubes/scripts/simulate-ceremony.sh
#
# What's REAL here:  ssss / SLIP-0039 shamir splits, qrencode, age, the akash
#                    address derivation, all the menu/flow/secret-hygiene logic.
# What's SIMULATED:  YubiKey (age-plugin-yubikey), Nitrokey HSM (sc-hsm-tool,
#                    pkcs11-tool — but it emits a real DER so the address derives),
#                    ykman, and printing (lp copies the "printout" to an outbox so
#                    you can open the QR PNGs / share sheets).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# this harness legitimately uses stubbed tools and may run off-Linux (no tmpfs):
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1

printf '\033[1;33m'
cat <<'BANNER'
┌──────────────────────────────────────────────────────────────────────┐
│  SIMULATION — this is NOT the real ceremony.                           │
│  Hardware + printer are faked; crypto (Shamir/QR/age/derive) is REAL.  │
│  Use it to rehearse the sequence. Do the real run on the Qubes laptop. │
└──────────────────────────────────────────────────────────────────────┘
BANNER
printf '\033[0m'

# ---- stub the hardware/printer tools (clearly labelled) ---------------------
FAKE="$(mktemp -d)"; export PATH="$FAKE:$PATH:$HOME/.local/bin:/opt/homebrew/bin"
SIM_OUTBOX="$(mktemp -d -t ceremony-sim-printouts.XXXXXX)"; export SIM_OUTBOX
mk(){ cat > "$FAKE/$1"; chmod +x "$FAKE/$1"; }
mk ip <<'S'
#!/usr/bin/env bash
exit 0       # report NO routes so preflight treats this box as air-gapped (simulation)
S
mk age-plugin-yubikey <<'S'
#!/usr/bin/env bash
echo "[SIMULATED] age-plugin-yubikey $*" >&2
echo "age1yubikey1qSIMULATED00recipient00rehearsal00only00do00not00use00zzzz"
S
mk sc-hsm-tool <<'S'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in *.pbe|*.bin) : >"$a";; esac; done
case "$*" in
  *--create-dkek-share*)
    # six placeholder shares in OpenSC's format, for the wizard's share round trip (#464)
    for i in 1 2 3 4 5 6; do
      printf '\nPrime       : 7f:00:00:00:00:00:00:6b\nShare ID    : %s\nShare value : 0%s:0%s\n' "$i" "$i" "$i"
    done;;
  *--import-dkek-share*--pwd-shares-total*) cat >/dev/null;;
esac
echo "[SIMULATED] sc-hsm-tool $*" >&2
S
mk pkcs11-tool <<'S'
#!/usr/bin/env bash
# emit a real, valid secp256k1 SPKI DER on pubkey export so address derivation works
prev=""; out=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
DER=3056301006072a8648ce3d020106052b8104000a034200047f41ffa6c0c377ce7660dfd2716ab96f18f9dbd7de5a6d360b3e89efbbae906cd5188e7d696b936777d5383256af1246980098dd9a16826a4f4984a136fbeab6
case "$*" in
  *--read-object*pubkey*) [ -n "$out" ] && python3 -c "import binascii;open('$out','wb').write(binascii.unhexlify('$DER'))";;
esac
echo "[SIMULATED] pkcs11-tool $*" >&2
S
mk ykman <<'S'
#!/usr/bin/env bash
echo "[SIMULATED] YubiKey 5 (rehearsal)"
S
# preflight also looks for these; stub any that may be absent on a non-Qubes box so
# the rehearsal isn't blocked (they aren't used by the actual ceremony steps).
for t in gpg zbarimg; do command -v "$t" >/dev/null 2>&1 || mk "$t" <<'S'
#!/usr/bin/env bash
echo "[SIMULATED] $0 $*"
S
done
mk lpstat <<'S'
#!/usr/bin/env bash
echo "printer SimBrother is idle.  enabled since now"
S
mk lp <<'S'
#!/usr/bin/env bash
# "print" by copying the artifact into the inspectable outbox
f="${!#}"
if [ -f "$f" ]; then cp "$f" "$SIM_OUTBOX/" 2>/dev/null; echo "[SIMULATED PRINT] $(basename "$f") -> $SIM_OUTBOX/"; else echo "[SIMULATED PRINT] (missing $f)"; fi
S

# ---- need the real crypto tools ---------------------------------------------
miss=0
for t in ssss-split ssss-combine shamir qrencode age age-keygen python3; do
  command -v "$t" >/dev/null || { echo "missing real tool: $t"; miss=1; }
done
[ "$miss" = 0 ] || { echo "install the missing tools first (brew install ssss qrencode age; pipx install 'shamir-mnemonic[cli]')"; rm -rf "$FAKE" "$SIM_OUTBOX"; exit 2; }

echo "Simulated printouts (QR sheets / shares) will collect in:"
echo "  $SIM_OUTBOX"
echo "(the real ceremony shreds the RAM workdir on quit — that part is faithful)"
echo

# ---- run the REAL wizard, sourced so we can keep the printout outbox ---------
# shellcheck disable=SC1090
source "$HERE/ceremony.sh"          # sourcing guard => main() does not auto-run
# Preserve the simulation's faithful behaviour (shred the RAM workdir) but also
# tidy the fake-bin; leave SIM_OUTBOX for the user to inspect.
cleanup(){ [ -n "${WORK:-}" ] && find "$WORK" -type f -exec shred -u {} + 2>/dev/null; rm -rf "${WORK:-}" "$FAKE" 2>/dev/null;
           printf '\n\033[1mSimulation done.\033[0m Inspect the simulated printouts in:\n  %s\nthen delete them: rm -rf %s\n' "$SIM_OUTBOX" "$SIM_OUTBOX"; }

main "$@"
