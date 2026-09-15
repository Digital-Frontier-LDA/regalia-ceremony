#!/usr/bin/env bash
# test-preflight-runtime-deps.sh — the preflight "== Tools ==" gate must prove the RUNTIME
# python dependencies of the seed backup exist, not just that `python3` is on PATH.
#
# Ceremony step 3 option c (bip39-slip39-backup.py) is the FUNDING/derivation seed's only
# Option-B backup. It does `from mnemonic import Mnemonic` + `import shamir_mnemonic`. The
# preflight tool loop checks the `shamir` CLI (from shamir-mnemonic) but NOT the BIP39
# `mnemonic` package — so on a vault image with `shamir` present but `mnemonic` missing,
# preflight reports OK while the money's backup would fail mid-ceremony on the air-gapped
# (no-pip) qube. This is the regression guard: preflight must import the modules and FAIL
# CLOSED when a package is missing. Runs natively, no daemons needed.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PRE="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/preflight.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

# Curate a sandbox PATH so EVERY CLI tool preflight's Tools loop checks resolves as a no-op.
# That isolates the single variable under test: whether python3 can import the BIP39/SLIP-39
# modules the seed backup needs. `ip` returns nothing -> preflight sees no default route.
SBOX="$(mktemp -d)"
trap 'rm -rf "$SBOX"' EXIT
for u in bash sh env grep cat ls wc tr sed timeout printf head mktemp chmod ln dirname; do
  p="$(command -v "$u" 2>/dev/null)" && ln -sf "$p" "$SBOX/$u"
done
for t in ip age sops age-plugin-yubikey pkcs11-tool sc-hsm-tool ykman ssss-split \
         shamir qrencode zbarimg gpg sha256sum growisofs xorriso opensc-tool lpstat lp; do
  printf '#!/usr/bin/env bash\nexit 0\n' > "$SBOX/$t"; chmod +x "$SBOX/$t"
done

# A python3 stub whose import behaviour we drive via $EMU_PY_MISSING (a module name that
# fails to import). Any other invocation is a no-op success.
cat > "$SBOX/python3" <<'PY'
#!/usr/bin/env bash
# emulate `python3 -c '...'`: fail if the snippet imports the "missing" module
if [ "${1:-}" = "-c" ]; then
  case "$2" in
    *import*"${EMU_PY_MISSING:-__none__}"*) exit 1;;
  esac
fi
exit 0
PY
chmod +x "$SBOX/python3"

hdr "BIP39 'mnemonic' package MISSING -> preflight must FAIL (not report the seed backup OK)"
out="$(PATH="$SBOX" CEREMONY_SIMULATE=1 EMU_PY_MISSING=mnemonic bash "$PRE" 2>&1)"
echo "$out" | grep -iE 'mnemonic|shamir' | sed 's/^/     /'
if grep -qiE 'FAIL.*mnemonic' <<< "$out"; then
  P "preflight emits a FAIL naming the missing 'mnemonic' module"
else
  F "preflight did NOT FAIL on a missing 'mnemonic' module — seed backup would die mid-ceremony"
fi

hdr "shamir_mnemonic package MISSING -> preflight must FAIL too"
out2="$(PATH="$SBOX" CEREMONY_SIMULATE=1 EMU_PY_MISSING=shamir_mnemonic bash "$PRE" 2>&1)"
if grep -qiE 'FAIL.*(shamir_mnemonic|mnemonic)' <<< "$out2"; then
  P "preflight emits a FAIL when shamir_mnemonic cannot be imported"
else
  F "preflight did NOT FAIL on a missing shamir_mnemonic module"
fi

hdr "control: both modules importable -> preflight reports the runtime deps OK (no over-reject)"
out3="$(PATH="$SBOX" CEREMONY_SIMULATE=1 EMU_PY_MISSING=__none__ bash "$PRE" 2>&1)"
if grep -qiE 'FAIL.*mnemonic' <<< "$out3"; then
  F "regression: preflight FAILs the module check even though both imports succeed"
  echo "$out3" | grep -iE 'mnemonic' | sed 's/^/        /'
else
  P "no spurious module FAIL when mnemonic + shamir_mnemonic both import"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
