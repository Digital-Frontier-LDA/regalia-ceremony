#!/usr/bin/env bash
# record-build-evidence.sh — capture EXACTLY what the vault-tools image contains, as
# ceremony evidence. Run on the template right after building it (before going air-gapped).
# This gives the audit/"prove what generated the keys" value without snapshot.debian.org
# (the quorum's MIDDLE call: authenticity is covered; record state for reproducibility).
#
#   bash record-build-evidence.sh > build-evidence-$(date +%Y%m%d).txt
#
# Non-secret: only package/version/hash inventory. Commit it / archive with the ceremony.

set -uo pipefail
say(){ printf '\n===== %s =====\n' "$1"; }

echo "Vault-tools build evidence"
echo "host: $(uname -a 2>/dev/null)"
echo "(no secrets below — package + tool inventory only)"

say "OS / Debian release"
cat /etc/os-release 2>/dev/null | sed -n '1,4p'
echo "snapshot/sources:"; cat /etc/apt/sources.list 2>/dev/null | grep -vE '^\s*#|^\s*$' | head

say "apt packages (ceremony-relevant)"
for p in age opensc pcscd libccid pcsc-tools yubikey-manager ssss qrencode zbar-tools gnupg scdaemon secure-delete python3-pip; do
  v="$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null || echo 'NOT INSTALLED')"; printf '  %-18s %s\n' "$p" "$v"
done

say "pip packages (full freeze)"
pip3 freeze 2>/dev/null || pip freeze 2>/dev/null || echo "pip not found"

say "pinned non-apt binaries (sha256)"
for f in /opt/vault-bin/sops /usr/bin/age-plugin-yubikey /usr/local/bin/age-plugin-yubikey; do
  [ -f "$f" ] && printf '  %-40s %s\n' "$f" "$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
done

say "tool versions"
for t in age sops age-plugin-yubikey pkcs11-tool sc-hsm-tool ykman ssss-split shamir qrencode python3; do
  printf '  %-20s ' "$t"; command -v "$t" >/dev/null 2>&1 && { "$t" --version 2>&1 | head -1; } || echo "MISSING"
done

say "requirements.txt hashes baked into the image"
if [ -f /opt/vault-ceremony/requirements.txt ]; then
  grep -E '==|--hash=' /opt/vault-ceremony/requirements.txt    # all pinned packages + every hash
else echo "(requirements.txt not found)"; fi

echo
echo "Record this output with the ceremony evidence (and a photo of the sealed media + holo serials)."
