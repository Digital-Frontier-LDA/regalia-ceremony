#!/usr/bin/env bash
# Install only after verify-release.sh succeeds and networking is physically/logically absent.
set -euo pipefail

HERE="${BUNDLE_ROOT:-$(cd "$(dirname "$0")" && pwd)}"
HERE="$(cd "$HERE" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
. /etc/os-release
[ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 12 ] || { echo "Debian 12 required" >&2; exit 2; }
for interface in /sys/class/net/*; do
  [ -d "$interface" ] || continue
  [ "$(basename "$interface")" = lo ] && continue
  state="$(cat "$interface/operstate" 2>/dev/null || echo unknown)"
  [ "$state" = down ] || { echo "non-loopback interface $(basename "$interface") is $state; disconnect it" >&2; exit 1; }
done
( cd "$HERE" && sha256sum --strict -c MANIFEST.sha256 )

mkdir -p /etc/apt/sources.list.d.disabled
for source in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [ -e "$source" ] || continue
  mv "$source" "/etc/apt/sources.list.d.disabled/$(basename "$source").pre-ceremony"
done
: > /etc/apt/sources.list
# Discard indexes inherited from the live image. With --no-download apt must not
# try to satisfy a dependency using a stale repository record with no local URI.
find /var/lib/apt/lists -mindepth 1 -delete
# Unpack the complete locked closure directly, then configure it as one set.
# apt rewrites local archive paths into basename-only cache records when no
# network indexes exist; dpkg preserves the absolute paths and performs no I/O.
# A lexical glob is not dependency order (python3-minimal sorts before its
# python3.11-minimal Pre-Depends). Bounded passes configure newly satisfiable
# prerequisites; the final pass remains strict and must succeed completely.
converged=0
for _attempt in 1 2 3; do
  if dpkg --unpack "$HERE"/apt/*.deb; then
    converged=1
    break
  fi
  DEBIAN_FRONTEND=noninteractive dpkg --configure -a || true
done
[ "$converged" -eq 1 ] || dpkg --unpack "$HERE"/apt/*.deb
DEBIAN_FRONTEND=noninteractive dpkg --configure -a
dpkg --audit
python3 "$HERE/bundle-tool.py" verify "$HERE"
PIP_NO_CACHE_DIR=1 pip3 install --no-index --find-links "$HERE/wheels" --require-hashes --break-system-packages -r "$HERE/requirements.txt" \
  || PIP_NO_CACHE_DIR=1 pip3 install --no-index --find-links "$HERE/wheels" --require-hashes -r "$HERE/requirements.txt"
install -D -m 0755 "$HERE/bin/sops" /opt/vault-bin/sops
install -d -m 0755 /etc/profile.d
printf '%s\n' '# Pinned standalone ceremony tools live outside mutable per-user paths.' \
  'export PATH="/opt/vault-bin:$PATH"' > /etc/profile.d/vault-bin.sh
chmod 0644 /etc/profile.d/vault-bin.sh
export PATH="/opt/vault-bin:$PATH"
install -d -m 0755 /opt/vault-ceremony
cp -a "$HERE/scripts/." /opt/vault-ceremony/
cp -a "$HERE/recovery" /opt/vault-ceremony/recovery
install -m 0644 "$HERE/requirements.txt" /opt/vault-ceremony/requirements.txt
install -m 0644 "$HERE/CEREMONY-PROFILES.md" /opt/vault-ceremony/CEREMONY-PROFILES.md

swap_entries=0
if [ -r /proc/swaps ]; then
  swap_entries="$(awk 'NR > 1 { count++ } END { print count + 0 }' /proc/swaps)"
fi
if [ "$swap_entries" -gt 0 ]; then
  if ! swapoff -a; then
    # Docker Desktop exposes its VM swap inside privileged containers but does
    # not grant the container authority to disable it. This narrowly scoped
    # escape hatch exists only to exercise package installation in local/CI
    # containers. It is rejected outside a container, and the real ceremony
    # preflight still requires zero active swap before any secret is present.
    if [ "${CEREMONY_CONTAINER_TEST:-0}" = 1 ] && [ -e /.dockerenv ]; then
      echo "TEST ONLY: container-host swap remains active; this is not ceremony evidence" >&2
    else
      echo "swap could not be disabled after installation" >&2
      exit 1
    fi
  fi
fi
if [ "${CEREMONY_CONTAINER_TEST:-0}" != 1 ] || [ ! -e /.dockerenv ]; then
  [ -r /proc/swaps ] && [ "$(awk 'NR > 1 { count++ } END { print count + 0 }' /proc/swaps)" -eq 0 ] \
    || { echo "swap could not be proved inactive after installation" >&2; exit 1; }
fi
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target \
  udisks2.service ModemManager.service apport.service whoopsie.service rsyslog.service 2>/dev/null || true
install -d -m 0755 /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\n' > /etc/systemd/journald.conf.d/90-regalia-volatile.conf
systemctl restart systemd-journald.service 2>/dev/null || true
printf '* hard core 0\n* soft core 0\n' > /etc/security/limits.d/90-regalia-no-core.conf

for tool in age sops age-plugin-yubikey pkcs11-tool sc-hsm-tool ykman ssss-split shamir qrencode zbarimg gpg openssl; do
  command -v "$tool" >/dev/null || { echo "offline install incomplete: $tool missing" >&2; exit 1; }
done
echo "OFFLINE INSTALL OK — reboot the live environment, keep networking absent, then run preflight.sh"
