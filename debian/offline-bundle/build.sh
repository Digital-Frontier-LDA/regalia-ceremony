#!/usr/bin/env bash
# Build inside a clean debian:12 amd64 container. Network is used only while assembling bytes.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
: "${DEBIAN_SNAPSHOT:?set YYYYMMDDTHHMMSSZ snapshot timestamp}"
: "${SOURCE_DATE_EPOCH:?set to the source commit timestamp}"
: "${BUILDER_IMAGE_DIGEST:?set to the pinned debian:12 image sha256 digest}"
case "$DEBIAN_SNAPSHOT" in
  [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
  *) echo "invalid DEBIAN_SNAPSHOT" >&2; exit 2;;
esac
[ "$(id -u)" -eq 0 ] || { echo "build inside the documented root container" >&2; exit 2; }
. /etc/os-release
[ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 12 ] || { echo "debian:12 builder required" >&2; exit 2; }
[ "$(dpkg --print-architecture)" = amd64 ] || { echo "amd64 builder required" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/regalia-ceremony-debian12-amd64"
mkdir -p "$root"/{apt,wheels,bin,scripts,recovery,licenses}

# debian:12-slim has no CA store. Bootstrap only the CA package through the
# digest-pinned base image signed repository, then replace every source with the
# immutable snapshot and reinstall ca-certificates from that snapshot below.
apt-get update
apt-get install -y --no-install-recommends ca-certificates
printf '%s\n' \
  "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT bookworm main" \
  "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT bookworm-security main" \
  > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
apt-get -o Acquire::Check-Valid-Until=false update
apt-get install -y --reinstall --no-install-recommends ca-certificates curl dpkg-dev git gzip python3 python3-pip
# The bundle copies whole directories. A tracked-only diff check would permit an
# untracked script or recovery file to enter a signed artifact while provenance
# still named the clean HEAD commit. Limit the check to actual bundle inputs so
# unrelated local scratch files do not block a build, but include untracked files.
source_status="$(git -c safe.directory="$REPO" -C "$REPO" status --porcelain --untracked-files=all -- \
  qubes debian/offline-bundle)"
if [ -n "$source_status" ]; then
  echo "modified or untracked bundle inputs are present; commit or remove them before recording provenance" >&2
  printf '%s\n' "$source_status" >&2
  exit 2
fi
source_commit="$(git -c safe.directory="$REPO" -C "$REPO" rev-parse HEAD)"

mapfile -t requested < <(sed 's/#.*//' "$REPO/qubes/packages.txt" | awk 'NF {print $1}')
mkdir -p "$root/apt/partial"
: > "$work/empty-dpkg-status"
# Resolve against an empty dpkg database. Using the builder state silently omits
# base packages already installed in the container and produces a bundle that
# works only on that exact base rather than any clean Debian 12 live system.
apt-get -y --download-only --no-install-recommends \
  -o Acquire::Check-Valid-Until=false -o Dir::State::status="$work/empty-dpkg-status" \
  -o Dir::Cache::archives="$root/apt" install "${requested[@]}"
rm -rf "$root/apt/partial" "$root/apt/lock"

curl -fsSL -o "$root/bin/sops" \
  https://github.com/getsops/sops/releases/download/v3.13.1/sops-v3.13.1.linux.amd64
printf '%s  %s\n' 620a9d7e3352ababeca6908cea24a6e8b14ce89a448ddbd3f94f1ef3398f470a "$root/bin/sops" | sha256sum -c -
chmod 0755 "$root/bin/sops"
curl -fsSL -o "$root/licenses/sops-3.13.1-LICENSE" \
  https://raw.githubusercontent.com/getsops/sops/v3.13.1/LICENSE
curl -fsSL -o "$root/apt/age-plugin-yubikey_0.5.0-1_amd64.deb" \
  https://github.com/str4d/age-plugin-yubikey/releases/download/v0.5.0/age-plugin-yubikey_0.5.0-1_amd64.deb
printf '%s  %s\n' bf7a02418de04b3d3df9791e185d493eb344829bca4009247a41bc4d7630b47f "$root/apt/age-plugin-yubikey_0.5.0-1_amd64.deb" | sha256sum -c -

pip3 download --require-hashes -r "$REPO/qubes/requirements.txt" -d "$root/wheels"
cp -a "$REPO/qubes/scripts/." "$root/scripts/"
rm -f "$root/scripts/test-ceremony.sh" "$root/scripts/recital-ceremony.sh" \
  "$root/scripts/simulate-ceremony.sh" "$root/scripts/prove-ceremony.sh"
cp -a "$REPO/qubes/recovery/." "$root/recovery/"
cp "$REPO/qubes/requirements.txt" "$REPO/qubes/packages.txt" \
  "$REPO/qubes/CEREMONY-PROFILES.md" "$root/"
cp "$HERE/bundle-tool.py" "$HERE/install.sh" "$HERE/verify-release.sh" "$HERE/sign-release.py" "$root/"
chmod 0755 "$root"/*.sh "$root/bundle-tool.py"

# Extract the complete closure into one tree first: Debian doc paths commonly use
# relative symlinks to another binary package (for example cpp-12 -> gcc-12-base).
license_root="$work/debian-license-root"
mkdir -p "$license_root"
for deb in "$root"/apt/*.deb; do dpkg-deb -x "$deb" "$license_root"; done
# Preserve the distro license/copyright text beside every Debian package. Missing
# copyright data is a release failure, not silently reported as a known license.
for deb in "$root"/apt/*.deb; do
  package="$(dpkg-deb -f "$deb" Package)"
  version="$(dpkg-deb -f "$deb" Version | tr ':/' '__')"
  copyright="$license_root/usr/share/doc/$package/copyright"
  [ -e "$copyright" ] || { echo "missing Debian copyright for $package" >&2; exit 1; }
  cp -L "$copyright" "$root/licenses/${package}_${version}.copyright"
done
printf '%s\n' \
  'Regalia ceremony scripts currently have no repository-level license declaration.' \
  'This internal bundle may not be redistributed until the owner supplies one.' \
  > "$root/licenses/REGALIA-SCRIPTS-NOASSERTION.txt"

( cd "$root/apt" && dpkg-scanpackages . /dev/null > Packages && gzip -n -9 < Packages > Packages.gz )
python3 "$root/bundle-tool.py" create "$root" --epoch "$SOURCE_DATE_EPOCH" \
  --source-commit "$source_commit" --builder-image "$BUILDER_IMAGE_DIGEST"
python3 "$root/bundle-tool.py" verify "$root"
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

out="${OUTPUT_DIR:-$REPO/dist/offline-ceremony}"
mkdir -p "$out"
artifact="$out/$(basename "$root").tar.gz"
tar --sort=name --format=posix --pax-option=delete=atime,delete=ctime \
  --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -C "$work" -cf - "$(basename "$root")" \
  | gzip -n -9 > "$artifact"
( cd "$out" && sha256sum "$(basename "$artifact")" > SHA256SUMS )
python3 "$HERE/bundle-tool.py" release "$artifact" "$out/RELEASE.json" \
  --source-commit "$source_commit" --epoch "$SOURCE_DATE_EPOCH" --snapshot "$DEBIAN_SNAPSHOT"

echo "UNSIGNED BUILD OUTPUT — use sign-release.py; production verification requires the centralized-KMS signature" \
  > "$out/SIGNING-REQUIRED"
echo "BUILT: $artifact"
