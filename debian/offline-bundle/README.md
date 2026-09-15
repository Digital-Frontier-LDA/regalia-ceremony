# Reproducible Debian 12 offline ceremony bundle

This is the supported artifact for the `debian-live` ceremony profile. It is a
deterministic tarball, not a custom operating-system image: boot reviewed Debian
12 live media, verify the release while no secrets are present, disconnect all
network interfaces, and install entirely from the bundle.

## Build

Build from a clean, digest-pinned `debian:12` amd64 container. The timestamp is
the reviewed source commit timestamp, not wall-clock time. The Debian snapshot
must be an immutable `snapshot.debian.org` timestamp.

```bash
image=debian@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443
digest=${image#*@}
docker pull --platform linux/amd64 "$image"
epoch=$(git show -s --format=%ct HEAD)
docker run --rm --platform linux/amd64 -v "$PWD:/repo" -w /repo \
  -e DEBIAN_SNAPSHOT=20260901T000000Z \
  -e SOURCE_DATE_EPOCH="$epoch" -e BUILDER_IMAGE_DIGEST="$digest" \
  "$image" debian/offline-bundle/build.sh
```

The artifact includes exact Debian/Python/standalone package versions and
SHA-256 hashes, an SPDX 2.3 SBOM, Debian copyright texts, build provenance,
scripts, recovery documentation, a complete internal checksum manifest, and a
local apt repository. The repository currently has no declared license, so the
bundle records `NOASSERTION` for Regalia scripts and must not be redistributed
until the owner supplies one.

Two builds are byte-identical only when source commit, Debian snapshot,
architecture, builder image digest, and `SOURCE_DATE_EPOCH` are identical. The
tar owner/group, ordering, mtimes, PAX metadata, and gzip timestamp are
normalized. Compare the two `SHA256SUMS` files; any mismatch is a release block
and should be investigated with `diffoscope` after extraction.
The slim base lacks a CA store, so the builder bootstraps only `ca-certificates`
from the digest-pinned image default signed repository, replaces all apt sources,
then reinstalls it and every other dependency from the immutable snapshot.

## Sign through the centralized KMS

The builder never accepts a local release private key. Commission a P-256
`release-signing` object in the custody manifest and allow only the release
principal/purpose/content type. Submit the canonical `RELEASE.json` digest:

```bash
python3 debian/offline-bundle/sign-release.py dist/offline-ceremony/RELEASE.json \
  --kms-url https://kms.internal:8443 --object-id ceremony-release-p256 \
  --client-cert /run/credentials/release.crt --client-key /run/credentials/release.key \
  --ca /etc/regalia/kms-ca.pem --public-key release-signing-public.pem \
  --output dist/offline-ceremony/RELEASE.sig.der \
  --receipt dist/offline-ceremony/RELEASE.signature.json
```

The signer verifies the returned signature against the commissioned public key
before writing its non-secret receipt. The short-lived client credential is a
KMS authentication credential, never the release-signing private key.

## Verify, extract, and install offline

Copy the tarball, `RELEASE.json`, signature, and separately pinned public key to
the clean environment. Before extraction and before any token/share is present:

```bash
verify-release.sh regalia-ceremony-debian12-amd64.tar.gz RELEASE.json \
  RELEASE.sig.der release-signing-public.pem
tar -xzf regalia-ceremony-debian12-amd64.tar.gz
cd regalia-ceremony-debian12-amd64
sudo ./install.sh
```

`verify-release.sh` requires both the artifact checksum bound into the signed
release manifest and the hardware-backed P-256 signature. `install.sh` refuses
non-Debian-12 systems and any active non-loopback interface, re-verifies every
internal file, disables external apt sources, installs with `--no-download`,
and applies the leak-control defaults. Reboot the live environment and run the
normal profile-aware preflight before exposing secrets.

For package-installation testing under Docker Desktop, which exposes VM swap
but will not let a container disable it, set `CEREMONY_CONTAINER_TEST=1`.
`install.sh` accepts that escape hatch only when `/.dockerenv` exists and prints
a prominent warning. The resulting run is dependency-closure evidence only:
it is never ceremony evidence, and the real preflight has no such bypass.

Do not promote a bundle based only on emulator results. Production approval also
requires the physical PicoHSM2/Nitrokey/YubiKey qualification and cross-profile
drill evidence tracked by the hardware issues.
