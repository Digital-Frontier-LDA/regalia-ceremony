# Provision the vault-tools TemplateVM for the wallet key ceremonies.
# Runs INSIDE the template (which has network during the build). Applies the apt
# manifest, the pip SLIP-39 tool, the hash-pinned non-apt binaries, and bakes the
# ceremony scripts into /opt (template root → inherited read-only by the vault AppVM).
#
#   sudo qubesctl --skip-dom0 --targets=vault-tools state.apply vault-tools
#
# The SHA-256 hashes for the non-apt binaries below are filled and pinned (verified
# 2026-06-28). Re-verify and update them whenever a version is bumped — never run a
# money-key toolchain off an unpinned download.

vault-tools-apt:
  pkg.installed:
    - pkgs:
      - age
      - opensc
      - pcscd
      - libccid
      - pcsc-tools
      - yubikey-manager
      - ykcs11             # PKCS#11 for YubiKey PIV — operation-proof.sh signs through it (regalia#28)
      - ssss
      - python3-pip
      - python3-venv
      - qrencode
      - zbar-tools
      - gnupg
      - scdaemon
      - secure-delete
      - vim                # hardened editor required by sops-edit-airgap.sh (fails closed without it)
      - openssl            # centralized-KMS P-256 offline-bundle signature verification

# SLIP-0039 `shamir` CLI (not packaged in Debian).
# MIDDLE supply-chain posture (quorum 2026-06-29): install the pip deps with
# --require-hashes from the committed, hash-pinned requirements.txt — closes the one
# artifact class lacking cryptographic verification (apt is GPG-authenticated; the sops
# & age-plugin binaries are SHA-pinned below).
ceremony-requirements:
  file.managed:
    - name: /opt/vault-ceremony/requirements.txt
    - source: salt://vault-ceremony-requirements.txt
    - makedirs: True

# Self-contained recovery: the plain-English + technical runbooks + contact-sheet
# template go in the image so they can be burned onto each M-DISC (a recoverer needs
# them WITHOUT repo/network access).
recovery-docs:
  file.recurse:
    - name: /opt/vault-ceremony/recovery
    - source: salt://vault-ceremony-recovery
    - file_mode: "0644"
    - dir_mode: "0755"
slip39-shamir:
  cmd.run:
    # --break-system-packages: a modern Debian (bookworm+) enforces PEP 668 and refuses a
    # system pip install without it. This template is a single-purpose vault image where a
    # system-wide install of the (hash-pinned) SLIP-39 tools IS the intent, so overriding the
    # externally-managed marker here is correct (and required for state.apply to succeed).
    # Fall back to a plain install for an older pip that doesn't recognize the flag (or a
    # distro that doesn't enforce PEP 668) so state.apply doesn't hard-fail on the flag alone.
    - name: pip3 install --break-system-packages --require-hashes -r /opt/vault-ceremony/requirements.txt || pip3 install --require-hashes -r /opt/vault-ceremony/requirements.txt
    - require:
      - pkg: vault-tools-apt
    # idempotent: only (re)install when requirements.txt actually changes
    - onchanges:
      - file: ceremony-requirements

# Bake the hash-pinned WHEELS into the image (network is available during this build) so
# ceremony.sh step_archive can burn them onto each M-DISC. A recoverer on a clean offline
# machine (the Tails path in RECOVERY-TECHNICAL.md) then installs the SLIP-39 tools with NO
# network:  pip install --no-index --find-links wheels/ --require-hashes -r requirements.txt
# Without these, `import shamir_mnemonic`/`mnemonic` fails air-gapped and the seeds cannot be
# recovered on anything but the vault-tools image — defeating the self-contained-disc claim.
slip39-wheels:
  cmd.run:
    - name: >
        pip3 download --require-hashes -r /opt/vault-ceremony/requirements.txt
        -d /opt/vault-ceremony/wheels
    - require:
      - pkg: vault-tools-apt
    - onchanges:
      - file: ceremony-requirements

# --- Non-apt binaries: pinned VERSION + verified SHA-256 ------------------------
# Installed to /opt/vault-bin (template root, inherited read-only). NOT /usr/local —
# that path is per-AppVM in Qubes and would NOT propagate from the template.
# Hashes verified 2026-06-28 by downloading the assets and sha256-summing them
# (sops cross-checked against the GitHub release-asset digest).

# sops (getsops/sops v3.13.1, linux amd64)
sops-binary:
  file.managed:
    - name: /opt/vault-bin/sops
    - source: https://github.com/getsops/sops/releases/download/v3.13.1/sops-v3.13.1.linux.amd64
    - source_hash: sha256=620a9d7e3352ababeca6908cea24a6e8b14ce89a448ddbd3f94f1ef3398f470a
    - mode: "0755"
    - makedirs: True

# age-plugin-yubikey v0.5.0 — installed from the upstream .deb (v0.5.1 dropped its
# Linux build, so v0.5.0 is the last with a Linux artifact). Needs pcscd at runtime
# (pulled by the apt manifest). The .deb is hash-verified before dpkg installs it.
age-plugin-yubikey-deb:
  file.managed:
    - name: /opt/vault-bin/age-plugin-yubikey_0.5.0-1_amd64.deb
    - source: https://github.com/str4d/age-plugin-yubikey/releases/download/v0.5.0/age-plugin-yubikey_0.5.0-1_amd64.deb
    - source_hash: sha256=bf7a02418de04b3d3df9791e185d493eb344829bca4009247a41bc4d7630b47f
    - makedirs: True
age-plugin-yubikey:
  pkg.installed:
    - sources:
      - age-plugin-yubikey: /opt/vault-bin/age-plugin-yubikey_0.5.0-1_amd64.deb
    - require:
      - file: age-plugin-yubikey-deb
      - pkg: vault-tools-apt
# Alternative (newer versions / no .deb): build from crates.io, integrity via the
# locked crate checksums:  apt install cargo pkg-config libpcsclite-dev &&
#   cargo install --locked --version 0.5.1 age-plugin-yubikey

ceremony-bin-path:
  file.managed:
    - name: /etc/profile.d/vault-bin.sh
    - contents: |
        # Baked into vault-tools template — adds the pinned binaries to PATH.
        export PATH="/opt/vault-bin:$PATH"
    - mode: "0644"

# Bake ONLY the real-ceremony scripts into /opt (template root = inherited read-only).
# Exclude the test/sim/proof harnesses — they prepend a fake-bin of STUBBED tools to PATH,
# so they must NOT ship in the image used for a real ceremony (ceremony.sh's guard_no_stubs
# is the second line of defence). Run those harnesses from a checkout, not the vault image.
ceremony-scripts:
  file.recurse:
    - name: /opt/vault-ceremony
    - source: salt://vault-ceremony-scripts
    - file_mode: "0755"
    - dir_mode: "0755"
    # E@ makes this a REGEX. Without E@, Salt treats exclude_pat as a GLOB, which can't do
    # alternation — so the stub test/sim/proof harnesses would NOT be excluded and would ship
    # in the real ceremony image (they prepend a fake-bin of STUBBED tools to PATH). Regex-anchor it.
    - exclude_pat: 'E@(test-ceremony|recital-ceremony|simulate-ceremony|prove-ceremony)\.sh$'

# Enable the smartcard daemon so the reader works once passed through.
pcscd-enabled:
  service.enabled:
    - name: pcscd
    - require:
      - pkg: vault-tools-apt
