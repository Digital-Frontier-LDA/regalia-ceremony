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
      - iproute2           # `ip`: the air-gap preflight needs it, and a *-minimal template may lack it
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
      # --- Qubes plumbing a *-minimal template lacks -----------------------------------
      - qubes-usb-proxy    # `qvm-usb attach` into the vault: WITHOUT it no token, reader, drive
                           # or webcam can be passed through, and debian-13-minimal omits it
      - xterm              # a terminal to run the wizard in; minimal templates ship none
      # --- ceremony media (step 4 M-DISC, paper, chip cards, scan-back) ----------------
      - dvd+rw-tools       # growisofs: burn the M-DISC on drive A (step_archive)
      - xorriso            # read the disc back from drive B without a kernel mount (osirrox)
      - cups               # print spooler; USB-only queues enforced by pick_printer/preflight
      - cups-client        # lp / lpstat / cancel, which ceremony.sh drives
      - cups-filters       # PNG/text -> printer; without it a QR page cannot be rendered
      - ipp-usb            # driverless IPP-over-USB (most current USB lasers)
      - ghostscript        # PostScript rendering for the recovery card and non-PS printers
      - printer-driver-brlaser   # Brother monochrome lasers that are not IPP-everywhere
      - python3-pyscard    # sle4442-manager: SLE-4442 chip cards over PC/SC
      - v4l-utils          # v4l2-ctl: find/focus the webcam used to scan printed QR back

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
    # A VENV IN THE TEMPLATE ROOT, not a system pip install. Measured on debian-13-minimal
    # (2026-09-24): the system install FAILS there, because yubikey-manager pulls Debian's
    # python3-click 8.1.8 and pip cannot uninstall a Debian package to put the pinned 8.5.0 in its
    # place (uninstall-no-record-file) — and forcing it would swap the click ykman runs on. A
    # system pip install also lands in /usr/local, which Qubes copies into a qube only on its
    # FIRST boot (/usr/local.orig -> /rw/usrlocal), so every template rebuild after that would be
    # invisible to the vault. /opt is template root: it reaches every disposable, every time.
    # --system-site-packages: the venv still sees Debian's python3-pyscard (sle4442-manager);
    # its own pinned packages shadow Debian's only inside the venv. --ignore-installed: EVERY pin
    # goes into the venv even when a same-version copy is visible outside it; otherwise pip counts
    # a leftover /usr/local install as satisfied and the venv silently lacks it (seen on a rebuild
    # after a failed system install: no `shamir` CLI).
    # --only-binary :all:: never compile. Every pinned package has a pinned wheel (checked for
    # Python 3.11 and 3.13, 2026-09-24); a missing one must fail HERE, not silently need gcc on a
    # minimal template or on the machine that later recovers from the disc.
    # QUOTED: ":all: " is a YAML mapping indicator in a plain scalar, and Salt could not render
    # the state at all (caught by CI on the Debian 12 build, 2026-09-24).
    - name: 'rm -rf /opt/vault-ceremony/venv && python3 -m venv --system-site-packages /opt/vault-ceremony/venv && /opt/vault-ceremony/venv/bin/pip install --no-cache-dir --ignore-installed --only-binary :all: --require-hashes -r /opt/vault-ceremony/requirements.txt && cp /opt/vault-ceremony/requirements.txt /opt/vault-ceremony/venv/requirements.installed'
    # Rebuilt unless the venv was COMPLETED for exactly this requirements.txt. Not `onchanges`:
    # the file lands before the install runs, so after a failed first build a re-run saw no change
    # and skipped the install, reporting success with no venv (found on the trixie build).
    - unless: 'cmp -s /opt/vault-ceremony/requirements.txt /opt/vault-ceremony/venv/requirements.installed'
    - require:
      - pkg: vault-tools-apt
      - file: ceremony-requirements

# The SLIP-0039 CLI on PATH, from the venv.
slip39-shamir-bin:
  file.symlink:
    - name: /opt/vault-bin/shamir
    - target: /opt/vault-ceremony/venv/bin/shamir
    - makedirs: True
    - require:
      - cmd: slip39-shamir

# Bake the hash-pinned WHEELS into the image (network is available during this build) so
# ceremony.sh step_archive can burn them onto each M-DISC. A recoverer on a clean offline
# machine (the Tails path in RECOVERY-TECHNICAL.md) then installs the SLIP-39 tools with NO
# network:  pip install --no-index --find-links wheels/ --require-hashes -r requirements.txt
# Without these, `import shamir_mnemonic`/`mnemonic` fails air-gapped and the seeds cannot be
# recovered on anything but the vault-tools image — defeating the self-contained-disc claim.
slip39-wheels:
  cmd.run:
    # For EVERY supported recovery interpreter, not just this template's: cffi's wheel is
    # per-version (cp311 vs cp313), and a disc read on the other Debian release would otherwise
    # hold no installable cffi (review of #46). Python 3.11 = Debian 12, 3.13 = Debian 13.
    - name: >
        for v in 3.11 3.13; do
        pip3 download --only-binary :all: --require-hashes
        --python-version "$v" --implementation cp
        --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux_2_34_x86_64
        -r /opt/vault-ceremony/requirements.txt -d /opt/vault-ceremony/wheels || exit 1;
        done;
        cp /opt/vault-ceremony/requirements.txt /opt/vault-ceremony/wheels/requirements.downloaded
    # Same completion stamp as the venv, for the same reason.
    - unless: 'cmp -s /opt/vault-ceremony/requirements.txt /opt/vault-ceremony/wheels/requirements.downloaded'
    - require:
      - pkg: vault-tools-apt
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

# sle4442-manager ships with the ceremony scripts; expose it on PATH like the other tools.
sle4442-manager:
  file.symlink:
    - name: /opt/vault-bin/sle4442-manager
    - target: /opt/vault-ceremony/sle4442-manager
    - makedirs: True
    - require:
      - file: ceremony-scripts

ceremony-bin-path:
  file.managed:
    - name: /etc/profile.d/vault-bin.sh
    - contents: |
        # Baked into vault-tools template — the pinned binaries, then the pinned-package venv.
        export PATH="/opt/vault-ceremony/venv/bin:/opt/vault-bin:$PATH"
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

# Enable the smartcard daemon and the print spooler so a reader, token or USB printer attached
# with qvm-usb just works in the disposable (its spool is discarded with it).
# `systemctl enable` only writes unit symlinks and needs no running systemd, so it behaves the same
# in the live template, a chroot and CI's container. Salt's service.enabled does not: without a
# running systemd it falls back to insserv, which Debian 13 no longer ships (trixie build, 2026-09-24).
vault-services-enabled:
  cmd.run:
    - name: systemctl enable pcscd.socket cups.service cups.socket
    # One unit at a time: with several units `systemctl is-enabled` succeeds when ANY is enabled
    # (checked on trixie with cups.socket disabled: rc 0), which would skip enabling the rest.
    - unless: 'for u in pcscd.socket cups.service cups.socket; do systemctl is-enabled -q "$u" || exit 1; done'
    - require:
      - pkg: vault-tools-apt
