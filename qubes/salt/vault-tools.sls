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
    # No Recommends: this is a single-purpose air-gapped image. With them, a debian-13-minimal
    # build pulled udisks2, gvfs, gnome-terminal, WebKit, NetworkManager's applet and a SPICE
    # server (2026-09-24). Every tool the ceremony needs is listed here explicitly instead.
    - install_recommends: False
    - pkgs:
      - age
      - iproute2           # `ip`: the air-gap preflight needs it, and a *-minimal template may lack it
      - curl               # fetches the pinned non-apt files through the Qubes updates proxy
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
      - printer-driver-brlaser   # older Brother monochrome lasers without driverless IPP-over-USB
      - python3-pyscard    # sle4442-manager: SLE-4442 chip cards over PC/SC
      - v4l-utils          # v4l2-ctl: find/focus the webcam used to scan printed QR back

# A Qubes TemplateVM has NO direct network: apt reaches the mirrors only through the Qubes updates
# proxy (127.0.0.1:8082, forwarded over qrexec). Every other download in this recipe must go the
# same way, or it fails with "Temporary failure in name resolution" (first real build on the
# owner's machine, 2026-09-25: pip and the GitHub downloads all failed while apt succeeded). This
# prints the proxy when it answers, and nothing elsewhere (CI, a build root with direct network),
# so one recipe serves both. Every download stays hash-pinned; the proxy only carries bytes.
vault-fetch-proxy:
  file.managed:
    - name: /opt/vault-build/fetch-proxy
    - mode: "0755"
    - makedirs: True
    - contents: |
        #!/bin/sh
        # Print the Qubes updates proxy if this machine has one, else nothing.
        P=http://127.0.0.1:8082
        # A GET of one small page, failing on any HTTP error (--fail): the bare /simple/ index is
        # the whole of PyPI (tens of MB) and overran the timeout, so the probe answered "no proxy"
        # (proxy-only build, 2026-09-25).
        if curl -sf -m 30 -o /dev/null -x "$P" https://pypi.org/simple/pip/ 2>/dev/null; then echo "$P"; fi

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
    - name: 'PX=$(/opt/vault-build/fetch-proxy); rm -rf /opt/vault-ceremony/venv && python3 -m venv --system-site-packages /opt/vault-ceremony/venv && /opt/vault-ceremony/venv/bin/pip install ${PX:+--proxy $PX} --no-cache-dir --ignore-installed --only-binary :all: --require-hashes -r /opt/vault-ceremony/requirements.txt && cp /opt/vault-ceremony/requirements.txt /opt/vault-ceremony/venv/requirements.installed'
    # Rebuilt unless the venv was COMPLETED for exactly this requirements.txt. Not `onchanges`:
    # the file lands before the install runs, so after a failed first build a re-run saw no change
    # and skipped the install, reporting success with no venv (found on the trixie build).
    - unless: 'cmp -s /opt/vault-ceremony/requirements.txt /opt/vault-ceremony/venv/requirements.installed'
    - require:
      - pkg: vault-tools-apt
      - file: ceremony-requirements
      - file: vault-fetch-proxy

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
        PX=$(/opt/vault-build/fetch-proxy);
        for v in 3.11 3.13; do
        pip3 download ${PX:+--proxy $PX} --only-binary :all: --require-hashes
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
      - file: vault-fetch-proxy

# --- Non-apt binaries: pinned VERSION + verified SHA-256 ------------------------
# Installed to /opt/vault-bin (template root, inherited read-only). NOT /usr/local —
# that path is per-AppVM in Qubes and would NOT propagate from the template.
# Hashes verified 2026-06-28 by downloading the assets and sha256-summing them
# (sops cross-checked against the GitHub release-asset digest).

# sops (getsops/sops v3.13.1, linux amd64)
# Fetched with curl (through the updates proxy on Qubes) and installed only after its SHA-256
# matches; Salt's own file.managed download cannot use the proxy.
sops-binary:
  cmd.run:
    - name: 'PX=$(/opt/vault-build/fetch-proxy); mkdir -p /opt/vault-bin && curl -fsSL --connect-timeout 30 --max-time 1200 --retry 3 ${PX:+-x $PX} -o /opt/vault-bin/sops.part https://github.com/getsops/sops/releases/download/v3.13.1/sops-v3.13.1.linux.amd64 && echo "620a9d7e3352ababeca6908cea24a6e8b14ce89a448ddbd3f94f1ef3398f470a  /opt/vault-bin/sops.part" | sha256sum -c - && install -m 0755 /opt/vault-bin/sops.part /opt/vault-bin/sops; rc=$?; rm -f /opt/vault-bin/sops.part; exit $rc'
    - unless: 'echo "620a9d7e3352ababeca6908cea24a6e8b14ce89a448ddbd3f94f1ef3398f470a  /opt/vault-bin/sops" | sha256sum -c --status -'
    - require:
      - pkg: vault-tools-apt
      - file: vault-fetch-proxy

# age-plugin-yubikey v0.5.0 — installed from the upstream .deb (v0.5.1 dropped its
# Linux build, so v0.5.0 is the last with a Linux artifact). Needs pcscd at runtime
# (pulled by the apt manifest). The .deb is hash-verified before dpkg installs it.
age-plugin-yubikey-deb:
  cmd.run:
    - name: 'PX=$(/opt/vault-build/fetch-proxy); D=/opt/vault-bin/age-plugin-yubikey_0.5.0-1_amd64.deb; mkdir -p /opt/vault-bin && curl -fsSL --connect-timeout 30 --max-time 1200 --retry 3 ${PX:+-x $PX} -o $D.part https://github.com/str4d/age-plugin-yubikey/releases/download/v0.5.0/age-plugin-yubikey_0.5.0-1_amd64.deb && echo "bf7a02418de04b3d3df9791e185d493eb344829bca4009247a41bc4d7630b47f  $D.part" | sha256sum -c - && mv $D.part $D; rc=$?; rm -f $D.part; exit $rc'
    - unless: 'echo "bf7a02418de04b3d3df9791e185d493eb344829bca4009247a41bc4d7630b47f  /opt/vault-bin/age-plugin-yubikey_0.5.0-1_amd64.deb" | sha256sum -c --status -'
    - require:
      - pkg: vault-tools-apt
      - file: vault-fetch-proxy
age-plugin-yubikey:
  pkg.installed:
    - sources:
      - age-plugin-yubikey: /opt/vault-bin/age-plugin-yubikey_0.5.0-1_amd64.deb
    - require:
      - cmd: age-plugin-yubikey-deb
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

# What the in-guest environment preflight requires of every ceremony VM, set in the image so the
# disposable passes it (measured on a real Qubes R4.2 VM, 2026-09-24):
# - journald keeps the journal in RAM only: Debian 13 persists it under /var/log/journal.
vault-journald-volatile:
  file.managed:
    - name: /etc/systemd/journald.conf.d/60-regalia-volatile.conf
    - makedirs: True
    - mode: "0644"
    - contents: |
        # regalia vault: never write the journal to disk (preflight-environment.py)
        [Journal]
        Storage=volatile

# - nothing automounts storage. systemd's GPT auto-generator mounts the template disk's EFI
#   partition on /efi on first access (a Qubes VM boots the dom0-provided kernel and never needs
#   it), and udisks2 automounts removable media. A mask in /etc outranks the generated unit.
# - no swap. Qubes gives every VM a swap partition on its volatile disk and turns it on twice:
#   dev-xvdc1-swap.service (swapon early in boot) and the unit systemd generates from the
#   "/dev/xvdc1 swap" line qubes-core-agent ships in /etc/fstab. With either, ceremony RAM can be
#   paged to disk; the in-VM preflight failed on it in the first real disposable (2026-09-25).
#   Masks in /etc outrank both; the fstab conffile is left untouched.
vault-no-swap:
  cmd.run:
    - name: systemctl mask dev-xvdc1-swap.service dev-xvdc1.swap
    - unless: 'test "$(readlink /etc/systemd/system/dev-xvdc1-swap.service)" = /dev/null && test "$(readlink /etc/systemd/system/dev-xvdc1.swap)" = /dev/null'

# - a UTF-8 locale. debian-13-minimal sets none, so the disposable's xterm ran in a single-byte
#   locale and showed every "—" in the scripts' messages as "â" (first real disposable,
#   2026-09-25). qvm-run sessions get their environment from /etc/default/locale (pam_env in
#   /etc/pam.d/qrexec); C.UTF-8 is built into Debian's libc, so no locales package is needed.
vault-utf8-locale:
  file.managed:
    - name: /etc/default/locale
    - mode: "0644"
    - contents: |
        LANG=C.UTF-8

vault-no-automount:
  cmd.run:
    - name: systemctl mask efi.automount udisks2.service
    - unless: 'test "$(readlink /etc/systemd/system/efi.automount)" = /dev/null && test "$(readlink /etc/systemd/system/udisks2.service)" = /dev/null'

