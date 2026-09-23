# Debian emulator image for the custodial-wallet key ceremony.
#
# Mirrors the vault-tools TemplateVM toolchain (apt manifest + pip SLIP-39) and adds a
# faithful EMULATOR for every hardware route ceremony.sh can take, so the whole wizard
# can be driven end-to-end in CI with no physical tokens, reader, printer, or burner:
#
#   route             real device            emulator in this image
#   ----------------  ---------------------  ---------------------------------------
#   pkcs11 keygen/    Nitrokey HSM 2         SoftHSM2 (real PKCS#11; real secp256k1
#     sign/pubkey       (SmartCard-HSM)        keygen + ECDSA sign + pubkey DER)
#   sc-hsm DKEK share  SmartCard-HSM host op  real sc-hsm-tool (host-side, no card)
#   sc-hsm init/wrap   SmartCard-HSM card op  functional model (documented gap)
#   age identity       YubiKey 5 (PIV)        age software identity behind a plugin shim
#   SLE-4442 card      SLE 4442 memory card   sle4442-vpicc.py over real pcscd + vpcd
#   printing           USB Brother + CUPS     CUPS + cups-pdf (real PDFs)
#   M-DISC burn/verify 2x optical drives      xorriso ISO + loopback cross-"drive" verify
#
# Build context is qubes (so the image can bake requirements.txt + the
# real ceremony scripts). Use the wrapper, which sets the context for you:
#
#   qubes/emulator/build.sh
#   # equivalently:
#   docker build -t ceremony-emu -f qubes/emulator/Dockerfile \
#                qubes
#
# Run  :  docker run --rm -it ceremony-emu              # boots emulators, drops to a shell
#         docker run --rm ceremony-emu run-route-tests  # CI: drive every route, assert
# PINNED BY DIGEST, because everything this image stands on is already pinned and the floor was
# not. sops is fetched by SHA-256 and the Python dependencies by `pip3 install --require-hashes`,
# so the base was the single input to a security-ceremony emulator that could change with no change
# in this repository — and the one every other pin sits on top of. hsm-host-role's Dockerfile has
# been pinned this way since it was written; this file was the outlier.
#
# The digest is the multi-arch index, so it still resolves per-architecture: linux/amd64 for CI and
# linux/arm64 for a developer machine both come from it.
#
# TO UPDATE, deliberately rather than by drift:
#
#   curl -s https://hub.docker.com/v2/repositories/library/debian/tags/bookworm-slim \
#     | python3 -c 'import sys,json; print(json.load(sys.stdin)["digest"])'
#   docker manifest inspect debian:bookworm-slim@<digest>   # confirm it resolves
#
# A pin means base-image security updates arrive when someone bumps this line and not before. That
# is the trade this file wants: an emulator whose result is only evidence if the thing it ran on is
# known. Bumping it is a reviewable commit; drifting is not.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_BREAK_SYSTEM_PACKAGES=1

# --- ceremony toolchain (mirrors packages.txt) + emulator stack ---------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      # ceremony toolchain
      age opensc pcscd libccid pcsc-tools yubikey-manager ykcs11 ssss qrencode zbar-tools \
      gnupg scdaemon secure-delete python3 python3-pip python3-dev build-essential xxd \
      # PKCS#11 HSM emulator
      softhsm2 opensc-pkcs11 \
      # virtual smart-card reader (vpcd) so the SLE-4442 vpicc shows up via PC/SC
      vsmartcard-vpcd \
      # printer emulator: CUPS + PDF backend
      cups cups-client printer-driver-cups-pdf \
      # optical / M-DISC emulator
      xorriso \
      # pyscard for the SLE-4442 manager CLI route
      python3-pyscard \
      # iproute2 provides `ip` — preflight fails CLOSED without it (air-gap unverifiable)
      iproute2 \
      # vim — sops-edit-airgap.sh fails CLOSED without a hardened editor (checks `command -v vim`)
      vim \
      ca-certificates procps curl \
  && rm -rf /var/lib/apt/lists/*

# --- sops (hash-pinned, same as salt/vault-tools.sls) — preflight.sh checks for it ----
RUN curl -fsSL -o /usr/local/bin/sops \
      https://github.com/getsops/sops/releases/download/v3.13.1/sops-v3.13.1.linux.amd64 \
 && echo "620a9d7e3352ababeca6908cea24a6e8b14ce89a448ddbd3f94f1ef3398f470a  /usr/local/bin/sops" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/sops

# --- SLIP-39 `shamir` CLI (hash-pinned, same posture as the real image) -------------
# (paths are relative to the build context = qubes)
COPY requirements.txt /opt/vault-ceremony/requirements.txt
RUN pip3 install --require-hashes -r /opt/vault-ceremony/requirements.txt

# --- bake the real ceremony scripts (so the wizard itself is what we test) -----------
COPY scripts /opt/vault-ceremony/scripts
COPY recovery /opt/vault-ceremony/recovery

# --- emulator code -------------------------------------------------------------------
COPY emulator/bin /opt/vault-emu/bin
COPY emulator/tests /opt/vault-emu/tests
RUN chmod +x /opt/vault-emu/bin/* /opt/vault-emu/tests/*.sh 2>/dev/null || true

# Put the emulator shims (age-plugin-yubikey, sc-hsm-tool model, sle4442-manager) and
# the real ceremony scripts on PATH. The shims live in /opt/vault-emu/bin which the
# wizard's guard_no_stubs allows (it only rejects shims under /tmp etc).
ENV PATH="/opt/vault-emu/bin:/opt/vault-ceremony/scripts:${PATH}"
ENV SOFTHSM2_CONF=/opt/vault-emu/softhsm2.conf
ENV CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1

WORKDIR /opt/vault-emu
ENTRYPOINT ["/opt/vault-emu/bin/emu-entrypoint.sh"]
CMD ["shell"]
