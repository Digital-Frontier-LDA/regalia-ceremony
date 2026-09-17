#!/usr/bin/env bash
# dev-image-bootstrap.sh — provision the Qubes DEV TemplateVM (development and testing).
#
# Run as root INSIDE the dev template (which has network during the build), NOT in dom0 and NEVER in
# the vault-tools ceremony template:
#   sudo GO_SHA256=<sha256 from go.dev> bash ~/regalia-ceremony/qubes/scripts/dev-image-bootstrap.sh
#
# It installs Go, git, Node/npm, VS Code, and the Claude Code + Codex CLIs into the template so dev
# AppVMs inherit them, plus everything the repo's test and hardware-qualification paths need: the
# smart-card stack (OpenSC, pcscd, SoftHSM2), the cgo headers the `-tags piv` build links against,
# the emulator-suite tools, Smart Card Shell, and a hash-pinned Python venv. This image has network
# and AI agents; it must never run a real key ceremony. See qubes/DEV-IMAGE.md.
#
# WHY THE LIST IS THIS LONG. The first Nitrokey HSM 2 gate run (2026-09-17) needed ten things
# installed by hand on a VM built from the previous version of this script: gh, python3-venv, a JRE,
# unzip, Smart Card Shell, xxd, shellcheck, age/qrencode/ssss/yubikey-manager, and
# pkg-config + libpcsclite-dev (without which `go build -tags piv ./...` fails). A dev image that
# cannot run the repo's own suites pushes that work onto whoever is at the bench.
#
# Every download is verified: Go by GO_SHA256 (from https://go.dev/dl/), Smart Card Shell by the
# SHA-256 recorded in qubes/PICO-DRILL-RUNBOOK.md, Python packages by --require-hashes. apt and the
# Microsoft repo are GPG-authenticated by apt itself. The script ends with a self-check that fails
# if anything it promised is absent.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root in the dev template" >&2; exit 1; }
# The checkout this script runs from provides qubes/requirements.txt. Run from stdin (no checkout),
# the file is fetched from this public repository at REQ_REF instead.
here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
REPO_DIR="${REPO_DIR:-}"
if [ -z "$REPO_DIR" ] && [ -n "$here" ] && [ -r "$here/../requirements.txt" ]; then
  REPO_DIR="$(cd "$here/../.." && pwd)"
fi
arch="$(dpkg --print-architecture)"                 # amd64 on the T430
GO_VERSION="${GO_VERSION:-1.26.6}"
GO_SHA256="${GO_SHA256:-}"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  git build-essential curl ca-certificates gnupg jq ripgrep nodejs npm gh unzip xxd shellcheck \
  python3 python3-pip python3-venv \
  pkg-config libpcsclite-dev \
  opensc opensc-pkcs11 pcscd libccid pcsc-tools softhsm2 \
  age qrencode zbar-tools ssss yubikey-manager python3-pyscard

# Smart Card Shell needs a Java runtime. Debian 12 ships openjdk-17, Debian 13 openjdk-21: take the
# newest headless JRE this release actually has rather than hardcoding one that may not exist.
jre=""
for v in 25 21 17; do
  if apt-cache show "openjdk-${v}-jre-headless" >/dev/null 2>&1; then jre="openjdk-${v}-jre-headless"; break; fi
done
[ -n "$jre" ] || { echo "no openjdk-{25,21,17}-jre-headless in this release's apt sources" >&2; exit 1; }
apt-get install -y --no-install-recommends "$jre"

# --- Go (verified tarball) --------------------------------------------------------------------
go_tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
if [ -z "$GO_SHA256" ]; then
  echo "REFUSING to install Go without a checksum. Look up ${go_tarball} at https://go.dev/dl/ and re-run:" >&2
  echo "  GO_SHA256=<sha256 from go.dev> bash dev-image-bootstrap.sh" >&2
  exit 2
fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$go_tarball" "https://go.dev/dl/${go_tarball}"
actual="$(sha256sum "$tmp/$go_tarball" | cut -d' ' -f1)"
if [ "$actual" != "$GO_SHA256" ]; then
  echo "Go checksum mismatch: expected $GO_SHA256, got $actual — refusing" >&2
  exit 1
fi
rm -rf /opt/dev-bin/go
mkdir -p /opt/dev-bin
tar -C /opt/dev-bin -xzf "$tmp/$go_tarball"          # -> /opt/dev-bin/go
cat > /etc/profile.d/dev-bin.sh <<'PROFILE'
# Baked into the dev-regalia template.
export PATH="/opt/dev-bin/go/bin:$HOME/go/bin:$PATH"
PROFILE
chmod 0644 /etc/profile.d/dev-bin.sh

# --- VS Code (Microsoft signed apt repo) ------------------------------------------------------
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /etc/apt/keyrings/microsoft.gpg
chmod 0644 /etc/apt/keyrings/microsoft.gpg
echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main" \
  > /etc/apt/sources.list.d/vscode.list
apt-get update
apt-get install -y --no-install-recommends code

# --- Claude Code + Codex CLIs (npm, global) ---------------------------------------------------
# INSTALL_AGENT_CLIS=0 refreshes an existing dev VM without replacing CLIs that may be running (the
# self-check below still requires both to be present).
if [ "${INSTALL_AGENT_CLIS:-1}" = 1 ]; then
  npm install -g @anthropic-ai/claude-code @openai/codex
fi

# --- Smart Card Shell (verified zip) ----------------------------------------------------------
# CardContact publish no checksum or signature; this is the hash recorded on first fetch
# (PICO-DRILL-RUNBOOK.md) and re-matched on dev-regalia 2026-09-17. A mismatch means the download
# changed, not that the pin is stale: stop and find out why.
SCSH_VERSION="3.18.77"
SCSH_SHA256="1e5a065b7888a660a088956d110ce5539e85b76cf3c3f02eb57e4d3104bcf280"
curl -fsSL -o "$tmp/scsh.zip" "https://www.openscdp.org/download/scsh3/scsh-${SCSH_VERSION}.zip"
actual="$(sha256sum "$tmp/scsh.zip" | cut -d' ' -f1)"
if [ "$actual" != "$SCSH_SHA256" ]; then
  echo "Smart Card Shell checksum mismatch: expected $SCSH_SHA256, got $actual — refusing" >&2
  exit 1
fi
rm -rf "/opt/dev-bin/scsh-${SCSH_VERSION}"
unzip -q "$tmp/scsh.zip" -d "$tmp/scsh"
# The zip nests the tree one level down (scsh-3.18.77/scsh-3.18.77/scriptrunner); install the level
# that holds scriptrunner, so SCSH_HOME is the directory every script in this repo cds into.
runner="$(find "$tmp/scsh" -maxdepth 3 -name scriptrunner -type f | head -1)"
[ -n "$runner" ] || { echo "scriptrunner not found in the Smart Card Shell zip" >&2; exit 1; }
mv "$(dirname "$runner")" "/opt/dev-bin/scsh-${SCSH_VERSION}"
chmod 0755 "/opt/dev-bin/scsh-${SCSH_VERSION}/scriptrunner" "/opt/dev-bin/scsh-${SCSH_VERSION}/scsh3"

# --- Python venv (hash-pinned) ----------------------------------------------------------------
# The ceremony scripts' dependencies (pycvc, shamir-mnemonic, …). hsm-auto-import.sh prefers
# $CEREMONY_VENV, so pointing it here makes the import path find pycvc without touching the system
# interpreter. The hash check refuses an unpinned file however it arrived.
if [ -n "$REPO_DIR" ] && [ -r "$REPO_DIR/qubes/requirements.txt" ]; then
  cp "$REPO_DIR/qubes/requirements.txt" "$tmp/ceremony-req.txt"
else
  REQ_REF="${REQ_REF:-main}"
  curl -fsSL -o "$tmp/ceremony-req.txt" \
    "https://raw.githubusercontent.com/Digital-Frontier-LDA/regalia-ceremony/${REQ_REF}/qubes/requirements.txt"
fi
grep -q -- '--hash=sha256:' "$tmp/ceremony-req.txt" \
  || { echo "requirements.txt carries no hashes — refusing an unpinned install" >&2; exit 1; }
rm -rf /opt/dev-bin/regalia-venv
python3 -m venv /opt/dev-bin/regalia-venv
/opt/dev-bin/regalia-venv/bin/pip install --quiet --require-hashes -r "$tmp/ceremony-req.txt"

cat >> /etc/profile.d/dev-bin.sh <<PROFILE
export SCSH_HOME="/opt/dev-bin/scsh-${SCSH_VERSION}"
export CEREMONY_VENV="/opt/dev-bin/regalia-venv"
PROFILE

# --- Self-check -------------------------------------------------------------------------------
# Every promise above, checked. A partial image is worse than a failed build: it looks usable.
missing=0
for c in git go gh jq rg node npm code claude codex unzip xxd shellcheck pkg-config \
         pkcs11-tool opensc-tool sc-hsm-tool pkcs15-tool pcscd softhsm2-util \
         age qrencode zbarimg ssss-split ykman java; do
  PATH="/opt/dev-bin/go/bin:$PATH" command -v "$c" >/dev/null 2>&1 || { echo "MISSING: $c" >&2; missing=1; }
done
pkg-config --exists libpcsclite || { echo "MISSING: libpcsclite pkg-config (needed by -tags piv)" >&2; missing=1; }
[ -x "/opt/dev-bin/scsh-${SCSH_VERSION}/scriptrunner" ] || { echo "MISSING: Smart Card Shell scriptrunner" >&2; missing=1; }
/opt/dev-bin/regalia-venv/bin/python -c 'import cvc, cryptography, shamir_mnemonic, mnemonic' \
  || { echo "MISSING: a Python package in /opt/dev-bin/regalia-venv" >&2; missing=1; }
p11="$(find /usr/lib -name opensc-pkcs11.so -path '*-linux-gnu*' 2>/dev/null | head -1)"
[ -n "$p11" ] || { echo "MISSING: opensc-pkcs11.so" >&2; missing=1; }
[ "$missing" = 0 ] || { echo "dev image INCOMPLETE — see MISSING lines above" >&2; exit 1; }

echo "dev image ready (self-check passed). In a dev AppVM: 'claude' and 'codex login' to authenticate, then clone the repo."
echo "PKCS#11 module: $p11   SCSH_HOME=/opt/dev-bin/scsh-${SCSH_VERSION}   CEREMONY_VENV=/opt/dev-bin/regalia-venv"
echo "Go: $(/opt/dev-bin/go/bin/go version 2>/dev/null || echo 'not on PATH until re-login')"
