#!/usr/bin/env bash
# dev-image-bootstrap.sh — provision the Qubes DEV TemplateVM (development and testing).
#
# Run as root INSIDE the dev template (which has network during the build), NOT in dom0 and NEVER in
# the vault-tools ceremony template:
#   qvm-run -u root --pass-io dev-regalia 'bash -s' < qubes/scripts/dev-image-bootstrap.sh
#
# It installs Go, git, Node/npm, VS Code, and the Claude Code + Codex CLIs into the template so dev
# AppVMs inherit them. This image has network and AI agents; it must never run a real key ceremony.
# See qubes/DEV-IMAGE.md.
#
# The Go toolchain is verified: pass GO_SHA256 (from https://go.dev/dl/ for this arch) or the script
# refuses to install it. apt and the Microsoft repo are GPG-authenticated by apt itself.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root in the dev template" >&2; exit 1; }
arch="$(dpkg --print-architecture)"                 # amd64 on the T430
GO_VERSION="${GO_VERSION:-1.26.6}"
GO_SHA256="${GO_SHA256:-}"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  git build-essential curl ca-certificates gnupg jq ripgrep nodejs npm

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
npm install -g @anthropic-ai/claude-code @openai/codex

echo "dev image ready. In a dev AppVM: 'claude' and 'codex login' to authenticate, then clone the repo."
echo "Go: $(/opt/dev-bin/go/bin/go version 2>/dev/null || echo 'not on PATH until re-login')"
