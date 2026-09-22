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

# --- Pico HSM: register its VID/PID with libccid ----------------------------------------------
# WITHOUT THIS A PICO IS INVISIBLE ON LINUX. libccid only binds readers listed in its Info.plist,
# and 1.6.2 (Debian 13) has no entry for 0x2E8A — so pcscd never creates a reader, `opensc-tool
# --list-readers` shows nothing, and every Pico drill fails as if no card were attached (measured
# on dev-regalia 2026-09-17; the bench work was done on macOS, whose CCID driver has its own list).
# The three arrays are index-aligned, so an entry is appended to each.
plist=/etc/libccid_Info.plist
if [ -w "$plist" ] || [ "$(id -u)" = 0 ]; then
  python3 - "$plist" <<'PICO'
import re, sys
p = sys.argv[1]
s = open(p).read()
# THE PAIR, AT THE SAME INDEX — not "0x2E8A appears somewhere". The three arrays are
# index-aligned, and libccid binds a reader only when the vendor and product entries line up. A
# plist that already lists 0x2E8A for a DIFFERENT product (another RP2040/RP2350 device) satisfied
# a VID-only search, so this exited without adding 0x10FD and the self-check below then accepted
# the unrelated entry: the Pico stays invisible and every drill fails as if no card were attached.
def entries(text, key):
    m = re.search(r'<key>' + key + r'</key>\s*<array>(.*?)</array>', text, re.S)
    return re.findall(r'<string>([^<]*)</string>', m.group(1)) if m else []

vids, pids = entries(s, 'ifdVendorID'), entries(s, 'ifdProductID')
if any(v.upper() == '0X2E8A' and p_.upper() == '0X10FD' for v, p_ in zip(vids, pids)):
    print("libccid: Pico entry already present"); raise SystemExit(0)
for key, val in (('ifdVendorID', '0x2E8A'), ('ifdProductID', '0x10FD'), ('ifdFriendlyName', 'Pico Key')):
    m = re.search(r'(<key>' + key + r'</key>\s*<array>)(.*?)(</array>)', s, re.S)
    if not m:
        print("libccid: array %s not found — leaving the plist alone" % key); raise SystemExit(0)
    s = s[:m.end(2)] + "\n\t\t<string>%s</string>\n\t" % val + s[m.end(2):]
arrays = {k: re.findall(r'<string>([^<]*)</string>',
          re.search(r'<key>' + k + r'</key>\s*<array>(.*?)</array>', s, re.S).group(1))
          for k in ('ifdVendorID', 'ifdProductID', 'ifdFriendlyName')}
if len({len(v) for v in arrays.values()}) != 1:
    print("libccid: arrays would be misaligned — refusing to write"); raise SystemExit(1)
open(p, 'w').write(s)
print("libccid: registered Pico HSM 0x2E8A:0x10FD")
PICO
  # RESTART IS NOT ENOUGH, AND ON ITS OWN IT IS THE WRONG THING. Debian runs pcscd with
  # `--foreground --auto-exit`, so the daemon leaves about a minute after the last client
  # disconnects. Restarting the SERVICE therefore buys one minute; what keeps the readers
  # available is pcscd.socket, which starts it again on the next request. With that socket
  # inactive — the state this box was in — a drill run any time after the last one reports
  #
  #     No smart card readers found.
  #
  # with two cards plainly on the USB bus, and the only way back is to start pcscd by hand.
  # Measured 2026-09-22: it had to be restarted three times in one session before this was
  # noticed, and each time it looked like a card fault.
  systemctl enable --now pcscd.socket 2>/dev/null || true
  systemctl restart pcscd 2>/dev/null || true
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
  # THE FILE THAT DECIDES WHAT ROOT INSTALLS MUST BE PINNED TO CONTENT, NOT TO A MOVING REF.
  # `--require-hashes` pins the PACKAGES named in this file; it says nothing about the file itself.
  # Fetched from a branch, whoever can move that branch chooses the package list — and pip then
  # runs as root on this image. Two ways to pin it, and nothing else is accepted:
  #   REQ_REF=<40-hex commit sha>   the content is the commit's, and a commit id is a digest
  #   REQ_SHA256=<sha256>           verified against the bytes that arrive
  REQ_REF="${REQ_REF:-main}"
  pinned_by_ref=0
  case "$REQ_REF" in
    *[!0-9a-fA-F]*) ;;                       # not hex: a branch or tag name
    ????????????????????????????????????????) pinned_by_ref=1 ;;   # exactly 40 hex digits
  esac
  if [ "$pinned_by_ref" != 1 ] && [ -z "${REQ_SHA256:-}" ]; then
    echo "REFUSING to install from https://raw.githubusercontent.com/.../${REQ_REF}/qubes/requirements.txt:" >&2
    echo "  that ref can move, and this file decides what pip installs AS ROOT on this image." >&2
    echo "  Re-run with one of:" >&2
    echo "    REQ_REF=<40-hex commit sha>  (content-addressed)" >&2
    echo "    REQ_SHA256=<sha256 of the file>" >&2
    echo "  or run this from a checkout, where qubes/requirements.txt is read directly." >&2
    exit 2
  fi
  curl -fsSL -o "$tmp/ceremony-req.txt" \
    "https://raw.githubusercontent.com/Digital-Frontier-LDA/regalia-ceremony/${REQ_REF}/qubes/requirements.txt"
  if [ -n "${REQ_SHA256:-}" ]; then
    got="$(sha256sum "$tmp/ceremony-req.txt" | awk '{print $1}')"
    [ "$got" = "$REQ_SHA256" ] || {
      echo "requirements.txt digest mismatch: got $got, expected $REQ_SHA256 — refusing" >&2; exit 1; }
    echo "requirements.txt: sha256 verified against REQ_SHA256"
  else
    echo "requirements.txt: fetched at commit $REQ_REF (content-addressed)"
  fi
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
# The PAIR at the same index, for the reason above: 0x2E8A present against another product is not
# a registered Pico, and a self-check that accepts it declares an image ready that cannot see the
# card.
python3 - /etc/libccid_Info.plist <<'PICOCHECK' || missing=1
import re, sys
s = open(sys.argv[1]).read()
def entries(key):
    m = re.search(r'<key>' + key + r'</key>\s*<array>(.*?)</array>', s, re.S)
    return re.findall(r'<string>([^<]*)</string>', m.group(1)) if m else []
ok = any(v.upper() == '0X2E8A' and p.upper() == '0X10FD'
         for v, p in zip(entries('ifdVendorID'), entries('ifdProductID')))
if not ok:
    sys.stderr.write("MISSING: aligned libccid entry for the Pico HSM (0x2E8A:0x10FD)\n")
raise SystemExit(0 if ok else 1)
PICOCHECK
p11="$(find /usr/lib -name opensc-pkcs11.so -path '*-linux-gnu*' 2>/dev/null | head -1)"
[ -n "$p11" ] || { echo "MISSING: opensc-pkcs11.so" >&2; missing=1; }
[ "$missing" = 0 ] || { echo "dev image INCOMPLETE — see MISSING lines above" >&2; exit 1; }

echo "dev image ready (self-check passed). In a dev AppVM: 'claude' and 'codex login' to authenticate, then clone the repo."
echo "PKCS#11 module: $p11   SCSH_HOME=/opt/dev-bin/scsh-${SCSH_VERSION}   CEREMONY_VENV=/opt/dev-bin/regalia-venv"
echo "Go: $(/opt/dev-bin/go/bin/go version 2>/dev/null || echo 'not on PATH until re-login')"
