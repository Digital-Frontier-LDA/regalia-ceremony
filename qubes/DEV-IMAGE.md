# Qubes dev image (development and testing) — SEPARATE from the ceremony image

Two images, on purpose:

- **Ceremony / prod image** — the existing `vault-tools` TemplateVM (`salt/vault-tools.sls`). The
  simplest possible: OpenSC and the pinned ceremony tools, **no editor, no AI agents, no network
  during use**. This is the only image a real key ceremony ever runs on. `nitrokey-qualify.sh` runs
  here with nothing but OpenSC.
- **Dev image** — this document. VS Code, the Claude Code and Codex CLIs, Go, git, the repo, and
  network, so you can `auth` once and develop and test. It is **never** used for a real ceremony.

**The boundary is a security control, not a convenience.** The dev image has network and runs AI
CLIs and an editor; a machine that mints money keys must have none of those. Do not install dev tools
into `vault-tools`, and do not attach a production token to a dev AppVM for anything but qualification
against a **staging** token. Under D1 the production Nitrokey HSM 2 is qualified as staging until the
registry flips its role to `prod`; once it is `prod`, it does not touch the dev image.

## Build the dev VM

The simplest image for "auth and go" is a **StandaloneVM** — its own root filesystem and real
network — kept entirely separate from the ceremony `vault-tools` template.

```
# dom0
qvm-create --class StandaloneVM --template debian-12 --label blue dev-regalia
qvm-prefs dev-regalia netvm sys-firewall     # dev needs network; vault-tools must NOT have one
qvm-prefs dev-regalia maxmem 8000
qvm-volume resize dev-regalia:root 30g       # room for Go + VS Code + node
qvm-run -a dev-regalia xterm                 # or open Terminal from the app menu
```

Then, **inside `dev-regalia`** (it has network; these repos are public, so no credentials needed):

```
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/Digital-Frontier-LDA/regalia-ceremony.git ~/regalia-ceremony
# look up the SHA-256 for go1.26.6.linux-amd64.tar.gz at https://go.dev/dl/
sudo GO_SHA256=<paste-that-hash> bash ~/regalia-ceremony/qubes/scripts/dev-image-bootstrap.sh
source /etc/profile.d/dev-bin.sh             # put Go on PATH (or log out/in)
```

TemplateVM alternative (if you want AppVMs to inherit the tools): `qvm-clone debian-12 dev-regalia`,
`qvm-prefs dev-regalia netvm sys-firewall`, run the bootstrap in it, then **`qvm-prefs dev-regalia
netvm none`** to re-isolate the template, and `qvm-create --template dev-regalia --label blue dev`.

The bootstrap installs (into the VM, so a template's AppVMs inherit it):

- **apt** (GPG-authenticated): `git build-essential curl ca-certificates gnupg jq ripgrep`.
- **Go** — the toolchain `kms/go.mod` requires. Fetch the tarball from <https://go.dev/dl/> and
  **verify its SHA-256 against the checksum published there** before extracting to `/opt/dev-bin/go`
  (Debian's `golang` is too old). The bootstrap prints the expected vs actual hash and aborts on a
  mismatch — never run a toolchain off an unverified download.
- **Node.js + npm** — from Debian apt (bookworm ships Node 18, enough for the CLIs) or NodeSource for
  a newer LTS.
- **VS Code** — Microsoft's signed apt repo (`packages.microsoft.com/repos/code`), key pinned into
  `/etc/apt/keyrings`.
- **Claude Code CLI** — `npm install -g @anthropic-ai/claude-code`.
- **Codex CLI** — `npm install -g @openai/codex`.

## Authenticate and test

In `dev-regalia` (or, for the TemplateVM path, the `dev` AppVM):

```
claude            # authenticate once (device flow)
codex login       # authenticate once
git clone https://github.com/Digital-Frontier-LDA/regalia-kms.git ~/regalia-kms
( cd ~/regalia-kms && go test ./... )        # the KMS module builds and its full suite runs here
```

## Qualify a token from the dev image

Attach a **staging** Nitrokey by USB and run the Go instrument (this image has Go):

```
qvm-usb attach dev-regalia sys-usb:<devid>
cd ~/regalia-kms
REGALIA_QUAL_MODULE=/usr/lib/$(uname -m)-linux-gnu/opensc-pkcs11.so \
REGALIA_QUAL_SERIAL=<serial> \
  go test -count=1 -v -run '^TestNitrokeyHSM2Qualification$' ./internal/backend/nitrokey
```

or, with only OpenSC (no Go), the ceremony script: `~/regalia-ceremony/qubes/scripts/nitrokey-qualify.sh
--serial <serial>`. See `NITROKEY-QUALIFY.md`.

## Why a runbook and not (yet) a salt state

`vault-tools.sls` pins every non-apt artifact by SHA-256, verified on a real build. The dev image
pulls Go, VS Code and two npm CLIs whose current hashes must be captured on the machine that builds
it. Do that on the T430, then this runbook becomes `salt/dev-tools.sls` with the hashes filled —
mirroring `vault-tools.sls`. Committing unverified hashes now would either fail to apply or assert a
checksum nobody checked.
