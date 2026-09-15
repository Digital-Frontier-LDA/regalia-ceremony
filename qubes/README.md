# Qubes air-gapped vault — pre-built ceremony image

A reproducible Qubes setup for the custodial-wallet key ceremonies described in
the operator's private secrets inventory (YubiKey `ops` identity, Nitrokey HSM 2
funding key, SLIP-0039 / DKEK Shamir shares). You build the **tools** into a TemplateVM
once (online), then run every ceremony in an **air-gapped AppVM/disposable** built from
it. No secret ever touches a networked machine.

> **Review before you run.** These artifacts provision tooling and stage *documented
> command sequences* — they deliberately do **not** auto-execute the key-touching steps.
> Read each command, understand it, and run it by hand on the airgap qube. This handles
> real money keys; there is no undo.

Supported Qubes and Debian-live execution profiles, their invariant controls, and
the teardown evidence contract are specified in
[`CEREMONY-PROFILES.md`](CEREMONY-PROFILES.md). Installed Debian is intentionally
rejected because disposability cannot be proved from inside that guest.

## Why Qubes fits

| Qubes concept | Role here |
|---|---|
| **TemplateVM** (`vault-tools`) | where the tools install (`apt`/`pip`/verified binaries). Its root is inherited **read-only** by every derived qube. |
| **AppVM / DisposableVM** (`vault`), `netvm = none` | the actual ceremony runs here, **air-gapped**. A disposable leaves no trace on shutdown. |
| **`sys-usb`** | holds the USB controller; the smartcard reader / YubiKey / HSM are **passed through** to `vault` with `qvm-usb`. |
| Per-qube `/home` + `/usr/local` | NOT inherited from the template — so ceremony scripts are baked into **`/opt/vault-ceremony`** (template root), and generated key material lives only in the throwaway AppVM. |

## What can / cannot be pre-installed

- **Pre-baked:** `age`, `age-plugin-yubikey`, `sops`, OpenSC (`pkcs11-tool`, `sc-hsm-tool`),
  `pcscd`, `ykman`, `ssss`, SLIP-0039 `shamir`, `qrencode`/`zbar` (paper QR), `gnupg`,
  `python3` + `derive-akash-address.py` (HSM pubkey → akash address) +
  `make-recovery-card.py` (DVD-case-sized break-glass instruction card) +
  `metal-stamp-worksheet.py` (SLIP-39 metal-plate stamping worksheet + read-back verify) +
  `bip39-slip39-backup.py` (back up a BIP39 wallet seed as SLIP-39 shares — Option B;
  `--from-entropy` to encode dice/hardware entropy) + `record-build-evidence.sh`, the
  ceremony scripts, `requirements.txt` (hash-pinned pip deps), and the `recovery/`
  break-glass runbooks. (This README is **not** baked into the image — the Salt formula
  installs `scripts/`, `recovery/`, and `requirements.txt`; keep a checkout handy.)
- **Never pre-baked:** any private key, mnemonic, PIN, or Shamir share. All of that is
  born on the air-gapped qube during the ceremony and leaves only as sealed offline media.

## Build (run in **dom0**)

```bash
# 1. clone a fresh template for the tools (keeps your base template clean)
qvm-clone debian-12 vault-tools

# 2. apply the Salt formula: installs apt packages + the non-apt binaries + scripts
#    (the TEMPLATE needs net to install; the vault AppVM below will not)
sudo cp -r salt/* /srv/salt/ ; sudo cp -r scripts /srv/salt/vault-ceremony-scripts
sudo cp requirements.txt /srv/salt/vault-ceremony-requirements.txt   # hash-pinned pip deps
sudo cp -r recovery /srv/salt/vault-ceremony-recovery               # break-glass runbooks (go on each M-DISC)
sudo qubesctl --skip-dom0 --targets=vault-tools state.apply vault-tools

# 3. create the AIR-GAPPED vault qube (no netvm) from that template
qvm-create --template vault-tools --label black vault
qvm-prefs vault netvm ''            # <- air-gap: no network, ever
qvm-prefs vault netvm none 2>/dev/null || true
qvm-prefs vault maxmem 0            # <- DISABLE memory ballooning (fixed RAM; dom0 can't reclaim/inspect pages)
qvm-prefs vault autostart False

# 4. RECOMMENDED: run ceremonies in a DisposableVM (no persistent /home; RAM wiped on
#    shutdown). Make this template a DispVM template and launch a fresh dispVM per ceremony.
qvm-prefs vault template_for_dispvms True
qvm-features vault appmenus-dispvm 1
#    Use a plain AppVM only if you have a documented reason (it persists /home).

# 5. snapshot the ready image so you can restore it anywhere
qvm-backup --dest-vm <backup-store> vault-tools
```

Before each real ceremony, run **both** preflights: `preflight-dom0.sh <vault>` in **dom0**
(asserts netvm/template/`maxmem 0`/DispVM/dom0-swap) and `/opt/vault-ceremony/preflight.sh`
**inside** the qube (air-gap, swap off, `/dev/shm` tmpfs, no history/core-dumps, USB-only
printer). The wizard also **fails closed** if `/dev/shm` isn't tmpfs and **refuses to run if a
stubbed tool is on PATH** (guard against the test harnesses). Edit SOPS secrets with
`sops-edit-airgap.sh` so the editor's temp/swap/undo files stay in tmpfs.
The in-guest preflight automatically derives the execution profile from QubesDB or
Debian-live mount evidence; there is no `--profile` override. Set
`CEREMONY_EVIDENCE_DIR` before a real run to retain its non-secret teardown JSON.

The non-apt tools are **version + SHA-256 pinned** in [`salt/vault-tools.sls`](salt/vault-tools.sls)
(hashes verified 2026-06-28 by downloading the assets and summing them): `sops` v3.13.1
(`620a9d7e…`) and `age-plugin-yubikey` **v0.5.0** via its upstream `.deb` (`bf7a0241…`) —
v0.5.1 dropped its Linux build, so v0.5.0 is the last with a Linux artifact (the formula
notes the `cargo install --locked` alternative for newer versions).

## Use (per ceremony)

```bash
# in dom0: attach the reader/token to the air-gapped vault
qvm-usb attach vault sys-usb:<device-id>     # qvm-usb list to find it

# in the vault qube — the GUIDED script walks every step (preflight, YubiKey, HSM,
# Shamir, printing, M-DISC archive, drill), shows each command, and confirms before running:
/opt/vault-ceremony/ceremony.sh

# or run the pieces by hand (it just orchestrates these):
/opt/vault-ceremony/preflight.sh             # tools + reader + printer + drives + air-gap (fails closed)
#   age-plugin-yubikey --generate --pin-policy once --touch-policy never  # unattended ops identity
#   # For an explicitly interactive ceremony only: set CEREMONY_YUBI_TOUCH_POLICY=always
#   sc-hsm-tool --create-dkek-share dkek.pbe --pwd-shares-threshold 4 --pwd-shares-total 6
#   slip39-mint.py --threshold 4 --shares 6  # SLIP-0039 shares -> qrencode -> archival paper
#   (NEVER `shamir create` — the CLI prints the master secret to stdout; the minter never
#    emits it and reconstruct-verifies every 4-of-6 subset before writing)
# print/seal shares, then power off the disposable (RAM wiped).
```

`ceremony.sh` is built for **both** tokens: a YubiKey step (PIV/P-256 `ops` age identity)
**and** a Nitrokey HSM 2 step (DKEK 4-of-6 backup + on-device secp256k1 funding key). It
prints paper shares to a CUPS printer and never echoes a secret to the terminal (secrets
flow file → `qrencode`/`lp`; workdir is tmpfs in RAM, shredded on exit).

**Recovery instruction card (menu step 6 / `make-recovery-card.py`):** prints a
DVD-case-sized card with the break-glass *procedure* — how to reconstruct from the Shamir
shares + M-DISC — with a dashed cut-guide + corner crop marks. Cut along the line and slip
it into the DVD keep-case beside the M-DISC. It contains **no secrets**, so it prints
freely (default 120×180 mm on Letter; `--paper a4`, `--width-mm/--height-mm` to resize).
Pass `--case-id DF-BG-01 --seal-serial HOLO-000001` (step 6 prompts for these) to print the
case ↔ holographic-sticker binding on the card, so a swapped card/case is detectable.

**Metal-plate backups:** `metal-stamp-worksheet.py` converts a SLIP-39 share into the
4-letter-prefix grid to stamp into metal (punch set), and `--verify` reads the stamped
prefixes back to catch a mis-stamp before you rely on the plate. See SECRETS.md →
"Metal-plate (punch-set) backups".

**Break-glass / incapacitation:** [`recovery/`](recovery/) holds the runbooks that must be
**burned onto every M-DISC** so a recoverer needs no repo/network: `RECOVERY-START-HERE.txt`
(plain-English, for a non-technical heir → engage the named helper), `RECOVERY-TECHNICAL.md`
(the exact offline recipe), and `custodian-contact-sheet.example.txt` (the **sealed sheet
placed in each case** — your chosen model — listing all 6 custodians, the executor, the
authorization trigger, the recorded funding address, and the safe sweep destination; fill in
the placeholders). The archive step stages this kit automatically; the recovery card points
to it. Fill the placeholders ([OWNER], executor, helper, custodians, safe destination) before
sealing.

**Seal registry:** record the holographic sticker serials in
[`seal-registry.example.yaml`](seal-registry.example.yaml) — non-secret integrity data
(serial ↔ case ↔ contents-hash) openly; the `serial → custodian → location` map in SOPS
(`seal-custody.sops.yaml`) only. See SECRETS.md → "Seal registry & tamper-evidence".

**Rehearse it on any machine first** (four harnesses, all throwaway data):
- **`bash scripts/simulate-ceremony.sh`** — run the wizard **interactively yourself**:
  hardware + printer are stubbed (clearly marked `[SIMULATED]`), but Shamir/QR/age/address
  derivation are REAL. You pick menu items, answer the prompts, and get real shares + a
  derived address; "printouts" collect in an outbox you can open. This is the one to use to
  practise the sequence before the Qubes run.
- **`bash scripts/test-ceremony.sh`** — automated per-step smoke test.
- **`bash scripts/recital-ceremony.sh`** (`--show` for the transcript) — automated full
  dress rehearsal: real interactive menu driven end-to-end + failure paths + share recovery
  + in-wizard address derivation + shred + leak scan.
- **`bash scripts/prove-ceremony.sh`** — fully automated run that emits **cryptographic
  proofs** (SHA-256 equality, address vs the cosmjs-canonical value) and writes a proof
  bundle (report + the 6 ssss shares + 6 SLIP-39 word-shares + a QR PNG) you can inspect.

## Hardware notes (T430-class airgap host)

- **Two optical drives (internal + external) = burn on one, verify-read on the other.**
  A marginal burn the *writing* drive can still read but a second drive cannot is the
  classic silent failure; cross-drive verify catches it. `ceremony.sh` step 4 + `preflight`
  check for ≥2 `/dev/sr*`.
- **M-DISC:** DVD M-DISC is written like DVD+R and most burners handle it, but confirm the
  drive's M-DISC support. DVD M-DISC ≈ 4.7 GB — vastly more than a key/shares need. (T430
  internal is DVD-multi: DVD M-DISC only, no Blu-ray.)
- **SD / USB flash is NOT archival.** Flash loses charge over years unpowered — fine as
  working/transfer media (the internal card reader), **never** for cold escrow. Archive
  only to **M-DISC + paper**.
- **Two reader types, don't confuse them:** the *smartcard* reader (for the HSM / YubiKey
  as a CCID device) vs. the *SD card* reader. Pass the smartcard/USB token through to the
  vault with `qvm-usb`.
- **Printer:** USB-attached Brother laser with **no network and no internal storage**;
  power-cycle it after printing to clear page memory. The CUPS spool lives in the
  disposable qube and dies on shutdown.

## Verification status (what's actually been tested)

| Tool | Status |
|---|---|
| `sops` 3.13.1, `age`, age recipient round-trip | ✅ exercised on real files (`age` v1.3.1 on macOS; the vault image ships Debian bookworm's `age` 1.1.1) |
| `ssss` 4-of-6 split/combine | ✅ recovers with 4, does **not** leak with 3 |
| SLIP-0039 `shamir` 4-of-6 | ✅ master secret recovered from a 4-subset |
| `qrencode` (encode) | ✅ produces scannable PNG |
| `simulate-ceremony.sh` interactive rehearsal | ✅ boots through preflight, real menu drives, HSM step derives + "prints" the real funding address, Shamir/QR/age real |
| `prove-ceremony.sh` automated proof run | ✅ 12/12 proven: address == cosmjs-canonical; ssss & SLIP-39 4-of-6 reconstruct (hash-identical) and 3 shares leak nothing; age round-trip; QR valid PNG; no leak; workdir shredded |
| `ceremony.sh` whole-wizard dry run (`test-ceremony.sh`) | ✅ all steps walk; 4-of-6 ssss reconstructs; **no secret leaks to stdout** |
| `ceremony.sh` full dress rehearsal (`recital-ceremony.sh`) | ✅ real interactive menu + failure paths (air-gap refusal, missing tool, declined confirm) + multi-subset ssss & SLIP-39 recovery from the wizard's own shares + in-wizard HSM→address derivation + shred + idempotency; **no leaks** |
| `derive-akash-address.py` (HSM pubkey → akash addr) | ✅ compressed / uncompressed / DER inputs all match the `@cosmjs/crypto` canonical address |
| binary hash pins (`sops`, `age-plugin-yubikey`) | ✅ verified against the real upstream artifacts |
| `zbarimg` (QR **decode**) | ⚠ segfaults on macOS; verify the decode path on the Debian qube |
| `age-plugin-yubikey`, `pkcs11-tool`, `sc-hsm-tool`, `ykman`, printing, SLE-4442, M-DISC | ✅ **emulated + exercised** in [`emulator/`](emulator/) (`docker run --rm --privileged ceremony-emu run-route-tests` → all route checks pass): SoftHSM2 derives a real akash address + ECDSA signature, DKEK 4-of-6 reconstructs, age round-trips, the SLE-4442 runs over real PC/SC, cups-pdf emits a real PDF, M-DISC cross-drive verify catches a fault. **Still do the first real run on Qubes as a DRY RUN** — the emulators prove the CLI routes, not the physical tokens. One documented gap: the SmartCard-HSM card-side DKEK APDUs are modelled (no free applet). |
| ceremony hardware emulators (`emulator/tests/route-coverage.sh` + the Python emulator models) | ✅ every hardware route has a faithful emulator and is driven end-to-end in a Debian image |

## Hardening notes
- Confirm `vault` has **no netvm** every time — `preflight.sh` fails closed if it sees a route.
- Keep the *template* offline too once built (`qvm-prefs vault-tools netvm ''`) and only
  re-attach net for deliberate tool updates.
- Do reconstruction/drills here as well: plain Shamir reassembles the secret in RAM, so it
  must be air-gapped and the qube discarded afterward (see SECRETS.md caveats).
- Verify every downloaded binary's signature/hash in the template build; pin versions.
