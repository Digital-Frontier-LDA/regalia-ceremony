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

dom0 has no network and no git, and nothing should be built from a working copy on another qube.
Fetch the recipe from the public repository at an exact, **merged** commit (take its full 40-character
SHA from the merged pull request on GitHub). A throwaway disposable downloads it; dom0 only
receives the bytes and checks that nothing changed on the way:

```bash
# 0. fetch the recipe at a pinned commit (dom0)
REV=<full 40-character commit SHA of the merged release>
URL="https://github.com/Digital-Frontier-LDA/regalia-ceremony/archive/$REV.tar.gz"
qvm-create --class DispVM --template default-dvm --label red vault-fetch   # any disposable template WITH network
qvm-run -p vault-fetch "curl -fsSL '$URL' | sha256sum"      # note the sum it prints
qvm-run -p vault-fetch "curl -fsSL '$URL'" > /tmp/vault-ceremony.tgz
sha256sum /tmp/vault-ceremony.tgz                           # must equal the sum above
qvm-kill vault-fetch; qvm-remove -f vault-fetch
rm -rf /tmp/vault-ceremony && mkdir /tmp/vault-ceremony
tar -xzf /tmp/vault-ceremony.tgz -C /tmp/vault-ceremony --strip-components=1 "regalia-ceremony-$REV/qubes"
cd /tmp/vault-ceremony/qubes                                # steps 1–5 run from here
```

GitHub builds the tarball from exactly that commit; two downloads of the same `$REV` give the
same bytes (checked 2026-09-24), so the two sums catch corruption between the disposable and dom0.

```bash
# 1. clone a fresh template for the tools (keeps your base template clean). Debian 13: its OpenSC
#    0.26.1, pcscd 2.3.3, libccid 1.6.2 and yubikey-manager 5.6.1 are exactly the versions the hardware
#    drills qualified (regalia-kms config/qualified-stack.json); Debian 12 ships older ones.
qvm-clone debian-13-minimal vault-tools
#    a *-minimal template lacks the salt connector and passwordless root that qubesctl needs:
qvm-run -p -u root vault-tools 'apt-get update && apt-get install -y qubes-mgmt-salt-vm-connector qubes-core-agent-passwordless-root'
qvm-shutdown --wait vault-tools

# 2. apply the Salt formula: installs apt packages + the non-apt binaries + scripts
#    (the TEMPLATE needs net to install; the vault AppVM below will not)
sudo cp -r salt/* /srv/salt/ ; sudo cp -r scripts /srv/salt/vault-ceremony-scripts
sudo cp requirements.txt /srv/salt/vault-ceremony-requirements.txt   # hash-pinned pip deps
sudo cp -r recovery /srv/salt/vault-ceremony-recovery               # break-glass runbooks (go on each archive disc)
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

### Updating the template to a new release (one command)

`dom0/vault-tools-update.sh` does step 0 and step 2 above for a release tag: download in a
throwaway disposable, **refuse unless the sha256 matches**, replace the Salt files, apply, check
`Failed: 0`, shut the template down. Every step prints one `OK`/`FAIL` line.

```bash
# first time: after fetching and checking a tag by hand as in step 0, from the unpacked copy
bash /tmp/vault-ceremony/qubes/dom0/vault-tools-update.sh --install <tag> <sha256>
# every later release
~/bin/vault-tools-update <tag> <sha256>        # e.g. vt-0929 d500b9a46416… (at least 16 hex)
```

To start a ceremony, open a terminal in a fresh disposable, then find its name (`dispNNNN`) to
attach devices to it:

```bash
qvm-run --dispvm=vault xterm & disown           # dom0; in the xterm: /opt/vault-ceremony/ceremony.sh
qvm-ls --class DispVM --running                  # its name, for qvm-usb / qvm-block attach
```

The disposable lives exactly as long as that xterm, and is destroyed with everything in its RAM
when the xterm closes. `&` gives the dom0 prompt back, so you can attach devices from the same
terminal. `disown` detaches it from that terminal: closing the dom0 terminal can then no longer
take the disposable down mid-ceremony. Without `disown`, closing the terminal may kill the xterm,
and so does Ctrl-C in the terminal if you ran it without `&`. End a session by typing `exit` in
the xterm (or closing it), never by closing the dom0 terminal.

Before the ceremony, choose where the share cases go with [CUSTODY-SITES.md](CUSTODY-SITES.md)
(`custody-plan-check.py --new plan.toml` guides you and checks the site rules).

Before each real ceremony, run **both** checks: `preflight-dom0.sh <vault>` in **dom0**
(asserts netvm/template/`maxmem 0`/DispVM/dom0-swap) and `/opt/vault-ceremony/go-nogo.sh`
**inside** the qube (air-gap, swap off, `/dev/shm` tmpfs, no history/core-dumps, USB-only
printer, every tool's self-test, the hardware this ceremony needs). The wizard also **fails closed** if `/dev/shm` isn't tmpfs and **refuses to run if a
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
# Shamir, printing, archive disc, drill), shows each command, and confirms before running:
/opt/vault-ceremony/ceremony.sh
# The Shamir scheme is a setting, 4-of-6 by default. For 3-of-5, start the wizard (and go-nogo) as:
#   CEREMONY_THRESHOLD=3 CEREMONY_SHARES=5 /opt/vault-ceremony/ceremony.sh
# Any 2 <= threshold <= shares <= 16. Every split, its reconstruct-verify, the share forms, the
# recovery card and the go-nogo supply counts follow it; anything else is refused before a split.

# or run the pieces by hand (it just orchestrates these):
/opt/vault-ceremony/go-nogo.sh               # air-gap + tools + self-tests + reader/printer/drives (fails closed)
#   age-plugin-yubikey --generate --pin-policy once --touch-policy never  # unattended ops identity
#   # Touch is always never: the YubiKey runs in a remote KMS, PIN-only (ADR-0002). Other values are refused.
#   sc-hsm-tool --create-dkek-share dkek.pbe --pwd-shares-threshold 4 --pwd-shares-total 6
#   slip39-mint.py --threshold 4 --shares 6  # SLIP-0039 shares -> qrencode -> archival paper
#   (NEVER `shamir create` — the CLI prints the master secret to stdout; the minter never
#    emits it and reconstruct-verifies every k-of-n subset before writing)
# hand-copy + verify shares onto their printed blank forms, seal them, power off (RAM wiped).
```

### The root's signing state between sessions

Nothing persists on the ceremony laptop, so the root's signing state (`state/`: the marker, `signing-record.jsonl`,
a rebuild's record) is burned on each archive disc and committed to `hsm-backups/state/`.

- **First ceremony:** the card record's writer creates it, as session 0.
- **A later session:** step t (or any step that signs) restores it from the NEWEST disc's `state/`, mounted
  read-only, and asks for the sheet's session count. An older disc, a disc newer than the sheet, a fork or (after
  genesis) a disc the chain's pin does not match are refused, and nothing is signed. The session then records
  itself as session S+1.
- **Writing the sheet:** do **not** write S+1 when the session opens. Burn the archive disc, run its checksum
  readback, mount the disc's `state/` read-only, and run **step w**. Only when it prints `WRITE ON THE SHEET AND ON
  THE DISC LABEL: SESSIONS n` do the sheet and the disc label take n. So the sheet always names a disc that exists
  and reads back.
- **A sheet written in error** (n written, but that session's disc never burned or read back): the next restore
  refuses the newest real disc as "an OLDER disc". Cross the wrong line out on the sheet, initial and date the
  correction, and type the last count that step w printed for a burned disc. Do not type a number no disc holds.
- **Two discs that disagree** (a fork), or a lost state: `offline-keys.py card-record --rebuild-from-disc`
  (regalia-kms#406).
- **Residual:** two sessions before genesis that both restore the same disc can still fork. Only the sheet bounds
  that.

### Ceremony media on a laptop (few USB ports, no hub)

Attach devices per step with `qvm-usb attach <dispvm> sys-usb:<id>` and detach what the step no
longer needs; the wizard runs one step at a time, so nothing needs a hub.

- **Webcam** (printed-QR scan-back) and a **built-in reader** are internal USB: no port used.
- **HSM funding** needs both Nitrokeys at once; every other step needs at most one token.
- **Archive disc:** burn on the USB writer (`qvm-usb`), push the slim tray shut, and read the disc back
  on the same drive (ADR-0002 D9: one writer is enough). A second drive is optional: a second USB
  drive is used automatically, and a laptop's bay drive (dom0's, read-only through
  `qvm-block attach --ro <dispvm> dom0:sr0`) is used with `CEREMONY_VERIFY_DEV=/dev/xvdi`.

**Wallet seed entropy (wizard step `e`).** A new seed is never taken from one random source: the
wizard collects 50 values from fair six-sided dice (2 dice x 25 throws, both values then Enter; typed hidden, ~129 bits, which is
the 128-bit backstop the dice provide on top of the HSM and the OS; hashed with
SHA-256), 32 bytes from the attached HSM's hardware RNG (Nitrokey HSM 2 or Pico HSM, read directly
over PC/SC with `hsm-random.py`), and 32 bytes of `/dev/urandom`,
XORs them (`entropy-mix.py`), and encodes the result as a 24-word BIP39 mnemonic for step 3 c. It
refuses without the dice or without the HSM. The dice values are checked for fairness: two faces
never appearing, counts too uneven (chi-square, p < 1e-4), no back-to-back repeat at all, or a
repeating pattern is refused (real dice: about once in 3,000 runs; roll again). That catches a bad
die or naive made-up typing, not a deliberate cheater, and fake dice cannot weaken the seed anyway,
because of the XOR with the HSM and the OS.

`ceremony.sh` is built for **both** tokens: a YubiKey step (PIV/P-256 `ops` age identity)
**and** a Nitrokey HSM 2 step (DKEK k-of-n backup + on-device secp256k1 funding key). It
never prints a Shamir share (ADR-0002 D12): the printer gets a BLANK form per share, and the share
is shown on screen once, copied by hand, cleared from the screen and its scrollback, and typed back
to verify. That deliberate display is the only time a secret reaches the terminal; the printer only
ever receives ciphertext (the payload QR sheet), blank forms and instructions. The workdir is tmpfs
in RAM, shredded on exit.

**Recovery instruction card (menu step 6 / `make-recovery-card.py`):** prints a
DVD-case-sized card with the break-glass *procedure* — how to reconstruct from the Shamir
shares + archive disc — with a dashed cut-guide + corner crop marks. Cut along the line and slip
it into the DVD keep-case beside the archive disc. It contains **no secrets**, so it prints
freely (default 120×180 mm on Letter; `--paper a4`, `--width-mm/--height-mm` to resize).
Pass `--case-id DF-BG-01 --seal-serial HOLO-000001` (step 6 prompts for these) to print the
case ↔ holographic-sticker binding on the card, so a swapped card/case is detectable.

**Metal-plate backups:** `metal-stamp-worksheet.py` converts a SLIP-39 share into the
4-letter-prefix grid to stamp into metal (punch set), and `--verify` reads the stamped
prefixes back to catch a mis-stamp before you rely on the plate. See SECRETS.md →
"Metal-plate (punch-set) backups".

**Break-glass / incapacitation:** [`recovery/`](recovery/) holds the runbooks that must be
**burned onto every archive disc** so a recoverer needs no repo/network: `RECOVERY-START-HERE.txt`
(plain-English, for a non-technical heir → engage the named helper), `RECOVERY-TECHNICAL.md`
(the exact offline recipe), and `custodian-contact-sheet.example.txt` (the **sealed sheet
placed in each case** — it names the executor and a backup, the authorization trigger, the
recorded funding address, the safe sweep destination, and THIS case's ID and seal serial; it
deliberately does not list the other holders, whose directory only the executor holds; fill in
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

- **One optical writer is enough** (ADR-0002 D9). `ceremony.sh` step 4 **shows** the burn
  (`growisofs -dvd-compat`, which closes the disc) and the readback (`sha256sum -c` of every file
  against the manifest); it does not run them. **Run both, and seal the disc only after the
  checksum check reports every file OK.** A second drive, when attached, does the readback instead and also catches a disc only
  the burning drive can read; the recovery drill and seal checks read the disc on other drives later.
- **Archive disc (ADR-0002 D10):** a **Verbatim AZO archival DVD-R** (any DVD-R-capable writer; proven on a
  TSSTcorp SE-S084F, 2026-09-25) or an **M-DISC** (needs a writer on the M-DISC compatibility
  list). 4.7 GB — vastly more than a key/shares need.
- **SD / USB flash is NOT archival.** Flash loses charge over years unpowered — fine as
  working/transfer media (the internal card reader), **never** for cold escrow. Archive
  only to the **archive disc + paper**.
- **Two reader types, don't confuse them:** the *smartcard* reader (for the HSM / YubiKey
  as a CCID device) vs. the *SD card* reader. Pass the smartcard/USB token through to the
  vault with `qvm-usb`. The Pico HSM (USB `2e8a:10fd`) is not in Debian 13's libccid reader list,
  so the recipe adds it to `/etc/libccid_Info.plist` (`ccid-add-reader.py`); without that, pcscd
  ignores an attached Pico. The Nitrokey HSM 2 is already listed.
- **Printer:** any USB-attached **laser** printer with **no network and no internal storage**
  that has a CUPS driver for the plain `usb://` backend. A fresh disposable has no queue: the wizard
  finds the printer attached with `qvm-usb`, matches an installed driver on its make-and-model, and
  offers to create the queue `vault-usb` (not shared). `printer-driver-brlaser` is in the recipe,
  which covers most Brother mono lasers (including the DCP-L2550DW); other brands may need their
  driver added to the recipe. Driverless IPP-over-USB is NOT used: it appears as `ipp://localhost`,
  a network URI, which the USB-only gate refuses. Power-cycle the printer after printing to clear
  its page memory. The CUPS spool lives in the disposable qube and dies on shutdown.

## Verification status (what's actually been tested)

| Tool | Status |
|---|---|
| `sops` 3.13.1, `age`, age recipient round-trip | ✅ exercised on real files (`age` v1.3.1 on macOS; the vault image ships Debian bookworm's `age` 1.1.1) |
| `ssss` k-of-n split/combine | ✅ recovers with k, does **not** leak with k−1 (run at 4-of-6, 3-of-5, 3-of-4, 2-of-3, 5-of-8) |
| SLIP-0039 `shamir` k-of-n | ✅ master secret recovered from a k-subset (run at 4-of-6 and 3-of-4) |
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
- Confirm `vault` has **no netvm** every time — `go-nogo.sh` fails closed if it sees a route.
- Keep the *template* offline too once built (`qvm-prefs vault-tools netvm ''`) and only
  re-attach net for deliberate tool updates.
- Do reconstruction/drills here as well: plain Shamir reassembles the secret in RAM, so it
  must be air-gapped and the qube discarded afterward (see SECRETS.md caveats).
- Verify every downloaded binary's signature/hash in the template build; pin versions.
