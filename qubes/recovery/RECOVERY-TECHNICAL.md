# BREAK-GLASS RECOVERY — technical runbook

**Read `RECOVERY-START-HERE.txt` first if you are not technical.** This document is for the
person who will actually run the commands (a custodian, the named technical helper, or a
trusted crypto-recovery professional). It is **self-contained**: everything you need is on
this M-DISC — you do **not** need the GitHub repo or any network.

> SCOPE: this recovers the custodial **wallet seeds** so funds can be moved to safety, and
> (optionally) the SOPS config vault. It is a 4-of-6 scheme: you need the shares from **any
> 4 of the 6 sealed cases**.

## 0. Authorization (do not skip)
Confirm you are entitled to do this and the trigger condition is met (see the sealed
**custodian-contact sheet** in each case, and the executor named there). An unauthorized
break-glass is theft. Two-person rule: do this with a second authorized person present.

## 1. Gather ≥4 of the 6 cases
Each case has a numbered holographic seal + a sealed custodian-contact sheet listing all
six custodians and the executor. Contact custodians until you physically hold **4** cases.
For each case, before opening, check the seal serial against the contact sheet / registry
and that the seal is intact; a broken seal or wrong serial → note it, the contents may be
compromised (you may still recover, but rotate afterward).

Each case contains: an **M-DISC** (this toolkit + ciphertext + `payload.age`), a **recovery
card**, **QR sheets** on cotton archival paper (the Tier-0 payload — see Section 3C), an
**SLE-4442 chip card** holding this case's share, and the
share material — printed **SLIP-39 word-shares** and/or **stamped metal plates** (4-letter
UPPERCASE prefixes of the SLIP-39 words). **If the optional born-in-HSM funding path was
used** (the recovery card is stamped with the HSM-restore steps, and the disc carries
`funding-wrapped.bin` + `dkek.pbe`), the funding key's share material is instead the printed
**DKEK password shares** (4-of-6) — there are **no** SLIP-39 funding word-shares; recover it
with **Section 3B** below, not Section 3.

## 2. Get an OFFLINE machine
Recovery must be **air-gapped** (no network) — the seeds appear in plaintext during recovery.
Two options:
- Boot a clean Linux from a USB (e.g. Tails) on a spare PC, **disconnect networking**, then
  copy this M-DISC's `recovery-kit/` folder to it and `cd` into it (the tools, `wheels/`, and
  `requirements.txt` all live there, so the relative commands below resolve); or
- Boot the Qubes `vault-tools` image / any offline Linux. Verify air-gap: `ip route` shows
  no default route.
Install the tools (they're standard): `apt install age opensc ssss qrencode python3-pip sops`
(`sops` is only needed for the optional Section 6 vault decrypt).
The SLIP-39 step needs two Python packages (`shamir-mnemonic` + `mnemonic`); install them
**offline from the wheels on this disc** — no network needed:
```
pip install --no-index --find-links wheels/ --require-hashes -r requirements.txt
```
The `wheels/` directory and `requirements.txt` are both on this disc (burned by the ceremony).
Only if `wheels/` is somehow missing do you need network: `pip install --require-hashes -r
requirements.txt`. (`--require-hashes` makes both paths verify every package against the
pinned SHA-256s.)

## 3. Reconstruct the wallet seeds (the important part)
From any **4** cases, collect each case's SLIP-39 word-share. If a case only has a metal
plate, expand the stamped 4-letter prefixes back to words first:
```
metal-stamp-worksheet.py --verify --in <stamped-prefixes-of-that-share>
```
Put the 4 full word-shares (one per line) in a file, then recover each wallet mnemonic:
```
bip39-slip39-backup.py --recover --in four-shares-funding.txt      # -> funding BIP39 mnemonic
bip39-slip39-backup.py --recover --in four-shares-derivation.txt   # -> derivation BIP39 mnemonic
```
(If a case bundles funding + derivation shares together, recover each from its 4 matching shares.)

> **Passphrase:** these backups use the **empty** SLIP-39 passphrase (the default), so
> `--recover` needs no passphrase. If — and only if — the custodian sheet records a
> passphrase, pass the **exact** same one with `--passphrase`. A wrong passphrase does **not**
> error: it silently yields a **different, wrong** mnemonic. Always do the Step 4 address
> check below before trusting any recovered seed.

## 3B. (HSM custody path only) Restore the born-in-HSM funding key from the DKEK backup
**Skip this section unless the disc carries `funding-wrapped.bin` + `dkek.pbe`** (i.e. the
optional Nitrokey HSM 2 funding-signer path was performed and the recovery card shows the
HSM-restore steps). In that path the funding key was **born non-exportable inside the HSM**,
so it has **no SLIP-39 word-shares and no plaintext seed** — its only backup is the
DKEK-wrapped blob on the disc plus the **4-of-6 DKEK password shares** printed in the cases.
Section 3 (SLIP-39) does **not** apply to this funding key; the **derivation** root is still
recovered via Section 3.

You need a **fresh, blank, compatible SmartCard-HSM / Nitrokey HSM 2** (a sealed spare from
the ceremony) and the disc files `dkek.pbe` + `funding-wrapped.bin`. The key is rebuilt
**inside** the new HSM and never appears in host RAM.
```
# 1) Initialise a FRESH HSM with a DKEK domain (this WIPES that card — use a blank spare):
sc-hsm-tool --initialize --dkek-shares 1 --label 'akash-funding'
# 2) Import the DKEK share. `--pwd-shares-total 4` is REQUIRED: without it OpenSC's
#    import_dkek_share() never enters the share-reconstruction prompt path and the import
#    cannot be driven. You will then be prompted, per share, for the PRIME, the SHARE ID,
#    and the SHARE VALUE — 4 of the 6 printed DKEK PASSWORD shares from ≥4 cases, typed at
#    the prompt, never on the command line:
sc-hsm-tool --import-dkek-share dkek.pbe --pwd-shares-total 4
# 3) Unwrap the funding key from the DKEK-wrapped backup into the HSM (key stays in the HSM):
sc-hsm-tool --unwrap-key funding-wrapped.bin --key-reference 1
# 4) Export the PUBLIC key (safe) so you can prove which address you now control:
pkcs11-tool --read-object --type pubkey --id 01 -o funding-pub.der
```
Then **verify before trusting** (same rule as Section 4, pubkey form): derive the akash
address from the restored public key and confirm it matches the address recorded on the
sealed custodian-contact sheet / seal registry:
```
derive-akash-address.py --der funding-pub.der     # -> akash1…  compare to the record
```
If it does not match, **STOP** — wrong card, wrong DKEK password shares, or a tampered backup;
do **not** move funds. Once it matches, the funding key lives in this HSM: **move the funds**
(Section 5) by signing with the HSM (`pkcs11-tool --login --sign` / your Cosmos signer against
this token) rather than importing a mnemonic. Keep ≥2 spare HSMs — a DKEK restore needs a
compatible device.

## 3C. Recover EVERY platform secret from the Tier-0 payload

The SLIP-39 shares reconstruct one seed. The platform needs many more secrets, and almost all
of them ROTATE — so they are deliberately NOT archived. Instead the archive holds the small set
of roots that never change, and everything else is recovered *through* them.

**The payload is on three media, any one is enough:**
  * the **QR sheets** (cotton paper) — scan every symbol, then follow `INSTRUCTIONS.txt`
    printed alongside them (join the base64 fields in index order, `base64 -d`, check sha256)
  * `payload.age` on the **M-DISC**
  * (the chip cards hold a SHARE, not the payload — an SLE-4442 has only 256 bytes)

**Decrypt it with the breakglass age key** — the same key the 4-of-6 `ssss` shares rebuild,
so no extra threshold and nothing new to find:

```sh
# after reconstructing the breakglass key from any 4 of the 6 password shares:
age -d -i breakglass.key payload.age > payload.txt
```

It contains: both wallet mnemonics, the ops age key, `API_KEY_HASH_SECRET`, and every hardware
PIN/SO-PIN/PSC/PUK. **It does NOT contain the breakglass key itself** — that key is what opens
this file, so it lives only in the Shamir shares.

**Everything else comes from the vault, not the archive.** The breakglass key decrypts
`example-service:infra/ansible/vault.sops.yaml` straight from the repository, which holds the ~45 deployment
secrets (database passwords, Keycloak, Stripe, DNS tokens, OAuth) and is always current:

```sh
SOPS_AGE_KEY=<breakglass key> sops decrypt example-service:infra/ansible/vault.sops.yaml
```

Cloud-provider and vendor API credentials are deliberately absent from both. They rotate, and
an archived copy would be wrong — reissue them from the provider account instead.

## 4. Verify before trusting
Derive the akash address **from the recovered funding mnemonic** and confirm it matches the
address recorded on the sealed custodian-contact sheet / in the seal registry. Do this OFFLINE with the
shipped tool — it needs no wallet, no network, and no extra packages (pure stdlib BIP39 →
BIP32 `m/44'/118'/0'/0/0` → secp256k1):
```
# the recovered mnemonic is SECRET — pass it via a file, never on the command line:
bip39-slip39-backup.py --recover --in four-shares-funding.txt --out funding.mnemonic  # Step 3
derive-akash-address.py --mnemonic-file funding.mnemonic     # -> akash1…  compare to the record
```
(If instead you recorded/exported the funding **pubkey**, cross-check that form:
`derive-akash-address.py --der <pubkey.der>`.) If a SLIP-39 passphrase was used at Step 3,
you must pass the exact same one there — a wrong one yields a different seed whose address
will simply not match here, which is the whole point of this check.

If the address does not match the recorded one, STOP — you have the wrong shares, the wrong
passphrase, or a tampered backup. Do **not** move any funds.

## 5. Move the funds to safety (the goal)
Import the **funding** mnemonic into an Akash/Cosmos wallet (Keplr, Leap, or `akash` CLI)
on the offline machine, and send the balance to the pre-agreed safe destination address
(see the sealed contact sheet — `SAFE_DESTINATION`). The **derivation** root controls every
customer-derived address; treat it as the master and follow the estate's plan for customer
obligations. Do NOT reuse these seeds afterward — they have been exposed.

## 6. (Optional) decrypt the SOPS config vault
If you also need the service configuration: the breakglass **age** key is split the same way
(`ssss-combine -t 4` over its 4 shares) → an `AGE-SECRET-KEY-1…`; then
`SOPS_AGE_KEY=<that key> sops decrypt vault.sops.yaml` (the recovered key is a *value*, so it
goes in `SOPS_AGE_KEY`; `SOPS_AGE_KEY_FILE` is for a *path* to a key file).

## 7. After
- **Rotate**: the seeds were exposed — generate new wallets and move funds again per the plan.
- **Log it**: record the open in the seal registry's `openings:` list (broken serial → new
  serial), re-seal opened cases with fresh holographic stickers from the reserve.
- **Wipe**: shut down the offline machine (RAM cleared); destroy any scratch files.

---
This disc also contains `RECOVERY-START-HERE.txt` (non-technical) and the self-contained
toolkit in `recovery-kit/` (the tools, `requirements.txt`, and `wheels/`), plus the encrypted
material at the disc root.
