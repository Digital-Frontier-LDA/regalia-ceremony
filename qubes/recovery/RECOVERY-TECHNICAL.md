# BREAK-GLASS RECOVERY — technical runbook

**Read `RECOVERY-START-HERE.txt` first if you are not technical.** This document is for the
person who will actually run the commands (a custodian, the named technical helper, or a
trusted crypto-recovery professional). It is **self-contained**: everything you need is on
this archive disc (an M-DISC or an archival AZO DVD-R) — you do **not** need the GitHub repo or any network.

> SCOPE: this recovers the custodial **wallet seeds** so funds can be moved to safety, and
> (optionally) the SOPS config vault. It is a **k-of-n** scheme: you need the shares from **any k
> of the n sealed cases**. The numbers for THIS ceremony are in `SCHEME.txt` on this disc and on the
> recovery card (4-of-6 unless they say otherwise). Below, "k" means that number.

## 0. Authorization (do not skip)
Confirm you are entitled to do this and the trigger condition is met (see the sealed
**custodian-contact sheet** in each case, and the executor named there). An unauthorized
break-glass is theft. Two-person rule: do this with a second authorized person present.

## 1. Gather ≥k of the n cases (4 of 6 by default)
Each case has a numbered holographic seal + a sealed custodian-contact sheet that names the
**executor only**, never the other holders, so one lost or coerced case does not lead to the
rest. The **executor** holds the directory of cases (who, where, which seal serial) and gathers
them: contact holders until you physically hold **k** cases. For each case, before opening,
check the seal serial against the directory / seal registry and that the seal is intact; a
broken seal or wrong serial → note it, the contents may be compromised (you may still recover,
but rotate afterward).

Each case contains: an **archive disc** (DVD: M-DISC or archival AZO DVD-R; this toolkit + ciphertext + `payload.age`), a **recovery
card**, **QR sheets** on cotton archival paper (the Tier-0 payload — see Section 3C), an
**SLE-4442 chip card** holding this case's share, and the
share material — hand-written **SLIP-39 word-shares** (on a printed form) and/or **stamped metal plates** (4-letter
UPPERCASE prefixes of the SLIP-39 words). **If the optional born-in-HSM funding path was
used** (the recovery card is stamped with the HSM-restore steps, and the disc carries
`funding-wrapped.bin` + `dkek.pbe`), the funding key's share material is instead the hand-written
**DKEK password shares** (k-of-n) — there are **no** SLIP-39 funding word-shares; recover it
with **Section 3B** below, not Section 3.

**Reading the chip card** (only if you need this case's share from it — the hand-written and metal
copies hold the same share). You need a PC/SC reader that supports SLE-4442 memory cards (e.g.
ACS ACR39U with the `libacsccid1` driver, or ACS ACR40U, validated with the stock Debian `libccid`);
ordinary chip-card readers cannot power these cards.
No PSC is needed to read. The share is plain ASCII text stored from **byte 32**; the rest of the
card after it is padded with `00` bytes, which the command strips:
```bash
( umask 077; ./sle4442-manager read --addr 32 --len 224 | xxd -r -p | tr -d '\377\000' > share.txt )
```
`share.txt` now holds the share's words. It is SECRET: keep it on the offline machine only.

## 2. Get an OFFLINE machine
Recovery must be **air-gapped** (no network) — the seeds appear in plaintext during recovery.
Two options:
- Boot a clean Linux from a USB (e.g. Tails) on a spare PC, **disconnect networking**, then
  copy this disc's `recovery-kit/` folder **and `payload.age`** (both at the disc root, side by side) to it and `cd` into `recovery-kit/` (the tools, `wheels/`, and
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
From any **k** cases, collect each case's SLIP-39 word-share. If a case only has a metal
plate, expand the stamped 4-letter prefixes back to words first:
```
metal-stamp-worksheet.py --verify --in <stamped-prefixes-of-that-share>
```
Put the k full word-shares (one per line) in a file, then recover each wallet mnemonic:
```
bip39-slip39-backup.py --recover --in k-shares-funding.txt      # -> funding BIP39 mnemonic
bip39-slip39-backup.py --recover --in k-shares-derivation.txt   # -> derivation BIP39 mnemonic
```
(If a case bundles funding + derivation shares together, recover each from its k matching shares.)

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
DKEK-wrapped blob on the disc plus the **k-of-n DKEK password shares** hand-written in the cases.
Section 3 (SLIP-39) does **not** apply to this funding key; the **derivation** root is still
recovered via Section 3.

You need a **fresh, blank, compatible SmartCard-HSM / Nitrokey HSM 2** (a sealed spare from
the ceremony) and the disc files `dkek.pbe` + `funding-wrapped.bin`. The key is rebuilt
**inside** the new HSM and never appears in host RAM.
```
# 1) Initialise a FRESH HSM with a DKEK domain (this WIPES that card — use a blank spare):
sc-hsm-tool --initialize --dkek-shares 1 --label 'akash-funding'
# 2) Import the DKEK share. `--pwd-shares-total <k>` (k from SCHEME.txt) is REQUIRED: without it OpenSC's
#    import_dkek_share() never enters the share-reconstruction prompt path and the import
#    cannot be driven. You will then be prompted, per share, for the PRIME, the SHARE ID,
#    and the SHARE VALUE — k of the n hand-written DKEK PASSWORD shares from ≥k cases, typed at
#    the prompt, never on the command line:
sc-hsm-tool --import-dkek-share dkek.pbe --pwd-shares-total <k>   # e.g. 4 for 4-of-6
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
  * `payload.age` on the **archive disc**
  * (the chip cards hold a SHARE, not the payload — an SLE-4442 has only 256 bytes)

**Decrypt it with the breakglass age key** — the same key the k-of-n `ssss` shares rebuild,
so no extra threshold and nothing new to find:

The breakglass key is a **post-quantum** age key (`AGE-SECRET-KEY-PQ-1…`), which needs **age 1.3 or
later**. Many systems ship an older age that will refuse it. Use the copy on the archive disc: it is
a static binary that runs on any 64-bit (amd64) Linux.

```sh
# (in recovery-kit/, as in Section 2; payload.age is at the disc root, one level up)
( cd bin && sha256sum -c SHA256SUMS )                        # age, age-keygen, sops: all OK
# rebuild the breakglass key from any k of the n shares, straight into a file (ssss-combine writes
# the secret on stderr; typing it into a command would leave it in the shell history):
( umask 077; ssss-combine -t <k> -q 2> breakglass.key )      # then type the k shares when asked
bin/age -d -i breakglass.key ../payload.age > payload.txt
```

It contains: both wallet mnemonics, the ops age key, `API_KEY_HASH_SECRET`, and every hardware
PIN/SO-PIN/PSC/PUK. **It does NOT contain the breakglass key itself** — that key is what opens
this file, so it lives only in the Shamir shares.

**Everything else comes from the vault, not the archive.** The breakglass key decrypts
`example-service:infra/ansible/vault.sops.yaml` straight from the repository, which holds the ~45 deployment
secrets (database passwords, Keycloak, Stripe, DNS tokens, OAuth) and is always current:

```sh
SOPS_AGE_KEY_FILE=breakglass.key bin/sops decrypt example-service:infra/ansible/vault.sops.yaml
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
bip39-slip39-backup.py --recover --in k-shares-funding.txt --out funding.mnemonic  # Step 3
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
(`ssss-combine -t <k>` over its k shares) → an `AGE-SECRET-KEY-PQ-1…`; then
`SOPS_AGE_KEY_FILE=breakglass.key bin/sops decrypt vault.sops.yaml` (from inside `recovery-kit/`), with the key file
written as in §3C (`ssss-combine … 2> breakglass.key`), so the key is never typed into a command. The sops
on the disc understands post-quantum age keys; an older sops may not. (A key split before this
change starts `AGE-SECRET-KEY-1…` and works the same way.)

## 6b. Keys created after the ceremony
The sealed cases hold what existed on ceremony day. Keys generated on the HSMs **later** (a release
signing key, a vault unseal key, a certificate authority) are backed up as **DKEK-wrapped blobs**, kept
in the operator's private repository and at each site, with a manifest giving each blob's sha256
and the DKEK check value (KCV). A blob is useless without the DKEK, so it was never secret. To restore
one: rebuild the DKEK from k shares (above), load it into a card, check the blob's sha256 against the
manifest, then `sc-hsm-tool --unwrap-key <blob> --key-reference <N>`.

## 6c. PINs changed after the ceremony
The payload holds the day-to-day PINs as they were on ceremony day. After any PIN change, the current
PINs are escrowed in the operator's private repository as `escrow/pins-NNNN.age`, encrypted to the
breakglass recipient, each with a `.mac` under the **escrow MAC key** (the payload's `escrow_mac_key`
line). Use the newest **verified** escrow, not the payload's PINs, and use this disc's tool, not the
repository's copy:

```sh
# the key goes straight from the payload into the verifier: never into a file of its own
rm -f /dev/shm/pins.age      # a stale copy must never be what gets decrypted
sed -n 's/^escrow_mac_key: *//p' payload.txt | python3 bin/pin_escrow_mac.py select <repository checkout> /dev/shm/pins.age
case $? in
  0) bin/age -d -i breakglass.key /dev/shm/pins.age ;;               # the verified escrow
  3) echo "no escrow verifies: use the payload's PINs" ;;
  *) echo "STOP: the selection failed; fix the cause, do NOT fall back" ;;
esac
```

The escrow also holds each KMS host's **TPM lockout authorization**, as `tpm_a=`, `tpm_b=` and
`tpm_c=` lines (the payload has them as `tpm_{a,b,c}_lockout_auth`). The same rule applies: the newest
verified escrow, not the payload. It matters more here than for a PIN: typed at a host, a stale value
is a **wrong attempt**, and after one wrong attempt that TPM refuses the right value too for its
lockout-recovery time (24 hours under the KMS policy). An escrow written before these lines existed
has none; then, and only then, the payload's values are the ones to use.

The escrow holds each KMS host's **disk recovery key** too, as `luks_a=`, `luks_b=` and `luks_c=` lines
(the payload has them as `luks_{a,b,c}_recovery_key`). It is what opens a KMS host's encrypted disk
when nothing else can: all three sites down, or a host whose TPM no longer releases its disk. Type
it at that host's boot prompt **exactly as written, lower case, dashes included** (8 groups of 8
letters); without the dashes it does not open the disk. Use the newest verified escrow, not the
payload: a key is replaced after every use, and the replaced key opens nothing. Once the host is
back, replace the key again: it has now been typed at a console. In this order, because the newest
verified escrow must never hold a key that opens nothing:

1. `bin/pin-escrow.sh --new-recovery-key` on the offline machine prints one new key (never invent
   one by hand); write it on a new KMS host recovery card.
2. At the host: `recovery-key.sh --replace` (KMS repository) with the used key and the new one, then
   `--check` with the key read from the new card.
3. Only then escrow it (`bin/pin-escrow.sh`).
 An escrow written before these lines existed has
none; then, and only then, the payload's keys are the ones to use.

`select` searches the repository's whole git history (use a full clone) and prints the escrow it
chose. Every `SKIPPED` or `NOTE` line is an incident to record. Only exit status **3** means no
escrow verifies: then use the payload's PINs. Any other failure (a malformed key, git, a full tmpfs)
means STOP and fix it; never fall back to the payload's older PINs because of it. Shred `/dev/shm/pins.age` afterwards.

## 7. After
- **Rotate**: the seeds were exposed — generate new wallets and move funds again per the plan.
- **Log it**: record the open in the seal registry's `openings:` list (broken serial → new
  serial), re-seal opened cases with fresh holographic stickers from the reserve.
- **Wipe**: shut down the offline machine (RAM cleared); destroy any scratch files.

---
This disc also contains `RECOVERY-START-HERE.txt` (non-technical) and the self-contained
toolkit in `recovery-kit/` (the tools, `requirements.txt`, and `wheels/`), plus the encrypted
material at the disc root.
