# Credential separation — what a ceremony may never merge

regalia#28 criterion 1: *per-device PINs, SO/admin credentials, DKEKs and transport artifacts follow
documented separation rules.* This is that document. Each rule says what it prevents, and **Verified
by** names the check that fails if the rule breaks. A rule marked *prose only* is a promise nobody
checks yet. It is listed so it can't be mistaken for a checked one.

## Why separation, in one sentence

Every merge turns one disclosure into several. If two cards share a PIN, one shoulder-surf opens both
sites. If a user PIN equals its SO PIN, the person who may *use* the card can also *reset* it. If a
DKEK sits beside a PIN, every key on the card can be exported in plaintext offline, and the card
records nothing.

## PINs, SO PINs, PUKs and management keys

**1. Every credential the ceremony escrows is its own value.** The seven step-0 fields are
`hsm_a_user_pin`, `hsm_a_so_pin`, `hsm_b_user_pin`, `hsm_b_so_pin`, `yubikey_piv_pin`,
`yubikey_piv_puk` and `yubikey_mgmt_key`. All seven are required. No two may be equal, compared
case-insensitively. Card
A's PIN is not card B's; a user PIN is not its own SO PIN; a YubiKey PIN is not its PUK, nor any
HSM PIN.
*Verified by:* `check_credential_separation` in step 0. PROD refuses, DEV warns, and no value is
printed in either mode. Test: `test-ceremony-credential-separation.sh`.

**2. Each credential has the shape its device accepts.**
- SmartCard-HSM user PIN: 6–15 characters.
- SmartCard-HSM SO PIN: exactly 16 hex digits.
- YubiKey PIV PIN and PUK: 6–8 bytes (checked as bytes: multibyte input is refused).
- PIV management key: 32, 48 or 64 hex digits.

A value the card would refuse at initialisation is found at step 0, before anything is written.
*Verified by:* the same check and test.

**3. No credential is a published default.** Rules 1 and 2 cannot catch a well-formed docs example.
That covers the SmartCard-HSM examples and the YubiKey factory PIN `123456`, PUK `12345678` and
management key. Escrowing a factory value would leave it on the card, because step_yubikey_ops
changes a card *to* the escrowed value.
*Verified by:* `fail_ceremony_default_pin` (PROD refuses). Test: `test-payload-step.sh`.

**4. The escrowed value is the value on the card.** A PIN engraved on metal that the card does not
answer to fails silently, and only on recovery day.
*Verified by:*
- Nitrokey: the PIN-binding proof in `step_payload` presents the escrowed user PIN to the card.
- YubiKey: `step_yubikey_ops` sets the PIN and PUK from step 0's values, never from a prompt, and
  proves the PIN before generating. Test: `test-ceremony-yubikey-factory-card.sh`.

**5. Two YubiKeys never share a PIN.** Continuity is multi-enrollment (ADR-0002 D5), and that is
worth something only if the tokens fail independently. Step 0 holds one `yubikey_piv_pin`, so a
run sets it on **one** factory token. The second token gets its own run, with its own `pins.env`.
*Verified by:* `step_yubikey_ops` refuses to set the escrowed PIN on a second factory token in the
same run. Test: `test-ceremony-yubikey-factory-card.sh`. **Not verified:** that two *separate*
runs used different values, because no run sees the other's file.

**6. A YubiKey's management key is protected by its PIN and stored on the card.**
age-plugin-yubikey requires this (measured 2026-09-23, fw 5.7.4). It also means the escrowed PIN
recovers the management key, so the separately escrowed `yubikey_mgmt_key` is not what opens the
card afterwards. *Verified by:* `step_yubikey_ops` refuses to generate until the change succeeds.

## DKEKs

**7. A DKEK never exists on a machine with PIN access to a card** (REQUIREMENTS B3). A PIN and a
DKEK together export every key on the token, offline, and leave nothing behind on the card.
*Verified by:* `hsm-host-role/files/assert-no-dkek.sh`, which fails the deploy. Test:
`test-day0-dkek-rule-and-roles.sh`.

**8. Each site has its own DKEK domain** (REQUIREMENTS A3/A5). SiteA and SiteB import the same seed
key under different DKEKs, so a wrapped backup from one site cannot be restored at the other.
*Verified by:* `test-day1-fleet-pins-failover.sh`. Where two cards *must* share a domain (a card
and the one it backs up to), step 6 refuses mismatched key check values. When a KCV cannot be
parsed it only warns, and its unwrap-and-compare of the restored public key is the gate.

**9. DKEK passwords are split 4-of-6 across custodians and never written whole.** *Verified by:* the
share step's `--pwd-shares-threshold 4 --pwd-shares-total 6`. A restore must also prove it rebuilt
the **same** DKEK. `sc-hsm-tool` accepts a wrong share set whenever the result happens to pad
correctly, about 1 time in 256, so the key check value is compared. Test: `test-dkek-kcv-control.sh`
(the parse, the all-zero rejection, and that the drill compares).

**10. YubiKeys have no DKEK.** A PIV key cannot be exported or imported under a key-encryption key.
Continuity is multi-enrollment (rule 5, ADR-0002 D5). Nothing in this ceremony wraps a YubiKey key.

## Transport artifacts

**11. Only ciphertext leaves the ceremony machine.**
- Wrapped keys (`funding-wrapped.bin`) are encrypted under the DKEK.
- DKEK share files (`dkek.pbe`) are encrypted under the split password.
- The tier-0 payload is age-encrypted to the break-glass recipient.

Plaintext shares, PINs and seeds live only in the RAM workdir.
*Verified by:* `init_work`, which refuses to run when `/dev/shm` is not tmpfs (only tests may set
`CEREMONY_ALLOW_NONTMPFS=1`); the workdir is removed on exit. Test: `test-archive-no-plaintext-shares.sh` (the archive carries
only the encrypted artifacts).

**12. A token travels without its credentials.** A card and the PIN or share that unlocks it never
ship in the same package or with the same courier. *Prose only:* this is a custody instruction, and
no tool here can see a courier.

## What this does not cover

- **Custodian identity.** Who holds which share, and how many sites they span, is the custody
  manifest's concern (regalia `config/escrow-register.json`).
- **Runtime PIN custody.** On the KMS host, the PIN is a TPM-sealed systemd credential (regalia-kms
  `PIN-CUSTODY.md`, ADR-0002 D2). This document covers the ceremony, which is where the escrowed
  values are chosen.
