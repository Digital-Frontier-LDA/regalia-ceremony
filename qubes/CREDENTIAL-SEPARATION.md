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

**1. Every credential the ceremony escrows is its own value.** The fleet is three HSMs and three
YubiKeys (ADR-0002 D17), and three KMS hosts, so step 0 has twenty-two fields: `hsm_{a,b,c}_user_pin`,
`hsm_{a,b,c}_so_pin`, `yubikey_{a,b,c}_piv_pin`, `yubikey_{a,b,c}_piv_puk`,
`yubikey_{a,b,c}_mgmt_key`, `escrow_mac_key` (the key that authenticates later PIN escrows;
always generated), `tpm_{a,b,c}_lockout_auth` (each KMS host's TPM lockout authorization; always
generated, see below), and `luks_{a,b,c}_recovery_key` (each KMS host's disk recovery key; always
generated, see below). The list is `PIN_FIELDS` in ceremony.sh. All are required. No two may
be equal, compared case-insensitively. Card A's PIN is not card B's; a user PIN is not its own SO
PIN; YubiKey A's PIN is not YubiKey B's, nor its own PUK, nor any HSM PIN.
*Verified by:* `check_credential_separation` in step 0. PROD refuses, DEV warns, and no value is
printed in either mode. Test: `test-ceremony-credential-separation.sh`.

**Each KMS host's TPM lockout authorization** (`tpm_{a,b,c}_lockout_auth`) is the value that lets its
holder change that host's TPM dictionary-attack settings or clear its failed-try counter (the KMS
repository's `deploy/baremetal/tpm-lockout.sh`). Left empty, anyone with root on the host can do
both; lost, nobody can. So the ceremony generates one per host, 20 characters from capitals and
digits with no `0`, `1`, `I`, `L` or `O` (99 bits), and treats it like a PIN:

- it rides in the tier-0 payload, and every later escrow repeats it (`escrow/pin-escrow.sh` asks for
  all three each time, so the newest escrow is always whole). The KMS host card is therefore KEPT,
  sealed like the PIN card, and not destroyed once the hosts are commissioned;
- it is shown once in step 0 and written by hand on the **KMS host card**, page 2 of the PIN card
  form, because it reaches the host by being typed at its console, once, at commissioning;
- a hand-made PIN file may hold any 16 to 32 printable characters with no space, which is what the
  host tool accepts.

**One wrong attempt at the host is expensive.** After a wrong lockout authorization the TPM refuses
the right one too until its lockout-recovery time has passed; the KMS policy sets that to 24 hours
(measured on a software TPM, not yet on the production hardware). The value is therefore read from
the card or from the escrow and never guessed, and the host tool asks for it once.
*Verified by:* `test-step0-generated-credentials.sh` (generated, shown once, distinct per host),
`test-ceremony-credential-separation.sh` (shape, distinctness), `test-escrow-tools.sh` (required at
every escrow, never in the tool's output), `test-pin-card-form.sh` (page 2 and its rules).

**Each KMS host's disk recovery key** (`luks_{a,b,c}_recovery_key`) opens that host's encrypted root
by itself: no TPM, no peer, no running KMS (regalia-kms#77; the KMS repository's
`deploy/baremetal/recovery-key.sh`). It exists for a total outage, or a host that can no longer
unlock its own disk. It is the one value here that is enough **alone**: a PIN needs its token and a
lockout authorization changes a TPM's settings, but this key gives a host's disk to whoever types it.
It adds to the k-of-n recovery and replaces none of it: the shares still guard the HSM keys and this
payload; the recovery key opens one disk.

- The ceremony generates one per host in systemd's recovery-key format: 256 random bits as 8 groups
  of 8 letters from `cbdefghijklnrtuv`, with a dash between groups. Those letters are on the same
  keys of the common keyboard layouts, which matters at a boot prompt. **The dashes are part of the
  key**, and it is lower case: step 0 requires it typed back exactly, dashes included, and the
  escrow tool and the host tool refuse any other shape.
- It rides in the tier-0 payload, and every later escrow repeats it (`escrow/pin-escrow.sh` asks for
  all three each time). After a total outage, recovery reads the newest verified escrow: a key that
  was replaced since the ceremony exists nowhere else.
- It is shown once in step 0 and written by hand on the **KMS host recovery card**, page 3 of the
  PIN card form. That page is sealed in an envelope **of its own**, apart from the servers and apart
  from pages 1 and 2.
- **Using it spends it.** Once typed at a host outside the ceremony, a rehearsal included, that host
  gets a new key, a new card and a new escrow, in that order: the archive disc's
  `pin-escrow.sh --new-recovery-key` prints the new key (it is never invented by hand: the host
  enrols it on the assumption of 256 random bits); `recovery-key.sh --replace` and `--check` at the
  host; and only then the escrow, so that the newest verified escrow never holds a key that opens
  nothing.
- A hand-made PIN file must hold keys made the same way. The shape check cannot tell a random key
  from a chosen one.

*Verified by:* `test-step0-generated-credentials.sh` (generated in that format, shown once, distinct
per host; a copy without dashes or in capitals is refused), `test-ceremony-credential-separation.sh`
(shape, distinctness), `test-escrow-tools.sh` (required at every escrow, never in the tool's output),
`test-pin-card-form.sh` (page 3, its printed dashes and its rules). That the key opens a disk alone
is tested in the KMS repository (`e2e/luks-recovery-key.sh`), on a loop device and not on a KMS host.

**2. Each credential has the shape its device accepts.**
- SmartCard-HSM user PIN: 10–15 digits (a 10-try counter needs a 10-digit PIN; ADR-0002 D15).
- SmartCard-HSM SO PIN: exactly 16 hex digits.
- YubiKey PIV PIN and PUK: 6–8 bytes (checked as bytes: multibyte input is refused).
- PIV management key: 32, 48 or 64 hex digits.
- Escrow MAC key: exactly 32 hex digits (128 bits).

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
worth something only if the tokens fail independently. Step 0 holds one credential set per
YubiKey (A, B, C). `step_yubikey_ops` gives each token, by serial, the next free set, keeps a
token's set when it is run again, and refuses a fourth token.
*Verified by:* rule 1's check (all three sets live in the same file, so equal PINs are refused)
and `step_yubikey_ops`'s set assignment. Test: `test-ceremony-yubikey-factory-card.sh`.

**6. A YubiKey's management key is protected by its PIN and stored on the card.**
age-plugin-yubikey requires this (measured 2026-09-23, fw 5.7.4). It also means the escrowed PIN
recovers the management key, so the separately escrowed `yubikey_<set>_mgmt_key` is not what opens the
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

**9. DKEK passwords are split k-of-n across custodians (4-of-6 by default) and never written whole.** *Verified by:* the
share step's `--pwd-shares-threshold 4 --pwd-shares-total 6`. A restore must also prove it rebuilt
the **same** DKEK. `sc-hsm-tool` accepts a wrong share set whenever the result happens to pad
correctly, about 1 time in 256, so the key check value is compared. Test: `test-dkek-kcv-control.sh`
(the parse, the all-zero rejection, and that the drill compares).

**10. YubiKeys have no DKEK.** A PIV key cannot be exported or imported under a key-encryption key.
Continuity is multi-enrollment (rule 5, ADR-0002 D5). Nothing in this ceremony wraps a YubiKey key.

**10a. The offline signing HSM and its spare are a DKEK domain of their own** (regalia#554). The keys
that sign the KMS hosts' boot image are generated on an offline Nitrokey HSM 2 and backed up as
DKEK-wrapped blobs (ADR-0002 D19). That card and its spare share a DKEK that no KMS host's card holds,
so an image-signing key cannot be unwrapped onto an online host. That DKEK's share is not split again:
it is a software secret under the break-glass key.
*Verified by:* `hsm-signing-key.sh restore`, which proves a blob restores and signs on the spare.
Test: `test-hsm-signing-key.sh` (a card of the KMS hosts' domain refuses the blob). *Prose only:* that
the two cards were initialised with their own DKEK, and where its share is kept; the script has not
run on a card.

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
