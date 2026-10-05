# Regalia Ceremony

Air-gapped key-ceremony tooling for hardware-backed custody: a reproducible **Qubes OS**
vault image, the ceremony scripts that run inside it, an **emulator test harness** that
exercises every ceremony branch without hardware, and an **offline Debian bundle** builder for
installing the tools on an air-gapped machine.

It is the operational companion to [Regalia KMS](https://github.com/Digital-Frontier-LDA/regalia-kms) —
this repository is about *creating and recovering* the keys (SLIP-0039 / DKEK Shamir shares,
Nitrokey HSM 2 funding keys, YubiKey PIV identities); the KMS repository is about *serving* them.

It also carries the **Pico HSM** staging-hardware work: a Raspberry Pi Pico (RP2350) running
[Pico-HSM](https://github.com/polhenarejos/pico-hsm) as a low-cost open-hardware SmartCard-HSM for
development and rehearsal — firmware fixes, upstream bug reports, a reset tool, and the emulator/drill
harness that exercises it. The Pico is a fully capable SmartCard-HSM and *could* hold production keys;
Regalia deliberately **chooses** not to (policy D1), reserving production for the Nitrokey HSM 2's
audited NXP firmware rather than an open-firmware reimplementation. So a Pico never informs a
production decision here — by policy, not by limitation.

> **Status: reference tooling.** These procedures are published so the approach can be reviewed and
> reused. They describe an air-gapped, multi-custodian ceremony; adapt the custody model, hardware,
> and thresholds to your own threat model before relying on them.

## What's here

| Path | What it is |
|---|---|
| `qubes/` | The air-gapped Qubes vault: TemplateVM build (`salt/`), ceremony scripts (`scripts/`), recovery runbook (`recovery/`), and the emulator test harness (`emulator/`) |
| `qubes/emulator/` | A software emulator + ~65 tests that drive the ceremony end-to-end (Shamir split/verify, HSM import/clone, CUPS print-and-purge, two-device failover) with no hardware |
| `hardware/pico-hsm/` | **Pico HSM (RP2350) staging hardware:** firmware patches, upstream bug reports (device-auth deadlock, watchdog scope), and a reset tool — see [`hardware/pico-hsm/README.md`](hardware/pico-hsm/README.md) |
| `debian/offline-bundle/` | Builds and verifies a signed, offline apt/wheel bundle so the tools install on an air-gapped host |

## The document map

The **document map** below is the entry point: what each document is for, and which one wins when
two disagree.

| Document | What it settles |
|---|---|
| [`qubes/README.md`](qubes/README.md) | how a ceremony is actually run, start to finish |
| [`qubes/CEREMONY-PROFILES.md`](qubes/CEREMONY-PROFILES.md) | the supported token profiles and what each requires |
| [`qubes/CREDENTIAL-SEPARATION.md`](qubes/CREDENTIAL-SEPARATION.md) | which PINs, SO PINs, PUKs, DKEKs and transport artifacts may never be merged, and what checks each |
| [`qubes/NITROKEY-QUALIFY.md`](qubes/NITROKEY-QUALIFY.md) | qualifying a Nitrokey HSM 2 on Qubes with OpenSC alone |
| [`qubes/PICO-DRILL-RUNBOOK.md`](qubes/PICO-DRILL-RUNBOOK.md) | the staging bench: what is installed, pinned, and rehearsed |
| [`qubes/PROOF-OF-WORKS.md`](qubes/PROOF-OF-WORKS.md) | what has actually been proven on hardware, and what has not |
| [`qubes/recovery/`](qubes/recovery/) | break-glass recovery, for a reader under deadline |
| [`hardware/pico-hsm/README.md`](hardware/pico-hsm/README.md) | the staging hardware, its firmware fixes and upstream reports |
| [`debian/offline-bundle/README.md`](debian/offline-bundle/README.md) | installing the tooling on an air-gapped host |
| [`tools/README.md`](tools/README.md) | the bench tooling and the default-deny staging registry |

**Precedence.** Most documents here predate the ratified ceremony design, so where an older
document contradicts a newer one, **the newer ratified decision wins** — and the older text is a
record of how the question was reached, not an instruction. When two disagree and neither is
obviously newer, `qubes/PROOF-OF-WORKS.md` wins on matters of fact, because it records what was
measured rather than what was intended.

### How claims are labelled

These words appear throughout, and they are not decoration:

- **MEASURED** — it was run on the hardware named on the same line, on the date given. A measured
  claim carries its device and date, because a finding without them cannot be attributed.
- **MODELLED** — an emulator or a piece of software pinned it, and no card confirmed it. Useful,
  and not the same thing.
- **DECIDED** — a ratified choice rather than an observation. It can be revisited by the same
  process that made it; it cannot be refuted by an experiment.

## Running the emulator tests

The harness is designed to run in the Debian `vault-tools` environment (or its container image).
It installs its own dependencies (`age opensc pcscd ssss qrencode …`) and drives the ceremony
against an emulated card and printer:

```sh
cd qubes/emulator
./run-tests.sh
```

Individual checks live under `qubes/emulator/tests/` and can be run directly.

## Current limitations

Kept current as work lands; each item names the issue that tracks it, and is removed when it is lifted.
What has and has not been proven on hardware is in [`qubes/PROOF-OF-WORKS.md`](qubes/PROOF-OF-WORKS.md).

- **No ceremony has run yet.** Nothing this tooling generates is in use. The tooling is exercised by the emulator
  suite, the dev environment and the staging bench only.
- **The offline keys (`qubes/scripts/offline-keys.py`, ADR-0002 D28):**
  - They have run in CI and on a development machine only, never on the ceremony laptop or against real developer
    cards (#123).
  - The owner authorizations run as `ceremony.sh` step a, to the OWNER pair (ADR-0002 D30.7), with a SOPS recovery copy
    opened by the offline set's shares; the disc waits for both owner cards' proof. The step needs the owner cards'
    exported keys and the card record, which no step makes yet (#122, #111 step 2). So no real disc that
    holds the offline keys can be burned until the owner cards' step exists: the cards come first.
  - The root's signing state lives in the session's RAM (`$WORK/state`) and travels on the archive disc (`state/`),
    since no ceremony profile persists anything. A later session restores it from the newest disc. The sheet's
    session count is typed, and an older disc is refused by name; other discs are compared, so a newer one or a fork
    is refused; after genesis the chain's pin is checked. The disc's readback of `state/` is the archive's own
    checksum readback, run by the operator. Two sessions that restore the same disc before genesis can still fork;
    only the sheet bounds that (as regalia-kms#406 accepts). The card-record writer has no ceremony step yet (#111),
    so the first ceremony's state is not made by `ceremony.sh` either.
  - Rotating the owner authorizations (`ceremony.sh` step t, #135) makes and proves a new set from the archived sealed
    file, but each node's switch is regalia-kms's `enrol ownerauth --rotate-from`, which is in review there. Neither
    side has run on hardware. The sealed file is authenticated only by the shares opening it; the step does not check
    it against the archived offline-keys record. A laptop clock set behind the current record is refused before
    anything is signed; one set AHEAD passes both sides (regalia-kms#461).
  - The tool's own docstring lists its limitations in full.
- **The laptop-side YubiKeys (D30):**
  - No tool makes the developer cards' keys yet. That step waits on the D30.6 bench measurements, which have not
    run (#111).
  - The release key's import onto the release cards is not implemented (#124).
  - The card-ceremony record's rules and verifier are in review (#121). Its writer, `offline-keys.py card-record`, is
    in review too. It signs inputs that no tool makes from the cards yet. A lost state directory is rebuilt from the
    disc (regalia-kms#406); before genesis only the paper sheet bounds that.
  - Nothing produces OpenPGP attestation certificates yet, so a record's "attested" has no certificate behind it
    (#127).
  - The release key's tool is in review (#126), modelled against a stand-in card only.
- **Open issues in the existing tooling:**
  - Every emulator suite is now kept off the real pcscd. What remains open is stand-ins for `opensc-tool`,
    `pcsc_scan` and `gpg --card-status`, and a reader with a vendor-specific USB class going unseen by the
    daemon-tier refusal (#104).
  - YubiKey PINs and PUKs are passed to `ykman` on the command line (#98).
- **Older documents predate the ratified design** (see Precedence above). Where they describe HSM-held root or
  revocation keys or approval YubiKeys, D28/D30 supersede them.

## Security

- **No secrets in this repository.** Age keys that appear in tests are `AGE-SECRET-KEY-1EXAMPLE…`
  placeholders. Secret scanning runs over the whole tree with content-only allowlists — see
  [`.gitleaks.toml`](.gitleaks.toml).
- **Custody model is intentionally omitted.** The specific physical share-holder map used by the
  original operators (who holds which share, and where) is *not* published — it is exactly the
  information an attacker would want. Define your own before running a real ceremony.
- **Report vulnerabilities** privately via GitHub Security Advisories.

## Design

The design philosophy — what the ceremony protects and why, phase by phase (ceremony → day-0 →
day-1 → day-2) — is in [`PRINCIPLES.md`](PRINCIPLES.md).

Some scripts and docs also cite internal design/requirements records that are part of the operators'
private repository and not included here. The in-repo runbooks (`qubes/README.md`,
`qubes/recovery/RECOVERY-TECHNICAL.md`) are self-contained for understanding the tooling.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
