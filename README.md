# Regalia Ceremony

Air-gapped key-ceremony tooling for hardware-backed custody: a reproducible **Qubes OS**
vault image, the ceremony scripts that run inside it, an **emulator test harness** that
exercises every ceremony branch without hardware, and an **offline Debian bundle** builder for
installing the tools on an air-gapped machine.

It is the operational companion to [Regalia KMS](../regalia-kms) — this repository is about
*creating and recovering* the keys (SLIP-0039 / DKEK Shamir shares, Nitrokey HSM 2 funding keys,
YubiKey PIV identities); the KMS repository is about *serving* them.

> **Status: reference tooling.** These procedures are published so the approach can be reviewed and
> reused. They describe an air-gapped, multi-custodian ceremony; adapt the custody model, hardware,
> and thresholds to your own threat model before relying on them.

## What's here

| Path | What it is |
|---|---|
| `qubes/` | The air-gapped Qubes vault: TemplateVM build (`salt/`), ceremony scripts (`scripts/`), recovery runbook (`recovery/`), and the emulator test harness (`emulator/`) |
| `qubes/emulator/` | A software emulator + ~65 tests that drive the ceremony end-to-end (Shamir split/verify, HSM import/clone, CUPS print-and-purge, two-device failover) with no hardware |
| `debian/offline-bundle/` | Builds and verifies a signed, offline apt/wheel bundle so the tools install on an air-gapped host |

## Running the emulator tests

The harness is designed to run in the Debian `vault-tools` environment (or its container image).
It installs its own dependencies (`age opensc pcscd ssss qrencode …`) and drives the ceremony
against an emulated card and printer:

```sh
cd qubes/emulator
./run-tests.sh
```

Individual checks live under `qubes/emulator/tests/` and can be run directly.

## Security

- **No secrets in this repository.** Age keys that appear in tests are `AGE-SECRET-KEY-1EXAMPLE…`
  placeholders. Secret scanning runs over the whole tree with content-only allowlists — see
  [`.gitleaks.toml`](.gitleaks.toml).
- **Custody model is intentionally omitted.** The specific physical share-holder map used by the
  original operators (who holds which share, and where) is *not* published — it is exactly the
  information an attacker would want. Define your own before running a real ceremony.
- **Report vulnerabilities** privately via GitHub Security Advisories.

## Design records

Some scripts and docs cite internal design/requirements records that are part of the operators'
private repository and not included here. The in-repo runbooks (`qubes/README.md`,
`qubes/recovery/RECOVERY-TECHNICAL.md`) are self-contained for understanding the tooling.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
