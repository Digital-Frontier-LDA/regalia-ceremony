# Security Policy

## Status

Regalia Ceremony is published as **reference tooling**. The procedures describe an air-gapped,
multi-custodian key ceremony; adapt the custody model, hardware, and thresholds to your own threat
model before relying on them. The specific physical share-holder map used by the original operators
is intentionally **not** published.

## Reporting a vulnerability

Please report security issues **privately**, never in a public issue or pull request.

Use GitHub's private vulnerability reporting:
**Security → Advisories → [Report a vulnerability](https://github.com/Digital-Frontier-LDA/regalia-ceremony/security/advisories/new)**.

We aim to acknowledge within a few business days and will coordinate disclosure with you.

## Scope

In scope: the code in this repository — the Qubes vault tooling, ceremony scripts, the emulator test
harness, the Pico HSM (RP2350) firmware/hardware work, and the offline Debian bundle builder.

Out of scope: the operators' private custody arrangements and any deployment not built from this
repository.

## Committed secrets

This repository is scanned for committed credentials by gitleaks in CI (fail-closed, full history)
and by GitHub secret scanning with push protection. Age keys that appear in tests are
`AGE-SECRET-KEY-1EXAMPLE…` placeholders. If you believe a real credential was committed, report it
privately — the fix is **rotation**, not deletion.
