# Ceremony hardware emulators

A faithful emulator for **every hardware route** the key ceremony (`../scripts/ceremony.sh`)
can take, so the whole wizard can be driven end-to-end — in CI on a native Debian/Ubuntu
runner, or on the Debian Qubes box itself — with **no physical tokens, reader, printer, or
burner**. This closed the gap in the ceremony README's "Verification status" table: the
hardware routes that were once `❌ untested — need the physical tokens + Qubes` are now
`✅ emulated + exercised`.

These emulators are for **rehearsal and testing only**. They never hold a real key. The real
ceremony still runs on the air-gapped Qubes vault qube with real hardware — see
[`../README.md`](../README.md). The emulator image is deliberately **not** baked into the
vault template (the Salt formula excludes the test harnesses; the wizard's `guard_no_stubs`
is the second line of defence).

## What each route maps to

| Ceremony route (tool) | Real device | Emulator | Fidelity |
|---|---|---|---|
| `pkcs11-tool` keygen / sign / pubkey | Nitrokey HSM 2 (SmartCard-HSM) | **SoftHSM2** real PKCS#11 module | **High** — real secp256k1 keygen, real ECDSA signatures, real pubkey DER → real akash address. Only difference: ECDSA's random `k` (signatures aren't byte-identical run-to-run; verification is). |
| `sc-hsm-tool --create-dkek-share` | SmartCard-HSM (OpenSC opens the reader for its random numbers) | OpenSC's password-share path: an 8-byte password, Shamir over a 64-bit prime, OpenSC's share output + AES blob | **High** — the 4-of-6 split genuinely reconstructs with 4 and fails with 3, and import rebuilds the password as OpenSC 0.27.1 does, including the leading zero byte it drops (1 share file in 128 refused with its correct shares, #460; force it with `EMU_SCHSM_PWD_LEADING_BYTE=zero`). Not modelled: OpenSC's padding-only check, which accepts about 1 wrong key in 255. |
| `sc-hsm-tool --initialize / --import-dkek-share / --wrap-key / --unwrap-key` | SmartCard-HSM card op | functional state model (real AES wrap round-trip) | **Medium** — no free SmartCard-HSM applet exists, so these are modelled. The cryptographically meaningful key ops run for real on SoftHSM2; wrap/unwrap genuinely round-trips so a DR drill works. **This is the one documented gap.** |
| `age-plugin-yubikey --generate` | YubiKey 5 (PIV / P-256) | native **age** identity behind the plugin interface | **High** — real `age1…` recipient usable in `.sops.yaml`; real encrypt→decrypt round-trip. Difference: no physical-touch gate (no PIV applet). |
| `ykman list / piv info` | YubiKey 5 management | **`ykman`** shim | **Low** — reports a plausible emulated YubiKey 5 + PIV touch policy so management/inspection calls don't abort a rehearsal (no crypto). |
| `sle4442-manager` (PC/SC) | SLE 4442 memory card | **`sle4442-vpicc.py`** over real `pcscd` + `vpcd` | **High** — the chip (256-byte memory, 32-bit write-once protection, PSC + error-counter lockout) modelled to datasheet behaviour and driven through the **real PC/SC stack** using the standard memory-card pseudo-APDUs. A real Identiv/SCM reader + card runs the same `sle4442-manager` unchanged. |
| `lp` / `lpstat` printing | USB Brother laser + CUPS | **CUPS + cups-pdf** | **High** — a real CUPS queue; `lp` produces a real PDF in the spool. |
| `growisofs` + cross-drive verify | 2× optical M-DISC drives | **xorriso** ISO + `optical-verify` | **High** — a real ISO9660 image is written and read back by an independent extractor (the "second drive"); fault injection proves the checksum verify rejects a marginal burn. |

## Run it (native — no Docker)

The supported path boots the emulator daemons **directly on Linux** (the Debian Qubes box
where the real ceremony runs, or a native Debian/Ubuntu CI runner). No container — Docker's
VM is heavy on memory/VRAM and a native runner mirrors the real target more faithfully.

```bash
# on a Debian/Ubuntu box (first time: install the toolchain + emulator stack):
sudo qubes/emulator/run-tests.sh --install-deps

# thereafter (boots emulators, runs every route + the wizard + go/no-go; needs root for
# pcscd/cups/mknod):
sudo qubes/emulator/run-tests.sh

# only the suites that need no Linux daemons (works on macOS too):
qubes/emulator/run-tests.sh --models-only
```

CI runs exactly this on a native `ubuntu-latest` runner — see
[`.github/workflows/ceremony-emulator.yml`](../../../.github/workflows/ceremony-emulator.yml).

What it runs:
- **`tests/route-coverage.sh`** — every hardware route vs the emulators (+ a coverage matrix).
- **`tests/test-go-nogo.sh`** — the day-of [`scripts/go-nogo.sh`](../scripts/go-nogo.sh)
  gate, asserting GO when all devices are present and NO-GO when e.g. a YubiKey is one wrong
  PIN from PUK lockout.
- **`tests/dress-rehearsal.sh`** — drives the **real `ceremony.sh` wizard** end-to-end
  (its actual menu, prompts, share-regex, printer + file flow, secret-leak hygiene) against
  the faithful emulators, so nothing about the *script* is a surprise on the day.

> Docker is still available as an optional convenience (`build.sh` + `docker run --rm
> --privileged ceremony-emu all-tests`) but it is **not** the test path.

The SLE-4442 chip model also has a **pure-Python unit test that runs anywhere** (no Docker,
no pcscd) — datasheet behaviour for read / PSC gate / wrong-PSC lockout / write-once
protection / change-PSC / persistence:

```bash
python3 qubes/emulator/tests/test_sle4442_model.py
```

## How the SLE-4442 emulator works

`sle4442-vpicc.py` is a self-contained **vpicc** (virtual ICC): it speaks the
[vsmartcard](https://frankmorgner.github.io/vsmartcard/) `vpcd` wire protocol (2-byte
length-prefixed frames; control bytes for power/reset/ATR; APDUs otherwise) and connects to
the `vpcd` virtual reader that `pcscd` loads. So from any PC/SC application's point of view
there is a real reader with a real SLE-4442 in it. The card answers the PC/SC 2.0 memory-card
pseudo-APDU set (`FF A4` select card type, `FF B0` read, `FF D0` update, `FF 20` present PSC,
`FF B1/B2` read security/protection, `FF D1` lock, `FF D2` change PSC) exactly as a reader's
synchronous-card firmware does — which is how every PC/SC SLE-4442 tool already talks to the
chip.

## Files

```
emulator/
  run-tests.sh            # PRIMARY native runner (boots emulators on Linux, runs all suites)
  bin/
    emu-boot.sh           # sourceable lib: boots pcscd+vpcd, SLE-4442 vpicc, SoftHSM2, cups-pdf
    sle4442-vpicc.py      # the SLE-4442 card emulator (vpcd protocol + chip model)
    sle4442-manager       # PC/SC route: store/read/verify a secret on the card (pyscard)
    pkcs11-tool           # shim: routes pkcs11 calls to SoftHSM2 + normalises pubkey to SPKI
    sc-hsm-tool           # model: DKEK 4-of-6 + key wrap/unwrap round-trip
    age-plugin-yubikey    # shim: software age identity behind the plugin interface
    ykman                 # shim: emulated YubiKey 5 management / PIV info
    growisofs             # shim: burn an M-DISC image with xorriso
    optical-verify        # cross-drive read-back + checksum (with fault injection)
    emu-entrypoint.sh     # OPTIONAL Docker entrypoint (thin wrapper over emu-boot.sh)
  tests/
    route-coverage.sh         # drive every route vs the emulators + coverage matrix
    dress-rehearsal.sh        # drive the REAL ceremony.sh wizard end-to-end vs the emulators
    test-go-nogo.sh           # exercise scripts/go-nogo.sh (GO when ready, NO-GO when not)
    test_sle4442_model.py     # pure-model unit tests (run anywhere)
  Dockerfile, build.sh    # OPTIONAL container path (not the test path)
```

## Secret-leakage hardening (`tests/test-secret-leak.sh` + `TestSecretLeak`)

An adversarial pass (`/nf:harden` spirit) hunts for any path where a secret could reach a
log, stdout, a loose-perm file, the process command line, the swap, or the print spool —
across the whole flow **including Shamir/SLIP-39 recombination**. Findings found and fixed:

| # | Severity | Leak | Fix |
|---|---|---|---|
| 1 | **Critical** | the SLE-4442 vpicc logged full APDU bodies → the **PSC**, the **stored Shamir share**, and **read-back secret bytes** landed in `sle4442.log` | `log_line()` redacts the secret data of VERIFY-PSC / WRITE / CHANGE-PSC commands and of memory-READ responses; only non-secret headers + status word are logged |
| 2 | High | the PSC was passed on `--psc` argv → visible in `ps` / `/proc/<pid>/cmdline` / shell history | PSC now resolves from `SLE4442_PSC` env or `--psc-file` (manager) / `SLE4442_EMU_PSC` (vpicc); a non-default argv PSC warns |
| 3 | Medium | the DKEK material + cleartext share-password stash were created with the caller's umask | `sc-hsm-tool` forces `umask 077`; state dir 0700, files 0600 |
| 4 | Medium | the SLE-4442 state file (stored share + PSC) used default perms | `_save()` writes it 0600 |
| 5 | Medium | `bip39-slip39-backup.py` + `metal-stamp-worksheet.py` wrote the SLIP-39 shares / recovered mnemonic with the caller's umask (world-readable under umask 022) | both now `os.open(..., 0o600)` + chmod, independent of umask |

A second, deeper pass then found **logic / crypto / backup-integrity** bugs (not just perms):

| # | Severity | Bug | Fix |
|---|---|---|---|
| 6 | **Critical** (real money) | the ssss split path (`ceremony.sh` option a) **distributed shares with no reconstruct-verify** — a silently-bad split = an unrecoverable breakglass key | reconstruct-verify inline (recover from a 4-subset, compare in-shell — no value printed) and **abort before printing** on mismatch |
| 7 | **Critical** (real money) | ssss **silently truncates** a multi-line or >128-byte secret → you'd back up the wrong bytes | refuse multi-line / oversized input and redirect to the SLIP-39 path |
| 8 | High | `sle4442-manager info` dumped `main[0:16]` card memory to stdout → a stored share could leak | `info` shows only status (counter/protection); contents only via explicit `read` |
| 9 | Medium | the DKEK key-wrap model was a **two-time pad** (deterministic keystream + same key for cipher & MAC) | per-wrap random nonce + distinct enc/MAC subkeys; authenticated; tamper- and wrong-key-rejecting |
| 10 | Medium | the SLE-4442 `WRITE` ignored `Lc` (wrote trailing bytes) and was **non-atomic** (partial write before a locked byte) | honour `Lc`, reject short data, and reject the whole write if any target byte is locked |
| 11 | Low | `bip39-slip39-backup.py --recover` printed the recovered seed to stdout with no warning | warns on a TTY; recommends `--out <tmpfs file>` |

A third pass found the **worst leak and a stranding bug** in the SLIP-39 mint path:

| # | Severity | Bug | Fix |
|---|---|---|---|
| 12 | **Critical** (real money) | option b minted a fresh secret and **distributed shares with no reconstruct-verify** — and the secret exists *only* in those shares, so a bad split = permanent loss | new `slip39-mint.py` verifies **every** 4-of-6 subset rebuilds the exact secret before writing |
| 13 | **Critical** (total compromise) | `shamir create` prints `Using master secret: <hex>` to **stdout**, and the ceremony redirected that into the **same file as the shares** — the master secret sat in cleartext next to its own shares, defeating Shamir entirely | replaced the CLI with `slip39-mint.py`, which **never emits the master secret** (it lives only in RAM, recoverable from the shares); file is 0600 |
| 14 | High (day-of stall) | `ceremony.sh` located its helper scripts via `$(dirname "$0")`, which breaks under a symlink / wrapper / `source` — the wizard could fail to find `derive-akash-address.py` / `slip39-mint.py` mid-ceremony | resolve all siblings from `${BASH_SOURCE[0]}` (`$HERE`), robust to how it's invoked |

The BIP-39 funding-seed path (`bip39-slip39-backup.py`, option c) already reconstruct-verified;
it now checks **two distinct k-subsets** (first-k and last-k), not one — defense in depth on
the seed that holds the money.

A fourth pass (manual; the quorum workflow hit the weekly account limit mid-run) found two
more — a false-confidence backup check and a false-GO:

| # | Severity | Bug | Fix |
|---|---|---|---|
| 15 | High | `metal-stamp-worksheet.py --verify` reported "VERIFY OK" if each stamped prefix was *a* valid SLIP-39 word — it could **not** catch a mis-stamp that landed on a **different** valid word (ACADEMIC→ACID), giving false confidence in the last-resort metal backup | verify now validates the reconstructed share against its **SLIP-39 RS1024 checksum** (`Share.from_mnemonic`) — a single wrong word fails it; refuses + prints nothing on a bad plate; also asserts the 1024-word list has no 4-letter-prefix collision |
| 16 | High (false GO) | `go-nogo.sh` accepted unknown `--need` tokens silently — a typo (`--need yubikey,sle442`) **skipped that device's check** and still reached GO | unrecognised `--need` tokens are now a hard error before any probe |

A fifth pass audited the **offline recovery procedure** a break-glass recoverer follows:

| # | Severity | Bug | Fix |
|---|---|---|---|
| 17 | High (silent wrong seed) | a non-empty SLIP-39 **passphrase** is not recoverable from the shares — a wrong/forgotten one silently yields a **different** seed (no error) → wrong address → funds lost. Nothing warned, and the runbook didn't mention it | `bip39-slip39-backup.py` + `slip39-mint.py` warn loudly on a non-empty passphrase; `RECOVERY-TECHNICAL.md` documents the requirement; `test_recovery_procedure.py` proves backup→recover round-trips from a 4-share file (the exact runbook steps) and that a wrong passphrase differs |

**Total: 17 bugs found & fixed across 5 passes (5 critical).** The host-native suite
(Python model/unit suites plus bash integration suites) runs with 0 failures, no Docker. A multi-agent quorum review
(6 reviewers → 3-voter adversarial verification → failing-test-first fixes) runs in parallel
as an independent cross-check.

The funding-address derivation (`derive-akash-address.py`) was audited and is **correct** —
`tests/test_derive_address.py` pins it to the secp256k1 generator whose `hash160` is the
canonical **BIP-173** vector (an independent check), and asserts compressed/uncompressed/SPKI
inputs all agree and that wrong-curve / truncated DER is rejected.

Confirmed-clean invariants (regression-guarded by the suite): shell history off, core dumps
off, `umask 077`, secret workdir is tmpfs (`/dev/shm`) and shredded on exit, secrets reach
`qrencode` from a file (never echoed), the CUPS spool is purged after printing, a single
Shamir share never contains the plaintext secret, recombination output is not persisted to
any file, and the age private key is 0600 and never printed (only the public `age1…`).

```bash
qubes/emulator/tests/test-secret-leak.sh        # adversarial leak hunt (host-native)
python3 qubes/emulator/tests/test_sle4442_model.py   # incl. TestSecretLeak
```

## Day-of go/no-go gate ([`../scripts/go-nogo.sh`](../scripts/go-nogo.sh))

Run on the air-gapped vault qube immediately before the ceremony — read-only, touches no
keys. It runs `preflight.sh`, then turns "this device is missing" warnings into **hard
gates** for exactly the devices this ceremony needs, with capability probes that catch the
day-of surprises (a reader that can't talk to the card, a YubiKey one wrong PIN from PUK
lockout, a network printer, a single optical drive), and ends in one **GO / NO-GO** verdict
plus an operator decision checklist (PINs/PUK/SO-PIN/PSC to confirm, not improvise):

```bash
/opt/vault-ceremony/go-nogo.sh --need yubikey,hsm,sle4442,printer,drives
```
