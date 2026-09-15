# Nitrokey HSM 2 qualification on Qubes OS

Why this exists: on macOS the built-in CCID driver will not negotiate the Nitrokey HSM 2's ATR
transmission speed, so the token resets but never completes a data connection (`SCARD_W_UNRESPONSIVE`).
A Linux/Qubes host with OpenSC's own CCID stack connects cleanly. This runbook qualifies the token
there and answers the two D1-gated questions with **only the OpenSC tools already in the vault-tools
TemplateVM** — no Go toolchain, so it runs in the minimal ceremony AppVM.

The questions (`qubes/scripts/nitrokey-qualify.sh`):
- **#448** — does the token expose its device-authentication certificate as a PKCS#11
  `CKO_CERTIFICATE`? If yes, the daemon's identity probe works on this token where it failed on the
  Pico; if no, the probe needs the EF 2F02 APDU fallback.
- **#447** — does a key **generated on the token** report `CKA_LOCAL` true? The wrap guard admits a
  KEK only when its public half is `local`. On the Pico it was false for every key.

## 1. Build (or update) the vault-tools TemplateVM

The image is defined by `qubes/salt/vault-tools.sls` (OpenSC, pcscd, libccid, sc-hsm-tool,
pkcs11-tool, yubikey-manager, hash-pinned SLIP-39). From dom0:

```
sudo qubesctl --skip-dom0 --targets=vault-tools state.apply vault-tools
```

Copy this repo's `qubes/scripts/` into the AppVM (or clone the repo into a dev AppVM). The
qualification script needs nothing outside OpenSC.

## 2. Attach the Nitrokey HSM 2 to the vault AppVM

Qubes routes USB through `sys-usb`. List and attach the token to the AppVM (here `vault`):

```
qvm-usb                              # find the Nitrokey's <backend>:<devid>
qvm-usb attach vault sys-usb:<devid>
```

In the AppVM, confirm OpenSC sees it and reads its serial:

```
opensc-tool --list-readers
pkcs11-tool --module /usr/lib/*/opensc-pkcs11.so -L    # note the "serial num"
```

If `--list-readers` shows the reader but a connect says "Unresponsive", the CCID stack is fine on
Qubes; re-attach the device. Two HSMs attached at once are addressed **by serial**, never by index.

## 3. Read-only qualification (spends no PIN, changes nothing)

```
cd qubes/scripts
./nitrokey-qualify.sh --serial <token serial>
```

It prints the `#448` (device certificate present or not) and `#447` (public keys, how many report
`CKA_LOCAL=true`) findings. A factory-fresh token has no keys, so `#447` needs step 4.

## 4. Provisioning qualification (DESTRUCTIVE — wipes the card)

Authorized for the two future-production units as staging (owner, 2026-09-15). It initialises the
card and generates a secp256k1 key **on** the token, then measures `#447` on that card-generated key:

```
./nitrokey-qualify.sh --serial <token serial> \
  --pin <user PIN> --so-pin <SO-PIN> \
  --provision --i-understand-this-wipes-the-card
```

The result line says whether a key generated on this token reports `CKA_LOCAL=true` (the wrap guard
admits it) or not (as on the Pico — provenance must then come from device attestation). Restore
staging posture afterwards. Do not exhaust the SO-PIN retry counter.

## What this feeds back

Record the `#447`/`#448` results on issues #447 and #448. If the Nitrokey exposes a `CKO_CERTIFICATE`
and reports card-generated keys as `local`, the production wrap/identity path works unchanged; if not,
those issues drive the attestation/APDU-fallback design. The same measurements are taken by the Go
instrument `TestNitrokeyHSM2Qualification` (kms/e2e/NITROKEY-QUALIFICATION.md) on a host with Go.

The script is verified in CI (`local-hsm-e2e`) against a SoftHSM token: it must see no device
certificate and read a generated key as `local` and an imported key as not.
