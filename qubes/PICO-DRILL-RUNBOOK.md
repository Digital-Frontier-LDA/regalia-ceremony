# Pico HSM import drill — runbook

**One question:** can a **seed-derived secp256k1** key be imported into a SmartCard-HSM and used?

## ✅ ANSWERED — YES, proven on real hardware 2026-07-29

Import → address-match → sign → verify passed end-to-end on the Pico (firmware 6.6), with a
negative control. See `PROOF-OF-WORKS.md` for the transcript. The `SW=6400` that blocked this
turned out to be a bug in `hsm-auto-import.js` — it encoded the key blob under a zero-valued
DKEK — **not** a firmware or curve limitation. The rest of this runbook is retained because the
manual sequence is still the fallback when `hsm-auto-import.sh` cannot run.

> Proven on a **Pico**, which is an open-source reimplementation. The Nitrokey's NXP firmware is
> a separate implementation — repeat on a scratch Nitrokey before opening the gate for real
> custody. `CEREMONY_ALLOW_HSM_IMPORT=1` stays closed until then.

Everything in the custody model rests on the funding key being *derived from the 4-of-6-backed
seed* rather than born on the card. That requirement is now **structural, not just preferred**:
a born-on-card key is non-exportable by construction, so N devices would hold N *different* keys
and N different akash addresses. A shared DKEK domain plus wrapped import is the **only** way a
fleet signs for one address.

**Run it on the Pico first.** It is an open-source SmartCard-HSM reimplementation on a ~€5 board:
same protocol, same tooling, reflashable when you brick it. A real Nitrokey gives you fifteen
wrong SO-PIN attempts before it is scrap (the user-PIN retry counter defaults to three — don't
confuse the two counters).

---

## Smart Card Shell — installed

`scsh3` / `scsh3gui` are on PATH (wrappers in `/opt/homebrew/bin`; app in `~/tools/scsh-3.18.77`).

| | |
|---|---|
| Version | **3.18.77** (engine reports 3.18.110) |
| Source | `https://www.openscdp.org/download/scsh3/scsh-3.18.77.zip` over **HTTPS** |
| SHA256 | `1e5a065b7888a660a088956d110ce5539e85b76cf3c3f02eb57e4d3104bcf280` |
| Java | runs on the installed **JDK 25** |

⚠️ **CardContact publish no checksum or signature.** The hash above is one *we* computed, so it
detects a changed download later — it does not attest the original. For a real ceremony this is a
supply-chain gap on a tool that will handle the funding key: fetch it once, hash it, and move it
onto the air-gapped machine through the same controls as every other artifact. For the drill it is
throwaway key material, so the exposure is low.

The wrappers set `-Dsun.security.smartcardio.library` explicitly. CardContact's own launcher notes
the JRE often fails to find PC/SC on macOS, and the symptom is *"no card reader found"* —
indistinguishable from a genuinely absent device, which is the wrong ambiguity during a one-shot
drill. Both framework paths were tested and load.

**Verify the GUI opens** before you need it — it could not be confirmed from a headless session:

```sh
scsh3gui        # a window should appear; File -> Keymanager
```

### What reading its source already told us

The two places a curve could have been rejected are both **curve-agnostic**:

- `HSMKeyStore.importECCKey` checks only `keytype == 12` (ECC) and hands the blob to
  `unwrapKey` — no OID check, no curve whitelist.
- `DKEK.encodeKey` encodes **explicit domain parameters** (`ECC_P`, `ECC_A`, `ECC_B`, `ECC_G`,
  `ECC_N`) taken from the key itself, not a named-curve table.

So the "Smart Card Shell cannot encode secp256k1" concern — which I had flagged as the *likelier*
failure — looks unfounded. The question reduces to whether the **card firmware** accepts a
secp256k1 key via unwrap, and Nitrokey's fact sheet lists that curve explicitly.

That is good news but it is **source reading, not a passing drill**. Run it anyway.

---

## Before you start

```sh
# everything green, no hardware needed
qubes/emulator/run-tests.sh --models-only
qubes/scripts/prove-ceremony.sh
```

Expected: the emulator model suite runs green (bash asserts + Python unit tests, exit 0), and
**12/12 proven** from `prove-ceremony.sh`.

> **Before opening the gate for real custody, run the drill on a real Pico.** The test in
> the emulator suite uses stubbed tools and a simulated card so it's hermetic and fast — good
> for CI, but it can drift from the hardware it stands in for. The devops validation step
> uses the real device:
>
> ```sh
> HSM_DRILL_HARDWARE=1 qubes/emulator/tests/test-hsm-import-drill.sh
> ```
>
> The test gates on a `THSM1`-carrying ATR appearing on the bus. Note the ATR does NOT
> distinguish a Pico from a genuine SmartCard-HSM — both carry `THSM1` (see the correction
> in §1 below) — so this gate detects a *compatible* card, not a specific make. If
> no such card is present, the test skips cleanly rather than failing — so it's safe in CI
> even when the Pico is not plugged in. On the devops host where the Pico lives, run the
> test with `HSM_DRILL_HARDWARE=1` and confirm the runbook's `--check` reads the real
> card. **Only then set `CEREMONY_ALLOW_HSM_IMPORT=1`** and trust the gate.
>
> The full drill sequence (`--check`/`--prepare`/`--verify`) is intentionally not run by
> the test. The destructive parts (`--prepare` creates a DKEK and initializes the card,
> erasing whatever was there; `--verify` imports a key via scsh3) require the operator to
> drive scsh3 between them. The test asserts the non-destructive part; the operator
> confirms the destructive part. A green hardware-mode run means the devops host can
> talk to the real device; the human then drives the rest:
>
> ```sh
> qubes/scripts/hsm-import-drill.sh --prepare
> # (reads the BIP39 test vector, builds the throwaway PKCS#12, prints the expected
> #  address and the three sc-hsm-tool commands plus the scsh3 import instruction)
> # (drive scsh3 here, per the printed instructions)
> qubes/scripts/hsm-import-drill.sh --verify
> # Expected: "DRILL PASSED" — the card's address matches the seed's, the sign proof
> # succeeds. If green, set CEREMONY_ALLOW_HSM_IMPORT=1.
> ```

If either is red, fix that first — a red drill result would be ambiguous between a script bug and
a device answer, and the whole point is that it isn't.

---

## 1. Plug it in and look

```sh
qubes/scripts/hsm-import-drill.sh --check
```

Writes nothing. Confirms:

- **which device** is attached. ⚠️ **The ATR does NOT distinguish a Pico from a Nitrokey.**
  This runbook and `hsm-import-drill.sh:44-70` both claimed only a genuine SmartCard-HSM carries
  ASCII `THSM1` in its ATR. That is **false** — measured 2026-07-29, a Pico HSM (firmware 6.6)
  reports `3b:fe:18:00:00:81:31:fe:45:80:31:81:54:48:53:4d:31:…`, in which `54 48 53 4d 31` is
  exactly `THSM1`. So `--check` cries wolf on every Pico, which trains operators to ignore the one
  warning that is supposed to stop them erasing a production Nitrokey.

  Use the **PKCS#11 token identity** instead — it is unambiguous:

  ```sh
  pkcs11-tool --module /opt/homebrew/lib/opensc-pkcs11.so --list-slots
  #   token label : Pico-HSM          serial num : ESPICOHSMTR     <- the staging board
  ```

  Pin the exact device with `CEREMONY_EXPECT_ATR` (full-ATR match) plus the serial, never the
  `THSM1` substring. If `--check` warns `REAL SmartCard-HSM`, confirm against the serial before
  believing it.
- the **toolchain** — `opensc-tool`, `sc-hsm-tool`, `pkcs11-tool`, `openssl`, `python3`, and
  **Smart Card Shell** (`scsh3gui`, from openscdp.org — it is Java, so a JRE too).
- the **PIN retry counters**, read-only.

**If no card is detected:** check `opensc-tool --list-readers`. On macOS the built-in PC/SC stack
is used — there is no `pcscd` to start. A USB-A→USB-C *adapter* has already caused
`Unresponsive card` here once; use a direct cable.

---

## 2. Build the throwaway container

```sh
qubes/scripts/hsm-import-drill.sh --prepare
```

Uses a **published BIP39 test vector**, hard-coded. It never reads your real mnemonic — the whole
point is that a €5 microcontroller and an unproven import path never touch the funding seed.

Prints the expected address: **`akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0`**

---

## 3. Import it (the step no CLI can drive)

The SmartCard-HSM supports **only encrypted import**, so the device needs a DKEK domain first.
`--prepare` prints these with the right paths filled in:

```sh
sc-hsm-tool --create-dkek-share <dir>/dkek.pbe --pwd-shares-threshold 2 --pwd-shares-total 3
sc-hsm-tool --initialize --dkek-shares 1 --label 'drill'      # ERASES the device
sc-hsm-tool --import-dkek-share <dir>/dkek.pbe --pwd-shares-total 2   # prime + 2 of the 3 shares
```

Without `--pwd-shares-total` the import asks for a typed password, and the generated one is never
shown. OpenSC refuses a split smaller than 2-of-3.

Then in **Smart Card Shell**: `File → Keymanager` → right-click **SmartCard-HSM** →
**Import from PKCS#12**.

- container: the `.p12` from step 2
- password: `cat` the password file — don't retype from screen
- **label: `akash-funding`** — `--verify` looks for exactly this

---

## 4. Verify

```sh
qubes/scripts/hsm-import-drill.sh --verify
```

Two proofs, both required:

| Proof | Catches |
|---|---|
| **Address match** | an import that landed a *different* key — it would sign perfectly and lose the funds |
| **Signature** | a key that reads back but cannot be used, or a card that signs with something else |

---

## Reading the result

**PASS on the Pico** → the Smart Card Shell toolchain *can* encode secp256k1 through PKCS#12.
That is the **software half**, and the likelier failure. The Nitrokey's NXP firmware is a separate
implementation — repeat on a scratch Nitrokey before opening the gate for real custody.

**PASS on a Nitrokey** → both halves proven. Open the gate:

```sh
CEREMONY_ALLOW_HSM_IMPORT=1
```

**FAIL — "did not parse as secp256k1"** → the import mangled the curve. This is the answer the
drill exists to get. The HSM cannot hold a seed-derived key; the funding key stays in software on
owned hardware and the HSM drops out of the funding path.

**FAIL — address mismatch or signature** → something is wrong with the import *procedure*, not
necessarily the curve. Re-run `--prepare` and redo the import before concluding anything.

---

## Afterwards

```sh
rm -rf "${TMPDIR:-/tmp}/hsm-import-drill"
```

Throwaway, but still key material.

**The Pico stays plugged in.** It becomes permanent CI: real firmware exercising the DKEK and
import paths, instead of a ~400-line Python model (`emulator/bin/sc-hsm-tool`) that can drift
from the hardware it stands in for.

⚠️ Once a Pico and a Nitrokey are attached together, **reader index stops being evidence** — it is
assigned in attach order. The ceremony's destructive steps fingerprint by ATR
(`assert_expected_device`), and `CEREMONY_EXPECT_ATR` pins one *specific* device, which is the only
way to tell two Nitrokeys apart since both carry `THSM1`.
