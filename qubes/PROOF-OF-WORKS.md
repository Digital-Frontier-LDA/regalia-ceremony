# Proof of works: this setup actually works on real hardware

A security architecture is only as good as the proof that it works. This document
defines the proof we run on the real Pico HSM **before** opening the gate, and what
artifact it produces.

> "This works" is not the same as "this is secure". This document covers the
> first. The second is a separate test — see "Red-team verification" below.

## The proof, end to end

The Pico HSM is plugged into the devops host. The drill (`hsm-import-drill.sh`)
runs against the real card. The artifact is:

1. The drill's `--check` output showing the real card is enumerated and the toolchain
   is complete.
2. The drill's `--prepare` output showing the BIP39 test vector, the throwaway
   PKCS#12 container, and the three `sc-hsm-tool` commands needed to put the card
   in a state that accepts imports.
3. The user drives `scsh3` to import the throwaway PKCS#12.
4. The drill's `--verify` output showing:
   - The card's public key (read from the real hardware)
   - The address derived from the card's public key
   - The address derived from the seed (in software)
   - The two addresses MATCH
   - A signature produced by the real card, verified in software against the card's
     public key
   - A "DRILL PASSED" line

If any of those fail, the round-trip is broken and the architecture does not work
on real hardware. The drill's --verify is the proof that the entire key path
(software seed → hardware device → signed output) works end-to-end on this
specific Pico.

A red CI run with the drill passing on the SoftHSM2 emulator is a *precondition*
to the real-Pico run, not a substitute. The hardened, hermetic test catches script
bugs and logic errors; only the real-device run catches firmware quirks, driver
quirks, and protocol-level mismatches.

## When this proof runs

- After any change to the drill, the ceremony, the seed handling, or the HSM
  client code
- Before the devops host is granted the ability to open the production gate
  (`CEREMONY_ALLOW_HSM_IMPORT=1`)
- On a regular cadence (recommendation: monthly, or every 90 days, to catch
  silent firmware regressions in the Pico's UF2)

## How far the automation actually goes (measured on real hardware)

The goal is a fully automated end-to-end validation with no human in the loop.
That is achievable, but **not for the whole sequence** — and the boundary was
found by running it, not by reading docs.

**The unlock:** `scsh3` is not GUI-only. The distribution ships
`scriptrunner` (`de.cardcontact.scdp.engine.ScriptRunner`), a headless JS
engine with the same `require("scsh/sc-hsm/…")` module tree the Key Manager
GUI uses. So the PKCS#12 import — the step the runbook previously described as
"no CLI can drive this" — **is** scriptable:

```js
var DKEK = require("scsh/sc-hsm/DKEK").DKEK;
var SmartCardHSM = require("scsh/sc-hsm/SmartCardHSM").SmartCardHSM;
var sc = new SmartCardHSM(new Card(_scsh3.reader));
sc.verifyUserPIN(new ByteString("648219", ASCII));
var p12 = new KeyStore("BC", "PKCS12", "/path/funding.p12", pw);  // plain strings, not ByteString
var key = new Key(); key.setType(Key.PRIVATE); key.setID(alias); p12.getKey(key);
var blob = new DKEK(new Crypto()).encodeKey(key, p12.getCertificate(alias).getPublicKey());
sc.unwrapKey(sc.determineFreeKeyId(), blob);
```

Verified working up to and including `encodeKey` (produces a 363-byte blob for
a secp256k1 key). Gotchas that cost real time, recorded so nobody re-finds them:

- `new ByteString(path, BASE64)` **decodes the path string as base64 data** — it
  does not read a file. Use `PKIXCommon.readFileFromDisk(path)`.
- `KeyStore(...)` wants plain JS strings for path and password, not `ByteString`
  and not `java.lang.String`.
- `DKEK` needs a plain `new Crypto()` (which has `.digest`), **not**
  `sc.getCrypto()` — that returns `SmartCardHSMCrypto`, which only wraps
  sign/encrypt/decrypt/verify.
- `sc-hsm-tool --create-dkek-share` and `--import-dkek-share` both accept
  `--password env:VARNAME`, which removes every interactive prompt. The value is
  treated as the **literal ASCII password**, not as hex bytes.
- Homebrew's `openjdk` and `openssl@3` dylibs are Gatekeeper-quarantined and
  must be cleared (`xattr -dr com.apple.quarantine …`) or `scriptrunner` aborts
  on `libjli.dylib`.

**The wall: `sc-hsm-tool --initialize` drops the Pico off the USB bus.** Every
single time. The reader disappears, then returns as "no card present", and only
a physical unplug/replug brings it back. This is firmware behaviour, not a
script bug — it reproduced on every attempt in this run. Because `--initialize`
is what reserves the DKEK key domains, any sequence that includes it **cannot**
run unattended.

So the automatable envelope is:

| step | automatable? |
|---|---|
| `--initialize --dkek-shares N` (reserves domains) | ❌ one-time, needs a hand on the USB port |
| `createDKEKKeyDomain` (APDU `80 52 01`, no re-init) | ✅ |
| `--import-dkek-share --password env:VAR` | ✅ |
| `seed-to-pkcs12.py` → container | ✅ |
| `DKEK.encodeKey` + `unwrapKey` via `scriptrunner` | ✅ |
| address match + sign + verify | ✅ |

**Conclusion:** treat `--initialize` as one-time provisioning, exactly like
flashing the UF2 — a human does it once when the device is commissioned. After
that, the whole import → address-match → sign → verify chain runs unattended on
every validation cycle. That is the shape the automated devops validation should
take.

⚠️ **Correction (2026-07-29):** `createDKEKKeyDomain` does **not** work on this
hardware. Pico HSM firmware 6.6 answers the APDU with `SW=6A86` (Incorrect
P1-P2) — the command is not implemented. Domain provisioning therefore goes
through `sc-hsm-tool --import-dkek-share` against an already-reserved domain,
which needs no `--initialize` and so still avoids the USB-drop entirely.

## PROVEN on real hardware — 2026-07-29

**A seed-derived secp256k1 key CAN be imported into SmartCard-HSM firmware and
used to sign.** This supersedes the "not yet proven" note that stood here.

```
STEP wrap:   keyblob=363 bytes under kcv=DA4BF33D408C5C57
STEP unwrap: OK into keyId=1
card key:    sensitive, always sensitive, never extractable
card pubkey → akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0   (the BIP39 vector's address)
verify-hsm-control.py: exit 0      negative control (wrong digest): exit 1
```

**Root cause of the `SW=6400` that blocked this for so long: a bug in
`hsm-auto-import.js`, not the card.** The script encoded the key blob under
`new DKEK(new Crypto())`, and that constructor initialises the DKEK to **32 zero
bytes** (`DKEK.js:35-38`). The card meanwhile held the random imported share, so
the blob was always encrypted under a DKEK the card did not have — a guaranteed
mismatch on every attempt, which the card reports as `SW=6400`. The wiped-domain
theory recorded above was a contributing factor but not the cause.

The fix is to rebuild the local DKEK from the same share the card holds, which
`DKEK` already supports:

```js
var dkek = new DKEK(new Crypto());
dkek.importDKEKShare(DKEK.decryptKeyShare(share, sharePW));   // <- the missing line
var blob = dkek.encodeKey(key, pub);
```

**The lesson worth keeping:** an `SW=6400` from a wrap/unwrap round-trip is
*indistinguishable* between "this card rejects this curve" and "these two DKEKs
differ". Nearly a full architecture decision was very nearly made on the first
reading when the second was true. Any future HSM script must assert the DKEK is
active and matching **before** attributing a failure to the key type.

## How to run the proof

```sh
# 1. Make sure the Pico is plugged in and enumerated
HSM_DRILL_HARDWARE=1 qubes/emulator/tests/test-hsm-import-drill.sh
# Expect: 3/3 (real card recognised, PIN retry counters read, toolchain confirmed)

# 2. Run --prepare (BIP39 vector, throwaway PKCS#12, prints the next steps)
CEREMONY_MODE=dev qubes/scripts/hsm-import-drill.sh --prepare

# 3. The output above prints three sc-hsm-tool commands. Run them.
#    - They create the DKEK share, initialize the card, and import the DKEK.
#    - The DKEK password file is on disk in the workdir.

# 4. Drive scsh3 to import the throwaway PKCS#12 (label: akash-funding).

# 5. Run --verify (the round-trip)
qubes/scripts/hsm-import-drill.sh --verify
# Expect: "DRILL PASSED" — the card's address matches the seed's, the sign proof
# succeeds.

# 6. Save the proof
mkdir -p /var/log/devops-validation/
qubes/scripts/hsm-import-drill.sh --verify \
  | tee /var/log/devops-validation/$(date -u +%Y%m%dT%H%M%SZ)-drill.txt
```

If step 5 is green, the gate is open: `export CEREMONY_ALLOW_HSM_IMPORT=1`.

## Red-team verification: the security claim

"This works" proves the key path. "This is secure" is a separate claim
that needs its own test: an attacker gets to try to break the system.

The scenarios the red team needs to test:

1. **Stolen session key, no VPS compromise.** The attacker has the
   `x-tx-signer-api-key` header value but no other access. They flood the
   signing endpoint with 10,000 transactions. The spend-guard should
   reject every transaction past the per-tx cap, the per-day cap, or
   the per-ops-minute rate. Verify the response codes and the on-chain
   transaction count.

2. **VPS compromise, no HSM access.** The attacker has full root on
   the VPS. They can call the signing endpoint at will. The spend-guard
   caps still hold — but they can sign at the cap rate. The proof: the
   cap on a 24-hour window limits the damage to a known bound, even with
   arbitrary access. Test that the cap is enforced server-side (not in
   the API client).

3. **Wrong-key import.** The attacker (or a careless operator) tries
   to import a key that does not match the seed. The drill's --verify
   catches this on every test run (it asserts address equality). The
   test confirms the real Pico behaves the same way.

4. **Card removal mid-operation.** The Pico is unplugged while a
   signing request is in flight. The signing request should fail, the
   spend-guard should not increment counters on a failed sign, and the
   next request after the card is re-plugged should resume correctly.

5. **Re-initialise attempt.** The attacker (or operator) tries
   `sc-hsm-tool --initialize` while the card holds a key. The card
   should refuse (DKEK import fails) OR the key should be unrecoverable
   (the seed's key is gone) — and the drill's --verify on a re-init
   card should fail.

The first three are unit tests. The last two are integration tests on the
real device. All five should be added to the devops validation suite.

## Why this is the right test plan

The "this works" proof runs the **positive** path. It's deterministic: same
seed, same device, same result every time. A green run is binary.

The "this is secure" proof runs the **negative** path. The system says
"no" a lot, and the test must enumerate the "no"s that matter: a stolen
key can't drain the wallet, a VPS compromise can't exceed the cap, a wrong
key can't be imported, a removed card doesn't leak a stale signature.

The architecture's claim is bounded. The proof is concrete. The test plan
above makes the claim verifiable, and a passing test run closes the gap
between "we think this is safe" and "we have evidence this is safe on
this specific Pico with this specific firmware".
