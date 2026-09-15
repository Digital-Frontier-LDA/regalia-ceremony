# Staging gate: 19/19 green — what it took

**Date:** 2026-08-06. `hsm-staging-ci.sh --tier gate` → `19 passed, 0 failed`, exit 0.

Starting point was five failing steps. Each fix below is a real defect or a real config gap, not
a test tweak.

## Reproducing a green gate

```sh
export PATH="$HOME/.local/share/regalia-ceremony-venv/bin:$PATH"   # pycvc etc. (see below)
export HSM_CI_SERIAL=ESP2202E14A                                    # this device's serial
bash qubes/scripts/hsm-staging-ci.sh --tier gate
```

## Identity values for this card (pin these)

| variable | value |
|---|---|
| `HSM_CI_SERIAL` | `ESP2202E14A` |
| `HSM_CI_EXPECT_CHR` | `ESP2202E14A00001` |
| `HSM_CI_EXPECT_ATR` | `3b:fe:18:00:00:81:31:fe:45:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:fa` |
| `HSM_CI_EXPECT_DEVAUT_SHA` | `3bb3964fd7637d76…` (full value in the gate transcript) |
| pinned public key | `~/.local/share/akash-hsm-staging/expected-pub.der` (secp256k1, key id `31`) |

**Caveat before pinning `DEVAUT_SHA`:** the current C.DevAut is a *self-signed bootstrap*
certificate minted by the DevAut fix. Pinning to it anchors staging identity to that cert. Decide
deliberately; it is not a CA-issued identity.

## What each failure actually was

### `unit_cvc` — dependency, not code
`pycvc` was only in a throwaway venv. **Do not** use
`pip3 install --break-system-packages`: this Mac's `python3` is Homebrew 3.14, PEP 668
externally-managed, with a root-owned `site-packages` — the install dies with
`uninstall-no-record-file` and then `Permission denied`. Instead:

```sh
python3 -m venv ~/.local/share/regalia-ceremony-venv
~/.local/share/regalia-ceremony-venv/bin/pip install --require-hashes -r qubes/requirements.txt
```

The orchestrator invokes bare `python3`, so putting that venv first on `PATH` is sufficient — no
sudo, no script change, and it ports to the DL360 unchanged.

### `hw_serial` — a consequence of the DevAut fix
The gate defaulted to `EXPECT_SERIAL=ESPICOHSMTR`. That constant was the *shared* fallback CHR;
after the DevAut bootstrap fix every device derives a unique serial from its board ID. Any
self-provisioned device now needs `HSM_CI_SERIAL` set. This will apply to every future card.

### `hw_devaut` — a real firmware bug (fixed)
C.DevAut was 940 bytes: a 497-byte EE authenticated request (tag `0x67`) concatenated with the
443-byte certificate (tag `7F21`). `asn1_cvc_aut()` and `asn1_cvc_cert()` both **append**
(`output->len += out_len`) and the shared buffer was never reset, so `EF_TERMCA` was written with
the cumulative length. OpenSC decodes the first object, so its "device certificate" was really the
request; offline TR-03110 verification failed outright.

Fixed by resetting `certificates.len = 0` before the certificate build (pico-hsm `c75ce19`).
EF 2F02 940 → 443 bytes; `hw_devaut` FAIL → PASS.

### `hw_rrc` — configuration, and the Pico *does* honour it
`sc-hsm-tool --initialize` hardcodes RRC on. Re-provisioning with the hardened script clears it:

```sh
cd ~/tools/scsh-3.18.77 && HSM_SO_PIN=… HSM_USER_PIN=… HSM_RRC_MODE=off \
  ./scriptrunner .../qubes/scripts/hsm-init-hardened.js
```

After this the `Config options: User PIN reset with SO-PIN enabled` line is **absent** — the D3
posture is in force. Note the script's own scsh flag readout (`isResetRetryCounterEnabled=true`)
is unreliable on this hardware and should not be used as evidence either way.

### `hw_sign` — needed a key on the *right curve*
Requires a key at id `31` **on secp256k1** plus a matching pinned pubkey. A `prime256v1` key gets
`public key is not on secp256k1 (wrong curve)`. Generate with
`--key-type EC:secp256k1 --id 31`, then export with
`pkcs11-tool --read-object --type pubkey --id 31` into `expected-pub.der`.

## A third firmware fix was required to get here

Refusing writes to `FILE_DATA_FUNC` files (the original memory-safety guard) **breaks scsh
provisioning**: `SmartCardHSM.js` aborts with `GPError ... Unexpected SW1/SW2=6581`. OpenSC
ignores the same failure, which is why it only appeared under scsh. Changed to accept-and-discard
(pico-keys-sdk `3af823e`) — still never writes through the function pointer, only the reported
status changes.

## Bench recovery note: no SRST on this rig

`reset_config` reports `none separate` — OpenOCD **cannot** assert a hardware reset here. A card
stuck in a bootrom HardFault (not enumerating, `pc=0x3ec`) was recovered over SWD with a
POWMAN-backed switched-core power cycle, no physical access:

```
halt
mww 0x40100030 0x5AFE1101     # POWMAN_WDSEL, 0x5AFE password | RESET_PSM|SWCORE|POWMAN_ASYNC
mww 0x40018008 0x01ffffff     # PSM_WDSEL
mww 0x400d8000 0x80000000     # WATCHDOG_CTRL TRIGGER
```

## Still open

- `--tier nightly` has never run (destructive; drives five child scripts, three of them
  uncommitted/untested from a prior session). Run attended.
- Intermittent `CKR_GENERAL_ERROR` on `--keypairgen` — fast failure, not a hang, cause unknown.
  It succeeded on demand here, but it is not reliable.
- `unit_emulator` is Linux-only and remains skipped on the Mac.

---

# Nightly tier — first ever run (2026-08-06)

`--tier nightly` had never been executed. First run: **19 passed, 3 failed, 2 skipped**.
The two skips are expected and honest (`unit_emulator` is Linux-only; `e2e_fleet` needs a second
card). All three failures shared one cause chain, and two of the three are now fixed.

## Fixed: `wait_card` raced the post-INITIALIZE reset

pico-hsm schedules a chip reset ~500 ms after INITIALIZE returns. `wait_card()` polled
`pkcs11-tool --list-slots` immediately and returned in **0 iterations**, having seen the
still-present *pre-reset* token — then the next command ran straight into the reset:

```
provisioning DKEK import failed
  -> sc_card_ctl(SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE) failed with File not found
```

The identical commands run by hand always worked, which is what made it look like a card fault.
Fixed by settling past the reset window and requiring the card to actually *answer*
(`sc-hsm-tool`) rather than merely enumerate.

## Confirmed: the post-INITIALIZE reset is genuinely needed — for a different reason than we said

Removing it looked attractive (upstream declined it as masking a panic, and the panic is now
properly fixed). Measured with it removed: INITIALIZE leaves the in-memory file table
inconsistent with flash. The card reports `DKEK shares: 1 / DKEK import pending`, yet the very
next IMPORT DKEK SHARE fails with `File not found`. A reboot re-scans flash and the same sequence
then succeeds every time. So the reset stays — but the *reason* recorded in the firmware is now
the correct one.

## Fixed: the drill's carrier keygen could never have worked

```
pkcs11-tool ... --keygen     --key-type EC:prime256v1  ->  error: Unknown key type EC:prime256v1
pkcs11-tool ... --keypairgen --key-type EC:prime256v1  ->  Key pair generated
```

`--keygen` makes *secret* keys and rejects an EC key type outright. "on-card keygen failed" was
never a card fault.

## Result

`hsm-recovery-drill.sh --run --auto` went from failing at its first post-init operation to:

```
PASS provisioning DKEK imported
PASS seed-derived drill key imported
PASS card holds the seed's key (akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0)
PASS key wrapped under the provisioning DKEK
PASS break-glass DKEK share created
PASS the corrected command entered the share-reconstruction prompt path (3B)
PASS break-glass DKEK imported (rep #1, shares fed programmatically)
PASS throwaway carrier key generated on-card
FAIL carrier wrap failed (key-reference 2)
```

## Resolved: generated keys ARE wrappable — the earlier diagnosis was wrong

The hypothesis that an on-card generated key must be created `--extractable` to be wrappable is
**disproven**. Measured with the DKEK domain complete:

```
ref 1: WRAPPED (879 bytes)     <- pkcs11-tool --keypairgen, no --extractable
ref 2: WRAPPED (878 bytes)     <- pkcs11-tool --keypairgen --extractable
ref 3: failed — File not found  (correct: no key at that reference)
```

Two distinct failure modes were being conflated, and the status words tell them apart:

| symptom | SW | meaning |
|---|---|---|
| `File not found` | `6A82` | `hsm_key_search()` found no key at that reference |
| `Data object not found` | `6A88` | key exists, but `cmd_key_wrap` rejected the **key domain** — `dkeks != current_dkeks`, i.e. the DKEK domain is not complete |

Every wrap failure in the earlier investigation was one of these two, and neither is about
extractability:

* The run where *all* references failed had `DKEK import pending, 1 share(s) still missing` — an
  incomplete domain, because that re-provision's share import never landed.
* The drill's `carrier wrap failed (key-reference 2)` reproduced by hand as `File not found`,
  i.e. **no key at reference 2** — not a domain problem.

### What the drill should actually change

`hsm-recovery-drill.sh` hardcodes `--key-reference 1` and `--key-reference 2`, assuming they
track the PKCS#11 `--id` it generated with. They do not: the card assigns references
**sequentially** and ignores the requested id. Measured — keys generated as `--id 02` and
`--id 04` landed at card references 1 and 2 (`0xC701`, `0xC702`; `KEY_PREFIX` 0xCC is the legacy
form, `HSM_OBJECT_PREFIX` 0xC7 the current one, and `hsm_key_search()` accepts either).

So the drill should **discover** the reference of the key it just created rather than assume it,
and should assert the DKEK domain is complete before wrapping. That is a script change, not a
firmware one, and it is NOT yet made — the two fixes already committed (`--keypairgen`, and
`wait_card` outlasting the reset) got the drill this far.

## Bench instability is now the limiting factor

The card went mute (dropped off USB entirely) five times during this session's later work, each
time recovered over SWD with the POWMAN sequence below — no physical access needed, which is the
only reason the work continued at all. There is no SRST on this rig (`reset_config: none
separate`), so that sequence is the recovery path until the switchable hub arrives.

```
halt
mww 0x40100030 0x5AFE1101     # POWMAN_WDSEL, 0x5AFE password | RESET_PSM|SWCORE|POWMAN_ASYNC
mww 0x40018008 0x01ffffff     # PSM_WDSEL
mww 0x400d8000 0x80000000     # WATCHDOG_CTRL TRIGGER
```

If OpenOCD reports `Target not examined yet`, restart the OpenOCD server first — its USB handle
goes stale when the device drops.

---

# Recovery drill — from "fails at the first import" to end-to-end (2026-08-06)

Four defects, none of them in the card. Each was making a *working* operation report failure, or
making a broken assumption look like a hardware fault.

## 1. `--keygen` cannot create an EC key

```
pkcs11-tool ... --keygen     --key-type EC:prime256v1  ->  error: Unknown key type EC:prime256v1
pkcs11-tool ... --keypairgen --key-type EC:prime256v1  ->  Key pair generated
```

`--keygen` makes *secret* keys. "on-card keygen failed" could never have succeeded as written.

## 2. Key references are assigned by the card, not by `--id`

```
generated with --id 0A   ->  PKCS#11 reports ID: 10 (0x0a)
wrap --key-reference 10  ->  File not found
wrap --key-reference 1   ->  WRAPPED
```

The card allocates references **sequentially** and ignores the requested id. The drill hardcoded
`--key-reference 1` and `2`, which is what produced `carrier wrap failed (key-reference 2)`.
Replaced with a before/after snapshot of which references actually wrap; the difference is the
new key.

## 3. `--unwrap-key` exits 1 on success

```
$ sc-hsm-tool --unwrap-key blob --key-reference 2 --pin ... ; echo $?
Wrapped key contains:
  Key blob
  Private Key Description (PRKD)
  Certificate
Key successfully imported
1
```

The key really is on the card afterwards — it wraps from the destination reference. Checking the
exit status reported FAIL on a working restore, which is why STEP 4 announced
`unwrap failed — the ceremony artefact did not survive the drill` and then **passed its own
address and signature proofs on that same key**. Now judged by output, which is this drill's
stated rule anyway ("behavioural proof, not a status readout").

## 4. Probing key references costs PIN attempts

Each `--wrap-key` probe performs a PIN verification. With the correct PIN that is free (a
successful verify resets the counter — measured: `User PIN tries left: 3` after a dozen probes).
With a **wrong** PIN it walks the counter to zero: six probes locked a card outright
(`Authentication method blocked`). `wrappable_refs()` therefore refuses to probe unless the PIN
verifies first.

## A guard I got wrong, and how

I added a check that the carrier reference must differ from the funding reference — reasoning
that if the "before" snapshot were empty, the diff would hand back the funding key and the drill
would wrap the FUNDING key under the break-glass DKEK while printing PASS.

It fired, and it was a **false positive**: `init_scratch()` wipes the card before the break-glass
step, so the funding key is gone by then and the card legitimately reuses reference 1. Comparing
references across a wipe is meaningless. Replaced with an invariant that holds regardless — the
carrier blob must not be byte-identical to the funding blob.

Worth recording because the failure mode was instructive: the guard was *safe* (it failed closed)
but *wrong*, and only inspecting the card's actual object list showed which.

## Bench recovery, and its limit

`tools/hsm-swd-powman-recover.sh` power-cycles the switched core over SWD. This rig has no SRST
(`reset_config: none separate`), so it is the only hands-off recovery available, and it revived
the card six times. It is **not** sufficient: twice the card reached a state where three
consecutive POWMAN cycles failed and a physical reseat was the only way back. The script now
reports that honestly instead of claiming success — an earlier version checked
`sc-hsm-tool` exit status, which can be 0 with no output, and announced "card is back" on a card
that was still absent.

`wait_card()` gained an opt-in `HSM_REENUM_RECOVER_CMD` hook. Default behaviour is unchanged: a
real ceremony still asks a human to reseat.

### Two failure states, not one

They look similar and need opposite treatment. Conflating them is what made the recovery tool
look unreliable:

| state | symptom | fix |
|---|---|---|
| enumerated but mute | `Pico Key` present in `ioreg`, `sc-hsm-tool` says `Card not present` | a plain `reset run` clears it, every time observed |
| absent from the bus | `Pico Key` count is 0 | POWMAN power cycle; twice today even that failed and a physical reseat was the only way back |

The recovery script originally went straight to POWMAN, so it reported "a physical reseat is
needed" for at least one card that a plain reset would have revived. POWMAN is also destructive
to diagnosis — it clears the watchdog scratch registers — and does not reliably bring the USB
peripheral back, which is why it worked six times and then stopped. It now escalates:
`reset run` → POWMAN (3×) → report that a reseat is needed.

### One diagnosis I got wrong

Seeing core1 parked at bootrom `0x19e` with `core1_alive = 0`, I read it as a core1 launch
failure — the exact defect our launch-verification patch exists for. It is not. `card_start()` is
called only from the command paths (`ccid.c`, `hid.c`, `rest_server.c`), so **core1 is launched
lazily on the first APDU**; parked-in-the-bootrom is its normal idle state before any command
arrives. The real state was narrower: core0 alive in TinyUSB (`osal_queue_receive`, infinite
wait) with the device simply not presenting on USB.
