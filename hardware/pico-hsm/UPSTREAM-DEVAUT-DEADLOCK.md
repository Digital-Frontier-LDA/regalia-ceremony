# EF.C_DevAut self-provisioning deadlock — root cause of the unusable staging card

**Date:** 2026-08-05
**Status:** root-caused, fixed, verified on hardware. Fix committed as pico-hsm `9094c0b`.

This is the actual reason the staging card could never complete provisioning. It is a different
and more fundamental defect than the `FILE_DATA_FUNC` write bug documented in
`UPSTREAM-REPRO-STOCK.md` — that one killed the card mid-command; this one made provisioning
impossible even when the card survived.

## The deadlock

1. OpenSC's sc-hsm PKCS#15 emulator **mandatorily** requires a decodable EF.C_DevAut (`0x2F02`):
   ```c
   r = sc_pkcs15emu_sc_hsm_decode_cvc(p15card, (const u8 **)&ptr, &len, &devcert);
   LOG_TEST_RET(card->ctx, r, "Could not decode EF.C_DevAut");   /* returns on error */
   ```
   Without it the emulator aborts, so **no PKCS#15 objects at all** are built — including PIN
   objects. `C_Login` then fails with `CKR_USER_PIN_NOT_INITIALIZED`, even though a raw
   `VERIFY` APDU returns `9000`.

2. pico-hsm creates EF.C_DevAut only inside `cmd_initialize`'s `if (recreate_dev_key)` block.

3. That block calls `asn1_cvc_aut()` first, whose opening guard is:
   ```c
   if (!output || ... || !fkey || !dev_name || !dev_name_len) return 0;
   ```

4. `dev_name` had exactly **one** assignment in the entire codebase (`src/hsm/sc_hsm.c`,
   `reset_puk_store`):
   ```c
   file_t *fterm = file_search(EF_TERMCA);          /* EF_TERMCA == 0x2F02 == EF.C_DevAut */
   dev_name = cvc_get_chr(file_get_data(fterm), file_get_size(fterm), &dev_name_len);
   ```

**So creating EF.C_DevAut required a value parsed from EF.C_DevAut.** Once the file was lost —
flash erase, `flash_nuke`, corruption — the device could never be initialized again. Every
subsequent INITIALIZE returned `SW_EXEC_ERROR`, and PKCS#11 was permanently unusable.

## Evidence (SWD, RP2350B, unmodified upstream)

SRAM trace instrumented into `cmd_initialize` (breakpoints raced the USB stack; UART on this
bench is unreliable, so the trace buffer was read over SWD after the fact):

```
0x100 fdkey            = 0x20057940   found
0x102 ret_mkek         = -1006
0x103 file_has_data    = 0            no device key yet (expected after erase)
0x104 recreate_dev_key = 1            block runs
0x105 otp_key_2        = 0x40131d00   present -> device key is SECP256K1 from OTP
0x106 ecp_read_key     = 0            ok
0x108 store_keys       = 0            ok
0x10a cvc_pk_wrap_ec   = 0            ok
0x10b asn1_cvc_aut     = 0            <-- FAILS on the !dev_name guard
```
and directly:
```
(gdb) printf "dev_name = %p   dev_name_len = %u\n", dev_name, dev_name_len
dev_name = (nil)   dev_name_len = 0
```

## The asymmetry that shows the intent

`cvc_configure_cert()` — one layer down, called by both `asn1_cvc_aut` and `asn1_cvc_cert` —
already tolerated `dev_name == NULL`:
```c
if (!car || !car_len) {
    car = dev_name ? dev_name : (const uint8_t *)"ESPICOHSMTR00001";
    ...
}
```
So first-provisioning was *meant* to work without `dev_name`; only `asn1_cvc_aut`'s hard
precondition blocked it. Note also that `asn1_cvc_cert()` — which builds the DevAut certificate
itself — never references `dev_name`.

## Why a constant CAR/CHR is not an acceptable bootstrap

OpenSC derives the PKCS#11 **token serial number** from the DevAut CHR
(`pkcs15-sc-hsm.c`):
```c
len = strnlen(devcert.chr, sizeof devcert.chr);
if (len < 8) return SC_ERROR_INTERNAL;
len -= 5;                                  /* last 5 stripped unconditionally */
memcpy(p15card->tokeninfo->serial_number, devcert.chr, len);
```
With the shared constant `ESPICOHSMTR00001`, **every device would report serial
`ESPICOHSMTR`** — unusable for a fleet, and this repo's own tooling keys on the serial
(`HSM_E2E_SERIAL:-ESPICOHSMTR`). All uniqueness must therefore live in the surviving prefix.

## The fix

Bootstrap `dev_name` at its single assignment site, reached only when EF.C_DevAut is absent or
its CHR is unparseable — a validly provisioned device is never touched, so existing attestation
chains and pinned serials are preserved:

```c
dev_name = cvc_get_chr(file_get_data(fterm), file_get_size(fterm), &dev_name_len);
if (!dev_name || !dev_name_len) {
    dev_name = hsm_bootstrap_dev_name(&dev_name_len);
}
```

with

```c
#define BOOTSTRAP_DEV_NAME_LEN 16
static uint8_t bootstrap_dev_name[BOOTSTRAP_DEV_NAME_LEN + 1];

const uint8_t *hsm_bootstrap_dev_name(uint16_t *len) {
    const uint8_t *sn = pico_serial.id + (PICO_UNIQUE_BOARD_ID_SIZE_BYTES - 4);
    snprintf((char *) bootstrap_dev_name, sizeof(bootstrap_dev_name),
             "ESP%02X%02X%02X%02X00001", sn[0], sn[1], sn[2], sn[3]);
    if (len) { *len = BOOTSTRAP_DEV_NAME_LEN; }
    return bootstrap_dev_name;
}
```

`cvc_configure_cert`'s constant fallback now calls the same helper, so no path can emit a
fleet-colliding CHR.

Layout is the conventional 11-char holder id + 5-digit sequence: `ESP` + 32 bits of board
serial + `00001`. After OpenSC's strip the token serial is `ESP` + 8 hex — device-unique
(~65,000-device birthday threshold) while keeping the established `ESPICOHSM…` prefix.

Design settled by a 4-round multi-model quorum (unanimous); record in
`.planning/quorum/debates/2026-08-05-pico-hsm-devaut-deadlock.md`.

## Verification

After a **full 16 MB erase** followed by a single INITIALIZE on the fixed firmware:

```
token flags   : login required, rng, token initialized, PIN initialized
serial num    : ESP2202E14A
```

`PIN initialized` is exactly the flag whose absence produced `CKR_USER_PIN_NOT_INITIALIZED`.
Filesystem state confirms the certificate chain is now built:

```
persistent chain:  fid=0x2f02 len=940   <- EF.C_DevAut (previously ABSENT)
                   fid=0xce00 len=497   <- EF_EE_DEV   (previously ABSENT)
                   fid=0xcc00 len=66    <- EF_KEY_DEV
                   fid=0xc400 len=58    <- EF_PRKD_DEV
num_files = 20 (was 8)
```

Regression test: `tools/hsm-devaut-bootstrap-test.sh` (full erase → INITIALIZE → assert a
PKCS#11 token exists and its serial matches `^ESP[0-9A-F]{8}$` and is not the shared constant).

## Corollary: the all-zero DKEK KCV is an unauthenticated-read artifact

Instrumenting `load_dkek` settled a long-standing question:

```
tag=0x202 file_get_size(EF_DKEK) = 65
tag=0x205 mkek_load_file         = -1005  (PICOKEYS_NO_LOGIN)
tag=0x207 dkek_is_complete       = 1
tag=0x211 load_dkek              = -1008  (WRONG_DATA)
```

`sc-hsm-tool` reads DKEK status without authenticating, so the MKEK cannot be unwrapped and
`dkek_kcv()` returns early leaving the buffer zeroed — and `cmd_key_domain.c` ignores that
return value, so the card reports `0000000000000000`. `dkek_is_complete = 1` proves the DKEK
domain is correctly established. **The all-zero KCV is therefore not evidence of a broken
DKEK**, and the earlier "zero KCV means lost DKEK state" reading in our original report was
wrong.

## Settled: `unwrapKey SW=6400`

`SW=6400` is **this firmware's generic execution error**, not a DKEK-specific code:

```c
/* pico-keys-sdk/src/apdu.h */
#define SW_EXEC_ERROR()   set_res_sw(0x64, 0x00)
```

It is returned from dozens of sites. In `cmd_key_unwrap` it is reached when `dkek_decode_key`
fails for every key domain — which includes both `PICOKEYS_WRONG_DKEK` and
`PICOKEYS_ERR_FILE_NOT_FOUND`. Critically, `cmd_initialize` returns **the same 6400** on the
DevAut deadlock, so the code carried no diagnostic information about which failure occurred.

**It does not reproduce on a card that can actually provision.** On the fixed firmware, after a
full 16 MB erase and a single INITIALIZE, the round trip succeeds:

```
wrap   key reference 3   -> wrapped3.bin, 367 bytes
unwrap into reference 7  -> "Wrapped key contains: Key blob, Private Key Description (PRKD)"
                            "Key successfully imported"
```

**Conclusion:** the original `unwrapKey SW=6400` was a downstream consequence of the DevAut
deadlock. The card spent the entire failing period unable to complete INITIALIZE, so no coherent
device-key / DKEK state ever existed and any unwrap was bound to fail — surfacing as the generic
`SW_EXEC_ERROR`. It is not an independent defect, and the earlier "the domain key is right, the
unwrap still refuses" reading was based on a card that had never been successfully provisioned.

## Separate defect found: large APDU responses hang the host

`pkcs11-tool --keypairgen` hangs indefinitely (reproduced at 120 s, 180 s and 300 s, across
`prime256v1` and `secp256k1`, after a clean reset with a healthy token). SWD shows both cores
sitting in the normal `core0_loop`/`hwrng_task` idle path — the card is not computing.

Instrumenting `cmd_keypair_gen` shows the card completes the operation successfully:

```
0x300 entry            = 1
0x301 ec_id            = 3      (MBEDTLS_ECP_DP_SECP256R1)
0x302 mbedtls_ecdsa_genkey = 0  ok
0x304 cvc_pk_wrap_ec   = 0      ok
0x305 asn1_cvc_aut     = 490    ok — 490-byte CVC produced
0x307 store_keys       = 0      ok
0x30f reached SW_OK()
```

So the key is generated, the certificate is built, the key is stored, and the handler returns
`SW_OK` — but the **490-byte response never reaches the host**, which waits forever. The key
really is persisted: after a reset it can be wrapped by reference, which is how the wrap/unwrap
round trip above was performed.

**Correction after more runs:** this is **intermittent**, not deterministic. Measured ~1 success
in 6 attempts — one run completed and printed the key pair; the rest hung past 180 s. A suspected
correlation with host-side slowdown (the one success had `OPENSC_DEBUG=9`) was **disproven**: two
further `OPENSC_DEBUG=9` runs also hung (0/2). What is solid is that the card side always
completes and the key is persisted. Trigger not identified; not root-caused. Recorded for
follow-up, and explicitly NOT one of the two goals this document closes.

Note this also explains the historical "keygen took ~35 minutes" and `CKR_GENERAL_ERROR`
observations — the host was blocked on a response that never arrived, not on slow on-card maths.

## Final end-to-end confirmation (repeated, independent runs)

Run A — automated regression test, `tools/hsm-devaut-bootstrap-test.sh`, exit 0:
```
full 16 MB erase (destroys EF.C_DevAut) -> flash -> INITIALIZE
PASS: card alive after INITIALIZE
PASS: PKCS#11 token present (EF.C_DevAut decodable)
PASS: serial 'ESP2202E14A' is device-unique and correctly formed
```

Run B — consolidated run from a destroyed filesystem:
```
STEP 2  INITIALIZE on a card with NO EF.C_DevAut  -> PASS
STEP 3  token flags: login required, rng, token initialized, PIN initialized
        serial num : ESP2202E14A                  -> PASS
        DKEK domain established                   -> PASS
        wrap key-reference 1 -> 367 bytes
        unwrap -> "Wrapped key contains: Key blob, Private Key Description (PRKD)"
                  "Key successfully imported"     -> PASS, no SW=6400
```

**Provisioning is not blocked.** The earlier claim that EF.DIR / EF.TokenInfo writes blocked it was
our own misdiagnosis: OpenSC ignores the EF.TokenInfo write failure
(`sc_hsm_initialize: returning with: 0 (Success)`), and EF.DIR is not written by INITIALIZE at
all. The real blocker was the DevAut deadlock documented above, now fixed.

## Root-caused: the keygen hang was OUR dead-man's switch eating CCID completions

Upstream predicted this in review and we kept the mechanism anyway:

> the dead-man switch ... competes with `card_status()` for `card_to_usb_q` and can consume
> normal completion or button events

That is precisely what it did. `card_watchdog_task()` popped `card_to_usb_q` itself, and a comment
we had written there claimed the handling was "identical" to the CCID layer's. It is not:

* `card_status()` pops `EV_EXEC_FINISHED` -> `ccid_task()` calls `driver_exec_finished_ccid()` ->
  **the response is sent to the host**.
* `card_watchdog_task()` pops it first -> only clears a local flag -> **the response is never
  sent** and the host waits forever.

Both run on core0, so it is a race — hence the intermittency.

Measured with `pkcs11-tool --keypairgen`:

| build | result |
|---|---|
| with the dead-man's switch | 1 ok / 5 bad, failures **hanging for minutes** |
| with it removed | **0 hangs**, successes complete in ~5 s |

In both cases the card completed normally (`asn1_cvc_aut = 490`, `store_keys = 0`, `SW_OK`, both
cores idle, key persisted) — only response delivery was lost. Removed in pico-keys-sdk `25fc4b3`.

A remaining intermittent `CKR_GENERAL_ERROR` on some keygens is a **different**, pre-existing
failure — fast rather than hanging, not fs exhaustion (68 files, ~3 MB free) — and is still open.
