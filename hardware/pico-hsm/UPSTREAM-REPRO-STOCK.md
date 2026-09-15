# Reproduction on unmodified upstream firmware — complete failure chain

**Date:** 2026-08-05
**Filed upstream as a comment on:** <https://github.com/polhenarejos/pico-keys-sdk/issues/25>

This closes the maintainer's Bug 6 question 4 ("Have the persistence failure and corrupted
`prev_addr` been reproduced on an unmodified upstream build after `flash_nuke`?") — **yes**,
and the reproduction yielded the complete chain from host APDU to device panic.

---

## Scope, and the limits of this evidence

- **Hardware: exactly one board** — Waveshare RP2350-PiZero (RP2350B), debugged with a
  Raspberry Pi Debug Probe (SWD + UART).
- **No RP2040 hardware exists on this bench.** Every RP2040 statement we have made upstream
  is **compile-only**. The RP2040 code path has never been executed by us and we cannot
  claim any runtime behaviour for it.
- Firmware under test: `pico-hsm 1ad8444` + `pico-keys-sdk 843a3dc`, **no local patches**.
  Verified by symbol check — none of our patch symbols (`low_flash_quiesce`,
  `schedule_chip_reset`, `chip_reset_now`, `flash_addr_in_fs`, `low_flash_busy`) are present
  in the built ELF, while all are present in our patched build.
- `flash_nuke` equivalent: full 16 MB chip erase over SWD (`flash erase_sector 0 0 last`,
  erase chunks ran through `0x00fe0000 -> 0x00ffffff`), then programmed the stock ELF
  (`** Verified OK **`).

## The trigger condition is the filesystem state

| Run | fs state | Result |
|---|---|---|
| 1 | blank (immediately post-nuke) | `--initialize` reports `Card command failed`, but the card **survives** and answers |
| 2 | populated (by run 1) | `--initialize` **kills the card** — this is Bug 1 |

This is why Bug 1 looked intermittent to us: it requires a populated filesystem, i.e.
INITIALIZE has to rewrite existing records rather than write into empty space.

## Host side (run 2, `OPENSC_DEBUG=9`)

```
12:41:35.429 sc_single_transmit: CLA:0, INS:D7, P1:2F, P2:3, data(23)   <- UPDATE BINARY, EF 2F03
             Outgoing APDU (28 bytes):
12:41:40.441 pcsc_detect_card_presence: returning with: 5
12:41:40.443 sc_single_transmit: unable to transmit APDU: -1107 (Transmit failed)
12:41:40.443 sc_hsm_write_ef: APDU transmit failed: -1107 (Transmit failed)
```

~5 s in flight, then the card stops answering — permanently.

## Device side — hardware watchpoint on `flash_pages[0].address`

```
Old value = 0x103F9000        (valid flash)
New value = 0x2000D000        (SRAM)

#0 find_free_page (addr=0x2000D5A5)                       low_flash.c:316
#1 flash_program_block (addr=0x2000D5A5, data={len=2})    low_flash.c:333
#2 flash_program_halfword (data@entry=17)                 low_flash.c:354
#3 flash_write_data_to_file_internal (file=0x20056b24 <file_entries+80>,
                                      offset=0, partial=false)      flash.c:195
#4 flash_write_data_to_file (file=0x20056b24)             flash.c:257
#5 file_put_data (file=0x20056b24)                        file.c:438
#6 cmd_update_ef ()                              src/hsm/cmd_update_ef.c:134
#7 sc_hsm_process_apdu ()                        src/hsm/sc_hsm.c:944
#8 apdu_thread ()                                         apdu.c:245
```

`file->data == 0x2000D5A5` — an **odd-aligned SRAM pointer** — is handed straight to the
flash write API at `flash.c:195`:

```c
r = extended_size ? flash_program_word((uintptr_t)file->data + sizeof(uint16_t), len)
                  : flash_program_halfword((uintptr_t)file->data, (uint16_t)len);
```

`find_free_page()` aligns it down to `0x2000D000`, `memcpy`s 4096 bytes **out of SRAM** into
the sector cache, and marks the slot `ready = 1`. (The cached page contents are ARM code and
pointers — e.g. a `70 b5` Thumb prologue — not record data, confirming the copy source.)

## The origin of the bad pointer — it is a FUNCTION POINTER, by design

**Correction (2026-08-05, later the same day).** An earlier revision of this document — and an
earlier upstream comment — attributed the pointer to `scan_region()` accepting a corrupt chain
link. **That was wrong.** The on-flash record chain is intact; it was walked over SWD at three
points (factory-clean, after INITIALIZE #1, and at the panic) and every link was in-region and
correctly terminated.

The real cause is simpler and fully deterministic:

```
gdb) printf "data=%p fid=0x%04x", ((file_t*)0x20056b24)->data, ((file_t*)0x20056b24)->fid
data=0x2000d5a5 fid=0x2f03
gdb) info symbol ((file_t*)0x20056b24)->data
parse_token_info + 1 in section .text
```

`0x2000D5A5` is **`parse_token_info + 1`** — a Thumb function pointer. EF.TokenInfo (`0x2F03`)
is declared in `pico-hsm/src/hsm/files.c` as:

```c
/*  4 */ { .fid = 0x2f03, // EF.TokenInfo
           .type = FILE_TYPE_WORKING_EF | FILE_DATA_FUNC,
           .data = (uint8_t *) parse_token_info,
           ... }
```

For a `FILE_DATA_FUNC` file, `->data` is a **generator function**, not a flash address. Every
other consumer checks the flag before using it:

- `file.c` (SELECT / FCI): `if ((type & FILE_DATA_FUNC) == FILE_DATA_FUNC) { call it }`
- `cmd_read_binary.c:137` (READ): same check, calls the handler

`flash_write_data_to_file_internal()` (`flash.c:191`) checks only `if (file->data && ...)`. It
never checks the flag, so an **UPDATE BINARY on a FILE_DATA_FUNC EF hands a `.text` address to
the flash layer.**

OpenSC's `sc_hsm_initialize` writes EF.TokenInfo as part of INITIALIZE — hence the
`CLA:0 INS:D7 P1:2F P2:03` APDU in the host trace. So this is reached by an ordinary,
spec-conformant host operation, not by corruption.

**No filesystem corruption is involved anywhere in this failure.**

### Why it looked fs-dependent

The in-place branch is taken only when `len <= old_size`, and for a `FILE_DATA_FUNC` file
`old_size` is derived by reading the first halfword of the *function's machine code*. That makes
which branch is taken depend on the written length versus a constant of the compiled binary,
not on filesystem population. The "blank fs survives / populated fs dies" pattern we originally
reported is therefore an artifact of what the host writes on each pass, not of fs state.

### The `scan_region()` weakness is real but separate

`file.c:336` still validates a chain link with only `base >= startp` — no upper bound, no
alignment check — so a genuinely corrupt link *would* be accepted. That remains worth fixing as
defence in depth (upstream proposed exactly this), but it is **not** the cause of this failure
and no corrupt link was ever observed on this device.

## The panic

```
#4 flash_range_erase (count=4096)      pico-sdk hardware_flash/flash.c:213
       hard_assert(flash_offs + count <= PICO_FLASH_SIZE_BYTES);
       0x2000D000 - XIP_BASE = 0x1000D000 ; + 4096 > 0x1000000  -> fires
#5 low_flash_task ()                   low_flash.c:122
#6 flash_task ()                       flash.c:285
#7 core0_loop ()                       main.c:136
#8 main ()                             main.c:228
```

## Why the card goes mute — Bug 1's mechanism, and how it ties to Bug 4

`low_flash.c:116-125`:

```c
if (multicore_lockout_start_timeout_us(1000) == false) { ...; continue; }
uint32_t ints = save_and_disable_interrupts();
flash_range_erase(...);        /* <-- panics HERE */
flash_range_program(...);
restore_interrupts(ints);
if (multicore_lockout_end_timeout_us(1000) == false) { ...; continue; }
```

The panic lands **between lockout START and END** and **after `save_and_disable_interrupts()`**.
Core0 ends inside `panic()` -> `_exit()` -> `__breakpoint()`, interrupts disabled, lockout still
held. Core1 is therefore parked forever:

```
Thread 2: multicore_lockout_handler ()          multicore.c:241
          <signal handler called>
          __wfe ()                              queue.c:64
          queue_remove_internal (q=0x200666a4 <usb_to_card_q>, block=true)
          queue_remove_blocking (usb_to_card_q)
          apdu_thread ()                        apdu.c:231
```

That is the whole "enumerated but mute" class: the USB device stays up at the host, but no
APDU can ever be serviced again.

## The maintainer's Bug 1 questions, answered on unmodified firmware

1. **Does the reader remain enumerated?** Yes — still listed, `Card: Yes`.
2. **Is card presence reported?** PCSC reports presence (`pcsc_detect_card_presence: 5`), but
   every subsequent connect fails: `Failed to connect to card: Card not present`.
3. **Which operation first fails to obtain the ATR?** None — the failure *precedes* ATR. The
   first failure is the in-flight `UPDATE BINARY (INS D7, EF 2F03)` issued inside
   `sc_hsm_initialize`'s `sc_hsm_write_ef`, which times out after ~5 s. Nothing activates
   afterwards.
4. **Is any APDU usable before replug?** No.

## Downstream symptoms that follow from the same defect

- `pkcs15-tool --list-pins` returns nothing, and PKCS#11 `C_Login` fails with
  `CKR_USER_PIN_NOT_INITIALIZED` — while a **raw `VERIFY` APDU (`00 20 00 81`) returns
  `9000`**. The PIN works; the PKCS#15 structures were never written, because the EF write
  that writes them is exactly what fails.
- `DKEK key check value : 0000000000000000` after a successful-looking share import.

Both reproduce on unmodified upstream firmware.

## Corrections to our own earlier report

1. **Bug 1 mechanism — our framing was wrong.** The card does not complete INITIALIZE and then
   need a reset; it **panics during** INITIALIZE. A post-INITIALIZE reset (PR #27 /
   pico-hsm#136) masks a panic rather than fixing it. What most likely made our patched build
   appear to recover was our panic->reboot handler, not the scheduled reset.
2. **Bug 4 — the END-timeout warning was never captured.** The parked core1 is not caused by an
   END timeout; it is caused by core0 panicking between START and END. PR #29 therefore
   addresses a scenario we never observed.
3. **Bug 4 concurrency audit.** In-tree, the only lockout callers are `low_flash.c:116/125/138/146`,
   all inside `low_flash_task()`'s drain loop on core0, plus `multicore_lockout_victim_init()`
   at `:243`. `phymarker_write()` does `flash_range_erase/program` without the lockout, but it
   is `#ifdef PICO_RP2040` and runs from `low_flash_init()` before core1 launches — not a
   concurrency hazard.
4. **Bug 5 — the ordering critique was correct.** PR #30 now validates before the first
   read/queue and returns an error. But this trace shows the guard is a **safety net, not the
   fix**: it converts the panic into a clean error return while `file->data` still points at
   SRAM. The actual fix is the `scan_region()` validation above.
5. **Bug 2 — correct, and worse than the code guard.** The POWMAN includes sat in the generic
   `PICO_PLATFORM` block, so an RP2040 build failed outright with
   `fatal error: hardware/powman.h: No such file or directory`. Fixed in PR #31. Both
   platforms now compile — **RP2040 compile-only, never run.**

## The fix, and its isolation test

`flash_write_data_to_file_internal()` must refuse `FILE_DATA_FUNC` files, exactly as the read
and SELECT paths already do:

```c
    /* A FILE_DATA_FUNC file's ->data is a generator FUNCTION POINTER, not a flash
     * address. The SELECT/FCI path (file.c) and the READ path (cmd_read_binary.c)
     * both check this flag before using ->data; this write path did not, so an
     * UPDATE BINARY on such an EF handed a .text address to the flash layer. */
    if ((file_get_type(file) & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
        return PICOKEYS_ERR_BLOCKED;
    }
```

Isolation test — this 8-line change applied to **otherwise-stock** firmware
(`pico-hsm 1ad8444` + `pico-keys-sdk 843a3dc`, nothing else changed), full 16 MB erase first:

| firmware | INITIALIZE runs | result |
|---|---|---|
| stock | 2 | **mute on the 2nd, permanently** |
| stock + this 8-line guard only | 4 | **4/4 alive**, correct state throughout |

Single-APDU confirmation on the guarded build (SO-PIN verified first, since the EF's ACL
requires it):

```
00 20 00 88 08 35 37 36 32 31 38 38 30      -> 9000   (VERIFY SO-PIN)
00 D7 2F 03 13 53 11 00*17                  -> 6581   (UPDATE BINARY EF 2F03, cleanly refused)
card still answering
```

Without the guard the same pair kills the card outright — no INITIALIZE required. That is the
minimal reproduction: **two APDUs.**

## Quantitative determinism

`file_get_size()` calls `file_read_uint16(tf->data)`, which for one of these files reads the
first halfword of the function's own machine code as the file size:

```
2000d5a4 <parse_token_info>:  01 29 01 d0 2c 20 70 47   ->  old_size = 0x2901 = 10497
```

The host writes a 17-byte TokenInfo blob, so the in-place branch condition
`!partial && len <= old_size && (extended_size || len < FLASH_FILE_EXTENDED_LENGTH)` is
`17 <= 10497 && 17 < 0xFFFF` — **always true**. It then calls
`flash_program_halfword((uintptr_t)file->data, 17)`, matching the captured frame
(`data@entry=17`) exactly. There is no race and no state dependence.

## Necessary but not sufficient: provisioning is still blocked

With the guard applied the card survives, but `sc-hsm-tool --initialize` still reports
`Card command failed` and the chain cannot complete:

```
INITIALIZE            -> Card command failed   (card SURVIVES; PIN 3/15, DKEK shares 1)
create/import DKEK    -> OK, "DKEK share imported"
raw VERIFY user PIN   -> 9000                  (the PIN genuinely works)
PKCS#11 C_Login       -> CKR_USER_PIN_NOT_INITIALIZED
pkcs11-tool objects   -> only a Profile object; no PKCS#15 structures
wrap-key              -> File not found        (keygen never ran)
```

Both **EF.DIR (`0x2F00`)** and **EF.TokenInfo (`0x2F03`)** are `FILE_DATA_FUNC` generated files,
and OpenSC's `sc_hsm_initialize` wants to *write* them. The guard converts a device-killing
panic into a clean refusal, but the write still fails, so the PKCS#15 structures are never
created and PKCS#11 concludes the PIN is not initialised.

That is a **semantic decision for upstream**: either pico-hsm accepts and stores an override for
these generated EFs, or the provisioning path must not require writing them. It also fully
explains the original `CKR_USER_PIN_NOT_INITIALIZED` symptom as a downstream consequence rather
than a persistence failure.

## Not a regression from the July flash rework

`flash_write_data_to_file_internal()` was introduced in pico-keys-sdk `4390947` (2026-07-16,
"Support multi-sector flash files with 32-bit lengths and cache draining"), but the code it
replaced did the same thing:

```c
uint16_t size_file_flash = file->data ? flash_read_uint16((uintptr_t) file->data) : 0;
if (file->data) {                                   // already in flash
    if (offset + len <= size_file_flash) {          // 17 <= 0x2901 -> true
        flash_program_halfword((uintptr_t) file->data, offset + len);
```

Same missing `FILE_DATA_FUNC` check, same arithmetic, same outcome. The defect predates the
rework.

## Still unattributed

`unwrapKey SW=6400` was **not reproduced**. The chain cannot reach the unwrap step because keygen
requires working provisioning. Given that the persistence narrative collapsed and the original
observation window overlapped the contaminated wrong-bounds-guard period (2026-08-03 -> 08-04),
the original `6400` report should be treated as unreliable until seen again on a clean build.
