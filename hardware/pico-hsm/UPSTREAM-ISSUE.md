# Draft — upstream issue for `polhenarejos/pico-keys-sdk` (+ `polhenarejos/pico-hsm`)

> **⚠️ SUPERSEDED IN PART (2026-08-05).** A reproduction on unmodified upstream firmware
> disproved several claims in this draft. Read `UPSTREAM-REPRO-STOCK.md` first, and treat the
> per-bug text below as the *original* report, not the current understanding. Corrections:
> Bug 1 is a panic **during** INITIALIZE (not a dead card after it) and the `pico-hsm#9`
> attribution was wrong; the Bug 4 END-timeout was **never observed** (core1 is orphaned by the
> panic between lockout START and END); "brick" in Bug 5 is wrong (BOOTSEL + flash_nuke
> recovers); Bug 6 symptoms 1 and 3 are consequences of the panic, and symptom 2 (`unwrapKey
> SW=6400`) is still unattributed. The live issue body upstream carries these corrections inline.


> **FILED:** <https://github.com/polhenarejos/pico-keys-sdk/issues/25>
>
> **How to use this file.** Everything below the line is intended to be pasted as the body of a
> GitHub issue. File it against `polhenarejos/pico-keys-sdk` (bugs 2–6 live there) and reference
> it from `polhenarejos/pico-hsm` (bug 1 / the INITIALIZE path lives there). The linked PR
> (`UPSTREAM-PR.md`) fixes bugs 1–5; bug 6 is reported here with full forensics but is NOT
> fixed by the PR.

---

## Title

Warm-boot reliability and flash-persistence failures on RP2350B, with forensics and fixes for the reset path — from a staging-HSM deployment

## Context — how we use pico-hsm (and why it matters for this report)

We run an open-source, hardware-rooted key-custody project. **Production tokens are Nitrokey
HSM 2s (genuine SmartCard-HSM). The Pico HSM is used strictly as a STAGING and
procedure-rehearsal device** — it speaks the same SmartCard-HSM protocol, so ceremonies and
drills can be exercised end-to-end before any production hardware is touched. Nothing in this
report asks you to treat the Pico HSM as a primary HSM, and none of our findings bear on
production use of the firmware for everyday smartcard workloads.

What staging demands that everyday use does not is **wipe-and-reprovision cycles**: our central
drill is "any card can die and be replaced from the seed with no loss", which means INITIALIZE
DEVICE, DKEK domain creation, share import, and wrapped-key unwrap in a tight loop, measured
statistically. That workload surfaces a family of reliability defects in the reset path and in
the flash persistence layer. All findings below were measured on a Waveshare RP2350-PiZero
(RP2350B, 16 MB flash) with SWD forensics (Raspberry Pi Debug Probe + OpenOCD `rp2350` target +
`arm-none-eabi-gdb`), not inferred. We are happy to provide raw logs, register dumps, and
reproduction scripts.

Environment: OpenSC `sc-hsm-tool` and CardContact Smart Card Shell (scsh 3.18.77) on the host;
`polhenarejos/pico-hsm` at `1ad8444` plus our patch series (see linked PR); Pico SDK 2.x.

## Bug 1 — INITIALIZE DEVICE leaves the card dead until a physical replug (already #9)

Known upstream as `polhenarejos/pico-hsm#9`. After re-personalisation the card completes the
wipe but never rebuilds state; the reader reports a card but no ATR, indefinitely. Our
measurement matches: only a replug recovers. The PR resets the device after INITIALIZE (the
response is transmitted first; the reset is deferred so it never lands mid-command).

## Bug 2 — warm boot wedges in ~5–10% of resets; both cores never start (fixed by deep resets)

Reproduced repeatedly via a cycle harness (`sc-hsm-tool --initialize` in a loop). Forensics on a
live hang: watchdog `REASON.TIMER` set — the watchdog **did** fire — then both Cortex-M33 cores
reading all-zero (PC/SP/xPSR), XIP SSI all-zero, and the bootrom's bootram diagnostics
untouched. The chip reset; the boot never started.

Reset **mechanism** was ruled out: identical signature with SDK `watchdog_reboot()` and the
bootrom's `rom_reboot()`. `AIRCR.SYSRESETREQ` was ruled out separately — on RP2040/RP2350 it
resets only the asserting core (raspberrypi/pico-feedback#329); we measured it as a complete
no-op (RAM statics survived the write).

What finally closed it: the default watchdog reset leaves the switched core domain powered.
Arming **POWMAN_WDSEL = RESET_SWCORE | RESET_PSM | RESET_POWMAN_ASYNC** (with PSM_WDSEL
all-ones, per the datasheet note that POWMAN ignores watchdog resets that don't select CLOCKS
or earlier) makes every watchdog-family reset power-cycle the switched core domain — "the same
effect as a power-on reset" per the RP2350 datasheet. Because RESET_POWMAN restores powman
defaults, the bits are re-armed at every boot.

**Validation: 100/100 consecutive reboots with zero hangs** against a ~5–10% measured wedge
rate (p ≈ 0.0007 under the old rate). The fix is in the PR.

## Bug 3 — multicore launch handshake reports success while core1 never starts

Twice caught live via SWD: core1 parked in the bootrom's wait-for-launch loop (PC `0x19e`,
polling SIO `FIFO_ST`, bootrom stack `0xf0000000`), one unread word in the FIFO (`VLD=1`),
while `card_locked_func` showed the launch "succeeded" and USB enumerated (TinyUSB runs on
core0). The card enumerates but never answers an APDU. The SDK's
`multicore_launch_core1_raw()` echo handshake can complete against stale/misaligned FIFO data —
plausibly residue across a warm reset or a word consumed by the trampoline's drain phase.
The PR verifies the launch (a flag set by the launched thread), retries, and escalates to a
bounded chip reset; it also adds a dead-man's switch (ping via the existing queue echo
protocol) for the mid-session variant, which we also caught live.

## Bug 4 — 1 ms multicore-lockout timeouts orphan core1 permanently

`low_flash.c` calls `multicore_lockout_start/end_timeout_us(1000)` around flash erases. A
timed-out END leaves core1 parked in the lockout victim handler **forever** (SWD: PC inside
`multicore_lockout_handler`, card mute, core0 healthy). 1 ms is far inside normal IRQ/entry
latency during real erase workloads. The PR raises the timeouts to 100 ms and re-syncs with a
start+end pair after an end-timeout.

## Bug 5 — hard_assert panics brick the device forever

A corrupted `flash_pages` entry (an SRAM pointer, `0x20001A00`, queued after interrupted wipe
cycles) reached `hard_assert(flash_offs + count <= PICO_FLASH_SIZE_BYTES)` and the device sat
in `panic()` → `__breakpoint` → `_exit` for a day — no APDU service, no reset, physical replug
required. The PR (a) validates queued page addresses against the real fs data region before
touching flash, and (b) overrides `hard_assertion_failure()` to reboot via `rom_reboot` instead
of bricking.

## Bug 6 — flash persistence layer: writes do not survive, and `find_free_page` hard-faults on corrupted metadata — **NOT FIXED, need upstream help**

This is the defect we cannot fix from the outside, and the one that most needs your eyes.

**Symptoms (all on the same fs, all reproducible):**

1. DKEK metadata reads as corrupt: `sc-hsm-tool` reports `DKEK key check value :
   0000000000000000` for a domain whose share was just imported successfully. On a truly
   factory-clean fs (fs region fully erased) the KCV reads correctly and host/card KCVs match —
   so the "always-zero KCV" behaviour is a persistence symptom, not a device quirk.
2. `unwrapKey` fails `SW=6400` even with host and card KCVs **identical**
   (`292848FACCC4F1BE`) — the domain key is right, the unwrap still refuses. The same unwrap
   flow passed on this exact card weeks earlier.
3. PKCS#11 reports `CKR_USER_PIN_NOT_INITIALIZED` minutes after the same PIN verified — the
   initialize's own writes (PIN state, PKCS#15 files) do not survive a chip reset.
4. **HardFault in the DKEK store path.** Captured live via SWD (fault escalated to a debug
   halt; register dump available):
   - backtrace: `isr_hardfault ← memcpy ← find_free_page (low_flash.c:403) ←
     flash_program_uintptr ← flash_clear_file (file.c:675) ← flash_write_data_to_file_internal ←
     file_put_data ← mkek_store_file ← store_dkek_key ← save_dkek_key(id=0, key=NULL) ←
     sc_hsm.c:478 (deferred save at PIN verify)`
   - `BFAR = 0x6CB44000` (bus fault, precise, `CFSR=0x8200`): `find_free_page` received
     `addr_alg = 0x6CB44000`, read from a `prev_addr` field in the fs metadata — i.e. the
     on-flash fs structure itself held a garbage pointer.

**Environment note that may matter:** the fs data region on this build is partition-dependent —
measured bounds `start_data_pool ≈ 0x100FF000`, `end_flash = 0x10400000` (≈ [1 MB, 4 MB)), not
`[FLASH_SIZE/2, FLASH_SIZE)` as `low_flash_init`'s own comment suggests. Any code assuming the
latter (including, candidly, a guard we added ourselves — corrected in the PR to use
`flash_addr_in_fs()` against the real bounds) misclassifies every address.

**Ask:** review of the page-cache/lazy-drain design in `low_flash.c` + `flash.c` —
`find_free_page`'s whole-sector `memcpy(p->page, (uint8_t *)addr_alg, FLASH_SECTOR_SIZE)` and
the erase-then-reprogram drain — for how interrupted operations (and resets landing while lazy
writes are queued, which our reset path now explicitly guards against) can persist garbage
`prev`/`next` links or stale sector images. We can reproduce on request and can test patches.

## What the linked PR changes

- reset after INITIALIZE (deferred until the APDU response is out),
- deep resets via POWMAN_WDSEL (Bug 2),
- launch verification + dead-man's switch (Bug 3),
- lockout timeout raise + re-sync (Bug 4),
- fs-page address guard with correct bounds + panic→reboot (Bug 5),
- `EV_PING` handling fix (our dead-man's probe re-executed staged APDUs — included for
  completeness since it touches shared code paths),
- and, defensively, a drain-guard so a scheduled reset never lands while lazy flash writes are
  queued (one plausible contributor to Bug 6's corruption).

Bug 6 is **not** claimed fixed by the PR.
