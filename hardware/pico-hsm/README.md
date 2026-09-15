# Pico HSM — firmware fixes for the STAGING device

**This directory is about the staging token only.** The production token is a **Nitrokey HSM 2**,
which runs a completely different implementation — nothing here applies to it, and nothing here
should be read as a statement about it.

The Pico HSM matters to this project for one reason: it is the device the procedures get drilled
on. A wipe-and-reprovision cycle that hangs is not a cosmetic problem when the whole point of the
exercise is to prove that a card can be replaced.

## What the patches contain

Two patch files, because the fix now spans the main firmware and the SDK submodule:

`0001-firmware-fixes.patch` — six commits against `polhenarejos/pico-hsm` at `1ad8444`, exported
with `git format-patch`. Apply with `git am`.

`0001-pico-keys-sdk-fixes.patch` — five commits against `polhenarejos/pico-keys-sdk` at
`843a3dc` (the merge-base with upstream). Apply with `git am` **inside the `pico-keys-sdk`
submodule** after checking out `843a3dc` (or a descendant that contains it).

**`cfc04a1` — reset the device after INITIALIZE DEVICE.** Without it the card completes the wipe
but does not come back on the USB bus on its own, so every re-provisioning needed a physical
replug. That turns "restore a dead card from the seed" from a procedure into a site visit.

**`301557f` — size the commit timeout from the hardware, and never reset on an unconfirmed
commit.** Two defects in the path the first commit introduced:

- The timeout was 10 s. The data region is `FLASH_SIZE/2`, so on a 16 MB board that is 8 MB —
  ~2048 sectors at ~30–45 ms per sector erase, meaning a legitimate wipe runs **60–90 seconds**.
  10 s was not a tight bound, it was far below the *normal* case, so the sync reported failure on
  erases that were proceeding perfectly. Raised to 180 s. The asymmetry justifies overshooting:
  the wait returns as soon as the queue drains, so a generous bound costs nothing, while a short
  one hangs the device.
- On an unconfirmed commit it fell back to an async commit and then **reset anyway** — the worst
  available ordering, since "unconfirmed" most likely means the erase is still in flight and the
  reset lands inside it. It now reports `SW_EXEC_ERROR` and stays alive.

**`48f7e5b` — reset via SYSRESETREQ with the flash quiesced, never the watchdog** (with the SDK
commits below). The full forensic basis is in the next section; in short: the watchdog reset
path wedges the boot intermittently, so the reset now goes through `AIRCR.SYSRESETREQ` with the
flash mutex held and no watchdog fallback, and core1's start is verified and watched.

SDK side (`0001-pico-keys-sdk-fixes.patch`): **`78e9f30`** bounds the USB blackout during
multi-sector erases (one sector per critical section); **`ba531cb`** adds
`low_flash_quiesce()`, launch-time core1 verification with retry + bounded chip reset, and the
core1 dead-man's switch. The intermediate `ea8325b`/`a4b305d` pair (CCID reset over USB and its
revert) is in the series for apply-cleanliness; the net effect is nil.

Plus a host-side reset tool and its revert (`7ea1e36`, `50f480d`): remote reset over USB was tried
as a build option, then dropped in favour of the rescue APDU, which needs no firmware change.

## Status: not upstreamed

The disposable staging inventory is a default-deny `hsm-staging-registry.json` (kept in the
operators' private repository) that lists which token serials may be used destructively.
It is the source of truth for both PicoHSM2 token serials, their RP2350 board IDs, and the
Raspberry Pi Debug Probe serial wired to each board. A unit may be marked `disconnected` while
remaining in the inventory; absence from USB must never cause its identity or probe binding to be
dropped. This file contains staging identifiers only and is not a production custody registry.

These have not been sent to `polhenarejos/pico-hsm`. They should be — the timeout defect will hit
anyone with a 16 MB board — but opening a PR against a third party's repository is a decision for
a human, not something to do on someone's behalf.

The patch is kept here rather than only on a local branch because that branch existed **nowhere
else**: its remote was upstream, so `git push` had no destination, and one disk failure would have
taken all of it.

## The known defect these did NOT fix — RESOLVED 2026-08-02 by SWD forensics

~~Roughly **7% of re-provisioning cycles still hang**~~ — the residual hang is now understood
and hardened against. With a Raspberry Pi Debug Probe on the SWD port (xPack OpenOCD,
`rp2350` target), the failure was caught live and read out register-by-register. The repo's
standing rule held: the answer was SWD and a backtrace, not a third theory.

**What the hang actually was — two shapes, both warm-boot core-start failures:**

- **Shape A (off-bus wedge).** Watchdog `REASON.TIMER` set — the watchdog DID fire — then both
  Cortex-M33 cores reading all-zero, XIP SSI all-zero, bootram diagnostics untouched: the chip
  reset but the boot never started. Reset TYPE was ruled out (AIRCR.SYSRESETREQ hung
  identically); flash-busy-at-reset was ruled out (holding the flash mutex across the reset hung
  identically). A physical replug or a debugger reset always boots — those take a different
  path. Not observed since the switch to SYSRESETREQ, but NOT firmware-fixable if it recurs:
  firmware never runs in this shape.
- **Shape B (core1 parked).** The boot completes, core0 runs fine, USB enumerates (TinyUSB is
  core0), but core1 never leaves the bootrom's wait-for-launch loop (parked at `pc=0x19e`,
  polling SIO `FIFO_ST`, bootrom stack) — the SDK's `multicore_launch_core1` FIFO handshake
  completes against stale/misaligned data and reports success anyway. The card enumerates but
  never answers an APDU. A mid-session variant was also caught: core1 parked AFTER it had been
  serving APDUs, with `core1_alive` state showing the launch had succeeded.

**The hardening (measured, not theorised):**

1. `cmd_initialize.c` — reset via `AIRCR.SYSRESETREQ` (both secure and non-secure bits, DSB
   barriers) after a 500 ms USB grace and `low_flash_quiesce()` (flash mutex held so no flash
   op is in flight). No watchdog fallback: a failed reset stays alive and reports
   `SW_EXEC_ERROR`, which is honest and retryable. An attribution marker in watchdog
   `scratch[0]` ties any future wedge to this code path.
2. `usb.c card_start()` — the launch is now VERIFIED: a flag set by `card_init_core1()` proves
   core1 actually entered; 3 relaunch attempts, then a bounded chip reset (`scratch[1]`, max 5
   boots, then alive-dark — never a reset loop).
3. `usb.c card_watchdog_task()` — a dead-man's switch on core0: while a card function is
   active and no command is in flight, it pings core1 through the existing queue protocol
   (apdu_thread echoes unknown events back +1) and treats a missing echo — or a command
   outstanding past 300 s — as core1 death. Recovery is a bounded chip reset ONLY: a bare
   core1 relaunch was measured insufficient (core0's CCID/TPDU state stays bound to the dead
   session; the card connects but every APDU fails "Transmit failed").
4. Forensic counters in `scratch[2..4]` (watchdog recoveries, relaunch attempts, chip resets)
   so any future failure reads out over SWD in seconds.

5. **Deep resets via POWMAN_WDSEL (the shape-A fix).** The residual wedge — boots that never
   start, identically across watchdog_reboot() and rom_reboot() — was the default watchdog
   reset leaving the switched core domain powered. The firmware now arms
   `POWMAN_WDSEL.RESET_SWCORE|RESET_PSM|RESET_POWMAN_ASYNC` (with PSM_WDSEL all-ones) at every
   boot, so every watchdog-family reset power-cycles the switched domain: "the same effect as a
   power-on reset" per the RP2350 datasheet. **Validation: 100/100 rapid reboots, zero hangs,
   against the ~5-10% measured wedge rate** (0.93^100 ≈ 0.07% if the rate were unchanged).

**Known remaining flakiness, honestly scoped:** CCID-level `Transmit failed` episodes on this
macOS host around long operations (one watched INITIALIZE died ~25 s in at the transmit layer
with zero flash work queued — neither wedge shape, device-side boot not implicated). Separating
host-side (pcscd) from device-side causes needs the UART console (Debug Probe port U on
GPIO0/GND, 115200) — the firmware's `INIT:`/`CARD:` printf trail lands there. The cycle harness
also misdiagnoses slow-but-recovering states: its 180 s init alarm races the firmware's 180 s
commit cap, and its 45 s identity window is shorter than the 300 s watchdog deadline, so a
recovery-in-progress is scored "declined".

The cryptographic path has never failed — every completed cycle verified correctly, across all
campaigns today.
