# Draft — upstream PR description (links the issue in `UPSTREAM-ISSUE.md`)

> **⚠️ SUPERSEDED IN PART (2026-08-05).** A reproduction on unmodified upstream firmware
> disproved several claims in this draft. Read `UPSTREAM-REPRO-STOCK.md` first, and treat the
> per-bug text below as the *original* report, not the current understanding. Corrections:
> Bug 1 is a panic **during** INITIALIZE (not a dead card after it) and the `pico-hsm#9`
> attribution was wrong; the Bug 4 END-timeout was **never observed** (core1 is orphaned by the
> panic between lockout START and END); "brick" in Bug 5 is wrong (BOOTSEL + flash_nuke
> recovers); Bug 6 symptoms 1 and 3 are consequences of the panic, and symptom 2 (`unwrapKey
> SW=6400`) is still unattributed. The live issue body upstream carries these corrections inline.


> **FILED:** <https://github.com/polhenarejos/pico-keys-sdk/pull/26> (pico-keys-sdk) and <https://github.com/polhenarejos/pico-hsm/pull/135> (pico-hsm).
>
> **How to use this file.** The PR is the two patch series in this directory:
> `0001-firmware-fixes.patch` (6 commits, apply with `git am` onto `polhenarejos/pico-hsm` at
> `1ad8444`) and `0001-pico-keys-sdk-fixes.patch` (8 commits, apply with `git am` inside the
> `pico-keys-sdk` submodule at `843a3dc`). Everything below the line is intended as the PR body.
> Filing notes: the pico-keys-sdk patch carries most of the substance; the pico-hsm patch is
> the INITIALIZE reset path plus the submodule bump.

---

## Title

fix(hsm): reliable reset and re-provisioning on RP2350B — deferred INITIALIZE reset, deep resets, core1 liveness, flash guards

Closes: (the issue from `UPSTREAM-ISSUE.md` — bugs 1–5; bug 6 documented, not fixed)

## Why (context)

We use the Pico HSM as a **staging / procedure-rehearsal device** for a hardware-rooted
key-custody project whose production tokens are Nitrokey HSM 2s (genuine SmartCard-HSMs). The
Pico is deliberately *not* the main HSM; it exists so that wipe-and-reprovision drills ("any
card can die and be replaced from the seed") can run end-to-end without touching production
hardware. That drill workload — INITIALIZE DEVICE in a loop, DKEK domain create, share import,
wrapped-key unwrap — exercises the reset path and the flash layer far harder than everyday
card use, and it measured out a family of reliability defects on RP2350B. This PR is the
minimal set of changes that makes that loop reliable, each validated on hardware with SWD
forensics (Debug Probe + OpenOCD `rp2350` target).

## What it changes

**Reset path**
- `cmd_initialize.c` — after re-personalisation, schedule a chip reset instead of leaving the
  card stateless (the response is transmitted first; a reset executed inside the handler lands
  before it — measured as `Transmit failed` on the host).
- `main.c` — arm `POWMAN_WDSEL.RESET_SWCORE|RESET_PSM|RESET_POWMAN_ASYNC` (+ PSM_WDSEL
  all-ones) at every boot, so every watchdog-family reset power-cycles the switched core
  domain ("same effect as a power-on reset", RP2350 datasheet). Fixes the ~5–10% of warm
  resets that never started the cores. **100/100 consecutive reboots validated.**
- Scheduled (post-wipe) resets use the bootrom's `rom_reboot()` with the deep bits cleared —
  the combination measured best for post-INITIALIZE boots (22/23 recovery cycles); recovery
  resets use the deep watchdog path (100/100 hammered). `AIRCR.SYSRESETREQ` is avoided: on
  RP2040/RP2350 it resets only the asserting core (raspberrypi/pico-feedback#329).
- A scheduled reset never fires while the flash layer has lazy writes queued (drain guard) —
  a reset landing mid-drain leaves a half-written file system.

**Core1 liveness**
- `usb.c` — `card_start()` verifies core1 actually entered (the SDK's FIFO launch handshake
  can complete against stale data while core1 stays parked in the bootrom — caught live via
  SWD), retries, and escalates to a bounded chip reset (budget in watchdog scratch, never a
  reset loop).
- A dead-man's switch pings core1 through the existing queue echo protocol while a card
  function is active and idle; a missing echo — or a command outstanding past a bound —
  recovers via bounded chip reset. (Includes the fix for the probe itself re-executing staged
  APDUs.)

**Flash layer (defensive, not the root fix)**
- `low_flash.c` — queued page addresses are validated against the **real** fs data region
  (`flash_addr_in_fs()`; the region is partition-dependent — hardcoding `FLASH_SIZE_BYTES>>1`
  is wrong on partition-table builds) before erase/program; a corrupt entry previously reached
  `hard_assert` and bricked the device.
- `hard_assertion_failure()` overridden: reboot via `rom_reboot` instead of
  panic → bkpt → `_exit` (measured: device catatonic for a day, needing a replug).
- Multicore lockout start/end timeouts 1 ms → 100 ms with an explicit re-sync: a timed-out
  END orphaned core1 in the lockout victim handler permanently (caught live).

## Validation

- 100/100 rapid reboots (rescue-APDU reboot loop) on the deep-reset build.
- 22/23 full wipe → DKEK import → key import → sign → verify cycles recovered, on hardware.
- Failure forensics throughout this work were register-level (SWD): watchdog REASON, core
  PCs/backtraces, BFAR/CFSR, POWMAN/PSM dumps — no guessed fixes.

## Explicitly NOT in this PR

The flash **persistence** defect (see the linked issue, Bug 6): fs metadata corruption
(zero-KCV symptom), `unwrapKey` `SW=6400` despite matching KCVs, initialize writes lost across
reset, and a `find_free_page` HardFault on a garbage `prev_addr` (`BFAR=0x6CB44000`). The
guards here contain it; they do not fix it. We believe that needs a review of the
page-cache/lazy-drain design in `low_flash.c`/`flash.c`, and we're glad to test patches.
