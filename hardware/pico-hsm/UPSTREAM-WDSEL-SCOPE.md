# POWMAN_WDSEL was armed globally, and it broke every other reset in the tree

**Device:** one RP2350B (Waveshare RP2350-PiZero) + Raspberry Pi Debug Probe. **No RP2040
hardware** — every RP2040 statement here is compile-only.
**Date:** 2026-08-06.

## What was wrong

`pico-keys-sdk/src/main.c` armed `POWMAN_WDSEL` on every boot:

```c
powman_set_bits(&powman_hw->wdsel,
                POWMAN_WDSEL_RESET_POWMAN_ASYNC_BITS |
                POWMAN_WDSEL_RESET_SWCORE_BITS |
                POWMAN_WDSEL_RESET_PSM_BITS);
psm_hw->wdsel = PSM_WDSEL_BITS;
```

The intent was sound: the default watchdog reset leaves the switched core domain powered and was
measured to wedge the warm boot ~5–10% of resets on RP2350B.

But `POWMAN_WDSEL` is **global state**, and nothing else in the tree knows about it. Every
unrelated `watchdog_reboot()` silently became a switched-core power cycle:

| call site | what it is |
|---|---|
| `rescue.c:490` | the rescue applet's reboot command |
| `ccid.c:465` | the USB reset-to-flash request |

Only `usb.c:chip_reset_now(deep=false)` knew to clear the bits first.

## The consequence

A deep reset does not reliably bring the USB peripheral back. So the rescue applet's reboot — a
warm reboot that returned the card **5/5 on stock firmware** — stopped returning it at all.

Downstream, scenario S5 ("the key survives a reboot") went from passing to wedging the card on
every run, and because a wedged card fails everything after it, it took the rest of the suite with
it. Two nightlies reported S5 plus a cascade of consequences; the cause was one register.

## Measurement

Same watchdog trigger (`WATCHDOG_CTRL` TRIGGER over SWD), only `POWMAN_WDSEL` differing:

| `POWMAN_WDSEL` | result |
|---|---|
| `0x1101` (armed) | device stayed off the USB bus. Three consecutive POWMAN cycles failed to recover it; a physical replug was required |
| `0x0000` (cleared) | card re-enumerated and answered in **5 s** |

Read off the live register while running, confirming it was armed at all times:

```
mdw 0x40100030  ->  0x40100030: 00001101
mdw 0x40018008  ->  0x40018008: 01ffffff
```

## The fix

Clear `POWMAN_WDSEL` at boot; arm it **only** inside `chip_reset_now(deep=true)`, the one caller
that has already given up on a warm reset and has nothing left to lose. A path that has not asked
for a power cycle can no longer be given one, including code added later.

### Validated on the real code path

Rescue-applet reboot (S5's exact APDU sequence: select `A0:58:3F:C1:9B:7E:4F:21`, then
`80:1F:00:00`), on firmware carrying the fix:

```
soak run 1               8/9   came back on their own, mean 3 s
soak run 2               2/3
persistence experiments 11/11
soak run 3              25/25  mean 5 s, zero wedges, zero human intervention
                        -----
                        46/48
```

**The confound is resolved: it was the PORT, not the firmware build.** Run 3 changed two things at
once — firmware `build_pz` -> `build_rtt` (identical source plus RTT stdio) and the device moving
from an Apple root port to a powered, switchable hub port. A fourth run put `build_pz` back on the
hub port, leaving the port as the only constant and the build as the only difference:

| firmware | port | reboots returned unaided |
|---|---|---|
| `build_pz` | root / self-powered Anker hub | 8/9, then 2/3 — **10/12** |
| `build_rtt` | powered hub (switchable) | **25/25** |
| `build_pz` | powered hub (switchable) | **22/23** |

25/25 and 22/23 are indistinguishable at these sample sizes, so the RTT stdio driver is
incidental. **What improved reliability was the port.** The plausible mechanism is power delivery —
the earlier ports were an Apple root port and a self-powered hub, and the device's failure mode is
a wedged warm boot — but this measures the correlation, not the mechanism, and no attempt was made
to instrument the supply.

Combined on the switchable hub port: **47/48**.

One caveat that applies to all four runs: a laptop clamshell sleep landing mid-soak suspends USB
and is recorded as a device failure. One run was corrupted exactly that way (sleep at 15:06 inside
a 14:28-15:14 run) and had to be partly discarded; the soak now holds the host awake with
`caffeinate` and says so, because nothing in the output revealed it — the overlap was only found
by correlating `pmset -g log` against file timestamps afterwards.

## A hypothesis this record previously carried, now DISPROVEN

`rescue.c`'s reboot calls `watchdog_reboot(0, 0, 100)` with **no `low_flash_quiesce()`**, unlike
`usb.c:chip_reset_now()`, whose comment is explicit that no flash op may be in flight when a reset
lands. Since pico-hsm's flash layer is lazy, the obvious inference was that a reset landing on a
pending write loses it — which would have explained scenario S5 ("the key survives a reboot")
failing with the card back but unable to sign.

**It does not happen.** Tested directly: provision, dirty the flash, reboot via the rescue applet,
then check the key is present and still signs. Twice — the second time with a load faithful to the
battery, since scenarios S2+S3 issue ~35 signatures (each updating the key-use counter) and S4
exercises the PIN retry counter immediately before S5 reboots, which is far more pending flash
work than a couple of PIN logins.

```
light load   immediate 3/3, settled 3/3   key survived and signs
heavy load   immediate 3/3, settled 2/2   key survived and signs
                                  ------
                                   11/11
```

The missing quiesce is still a real difference from the careful design in `usb.c`, but it is not
observed to cost anything here and is **not** being reported upstream as a defect. Recorded so the
next person does not re-derive the same plausible, wrong explanation.

The cause of S5's post-reboot signing failure in the 2026-08-07 battery run is therefore still
**open**, and it is NOT reproducible in isolation: 11 deliberate attempts to provoke it, including
five under a load matched to the battery's, all kept the key. What is known is that the key was
demonstrably working immediately before it (S2 verified 20/20 signatures, S3 another 15), and that
the reboot itself now returns the card reliably.

The remaining difference between the isolated test and the battery is everything that runs BEFORE
the scenarios — `e2e_phases` initialises the card with `--public-key-auth 3 --required-pub-keys 2`
in phase d, and a card in that posture refuses key import with SW=6982. Whether some of that state
survives the plain `--initialize` that scenario S1 performs is the obvious next thing to test, and
has not been tested.

## What is NOT fixed

The residual failures (2 of 23) are the warm-boot wedge the global arming was originally trying to
solve. Real, and in that state the chip is past software help:

```
targets  ->  rp2350.cm0   running     <- and it will NOT halt: "Halt timed out, wake up GDB"
             rp2350.cm1   halted      <- parked in the bootrom
usb Pico Key count: 0
```

No reset issued over SWD recovers it. Only removing power does.

So this change trades a **total** failure (deep reset: USB never comes back, 0/N) for one that is
mostly or entirely absent depending on bench configuration (warm reset: 46/48 overall, and 25/25
on the current setup).

**The "needs hands" part is now solved regardless of the residual rate**, which is the property
that actually mattered: with the device on a switchable port the recovery ladder cuts VBUS itself,
so a wedge costs a delay rather than a human. See below.

Note the recovery ladder itself was independently broken, which made this look worse than it was —
it issued `halt` before the POWMAN writes, and `halt` times out in exactly this state, so OpenOCD
dropped the connection and the recovery writes never ran. Fixed; a no-halt POWMAN cycle recovered
an unhaltable core0 immediately. See `tools/hsm-swd-powman-recover.sh`.

### RETRACTED: the bench CANNOT power-cycle itself (corrected 2026-08-07)

An earlier revision of this document claimed the opposite — that moving the device to a `ppps` hub
port meant `uhubctl` could cut VBUS and that this was "electrically what a physical replug does",
citing a card that returned in 7 s. **That claim was wrong**, and the measurement that appeared to
support it was a host-side USB re-enumeration, not a board reset.

Disproved directly:

```
uhubctl -l <hub> -p <port> -a off   ->  Port 2: 0000 off
openocd                             ->  SWD DPIDR 0x4c013477
                                        [rp2350.cm0] Examination succeed
                                        [rp2350.cm1] Examination succeed
```

**With VBUS off, SWD still reads the target.** The board remains powered through the Debug Probe
connection, so cutting the device's port never removes power. Cutting the probe's port as well did
not recover a wedged card either.

This matters beyond the bookkeeping: it explains why the wedge "survives a power cycle". It was
never surviving one. No power cycle was ever performed.

So unattended recovery of a hard wedge is **not** available on this bench, and the recovery
ladder's VBUS stage should be understood as a USB re-enumeration — useful for a mute-but-powered
card, useless for a chip that needs a cold start. Genuinely power-cycling this board requires
either a supply the host can switch independently of the debug probe, or hands.

### CORRECTION TO THE ABOVE: it is the HUB, not the probe (measured 2026-08-13)

The conclusion — no power cycle is ever performed — stands, and is now confirmed harder. **The
attributed cause was wrong.** The board is not being kept alive by the Debug Probe. `uhubctl` on
this hub does not switch VBUS at all.

Isolated by removing the probe from the equation entirely:

```
probe USB cable PHYSICALLY UNPLUGGED (probe unpowered; SWD ribbon left attached)
card wedged — enumerated nothing, port powered, no SWD available

uhubctl -l 1-1.3 -p 3 -a off, 10 s   ->  hub reports "Port 3: 0000 off"   -> NOT recovered
uhubctl -l 1-1.3 -p 3 -a off, 30 s   ->  hub reports "Port 3: 0000 off"   -> NOT recovered
PHYSICAL unplug and replug of the card's own USB cable   ->  RECOVERED, healthy, PIN counters intact
```

The deduction is clean. The probe had no power of its own, so it cannot have been sourcing the
target. If the hub had genuinely removed VBUS, the 30 s cut would have been a cold start and would
have recovered the card exactly as the physical replug did. It did not. Therefore the hub reports
`0000 off` while continuing to supply VBUS.

The hub is `2109:2817 VIA Labs, Inc. USB2.0 Hub`, which advertises `ppps`. Advertising it is not
implementing it. **Do not treat a `ppps` flag, or uhubctl's own "Sent power off request" and
`0000 off` readback, as evidence that power was removed** — all three are present here on a port
that stays powered. The only trustworthy check found so far is behavioural: cut the port and see
whether the device undergoes a full firmware boot on restore (`tools/hsm-power-cycle-verify.sh`
times this against a rescue-applet reboot as a known-boot positive control).

Two consequences:

* Every "survives a power cut" claim made on this bench, including the ones in this document, is
  really "survives a data disconnect". No genuine power cycle had been performed here until
  2026-08-13.
* A real power cycle DOES recover a wedge that the full SWD ladder's VBUS rung could not touch
  (n=1, the event above). That is the first evidence that recovery without a debug probe is
  possible, and it is why unattended testing now needs a supply that actually switches — not this
  hub.

### BOTH MECHANISMS VERIFIED ON HARDWARE (2026-08-07)

The card that produced the HardFault evidence was recovered by physical BOOTSEL (the only path
left once the stuck XIP subsystem had taken out every ROM-mediated operation) and reflashed by UF2.

A UF2 flash rewrites only the program region — it does not erase the filesystem — so the corrupt
chain link that caused the fault was still present. The card booted straight through it, which is
the scan guard doing its job.

Then, with both fixes applied:

```
40 reboots: 38 returned directly, 2 debugger false alarms, 0 wedges
```

against reproductions at reboot 23 and reboot 37 on the two runs before the fixes. The rescue
applet's reboot is the exact path scenario S5 exercises.

Note the false alarms: an attached OpenOCD halts the target when it re-examines after the device
drops off USB, and a halted core cannot enumerate — so the debugger manufactures this symptom. In
an earlier 40-reboot run, 4 of 5 apparent wedges were that. Any measurement of this must either
detach the debugger or rule it out with a `reset run` before counting a failure; the soak now does
the former and the hunt the latter.

### Repeatable green: three consecutive nightlies (2026-08-08)

A single green battery is a data point. Three back-to-back runs, with the staging posture restored
between each, are evidence of stability — and the first attempt at that was NOT stable:

```
before the VBUS/OpenOCD fix:   22/0/2,  21/1/2,  19/3/2      <- degrading
after  the VBUS/OpenOCD fix:   22/0/2,  22/0/2,  22/0/2      <- stable
```

Each green run is: 8 hardware gate checks, e2e_phases 7/0/0 (hardened init, RRC behaviour, PIN
posture, the PKA probe, the break-glass recovery drill), e2e_scenarios 19/0/0, and e2e_recovery
26/0/1.

**What the degradation was.** Not filesystem growth and not PIN depletion — both were hypothesised
and both were MEASURED FALSE (the boot scan is a flat 15 files / 1294 bytes with no corrupt links;
SO-PIN 15 and user PIN 3 stayed unconsumed). It was the recovery ladder wasting its own strongest
remedy: cutting VBUS makes the target disappear and return, which leaves OpenOCD's handle on it
stale, so the `reset run` immediately afterwards went into a dead handle and did nothing. Failed
recoveries then stranded each later run.

Run 2 of the stable loop is the proof it now works: e2e_phases took 1170 s instead of ~142 s — a
wedge occurred mid-run and was recovered unattended — and the run still passed 22/0/2.

**Still true, and not softened by three green runs:** D1 is open (this is a Pico standing in for
the Nitrokey HSM 2), e2e_recovery reports 1 unverified, and e2e_fleet is skipped for want of a
second card, so A3/A5/A6/A7 remain MODELLED rather than performed.

### Reliability after both fixes, measured with a clean instrument

```
40 reboots (debugger attached, false alarms filtered): 38 direct, 0 wedges
60 reboots (debugger detached throughout)            : 56 direct, 4 wedges,
                                                       4/4 recovered unattended,
                                                       0 human interventions
```

So roughly 93% of reboots return the card unaided, and the remainder recover without hands. The
mean time back is 3 s.

Getting to a trustworthy number required closing THREE ways the instrument manufactured the very
failure it counted, all measured:

1. **an attached debugger** halts the target when it re-examines after the device drops off USB,
   and a halted core cannot enumerate — 4 of 5 apparent wedges in one run;
2. **the recovery ladder restarts OpenOCD** to do its work and leaves it running, so every
   iteration after the first wedge ran contaminated — a "5 wedges in 60" result was really
   "1 measured, 4 unusable";
3. **a long-lived OpenOCD goes stale** and reports the chip confidently wrong — `targets` said
   core0 was in state `reset` with all memory reads failing, persisting across `reset run`, while a
   fresh server on the same chip said `halted` and one `reset run` returned the card in 4 s.

Alongside five separate premature-verdict bugs and one run corrupted by host sleep, that is nine
instrument defects against two firmware defects. Both firmware bugs only became visible after
enough of the nine were removed to see past them. On this bench an apparent device failure is more
likely to be a measurement failure, and the correct first move is to falsify the instrument.

### The second wedge mechanism: a HardFault on an out-of-range pointer (ROOT-CAUSED 2026-08-07)

With the watchdog loop fixed, a clean 40-reboot run produced 32 normal returns, 4 false alarms
(the debugger holding the core — see below) and **one genuine wedge at reboot 37** that survived a
`reset run`. Its signature differs from the watchdog loop:

```
targets          -> both cores halted
WATCHDOG_CTRL    -> 0x00000000   (the preinit disarm is working)
POWMAN_WDSEL     -> 0x00000000   (the scoping fix is holding)
flash vector     -> 20082000 10000163   (image intact)
USB port         -> "power" with NO "connect"
RTT              -> 0 bytes
```

It subsequently resisted `reset run`, POWMAN cycles, VBUS cuts on both the device and probe ports,
and a reflash — the reflash failing with `Failed to call ROM function batch` / `failed to exit
flash XIP mode` at both 5000 kHz and 1000 kHz adapter speeds, so not signal integrity. Recovery
requires a physical BOOTSEL entry, which is the one path that does not route through the ROM
functions that are failing.

**The fault, read off the core while parked in it:**

```
pc   = 0x000003ec        bootrom exception handler
lr   = 0xfffffff9        EXC_RETURN — the core is INSIDE an exception

CFSR = 0x00008200        BFSR = 0x82: precise bus fault, BFAR valid
HFSR = 0x40000000        FORCED — escalated to HardFault
BFAR = 0x40130000        the faulting address
```

The firmware dereferenced a pointer to `0x40130000` — peripheral space, neither flash nor SRAM —
and took a precise bus fault that escalated to a HardFault. The core parks in the bootrom handler
and never enumerates. That is why the state survives every reset: the reset re-runs the same boot,
the same corrupt structure is read back out of flash, and the same pointer faults again.

This is the SAME CLASS as the `scan_region()` defect already documented in
UPSTREAM-REPRO-STOCK.md, where a chain link accepted by the scan yielded
`file->data = 0x2000D5A5` (SRAM). Same failure, different garbage value — and it is precisely what
`polhenarejos/pico-keys-sdk#30`'s `flash_range_in_fs()` validation exists to prevent. That this
still happens with #30 applied means its coverage does not reach this access path.

Recovery requires erasing the offending filesystem, which needs BOOTSEL — the only path that does
not route through the ROM functions the stuck XIP subsystem has taken out.

**Measurement hazard worth repeating:** a debugger attached to the target manufactures this
symptom. OpenOCD halts the core when it re-examines after the device drops off USB, and a halted
core cannot enumerate. In the run above, 4 of 5 apparent wedges were that. Any wedge measurement
must issue a `reset run` and re-check before counting one.

## Also found: the RP2040 build was broken

While guarding the POWMAN code it turned out the RP2040 target did not compile at all, and had not
for days — so the series' "RP2040 is compile-only clean" claim was false:

- `usb.c` included `hardware/powman.h` under `PICO_PLATFORM` instead of `PICO_RP2350`. POWMAN does
  not exist on RP2040; `main.c` guarded the same include correctly.
- `rom_reboot()` is a bootrom-v2 (RP2350) API, used unguarded in `usb.c` and `main.c`.

RP2040 now takes `watchdog_reboot()` on both paths and `main.c` gained `hardware/watchdog.h`.
Both targets build clean. The RP2040 paths remain **compile-only and hardware-untested**.

## Upstream status

The global arming is what `polhenarejos/pico-keys-sdk#31` proposes. Reported there on 2026-08-07
with the A/B, the validation numbers and the RP2040 build breakage, and the PR converted to
**draft** — recommending against merging it while leaving it marked ready would be inconsistent.
