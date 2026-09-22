# Upstream landed a flash journal — what it addresses, and the test that would settle Bug 6

**Assessed 2026-09-22** against `polhenarejos/pico-keys-sdk` at the time of writing. Nothing here
has been RUN: this is a reading of the upstream commits against our own forensics, and it ends with
the experiment that would replace it with a measurement.

## What landed

| commit | date | what it does |
|---|---|---|
| `5efcd251` | — | **Introducing a flash journal to recover sectors on power lost** — `+350/-30` in `src/fs/low_flash.c` |
| `ab24e57b` | 2026-09-09 | Fix stalled fs on power cut when deleting a file **between consecutive sectors** |
| `e1fba2e6` | 2026-09-11 | Record the journal on first flash initialisation too |
| `7892b8ce` | 2026-09-15 | Fix flash write overflow |
| `ebdbb28f` | 2026-09-18 | Fix a race getting the command ack between cores |

The journal is a **per-sector write-ahead log**. A 32-byte entry carries a magic (`0x504A524E`,
"NPRJ") and a status that advances by clearing bits only, so it moves without an erase:

```
JOURNAL_STATUS_EMPTY    0xFF
JOURNAL_STATUS_PENDING  0xFE
JOURNAL_STATUS_DONE     0xFC
```

`_Static_assert`s pin that each state is a bit-subset of the previous one, which is what makes the
transitions writable in place on NOR flash.

Recovery (`low_flash_recover_journal`) is called from `scan_region()` — at filesystem scan, i.e.
boot — when the scan finds the fs corrupted. It walks journal sectors for a `PENDING` entry,
restores it, and then **rescans**:

```c
if (!persistent && (!corrupted || allow_force_restore)) {
    if (low_flash_recover_journal(corrupted) == PICOKEYS_OK) {
        printf("INFO: flash redo restored\n");
        scan_region_internal(persistent, false);
    }
}
```

## Against our Bug 6 symptoms

`UPSTREAM-ISSUE.md` reports Bug 6 as three symptoms, "NOT FIXED, need upstream help".

| symptom | assessment |
|---|---|
| **1. writes do not survive** | Plausibly addressed. An interrupted sector program/erase is exactly what a per-sector WAL exists to undo, and the entry is written before the operation. |
| **2. `unwrapKey SW=6400`** | Already attributed elsewhere and NOT a firmware bug: it was a zero-valued DKEK in our own `hsm-auto-import.js`, recorded in `ceremony.sh`. It should be struck from the upstream issue. |
| **3. `find_free_page` hard-faults on corrupted metadata** | Plausibly addressed, and this is the one the recovery hook targets most directly — recovery fires precisely when the scan finds the fs corrupted, and rescans afterwards. |

## What it does NOT obviously address

Our stated Bug 6 hypothesis is about **ordering between two sectors**, not about one sector being
half-written:

> `low_flash_task()` programs `flash_pages[0..5]` in SLOT order, which is allocation order, not
> dependency order. If power is lost between a link's sector reaching flash and its referent's
> sector reaching flash, the chain points at bytes that were never written.

A per-sector WAL makes each sector update atomic. It does not, on its face, impose an order between
two independent sector updates — so a link could still become durable before its referent. What
changes is the consequence: a dangling link that is *detected* as corruption can now be recovered
from rather than wedging the device. `ab24e57b` suggests upstream is attacking cross-sector cases
directly as well.

**So the honest position is: the corruption class looks addressed, the ordering class is
unproven — and our own rig can decide it.**

## The experiment that settles it

`tools/hsm-bug6-powerloss.sh` already does the right thing and explains why a reboot soak cannot:

> Measured 2026-08-09: a 56-reboot instrumented run produced 56 bytes of trace and zero events. The
> rescue-applet reboot path performs no filesystem writes … Ordering evidence needs a WRITE
> workload, interrupted.

1. Build pico-hsm firmware against current `pico-keys-sdk`, **without** our 15 carried patches, so
   what is measured is upstream's fix and not ours.
2. Run `tools/hsm-bug6-powerloss.sh` with the usual cut delays on a registered staging board.
3. Compare against the recorded stock-firmware runs in `UPSTREAM-REPRO-STOCK.md`.
4. Look for `INFO: flash redo restored` in the trace: it distinguishes "the cut did no damage" from
   "the cut did damage and the journal undid it", and only the second is evidence about the journal.

**Not run here.** Building the firmware needs the pico-sdk, the ARM toolchain and the pico-hsm tree;
this box has ~650 MB free on a 2 GB `/home`, which is the same constraint that blocked building
`simd` for regalia#439. The board and the debug probe are both present, so it is a build-host
problem rather than a hardware one.

## Our patches

PRs 26, 27, 28, 29, 31 and 34 were **closed unmerged**; 30, 32 and 33 are still open. Upstream did
not take our approach and has since written its own. That matters for the rebase: some of our 15
patches may now be redundant, and some may conflict with the journal, since
`0001-pico-keys-sdk-fixes.patch` touches `src/fs/low_flash.c` — the same file the journal rewrites.
Deciding which to drop is part of the build in step 1, not a separate exercise.
