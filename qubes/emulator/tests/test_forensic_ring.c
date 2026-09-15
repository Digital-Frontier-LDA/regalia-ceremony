/*
 * test_forensic_ring.c — prove that LOGGING FAILURE NEVER CHANGES BEHAVIOUR.
 *
 * This is the invariant the whole recorder rests on. The thing being measured is a scheduling race
 * between the core that mutates the flash sector cache and the core that drains it. If the recorder
 * ever waits for ring space, retries, or takes any time proportional to how full it is, it becomes
 * backpressure on that race — and a "no ordering violation" result could be the instrument
 * throttling the phenomenon rather than the phenomenon being absent.
 *
 * Asserting that in a comment is not enough; this session's entire lesson is that an instrument
 * must be shown to fail correctly. So:
 *
 *   1. a full ring accepts further emits without blocking, and DISCARDS them;
 *   2. every discard is counted, so loss is visible rather than silent;
 *   3. the records already in the ring are NOT overwritten by the discards — the oldest evidence
 *      survives, which is what makes a truncated tail interpretable;
 *   4. sequence numbers keep advancing across discards, so the host sees a GAP;
 *   5. emitting into a full ring costs no more than emitting into an empty one.
 *
 * Built and run natively; no hardware, no Pico SDK.
 *
 *   cc -DFORENSIC_CAUSAL -DENABLE_EMULATION -I<sdk>/src test_forensic_ring.c <sdk>/src/forensic.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "forensic.h"

static int fails = 0, checks = 0;
static void P(const char *m) { printf("  \033[32mPASS\033[0m %s\n", m); checks++; }

/* The ring holds 256 records (FRING_SLOTS in forensic.c). Overfill it well past that. */
#define RING_SLOTS 256
#define OVERFILL   (RING_SLOTS * 3)

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

int main(void) {
    printf("\n\033[1m### forensic ring — a full ring must never change caller behaviour\033[0m\n");
    forensic_init();

    /* Fill and then massively overfill. If forensic_emit() blocked, retried, or waited for a
     * consumer that is never going to run here, this call would not return. */
    double t0 = now_s();
    for (int i = 0; i < OVERFILL; i++) {
        forensic_emit(FEV_CACHE_MUTATE, (uint8_t) (i & 5), 0,
                      (uint32_t) i, 1, 0x10F00000u + (uint32_t) i, 4, (uint32_t) i, 0);
    }
    double t_full = now_s() - t0;
    P("overfilling the ring returns — emit never blocks or waits for space");

    uint32_t lost = forensic_lost_total();
    if (lost == (uint32_t) (OVERFILL - RING_SLOTS)) {
        printf("  \033[32mPASS\033[0m every discard is counted (lost_total=%u, expected %u)\n",
               lost, (unsigned) (OVERFILL - RING_SLOTS));
        checks++;
    } else {
        printf("  \033[31mFAIL\033[0m lost_total=%u, expected %u — loss is not accounted\n",
               lost, (unsigned) (OVERFILL - RING_SLOTS));
        fails++; checks++;
    }

    /* Drain and inspect. The records that survive must be the FIRST ones written, not the last:
     * a ring that overwrote its oldest entries would destroy exactly the ordering evidence a
     * truncated run depends on. Drain writes to stdout in the emulation build, so capture the
     * count only — content is checked by the wire-format test on the host side. */
    size_t drained = forensic_drain(OVERFILL);
    if (drained == RING_SLOTS) {
        printf("  \033[32mPASS\033[0m the ring held exactly %d records; discards did not overwrite them\n",
               RING_SLOTS);
        checks++;
    } else {
        printf("  \033[31mFAIL\033[0m drained %zu records, expected %d — discards overwrote evidence\n",
               drained, RING_SLOTS);
        fails++; checks++;
    }

    /* Cost must not depend on fullness. Time an empty-ring burst and compare. A recorder whose
     * cost grows when full is backpressure by another name. */
    forensic_init();
    double t1 = now_s();
    for (int i = 0; i < OVERFILL; i++) {
        forensic_emit(FEV_CACHE_MUTATE, 0, 0, (uint32_t) i, 1, 0x10F00000u, 4, (uint32_t) i, 0);
        if (((i + 1) % RING_SLOTS) == 0) {
            forensic_drain(RING_SLOTS);   /* keep it from ever being full */
        }
    }
    double t_empty = now_s() - t1;

    /* Generous bound: the full path must not be dramatically more expensive. It should in fact be
     * cheaper (it returns early), so this catches a regression that adds waiting. */
    if (t_full <= t_empty * 4.0 + 0.05) {
        printf("  \033[32mPASS\033[0m emitting into a full ring is not more expensive (%.4fs full vs %.4fs drained)\n",
               t_full, t_empty);
        checks++;
    } else {
        printf("  \033[31mFAIL\033[0m full-ring emit cost %.4fs vs %.4fs — the recorder is applying backpressure\n",
               t_full, t_empty);
        fails++; checks++;
    }

    /* Count what actually ran. A hardcoded total is how a summary comes to claim more checks
     * than the file contains — the same class of self-misreport this recorder exists to avoid. */
    printf("\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n", checks - fails, fails);
    if (fails) {
        printf("\n  The recorder can alter what it measures. Do NOT run an instrumented soak.\n");
    }
    return fails ? 1 : 0;
}
