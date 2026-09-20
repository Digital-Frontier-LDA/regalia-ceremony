#!/usr/bin/env python3
"""test_drain_analyzer.py — prove the drain analyzer detects a deliberately engineered ordering
inversion, and stays silent when the same trace is inverted. NO HARDWARE REQUIRED.

WHY THIS TEST IS THE POINT.

The analyzer exists to decide whether a link to a record reached flash before the record itself —
the mechanism upstream proposed for Bug 6. That verdict will be used to make a claim to a
maintainer about his own filesystem. This bench has spent days discovering instruments that could
not observe what they claimed: a probe piped into a dead socket, a predicate inverted by SIGPIPE, a
capture read after OpenOCD had already wiped it. Every one of them ran, printed plausible output,
and was worthless.

So the analyzer is not trusted because it looks right. It is trusted because it is shown, here, to
report a violation on a trace built to contain one, and to report none on a trace built not to.

THE PATHOLOGICAL LAYOUT, taken from the real code path. `allocate_free_addr()` queues four
structural writes into the six-entry sector cache, and `low_flash_task()` drains flash_pages[0..5]
in SLOT ORDER. Slot order is allocation order, not dependency order. So:

    slot 0  <- sector holding the PREDECESSOR's next_addr link, which points at the new record
    slot 5  <- sector holding the NEW RECORD itself

drains the link first. If power is lost between the two, the chain references a record whose
sector was never written.
"""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ANALYZER = os.path.join(REPO, "tools", "hsm-drain-analyzer.py")

SECTOR = 4096
LINK_SECTOR = 0x10F00000      # predecessor's sector — holds the next_addr link
REFERENT_SECTOR = 0x10F02000  # the new record's own sector
NEW_BASE = REFERENT_SECTOR + 0x40
LINK_ADDR = LINK_SECTOR + 0x100
ORIG_PREV = 0x10F01234        # deliberately unaligned, as upstream asked us to preserve verbatim


def trace(link_slot, referent_slot, link_first):
    """Build a trace. `link_first` decides which sector's program is emitted first."""
    ev, seq = [], [0]

    def add(**kw):
        seq[0] += 1
        kw["seq"] = seq[0]
        ev.append(kw)

    add(ev="ALLOC_DECISION", txn=42, new_base=NEW_BASE, original_prev_base=ORIG_PREV,
        next_base=0, real_size=128, persistent=0)
    add(ev="CACHE_ACQUIRE", slot=link_slot, generation=1, sector_addr=LINK_SECTOR)
    add(ev="CACHE_ACQUIRE", slot=referent_slot, generation=1, sector_addr=REFERENT_SECTOR)
    # the predecessor's next_addr is made to point at the new record
    add(ev="LINK_QUEUED_TO_CACHE", txn=42, which="predecessor_next", target_addr=LINK_ADDR,
        value=NEW_BASE, slot=link_slot, dirty_version=1)
    # the new record finishes assembling in its own cached sector
    add(ev="REFERENT_COMPLETE_IN_CACHE", txn=42, new_base=NEW_BASE, slot=referent_slot,
        dirty_version=1)

    def program(slot, sector):
        add(ev="DRAIN_BEGIN", slot=slot, generation=1, dirty_version=1, sector_addr=sector)
        add(ev="FLASH_PROGRAM_RETURNED", slot=slot, generation=1, dirty_version=1,
            sector_addr=sector, crc32=0)

    if link_first:
        program(link_slot, LINK_SECTOR)
        program(referent_slot, REFERENT_SECTOR)
    else:
        program(referent_slot, REFERENT_SECTOR)
        program(link_slot, LINK_SECTOR)
    return ev


def make_flash(link_value, referent_written):
    """A synthetic post-wedge dump covering the two sectors of interest, based at LINK_SECTOR."""
    size = (REFERENT_SECTOR - LINK_SECTOR) + SECTOR
    buf = bytearray(b"\xff" * size)                     # erased flash
    off = LINK_ADDR - LINK_SECTOR
    buf[off:off + 4] = int(link_value).to_bytes(4, "little")
    if referent_written:
        off = NEW_BASE - LINK_SECTOR
        buf[off:off + 8] = b"RECORD01"
    return bytes(buf)


def run(events, post_flash=None):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
        path = fh.name
    flashpath = None
    cmd = [sys.executable, ANALYZER, path, "--json"]
    if post_flash is not None:
        with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as bf:
            bf.write(post_flash)
            flashpath = bf.name
        cmd += ["--post-flash", flashpath, "--flash-base", hex(LINK_SECTOR)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(p.stdout)
    finally:
        os.unlink(path)
        if flashpath:
            os.unlink(flashpath)


def main():
    P = lambda m: (print(f"  \033[32mPASS\033[0m {m}"), 0)[1]
    F = lambda m: (print(f"  \033[31mFAIL\033[0m {m}"), 1)[1]
    fails = 0

    print("\n\033[1m### drain analyzer — engineered inversion must be caught\033[0m")

    # 1. The pathological layout the real drain can produce: link in a LOW slot, referent HIGH.
    r = run(trace(link_slot=0, referent_slot=5, link_first=True))
    if r["violations"] and r["usable"]:
        v = r["violations"][0]
        if (v["link_sector"] == LINK_SECTOR and v["referent_sector"] == REFERENT_SECTOR
                and v["link_program_seq"] < v["referent_program_seq"]):
            fails += P("slot 0 link drained before slot 5 referent -> ORDERING_VIOLATION, "
                       f"seq {v['link_program_seq']} < {v['referent_program_seq']}")
        else:
            fails += F(f"violation reported but the detail is wrong: {v}")
    else:
        fails += F("the engineered inversion was NOT detected — the analyzer is not evidence")

    # 2. It must carry the unaligned prev_addr through verbatim; upstream asked for that value and
    #    an analyzer that normalises it destroys the thing being asked about.
    if r["violations"] and r["violations"][0].get("original_prev_addr") == ORIG_PREV:
        fails += P(f"the original unaligned prev_addr is reported verbatim (0x{ORIG_PREV:08x})")
    else:
        fails += F("the unaligned prev_addr was lost or altered")

    # 3. Invert the drain order. Same records, same slots, referent programmed first.
    r2 = run(trace(link_slot=0, referent_slot=5, link_first=False))
    if r2["usable"] and not r2["violations"]:
        fails += P("referent drained before the link -> NO violation (no false positive)")
    else:
        fails += F(f"a correct ordering was reported as a violation: {r2['violations']}")

    # 4. A link living in the SAME sector as the record cannot expose it — one program makes both
    #    durable together. Guards against counting a same-sector write as an inversion.
    ev = trace(link_slot=0, referent_slot=5, link_first=True)
    for e in ev:
        if e["ev"] == "LINK_QUEUED_TO_CACHE":
            e["target_addr"] = REFERENT_SECTOR + 0x10
            e["slot"] = 5
    r3 = run(ev)
    if r3["usable"] and not r3["violations"]:
        fails += P("a link in the referent's own sector is not counted as an inversion")
    else:
        fails += F("same-sector link wrongly reported as an ordering violation")

    # 5. A dropped record must invalidate the run. Ordering is the whole question and a gap can
    #    hide the program that would change the verdict.
    ev = trace(link_slot=0, referent_slot=5, link_first=False)
    ev.append({"ev": "DROPPED", "seq": ev[-1]["seq"] + 1, "count": 3})
    r4 = run(ev)
    if not r4["usable"]:
        fails += P("a DROPPED record marks the run UNUSABLE rather than analysing the remains")
    else:
        fails += F("dropped records did not invalidate the ordering verdict")

    # 6. A sequence gap must be caught even when the DROPPED marker itself was lost.
    ev = [e for e in trace(link_slot=0, referent_slot=5, link_first=False) if e["seq"] != 4]
    r5 = run(ev)
    if not r5["usable"]:
        fails += P("a sequence gap invalidates the run even with no DROPPED marker")
    else:
        fails += F("a silent sequence gap was analysed as if complete")

    # 7. THE TRUNCATED-TAIL CASE. The program happened, but the card wedged before its event
    #    reached the Mac. The dump proves the link physically landed. The dump shows FINAL STATE,
    #    not order, so the analyzer must NOT infer an ordering — it must say INDETERMINATE.
    ev = [e for e in trace(link_slot=0, referent_slot=5, link_first=True)
          if not (e["ev"] == "FLASH_PROGRAM_RETURNED" and e["sector_addr"] == LINK_SECTOR)]
    for i, e in enumerate(ev, 1):
        e["seq"] = i                        # renumber so the removal is a truncation, not a gap
    r6 = run(ev, post_flash=make_flash(link_value=NEW_BASE, referent_written=True))
    if r6["verdict"] == "INDETERMINATE":
        fails += P("missing program event + dump showing both present -> INDETERMINATE, not inferred")
    else:
        fails += F(f"silently inferred an ordering from a final-state dump: {r6['verdict']}")

    # 8. THE DECISIVE PHYSICAL OUTCOME. Link physically present, referent still ERASED. That is a
    #    dangling reference and it needs no ordering events at all to establish.
    r7 = run(ev, post_flash=make_flash(link_value=NEW_BASE, referent_written=False))
    if r7["verdict"] == "ORDERING_VIOLATION" and any(
            f.get("evidence") == "physical" for f in r7["violations"]):
        fails += P("dump showing link present against an ERASED referent -> violation from physical evidence alone")
    else:
        fails += F(f"a dangling physical reference was not reported: {r7['verdict']}")

    # 9. NO_ORDERING_VIOLATION must require complete evidence. A transaction whose referent never
    #    completed in cache cannot support a clean bill of health.
    ev = [e for e in trace(link_slot=0, referent_slot=5, link_first=False)
          if e["ev"] != "REFERENT_COMPLETE_IN_CACHE"]
    for i, e in enumerate(ev, 1):
        e["seq"] = i
    r8 = run(ev)
    if r8["verdict"] == "INCOMPLETE":
        fails += P("an incomplete transaction reports INCOMPLETE, never NO_ORDERING_VIOLATION")
    else:
        fails += F(f"absence of evidence was reported as evidence of correctness: {r8['verdict']}")

    # 10. lost_total must condemn the run even when no DROPPED record arrives and seq is contiguous
    #     — the DROPPED record is the one most likely to be lost when the ring is full.
    ev = trace(link_slot=0, referent_slot=5, link_first=False)
    for e in ev:
        e["lost_total"] = 0
    ev[-1]["lost_total"] = 4
    r9 = run(ev)
    if not r9["usable"]:
        fails += P("a rising lost_total condemns the run with no DROPPED record and no seq gap")
    else:
        fails += F("lost_total was ignored — silent loss would pass as a clean run")

    # 11. A TRANSACTION WITH NO LINK TO THE NEW RECORD ANSWERS NOTHING. Completeness used to mean
    #     only "the referent was seen", so a run where nothing ever pointed at the new record —
    #     no comparison possible, in either direction — reached NO_ORDERING_VIOLATION, the
    #     strongest verdict this tool can print, from evidence that could not have produced any
    #     other. Same defect as scoring an empty trace usable, one level in.
    ev = [e for e in trace(link_slot=0, referent_slot=5, link_first=False)
          if e["ev"] != "LINK_QUEUED_TO_CACHE"]
    for i, e in enumerate(ev, 1):
        e["seq"] = i
    r10 = run(ev)
    if r10["verdict"] == "INCOMPLETE":
        fails += P("a referent with no link pointing at it reports INCOMPLETE, not a clean bill")
    else:
        fails += F(f"a run that could not have shown a violation was scored clean: {r10['verdict']}")

    # 12. …and a link that points somewhere ELSE does not count as the missing evidence either.
    ev = trace(link_slot=0, referent_slot=5, link_first=False)
    for e in ev:
        if e["ev"] == "LINK_QUEUED_TO_CACHE":
            e["value"] = ORIG_PREV          # points at the predecessor, not at the new record
    r11 = run(ev)
    if r11["verdict"] == "INCOMPLETE":
        fails += P("a link that does not point at the new record leaves the run INCOMPLETE")
    else:
        fails += F(f"an unrelated link was accepted as ordering evidence: {r11['verdict']}")

    # 13. A TRACE TRUNCATED BEFORE THE LINK'S PROGRAM EVENT, WITH NO DUMP. Neither source says what
    #     happened to the link, but the transaction looked complete (the link event exists) and the
    #     branch fell through silently, so the run reached NO_ORDERING_VIOLATION on the strength of
    #     evidence that stops exactly where the question begins.
    ev = [e for e in trace(link_slot=0, referent_slot=5, link_first=False)
          if not (e["ev"] == "FLASH_PROGRAM_RETURNED" and e["sector_addr"] == LINK_SECTOR)]
    for i, e in enumerate(ev, 1):
        e["seq"] = i
    r12 = run(ev)
    if r12["verdict"] == "INDETERMINATE":
        fails += P("no link program event and no dump -> INDETERMINATE, not a clean bill")
    else:
        fails += F(f"a truncated trace was scored as evidence of correct ordering: {r12['verdict']}")

    # 14. …but a dump that shows the link ABSENT is a real answer: it never became durable, so it
    #     cannot have preceded the referent. Refusing to conclude here would make the tool useless.
    r13 = run(ev, post_flash=make_flash(link_value=0xFFFFFFFF, referent_written=True))
    if r13["verdict"] == "NO_ORDERING_VIOLATION":
        fails += P("a dump showing the link absent settles it — no violation, not indeterminate")
    else:
        fails += F(f"a physically absent link was not treated as settled: {r13['verdict']}")

    # 15. THE REFERENT'S PROGRAM EVENT IS MISSING AND THE DUMP DOES NOT COVER IT. Having *a* dump
    #     was treated as proof the referent stayed erased, which promoted a gap to ORDERING_VIOLATION
    #     — the strongest claim in the tool — on no physical evidence at all. The address here is
    #     outside the dump, so `_phys_is_erased` answers None.
    ev = [e for e in trace(link_slot=0, referent_slot=5, link_first=True)
          if not (e["ev"] == "FLASH_PROGRAM_RETURNED" and e["sector_addr"] == REFERENT_SECTOR)]
    for i, e in enumerate(ev, 1):
        e["seq"] = i
    short = make_flash(link_value=NEW_BASE, referent_written=False)[:SECTOR]   # link sector only
    with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as bf:
        bf.write(short); shortpath = bf.name
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        for e in ev:
            fh.write(json.dumps(e) + "\n")
        evpath = fh.name
    pr = subprocess.run([sys.executable, ANALYZER, evpath, "--json", "--post-flash", shortpath,
                         "--flash-base", hex(LINK_SECTOR)], capture_output=True, text=True)
    os.unlink(shortpath); os.unlink(evpath)
    r14 = json.loads(pr.stdout)
    if r14["verdict"] == "INDETERMINATE":
        fails += P("a dump that does not cover the referent gives INDETERMINATE, not a violation")
    else:
        fails += F(f"a missing program event was promoted to {r14['verdict']} with no physical evidence")

    print("\n\033[1m### RESULT\033[0m")
    print(f"  {15 - fails} passed, {fails} failed")
    if fails:
        print("\n  The analyzer has NOT been shown to detect an engineered inversion.")
        print("  Do not use its verdict as evidence about the device.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
