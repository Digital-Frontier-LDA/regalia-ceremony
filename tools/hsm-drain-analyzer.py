#!/usr/bin/env python3
"""hsm-drain-analyzer.py — reconstruct the flash sector cache from a firmware event trace and
decide, objectively, whether a link to a record became durable before the record itself did.

    tools/hsm-drain-analyzer.py trace.jsonl [--baseline flash.bin] [--json]

WHY THIS EXISTS, AND WHY IT IS SEPARATE FROM THE FIRMWARE.

Upstream's hypothesis for Bug 6 is that "the current asynchronous, slot-ordered drain can expose a
list link before the referenced record sector is durable". That is a claim about PHYSICAL ORDERING,
not about which C statement ran first. `allocate_free_addr()` queues four structural writes — the
new record's next_addr and prev_addr, the successor's prev_addr, and the predecessor's next_addr —
all into a six-entry SRAM sector cache. `low_flash_task()` then programs flash_pages[0..5] in SLOT
ORDER, and slot order is allocation order, not dependency order. So a sector holding a link TO the
new record can be programmed before the sector holding the new record.

THE FIRMWARE MUST NOT DECIDE THIS. It emits facts it can actually observe — a slot was acquired, a
cached sector was modified, flash_range_program() returned — and nothing else. Words like
"durable" and "exposed" are conclusions, and conclusions belong here, where they can be recomputed,
argued with, and checked against the post-wedge physical dump. A firmware that emits
LINK_EXPOSED has already assumed the answer.

Note the deliberate name: FLASH_PROGRAM_RETURNED, not SECTOR_DURABLE. The only thing the firmware
witnesses is that the call returned. What actually reached the medium is established afterwards, by
dumping flash in the bootrom window and comparing.

TRUST THE ANALYZER ONLY IF IT FAILS CORRECTLY. This bench has spent days finding instruments that
could not observe what they claimed. So the accompanying test builds a trace with a deliberately
pathological slot layout (link sector in a low slot, referent record in a high slot) and requires a
violation to be reported — then inverts the layout and requires silence. An analyzer that has not
been shown to detect an engineered inversion is not evidence.

EVENTS CONSUMED (JSON Lines, one object per line, `ev` names the type):

  ALLOC_DECISION              seq txn new_base original_prev_base next_base real_size persistent
  CACHE_ACQUIRE               seq slot generation sector_addr
  CACHE_WRITE                 seq slot generation dirty_version addr len [data]
  LINK_QUEUED_TO_CACHE        seq txn which target_addr value slot dirty_version
  REFERENT_COMPLETE_IN_CACHE  seq txn new_base slot dirty_version
  DRAIN_BEGIN                 seq slot generation dirty_version sector_addr
  FLASH_PROGRAM_RETURNED      seq slot generation dirty_version sector_addr [crc32]
  DROPPED                     seq count            <- transport lost records; see below

A DROPPED record invalidates ordering conclusions for the whole run. Ordering is the entire
question, and a gap could hide exactly the program that would change the verdict. The analyzer
reports the run as UNUSABLE rather than quietly analysing what survived.
"""
import argparse, json, sys
from collections import defaultdict

SECTOR = 4096


def sector_of(addr):
    return addr & ~(SECTOR - 1)


class Analyzer:
    def __init__(self, sector_size=SECTOR, post_flash=None, flash_base=0x10000000):
        self.post = post_flash          # bytes of the post-wedge physical dump, or None
        self.flash_base = flash_base
        self.sector_size = sector_size
        self.events = []
        self.dropped = 0
        self.errors = []
        # slot -> last programmed dirty_version, and the seq at which it happened
        self.programmed = defaultdict(list)   # sector_addr -> [(seq, dirty_version, slot)]
        self.txns = {}

    def load(self, path):
        with open(path) as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    self.events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    self.errors.append(f"line {lineno}: unparseable ({e})")
        # A trace whose sequence numbers are not contiguous has lost records in transport even if
        # no DROPPED marker arrived — the marker itself can be the thing that was lost.
        seqs = [e["seq"] for e in self.events if "seq" in e]
        for a, b in zip(seqs, seqs[1:]):
            if b != a + 1:
                self.errors.append(f"sequence gap: {a} -> {b} ({b - a - 1} record(s) missing)")
        for e in self.events:
            if e.get("ev") == "DROPPED":
                self.dropped += int(e.get("count", 0))
        # LOSS MUST NOT DEPEND ON A LOSS RECORD ARRIVING. If the ring is full, the DROPPED record
        # is the one most likely to be dropped as well. So every emitted frame carries a cumulative
        # lost_total, and any increase in it condemns the run independently of the sequence check.
        lost = [int(e["lost_total"]) for e in self.events if "lost_total" in e]
        if lost:
            if lost != sorted(lost):
                self.errors.append("lost_total is not monotonic — the transport is unreliable")
            if lost[-1] > 0:
                self.dropped = max(self.dropped, lost[-1])
                self.errors.append(f"firmware reported lost_total={lost[-1]} events never enqueued")

    def run(self):
        for e in self.events:
            ev = e.get("ev")
            if ev == "ALLOC_DECISION":
                self.txns[e["txn"]] = {
                    "txn": e["txn"],
                    "new_base": e["new_base"],
                    "original_prev_base": e.get("original_prev_base"),
                    "next_base": e.get("next_base"),
                    "links": [],
                    "referent": None,
                }
            elif ev == "LINK_QUEUED_TO_CACHE":
                t = self.txns.get(e["txn"])
                if t is None:
                    self.errors.append(f"seq {e.get('seq')}: link for unknown txn {e['txn']}")
                    continue
                t["links"].append(e)
            elif ev == "REFERENT_COMPLETE_IN_CACHE":
                t = self.txns.get(e["txn"])
                if t is None:
                    self.errors.append(f"seq {e.get('seq')}: referent for unknown txn {e['txn']}")
                    continue
                t["referent"] = e
            elif ev == "FLASH_PROGRAM_RETURNED":
                self.programmed[e["sector_addr"]].append(
                    (e["seq"], e.get("dirty_version", 0), e.get("slot"))
                )

    def _first_program_at_or_after(self, sector_addr, dirty_version):
        """The first program of this sector that carried at least the given cache version.

        Programming is whole-sector: a program that ran when the slot's dirty_version had reached
        or passed the version a write produced necessarily carried that write.
        """
        for seq, ver, slot in self.programmed.get(sector_addr, []):
            if ver >= dirty_version:
                return seq, ver, slot
        return None

    # ---- physical evidence from the post-wedge dump ----------------------------------------
    #
    # The dump shows the FINAL state, not an order. It can therefore never prove that A was
    # programmed before B. What it CAN prove is the outcome that matters: a link that physically
    # references a record whose bytes were never written. That is the damage upstream's hypothesis
    # predicts, and it is decisive on its own.
    def _phys_u32(self, addr):
        if self.post is None:
            return None
        off = addr - self.flash_base
        if off < 0 or off + 4 > len(self.post):
            return None
        return int.from_bytes(self.post[off:off + 4], "little")

    def _phys_is_erased(self, addr, length=8):
        if self.post is None:
            return None
        off = addr - self.flash_base
        if off < 0 or off + length > len(self.post):
            return None
        return all(b == 0xFF for b in self.post[off:off + length])

    def findings(self):
        out = []
        for txn in sorted(self.txns):
            t = self.txns[txn]
            ref = t["referent"]
            if ref is None:
                # The record never finished assembling in cache; nothing to order against.
                continue
            ref_sector = sector_of(t["new_base"])
            ref_prog = self._first_program_at_or_after(ref_sector, ref["dirty_version"])

            for link in t["links"]:
                # Only links that POINT AT the new record can expose it. A link written into the
                # new record itself (its own next/prev) cannot be a premature reference to it.
                if link.get("value") != t["new_base"]:
                    continue
                link_sector = sector_of(link["target_addr"])
                if link_sector == ref_sector:
                    # Same sector: one program makes both durable together. Not an inversion.
                    continue
                link_prog = self._first_program_at_or_after(link_sector, link["dirty_version"])

                # PHYSICAL OUTCOME FIRST — it is the strongest evidence and needs no ordering.
                phys_link = self._phys_u32(link["target_addr"])
                phys_ref_erased = self._phys_is_erased(t["new_base"])
                if phys_link == t["new_base"] and phys_ref_erased is True:
                    f = self._violation(t, link, link_sector, ref_sector, link_prog, ref_prog,
                                        "the physical dump shows the link present while the "
                                        "referent record is still ERASED — a dangling reference")
                    f["evidence"] = "physical"
                    f["verdict"] = "ORDERING_VIOLATION"
                    out.append(f)
                    continue

                if link_prog is None:
                    # A truncated tail cannot distinguish "never programmed" from "the event was
                    # still in the ring when the card wedged". Only the dump can settle it, and if
                    # it cannot, say so rather than inferring.
                    if phys_link == t["new_base"]:
                        f = self._violation(t, link, link_sector, ref_sector, None, ref_prog,
                                            "the link is physically present but its "
                                            "FLASH_PROGRAM_RETURNED never arrived; the dump shows "
                                            "final state, not order")
                        f["evidence"] = "physical-partial"
                        f["verdict"] = "INDETERMINATE"
                        out.append(f)
                    continue

                if ref_prog is None:
                    if phys_ref_erased is False:
                        # The referent physically exists, so it was programmed; we simply never saw
                        # the event. Order is unknown.
                        f = self._violation(t, link, link_sector, ref_sector, link_prog, None,
                                            "the referent is physically present but its "
                                            "FLASH_PROGRAM_RETURNED never arrived; order unknown")
                        f["evidence"] = "physical-partial"
                        f["verdict"] = "INDETERMINATE"
                    else:
                        f = self._violation(t, link, link_sector, ref_sector, link_prog, None,
                                            "the referent sector was never observed programmed")
                        f["evidence"] = "trace"
                        f["verdict"] = "INDETERMINATE" if self.post is None else "ORDERING_VIOLATION"
                    out.append(f)
                elif link_prog[0] < ref_prog[0]:
                    f = self._violation(t, link, link_sector, ref_sector, link_prog, ref_prog,
                                        "the link was programmed BEFORE the referent")
                    f["evidence"] = "trace"
                    f["verdict"] = "ORDERING_VIOLATION"
                    out.append(f)
        return out

    def _violation(self, t, link, link_sector, ref_sector, link_prog, ref_prog, why):
        return {
            "txn": t["txn"],
            "why": why,
            "new_base": t["new_base"],
            "original_prev_addr": t["original_prev_base"],
            "which_link": link.get("which"),
            "link_target_addr": link["target_addr"],
            "link_sector": link_sector,
            "referent_sector": ref_sector,
            "link_program_seq": link_prog[0] if link_prog else None,
            "link_slot": link_prog[2] if link_prog else None,
            "referent_program_seq": ref_prog[0] if ref_prog else None,
            "referent_slot": ref_prog[2] if ref_prog else None,
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--post-flash", help="physical flash dump taken in the bootrom window after "
                                         "the wedge; settles what actually landed")
    ap.add_argument("--flash-base", default="0x10000000",
                    help="XIP address the post-flash dump starts at (default 0x10000000)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    post = None
    if args.post_flash:
        with open(args.post_flash, "rb") as fh:
            post = fh.read()
    a = Analyzer(post_flash=post, flash_base=int(args.flash_base, 0))
    a.load(args.trace)
    a.run()
    v = a.findings()

    usable = not a.errors and a.dropped == 0
    violations = [f for f in v if f.get("verdict") == "ORDERING_VIOLATION"]
    indeterminate = [f for f in v if f.get("verdict") == "INDETERMINATE"]

    # THE VERDICT IS DELIBERATELY ASYMMETRIC.
    #
    # A violation can be established from the trace, or from the physical dump alone when it shows
    # a link present against an erased referent. But "no violation" is a much stronger claim: it
    # requires having actually observed both outcomes. A card that wedges abruptly can leave the
    # final event sitting unsent in the ring, and absence of evidence there is not evidence of
    # correct ordering. So anything incomplete reports INCOMPLETE, never NO_ORDERING_VIOLATION.
    # AN EMPTY TRACE IS NOT A USABLE TRACE.
    #
    # `usable` tracked only whether the records that ARRIVED were self-consistent, so a file with
    # zero records passed it trivially: nothing arrived, so nothing was inconsistent. Observed
    # 2026-08-09 on a run whose capture never started — the analyzer printed
    # `verdict=INCOMPLETE usable=True violations=0`, which reads like a clean bill of health for a
    # firmware change that had not been exercised at all. INCOMPLETE was technically right and
    # `usable: True` was actively misleading beside it.
    #
    # A caller comparing violation counts across builds is exactly who gets hurt: 0 violations from
    # 0 records looks like an improvement over 24.
    if not a.events:
        usable = False
        a.errors.append("trace contains no events — the capture produced nothing, so this run "
                        "cannot support any claim about ordering, in either direction")

    if not usable:
        verdict = "UNUSABLE"
    elif violations:
        verdict = "ORDERING_VIOLATION"
    elif indeterminate:
        verdict = "INDETERMINATE"
    elif not a.txns:
        verdict = "INCOMPLETE"
    else:
        incomplete = [t for t in a.txns.values() if t["referent"] is None]
        verdict = "INCOMPLETE" if incomplete else "NO_ORDERING_VIOLATION"

    if args.json:
        print(json.dumps({"verdict": verdict, "usable": usable, "dropped": a.dropped,
                          "errors": a.errors, "violations": v,
                          "have_post_flash": post is not None}, indent=2))
    else:
        print(f"RESULT={verdict}")
        if not usable:
            print(f"  dropped records: {a.dropped}")
            for e in a.errors:
                print(f"  {e}")
            print("  Ordering is the entire question, and a gap can hide exactly the program that")
            print("  would change the verdict. This run cannot be used for an ordering claim.")
            return 2
        if verdict == "NO_ORDERING_VIOLATION":
            print(f"  {len(a.txns)} transaction(s) examined; every link to a new record was")
            print("  programmed after the record's own sector, or in the same sector.")
            return 0
        if verdict == "INCOMPLETE":
            print("  No violation was seen, but the evidence is not complete enough to say there")
            print("  was none. A card that wedges abruptly can leave the deciding event unsent in")
            print("  the ring. Supply --post-flash from the bootrom window to settle it.")
            return 3
        for f in v:
            print(f"\n  txn                  {f['txn']}")
            print(f"  why                  {f['why']}")
            print(f"  new_base             0x{f['new_base']:08x}")
            if f["original_prev_addr"] is not None:
                print(f"  original_prev_addr   0x{f['original_prev_addr']:08x}")
            print(f"  which_link           {f['which_link']}")
            print(f"  link_target_addr     0x{f['link_target_addr']:08x}")
            print(f"  link_sector          0x{f['link_sector']:08x}")
            print(f"  referent_sector      0x{f['referent_sector']:08x}")
            print(f"  link_program_seq     {f['link_program_seq']} (slot {f['link_slot']})")
            print(f"  referent_program_seq {f['referent_program_seq']} (slot {f['referent_slot']})")
            print(f"  verdict / evidence   {f.get('verdict')} / {f.get('evidence')}")
        print("\n  A link to the new record reached flash before the record did. If power is lost")
        print("  in that window, the chain references bytes that were never written — which is the")
        print("  mechanism upstream proposed for Bug 6.")
        return 1
    return {"UNUSABLE": 2, "ORDERING_VIOLATION": 1, "INDETERMINATE": 3,
            "INCOMPLETE": 3, "NO_ORDERING_VIOLATION": 0}[verdict]


if __name__ == "__main__":
    sys.exit(main())
