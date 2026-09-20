#!/usr/bin/env python3
"""hsm-forensic-decode.py — turn the firmware's framed binary event stream into the JSONL the
drain analyzer consumes.

    hsm-forensic-decode.py raw.bin > trace.jsonl
    cat /dev/cu.usbmodem* | hsm-forensic-decode.py - > trace.jsonl

WHY A SEPARATE STAGE. The analyzer is frozen as the ordering baseline; the firmware is deliberately
kept ignorant of cache slots at the semantic layer. Something has to join the two, and it belongs
here rather than in either of them:

  * the firmware records transactions (TXN_ALLOC, LINK_QUEUED_TO_CACHE) without knowing which cache
    slot a write landed in — teaching it would mean threading transaction identity through
    flash_program_block() and low_flash_task(), i.e. reshaping the filesystem to observe it;
  * the analyzer needs each link and referent stamped with the dirty_version of its sector, so it
    can tell "this program carried that write" from "this program ran before it".

So this stage tracks the per-sector dirty_version from the CACHE_MUTATE stream and stamps the
semantic events with it. That join is a property of the data — addresses and sectors — not of the
code, which is why neither end has to know about the other.

FRAMING. Each frame is a 0xA5 sync byte, a 36-byte packed record, then a checksum byte
(0xFF - sum8). UART has no delivery guarantee, so a torn frame must be REJECTED and the decoder
must resynchronise on the next sync byte — never silently mis-parsed into a plausible event. Every
rejected frame is counted and emitted as a DROPPED record, which condemns the run: ordering is the
entire question and a mis-parse could invent or destroy the deciding event.
"""
import json, struct, sys

SYNC = 0xA5
REC = "<II BBBB IIIIII"          # seq, lost_total, ev/core/slot/flags, a..f
REC_SIZE = struct.calcsize(REC)  # 36
SECTOR = 4096

EV = {
    1: "ALLOC_DECISION",              # firmware calls it TXN_ALLOC
    2: "CACHE_ACQUIRE",
    3: "CACHE_MUTATE",
    4: "LINK_QUEUED_TO_CACHE",
    5: "REFERENT_COMPLETE_IN_CACHE",
    6: "DRAIN_BEGIN",
    7: "FLASH_PROGRAM_RETURNED",
    8: "CACHE_SLOT_CLEAN",
    9: "FILE_HANDLE_PUBLISHED",
}
ROLE = {1: "new_next", 2: "new_prev", 3: "successor_prev", 4: "predecessor_next"}


def sum8(b):
    return (0xFF - (sum(b) & 0xFF)) & 0xFF


def frames(data, stats):
    """Yield validated records, recording every byte the decoder had to throw away in `stats`.

    THE COUNT MUST LEAVE THIS FUNCTION. It used to accumulate into a local `lost` that a generator
    `return` discarded, so a stream of torn frames decoded whatever survived and reported NOTHING:
    no DROPPED record, no stderr count. After the sort by sequence number the result looks like a
    short but contiguous trace, and the analyzer — which condemns a run on any DROPPED — had
    nothing to condemn it with. Framing loss is exactly the case the DROPPED record exists for.
    """
    i = 0
    n = len(data)
    while i < n:
        if data[i] != SYNC:
            i += 1
            stats["resync_bytes"] += 1
            continue
        if i + 1 + REC_SIZE + 1 > n:
            # A capture cut mid-frame is EXPECTED here: the power cut is the experiment. Recorded
            # so it appears on stderr, but a partial trailing frame alone does not condemn the run.
            stats["truncated_tail"] = n - i
            break
        body = data[i + 1:i + 1 + REC_SIZE]
        ck = data[i + 1 + REC_SIZE]
        if sum8(body) != ck:
            # A corrupt frame must never be parsed. Skip this sync byte only — the real frame
            # start may be inside what we would otherwise swallow.
            i += 1
            stats["bad_checksum"] += 1
            continue
        yield struct.unpack(REC, body)
        i += 1 + REC_SIZE + 1
    return


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    data = sys.stdin.buffer.read() if src == "-" else open(src, "rb").read()

    # sector -> current dirty_version, and sector -> slot, learned from the cache stream
    ver, slot_of = {}, {}
    bad = 0
    out = []

    stats = {"resync_bytes": 0, "bad_checksum": 0, "truncated_tail": 0}
    gen = frames(data, stats)
    while True:
        try:
            rec = next(gen)
        except StopIteration:
            break
        seq, lost_total, ev, core, slot, flags, a, b, c, d, e, f = rec
        name = EV.get(ev)
        if name is None:
            bad += 1
            continue
        o = {"seq": seq, "lost_total": lost_total, "ev": name, "core": core}

        if name == "ALLOC_DECISION":
            o.update(txn=a, new_base=b, original_prev_base=e, next_base=d,
                     predecessor_base=c, real_size=f, persistent=0)
        elif name == "CACHE_ACQUIRE":
            o.update(slot=slot, generation=b, sector_addr=c)
            ver[c] = 0
            slot_of[c] = slot
        elif name == "CACHE_MUTATE":
            sec = c & ~(SECTOR - 1)
            ver[sec] = e
            slot_of[sec] = slot
            o.update(slot=slot, generation=b, dirty_version=e, addr=c, len=d)
        elif name == "LINK_QUEUED_TO_CACHE":
            sec = c & ~(SECTOR - 1)
            # THE JOIN. Stamp the link with the sector's dirty_version as of now, so the analyzer
            # can ask "was this write carried by that program?" rather than guessing.
            o.update(txn=a, which=ROLE.get(b, str(b)), target_addr=c, value=d,
                     slot=slot_of.get(sec, 0xFF), dirty_version=ver.get(sec, 0))
        elif name == "REFERENT_COMPLETE_IN_CACHE":
            sec = b & ~(SECTOR - 1)
            o.update(txn=a, new_base=b,
                     slot=slot_of.get(sec, 0xFF), dirty_version=ver.get(sec, 0))
        elif name in ("DRAIN_BEGIN", "FLASH_PROGRAM_RETURNED", "CACHE_SLOT_CLEAN"):
            o.update(slot=slot, generation=b, dirty_version=e, sector_addr=c)
            if name == "FLASH_PROGRAM_RETURNED":
                o["lockout_end_ok"] = bool(flags & 0x01)
        elif name == "FILE_HANDLE_PUBLISHED":
            o.update(txn=a, fid=b, old_data=c, new_data=d)
        out.append(o)

    # SORT BY SEQUENCE BEFORE EMITTING.
    #
    # There are two per-core rings and the drain round-robins between them, so WIRE ORDER IS NOT
    # EMISSION ORDER: a real capture arrived 58, 61, 59, 62, 60, 63 — interleaved, not lossy. The
    # analyzer's contiguity check read those as gaps and condemned the run, which was the correct
    # response to what it was given and the wrong conclusion about the device.
    #
    # The sequence number is allocated from a single global counter before enqueue, so it IS the
    # emission order, and sorting by it reconstructs exactly that. This hides nothing: a genuine
    # discard still leaves a gap after sorting, because the number was allocated and never used.
    out.sort(key=lambda o: o["seq"])

    for o in out:
        print(json.dumps(o))
    # EVERY KIND OF LOSS COUNTS, not just an unrecognised event id. A byte discarded resynchronising
    # and a frame that failed its checksum are both records that did not arrive, and either can be
    # the program that decides the ordering question.
    lost = bad + stats["bad_checksum"] + stats["resync_bytes"]
    if lost:
        # Emitted last so it is never mistaken for a real event; the analyzer treats any DROPPED
        # as fatal to an ordering verdict, which is the correct response to a mis-framed stream.
        print(json.dumps({"seq": (out[-1]["seq"] + 1) if out else 1,
                          "ev": "DROPPED", "count": lost,
                          "unknown_event": bad, "bad_checksum": stats["bad_checksum"],
                          "resync_bytes": stats["resync_bytes"]}))
    print(f"decoded {len(out)} records, {lost} lost "
          f"({bad} unknown event id, {stats['bad_checksum']} bad checksum, "
          f"{stats['resync_bytes']} byte(s) resynchronising)", file=sys.stderr)
    if stats["truncated_tail"]:
        print(f"  note: {stats['truncated_tail']} trailing byte(s) were a partial frame — expected "
              "when the capture ends at a power cut", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
