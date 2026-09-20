#!/usr/bin/env python3
"""test_forensic_decode.py — the firmware's real wire format must reach the frozen analyzer intact.

WHY THIS EXISTS SEPARATELY FROM test_drain_analyzer.py. That test proves the analyzer's logic
against synthetic JSON. This one proves the transport: actual packed binary frames, as
pico-keys-sdk/src/forensic.c emits them, through hsm-forensic-decode.py, into the analyzer. A
decoder that produces traces the analyzer mis-reads would be the same failure class this whole
effort exists to avoid — an instrument that runs, prints plausible output, and cannot support its
claim.

It also covers the JOIN, which lives only in the decoder: the firmware deliberately does not know
which cache slot a semantic write landed in, so the decoder stamps links and referents with the
dirty_version of their sector, learned from the CACHE_MUTATE stream. If that join is wrong the
analyzer silently compares the wrong versions and every ordering verdict is worthless.
"""
import json, os, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DECODE = os.path.join(REPO, "tools", "hsm-forensic-decode.py")
ANALYZER = os.path.join(REPO, "tools", "hsm-drain-analyzer.py")

REC = "<II BBBB IIIIII"
SYNC = 0xA5
LINK_SECTOR, REF_SECTOR = 0x10F00000, 0x10F02000
NEW_BASE = REF_SECTOR + 0x40
LINK_ADDR = LINK_SECTOR + 0x100
ORIG_PREV = 0x10F01234


def frame(seq, lost, ev, core, slot, flags, a, b, c, d, e, f):
    body = struct.pack(REC, seq, lost, ev, core, slot, flags, a, b, c, d, e, f)
    return bytes([SYNC]) + body + bytes([(0xFF - (sum(body) & 0xFF)) & 0xFF])


def build(link_first=True, lost=0):
    s = [0]
    out = []

    def add(*a, **kw):
        s[0] += 1
        out.append(frame(s[0], kw.get("lost", lost), *a))

    add(1, 0, 0xFF, 0, 42, NEW_BASE, LINK_ADDR, 0, ORIG_PREV, 128)   # TXN_ALLOC
    add(2, 0, 0, 0, 0, 1, LINK_SECTOR, 0, 0, 0)                      # CACHE_ACQUIRE slot0
    add(2, 0, 5, 0, 0, 1, REF_SECTOR, 0, 0, 0)                       # CACHE_ACQUIRE slot5
    add(3, 0, 5, 0, 0, 1, NEW_BASE, 8, 1, 0)                         # CACHE_MUTATE referent
    add(5, 0, 0xFF, 0, 42, NEW_BASE, 0, 0, 0, 0)                     # REFERENT_COMPLETE
    add(3, 0, 0, 0, 0, 1, LINK_ADDR, 4, 1, 0)                        # CACHE_MUTATE link
    add(4, 0, 0xFF, 0, 42, 4, LINK_ADDR, NEW_BASE, 0, 0)             # LINK_QUEUED predecessor_next

    def program(slot, sector):
        add(6, 0, slot, 0, 0, 1, sector, 0, 1, 0)
        add(7, 0, slot, 1, 0, 1, sector, 0, 1, 0)   # flags bit0 = lockout_end_ok

    if link_first:
        program(0, LINK_SECTOR); program(5, REF_SECTOR)
    else:
        program(5, REF_SECTOR); program(0, LINK_SECTOR)
    return b"".join(out)


def pipeline(raw):
    rf = tempfile.NamedTemporaryFile(suffix=".bin", delete=False); rf.write(raw); rf.close()
    d = subprocess.run([sys.executable, DECODE, rf.name], capture_output=True, text=True)
    tf = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
    tf.write(d.stdout); tf.close()
    a = subprocess.run([sys.executable, ANALYZER, tf.name, "--json"], capture_output=True, text=True)
    os.unlink(rf.name); os.unlink(tf.name)
    return json.loads(a.stdout) if a.stdout.strip() else {"verdict": "CRASH", "stderr": a.stderr}


def main():
    P = lambda m: (print(f"  \033[32mPASS\033[0m {m}"), 0)[1]
    F = lambda m: (print(f"  \033[31mFAIL\033[0m {m}"), 1)[1]
    fails = 0
    print("\n\033[1m### forensic wire format — real frames must reach the analyzer intact\033[0m")

    r = pipeline(build(link_first=True))
    if r["verdict"] == "ORDERING_VIOLATION":
        v = r["violations"][0]
        ok = (v["which_link"] == "predecessor_next"
              and v["original_prev_addr"] == ORIG_PREV
              and v["link_program_seq"] < v["referent_program_seq"])
        fails += P("packed binary frames -> decoder -> analyzer detects the inversion") if ok \
            else F(f"verdict right but the detail is wrong: {v}")
    else:
        fails += F(f"the inversion did not survive the wire format: {r['verdict']}")

    r2 = pipeline(build(link_first=False))
    fails += P("inverted drain order over the wire -> no false positive") \
        if r2["verdict"] == "NO_ORDERING_VIOLATION" \
        else F(f"correct ordering reported as {r2['verdict']}")

    # A corrupted frame must be REJECTED and condemn the run, never mis-parsed into a plausible
    # event. Flip a byte in the middle of the stream so the checksum fails.
    raw = bytearray(build(link_first=False))
    raw[len(raw) // 2] ^= 0xFF
    r3 = pipeline(bytes(raw))
    fails += P("a corrupted frame is rejected and the run is condemned, not mis-parsed") \
        if r3["verdict"] == "UNUSABLE" else F(f"corrupt frame produced {r3['verdict']}")

    # lost_total set by the firmware must survive decoding and condemn the run.
    r4 = pipeline(build(link_first=False, lost=7))
    fails += P("firmware lost_total survives the wire and condemns the run") \
        if r4["verdict"] == "UNUSABLE" else F(f"lost_total ignored: {r4['verdict']}")

    # A TORN FRAME AT THE END OF THE STREAM. The case above is caught by the sequence gap it leaves
    # behind — but corrupt the LAST frame and there is no gap to find, only a shorter trace. The
    # decoder counted that loss into a local variable a generator `return` threw away, so it emitted
    # no DROPPED record and printed "0 frame(s) rejected": the analyzer then scored the remains
    # NO_ORDERING_VIOLATION. Framing loss must reach the verdict on its own, not via a side effect.
    raw = bytearray(build(link_first=False))
    raw[-1] ^= 0xFF                                  # break the final frame's checksum byte
    r5 = pipeline(bytes(raw))
    fails += P("a torn frame at the END of the stream still condemns the run") \
        if r5["verdict"] == "UNUSABLE" else F(f"a lost trailing frame produced {r5['verdict']}")

    rf = tempfile.NamedTemporaryFile(suffix=".bin", delete=False); rf.write(bytes(raw)); rf.close()
    d = subprocess.run([sys.executable, DECODE, rf.name], capture_output=True, text=True)
    os.unlink(rf.name)
    dropped = [json.loads(l) for l in d.stdout.splitlines() if '"DROPPED"' in l]
    fails += P("…and the decoder emits a DROPPED record naming the framing loss") \
        if dropped and dropped[0].get("bad_checksum", 0) >= 1 \
        else F("no DROPPED record was emitted for a frame that failed its checksum")
    fails += P("…and says so on stderr rather than reporting 0 rejected") \
        if "0 lost" not in d.stderr else F(f"stderr claims nothing was lost: {d.stderr.strip()}")

    # Bytes the decoder had to skip to resynchronise are records that did not arrive either.
    r6 = pipeline(b"\x00\xa5garbage" + build(link_first=False))
    fails += P("bytes discarded resynchronising also condemn the run") \
        if r6["verdict"] == "UNUSABLE" else F(f"leading garbage was ignored: {r6['verdict']}")

    print("\n\033[1m### RESULT\033[0m")
    print(f"  {7 - fails} passed, {fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
