"""Does a dangling link crash the filesystem scan, or does the scan tolerate it?

Both external reviewers named this as THE open question behind Bug 6: an ordering inversion only
matters if a link pointing at an unwritten record actually hurts. The referent sector may hold valid
old data, or scan_region() may notice and stop. Nobody had checked.

This replicates scan_region()'s loop from pico-keys-sdk src/fs/file.c exactly:

    for (uintptr_t base = flash_read_uintptr(endp); base >= startp; base = flash_read_uintptr(base)) {
        if (base == 0x0) break;
        ... read fid, length, publish file->data ...
        if (flash_read_uintptr(base) == 0x0) break;
    }

The guards are `base >= startp` and `base == 0x0`. Nothing checks that the record at `base` was ever
written. Reading erased flash yields 0xFFFFFFFF, which is neither 0x0 nor below startp — so the walk
follows it.

Run against a synthetic image rather than the card: deterministic, and it does not risk bricking the
one board on the bench by deliberately corrupting its filesystem.
"""
import unittest

FLASH_BASE = 0x103F0000
FLASH_SIZE = 0x10000
FLASH_END = FLASH_BASE + FLASH_SIZE
START_POOL = FLASH_BASE
END_POOL = FLASH_BASE + 0xF000


class Flash:
    """Erased flash reads as 0xFF. Reads outside the device raise, exactly as an unmapped access
    faults on the RP2350 rather than quietly returning something."""

    def __init__(self):
        self.mem = bytearray(b"\xff" * FLASH_SIZE)
        self.oob_reads = []

    def _off(self, addr, n):
        if addr < FLASH_BASE or addr + n > FLASH_END:
            self.oob_reads.append(addr)
            raise MemoryError(f"read at {addr:#010x} is outside flash "
                              f"[{FLASH_BASE:#x},{FLASH_END:#x}) — on hardware this is a bus fault")
        return addr - FLASH_BASE

    def u32(self, addr):
        o = self._off(addr, 4)
        return int.from_bytes(self.mem[o:o + 4], "little")

    def u16(self, addr):
        o = self._off(addr, 2)
        return int.from_bytes(self.mem[o:o + 2], "little")

    def write_u32(self, addr, val):
        o = self._off(addr, 4)
        self.mem[o:o + 4] = val.to_bytes(4, "little")

    def write_record(self, base, next_addr, prev_addr, fid, length):
        self.write_u32(base, next_addr)
        self.write_u32(base + 4, prev_addr)
        o = self._off(base + 8, 2)
        self.mem[o:o + 2] = fid.to_bytes(2, "little")
        o = self._off(base + 10, 2)
        self.mem[o:o + 2] = length.to_bytes(2, "little")


def scan_region(fl, guarded=False, max_steps=1000):
    """scan_region() as written (guarded=False), and with the proposed fix (guarded=True)."""
    seen = []
    base = fl.u32(END_POOL)
    steps = 0
    while base >= START_POOL:
        steps += 1
        if steps > max_steps:
            raise RuntimeError("scan did not terminate")
        if base == 0x0:
            break
        # THE FIX. An earlier attempt guarded only the POINTER (base == 0xFFFFFFFF or base >
        # END_POOL). That is not enough and this test caught it: the dangling link points at a
        # perfectly valid in-range address — the sector there was simply never written. The pointer
        # looks fine; the RECORD is erased. So validate the record before trusting it.
        if guarded and (base == 0xFFFFFFFF or base > END_POOL
                        or (fl.u32(base) == 0xFFFFFFFF and fl.u16(base + 8) == 0xFFFF)):
            break
        fid = fl.u16(base + 8)
        seen.append((base, fid))
        if fl.u32(base) == 0x0:
            break
        base = fl.u32(base)
    return seen


class TestDanglingLink(unittest.TestCase):
    def _image_with_dangling_link(self):
        """One good record whose next_addr points at a record that was never written.

        This is precisely the state the measured ordering inversion produces: the link reached flash
        (predecessor_next programmed at seq 1369) and the referent sector did not (seq 4330, after
        the cut).
        """
        fl = Flash()
        good = FLASH_BASE + 0x8000
        dangling = FLASH_BASE + 0x7000   # left erased on purpose
        fl.write_u32(END_POOL, good)
        fl.write_record(good, next_addr=dangling, prev_addr=0, fid=0xCA01, length=16)
        return fl, dangling

    def test_unguarded_scan_walks_out_of_flash(self):
        """The shipping scan follows the dangling link and reads outside the device."""
        fl, dangling = self._image_with_dangling_link()
        with self.assertRaises(MemoryError) as cm:
            scan_region(fl, guarded=False)
        self.assertIn("bus fault", str(cm.exception))
        # It did not merely stop at the erased record — it read 0xFFFFFFFF as the next link and
        # dereferenced it.
        self.assertTrue(any(a >= 0xFFFF0000 for a in fl.oob_reads),
                        f"expected a read near 0xFFFFFFFF, got {[hex(a) for a in fl.oob_reads]}")

    def test_unguarded_scan_publishes_a_garbage_file_first(self):
        """Before it faults it registers the erased record as a real file with fid 0xFFFF."""
        fl, _ = self._image_with_dangling_link()
        # Collect as it walks: the call raises, so an assignment from its return value never
        # happens and the evidence would be lost.
        seen = []
        orig = Flash.u16
        def spy(self, addr):
            v = orig(self, addr)
            if addr >= FLASH_BASE + 8:
                seen.append(v)
            return v
        Flash.u16 = spy
        try:
            scan_region(fl, guarded=False)
        except MemoryError:
            pass
        finally:
            Flash.u16 = orig
        self.assertIn(0xFFFF, seen,
                      "the erased record should have been read out as fid 0xFFFF and published")

    def test_guarded_scan_stops_cleanly(self):
        """With the one-line guard the chain simply ends. No fault, no bogus file."""
        fl, _ = self._image_with_dangling_link()
        seen = scan_region(fl, guarded=True)
        self.assertEqual([fid for _, fid in seen], [0xCA01])
        self.assertEqual(fl.oob_reads, [])

    def test_guarded_scan_still_reads_a_healthy_chain(self):
        """The guard must not truncate a chain that is actually fine — otherwise it 'fixes' the
        crash by losing files, which is worse than the crash."""
        fl = Flash()
        a, b, c = FLASH_BASE + 0x8000, FLASH_BASE + 0x7000, FLASH_BASE + 0x6000
        fl.write_u32(END_POOL, a)
        fl.write_record(a, next_addr=b, prev_addr=0, fid=0xCA01, length=16)
        fl.write_record(b, next_addr=c, prev_addr=a, fid=0xCA02, length=16)
        fl.write_record(c, next_addr=0x0, prev_addr=b, fid=0xCA03, length=16)
        self.assertEqual([fid for _, fid in scan_region(fl, guarded=True)],
                         [0xCA01, 0xCA02, 0xCA03])

    def test_guard_does_not_depend_on_drain_ordering(self):
        """Any interrupted write leaves this shape, not just the measured inversion. The guard
        should cover the class."""
        for offset in (0x7000, 0x5000, 0x2000):
            fl = Flash()
            good = FLASH_BASE + 0x8000
            fl.write_u32(END_POOL, good)
            fl.write_record(good, next_addr=FLASH_BASE + offset, prev_addr=0, fid=0xCA01, length=16)
            with self.assertRaises(MemoryError):
                scan_region(fl, guarded=False)
            self.assertEqual([fid for _, fid in scan_region(fl, guarded=True)], [0xCA01])


if __name__ == "__main__":
    unittest.main(verbosity=2)
