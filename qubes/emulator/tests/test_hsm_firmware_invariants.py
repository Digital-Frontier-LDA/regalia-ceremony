import subprocess
import tempfile
import unittest
from pathlib import Path


# qubes/emulator/tests/ -> the repository root, where tools/ lives.
ROOT = Path(__file__).resolve().parents[3]
CHECK = ROOT / "tools" / "hsm-firmware-invariants.sh"


GOOD_FILE_C = """\
void fs_scan(void) {
    for (uintptr_t base = flash_read_uintptr(endp); base != 0x0;) {
        if (!flash_range_in_fs(base)) {
            fs_corruption_detected = 1;
            break;
        }
        uintptr_t next = flash_read_uintptr(base);
        base = next;
    }
}
"""

# The defect: validated, but only after the read that faults.
LATE_GUARD_FILE_C = """\
void fs_scan(void) {
    for (uintptr_t base = flash_read_uintptr(endp); base != 0x0;) {
        uintptr_t next = flash_read_uintptr(base);
        if (!flash_range_in_fs(base)) {
            break;
        }
        base = next;
    }
}
"""

# The other defect: the call is there, its answer is thrown away.
IGNORED_GUARD_FILE_C = """\
void fs_scan(void) {
    for (uintptr_t base = flash_read_uintptr(endp); base != 0x0;) {
        if (!flash_range_in_fs(base)) {
            log_it("bad link");
        }
        base = flash_read_uintptr(base);
    }
}
"""

GOOD_MAIN_C = """\
static void disarm_stale_watchdog(void) {
    hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
}
PICO_RUNTIME_INIT_FUNC_HW(disarm_stale_watchdog, PICO_RUNTIME_INIT_EARLY);
int main(void) {
    return 0;
}
"""

# Both tokens present, but the disarm is in main() — measured NOT to work, because the reset loop
# never reaches main().
SPLIT_MAIN_C = """\
static void something_else(void) {
    gpio_init();
}
PICO_RUNTIME_INIT_FUNC_HW(something_else, PICO_RUNTIME_INIT_EARLY);
int main(void) {
    hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
    return 0;
}
"""

GOOD_FLASH_C = """\
int flash_write(file_t *f) {
    if (f->type == FILE_DATA_FUNC) {
        return 0;
    }
    return do_write(f);
}
"""

ERRORING_FLASH_C = """\
int flash_write(file_t *f) {
    if (f->type == FILE_DATA_FUNC) {
        return CCID_ERR_FILE_NOT_FOUND;
    }
    return do_write(f);
}
"""

GOOD_RESCUE_C = "void rescue(void) { vetted_reset(); }\n"


def sdk(scratch, file_c=GOOD_FILE_C, main_c=GOOD_MAIN_C, rescue_c=GOOD_RESCUE_C,
        flash_c=GOOD_FLASH_C):
    root = Path(scratch) / "sdk"
    (root / "src" / "fs").mkdir(parents=True)
    (root / "src" / "fs" / "file.c").write_text(file_c, encoding="utf-8")
    (root / "src" / "main.c").write_text(main_c, encoding="utf-8")
    (root / "src" / "rescue.c").write_text(rescue_c, encoding="utf-8")
    (root / "src" / "fs" / "flash.c").write_text(flash_c, encoding="utf-8")
    return root


def run(root):
    return subprocess.run(["bash", str(CHECK), str(root)], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)


class FirmwareInvariantSourceTests(unittest.TestCase):
    # A CHECK THAT ONLY EVER SAYS NO IS NOT A CHECK EITHER. Every negative case below has this
    # positive one beside it, so the suite proves the invariants can be satisfied as well as
    # violated — five source assertions that can never pass would simply be deleted by whoever
    # next bumps the SDK.
    def test_firmware_with_every_fix_in_place_passes(self):
        with tempfile.TemporaryDirectory() as scratch:
            result = run(sdk(scratch))
        self.assertIn("validates chain links against the pools before dereferencing", result.stdout)
        self.assertIn("disarmed in preinit", result.stdout)
        self.assertIn("accepts and discards", result.stdout)
        self.assertNotIn("FAIL", result.stdout, result.stdout)

    def test_a_link_validated_after_the_dereference_is_not_the_invariant(self):
        # Token presence passed this: the call is in the loop, just too late to prevent the bus
        # fault it exists to prevent.
        with tempfile.TemporaryDirectory() as scratch:
            result = run(sdk(scratch, file_c=LATE_GUARD_FILE_C))
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("validates the link AFTER dereferencing it", result.stdout)

    def test_a_validation_whose_answer_is_ignored_is_not_the_invariant(self):
        with tempfile.TemporaryDirectory() as scratch:
            result = run(sdk(scratch, file_c=IGNORED_GUARD_FILE_C))
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("does not act on it", result.stdout)

    def test_the_watchdog_disarm_must_be_in_the_registered_preinit_function(self):
        # Both tokens are present in main.c; the disarm runs in main(), which the reset loop never
        # reaches. That is the measured defect, and the old check called it a PASS.
        with tempfile.TemporaryDirectory() as scratch:
            result = run(sdk(scratch, main_c=SPLIT_MAIN_C))
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("does not clear WATCHDOG_CTRL_ENABLE_BITS", result.stdout)

    def test_a_file_data_func_guard_that_errors_is_the_defect_not_the_fix(self):
        # Returning an error maps to SW=6581 and aborts Smart Card Shell initialisation — the
        # thing the guard was written to stop. The token is present either way.
        with tempfile.TemporaryDirectory() as scratch:
            result = run(sdk(scratch, flash_c=ERRORING_FLASH_C))
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("RETURNS AN ERROR", result.stdout)

    def test_c_comments_cannot_satisfy_or_trip_firmware_invariants(self):
        with tempfile.TemporaryDirectory() as scratch:
            sdk = Path(scratch) / "sdk"
            (sdk / "src" / "fs").mkdir(parents=True)
            (sdk / "src" / "fs" / "file.c").write_text(
                "/* for (uintptr_t base = flash_read_uintptr(endp)\n"
                "   flash_range_in_fs(base);\n    } */\n",
                encoding="utf-8",
            )
            (sdk / "src" / "main.c").write_text(
                "/* PICO_RUNTIME_INIT_FUNC_HW WATCHDOG_CTRL_ENABLE_BITS\n"
                "powman_set_bits(); */\n",
                encoding="utf-8",
            )
            (sdk / "src" / "rescue.c").write_text(
                "/*\nwatchdog_reboot();\n*/\n", encoding="utf-8")
            (sdk / "src" / "fs" / "flash.c").write_text(
                "// FILE_DATA_FUNC\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", str(CHECK), str(sdk)], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        self.assertEqual(1, result.returncode, result.stdout)
        for detector in (
            "fs scan does NOT validate chain links",
            "no preinit watchdog disarm",
            "FILE_DATA_FUNC guard missing",
        ):
            self.assertIn(detector, result.stdout,
                          f"comment-only fixture did not trip the {detector!r} detector")
        self.assertIn("POWMAN_WDSEL is not armed globally", result.stdout)
        self.assertIn("reboots through the vetted reset path", result.stdout)


if __name__ == "__main__":
    # WITHOUT THIS BLOCK THE FILE RAN NOTHING. run-tests.sh executes each suite as
    # `python3 tests/<file>.py`, and a unittest module with no entry point exits 0 having
    # collected nothing — a green line for a check that never ran, which is the failure this
    # repository's suites are written to make impossible.
    unittest.main(verbosity=2)
