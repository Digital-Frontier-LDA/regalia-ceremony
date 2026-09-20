import subprocess
import tempfile
import unittest
from pathlib import Path


# qubes/emulator/tests/ -> the repository root, where tools/ lives.
ROOT = Path(__file__).resolve().parents[3]
CHECK = ROOT / "tools" / "hsm-firmware-invariants.sh"


class FirmwareInvariantSourceTests(unittest.TestCase):
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
