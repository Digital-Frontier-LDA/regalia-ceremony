#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("preflight_environment", HERE.parent.parent / "scripts" / "preflight-environment.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def safe(**updates):
    value = {
        "qdb": {"/qubes-vm-type": "AppVM", "/qubes-vm-persistence": "none"},
        "os_id": "debian",
        "root_mount": {"target": "/", "source": "overlay", "fstype": "overlay", "options": "rw,lowerdir=/live"},
        "mounts": [{"target": "/", "source": "overlay", "fstype": "overlay", "options": "rw"}],
        "swap_active": False,
        "hibernate_enabled": False,
        "journal_volatile": True,
        "service_manager_known": True,
        "active_unsafe_services": [],
        "epoch": 1_800_000_000,
        "rtc_epoch": 1_800_000_001,
    }
    value.update(updates)
    return value


def profile_snapshots():
    return {
        "qubes-disposable": safe(),
        "qubes-vault": safe(qdb={"/qubes-vm-type": "AppVM", "/qubes-vm-persistence": "rw-only"}),
        "debian-live": safe(qdb={}),
    }


class EnvironmentPreflightTests(unittest.TestCase):
    def assert_safe(self, snapshot, profile):
        got, failures, _ = MODULE.evaluate(snapshot)
        self.assertEqual(got, profile)
        self.assertEqual(failures, [])

    def assert_rejected(self, key, value):
        _, failures, _ = MODULE.evaluate(safe(**{key: value}))
        self.assertTrue(failures, key)

    def test_supported_profiles_are_derived_from_evidence(self):
        self.assert_safe(safe(), "qubes-disposable")
        self.assert_safe(safe(qdb={"/qubes-vm-type": "AppVM", "/qubes-vm-persistence": "rw-only"}), "qubes-vault")
        self.assert_safe(safe(qdb={}), "debian-live")

    def test_operator_label_cannot_make_installed_debian_disposable(self):
        snap = safe(qdb={}, root_mount={"target": "/", "source": "/dev/vda1", "fstype": "ext4", "options": "rw"})
        profile, failures, _ = MODULE.evaluate(snap)
        self.assertIsNone(profile)
        self.assertTrue(failures)

    def test_unknown_qubes_persistence_is_rejected(self):
        snap = safe(qdb={"/qubes-vm-type": "AppVM", "/qubes-vm-persistence": "full"})
        self.assertTrue(MODULE.evaluate(snap)[1])

    def test_each_common_control_fails_closed(self):
        mutations = {
            "swap": ("swap_active", True),
            "unknown-swap": ("swap_active", None),
            "hibernate": ("hibernate_enabled", True),
            "journal": ("journal_volatile", False),
            "service-manager": ("service_manager_known", False),
            "automount": ("active_unsafe_services", ["udisks2.service"]),
            "clock": ("epoch", 1),
            "rtc": ("rtc_epoch", 1_700_000_000),
            "unknown-mounts": ("mounts", None),
            "persistent-mount": ("mounts", [{"target": "/media/usb", "source": "/dev/sdb1", "fstype": "ext4", "options": "rw"}]),
        }
        for profile, snapshot in profile_snapshots().items():
            for control, (key, value) in mutations.items():
                with self.subTest(profile=profile, control=control):
                    changed = dict(snapshot)
                    changed[key] = value
                    self.assertTrue(MODULE.evaluate(changed)[1])

    def test_missing_rtc_is_explicit_warning_not_false_evidence(self):
        _, failures, notes = MODULE.evaluate(safe(rtc_epoch=None))
        self.assertEqual(failures, [])
        self.assertTrue(any("RTC" in note for note in notes))


if __name__ == "__main__":
    unittest.main()
