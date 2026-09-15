#!/usr/bin/env python3
"""Fail-closed execution-profile and host-residue checks for key ceremonies.

The normal CLI inspects the live host. ``--snapshot`` exists only to make every
decision deterministic in tests; preflight.sh never forwards operator arguments.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


ALLOWED_PROFILES = {"qubes-disposable", "qubes-vault", "debian-live"}


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return ""


def _run(*argv: str) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=5)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def inspect_host() -> dict[str, object]:
    qdb = {}
    if Path("/usr/bin/qubesdb-read").exists() or Path("/bin/qubesdb-read").exists():
        for key in ("/qubes-vm-type", "/qubes-vm-persistence", "/qubes-base-template"):
            rc, value = _run("qubesdb-read", key)
            if rc == 0:
                qdb[key] = value

    rc, root = _run("findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "/")
    try:
        root_mount = json.loads(root)["filesystems"][0] if rc == 0 else {}
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        root_mount = {}

    rc, mounts = _run("findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS")
    try:
        mount_tree = json.loads(mounts).get("filesystems", []) if rc == 0 else []
    except (json.JSONDecodeError, TypeError):
        mount_tree = []

    def flatten(items: list[dict[str, object]]) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for item in items:
            item = dict(item)
            children = item.pop("children", [])
            result.append(item)
            if isinstance(children, list):
                result.extend(flatten(children))
        return result

    all_mounts = flatten(mount_tree)

    systemctl_rc, _ = _run("systemctl", "--version")
    service_manager_known = systemctl_rc == 0
    rc, journal = _run("systemctl", "is-active", "systemd-journald.service")
    journal_active = rc == 0 and journal == "active"
    conf_rc, journal_conf = _run("systemd-analyze", "cat-config", "systemd/journald.conf")
    if conf_rc != 0:
        journal_conf = _read("/etc/systemd/journald.conf")
    storage_values = [
        line.split("=", 1)[1].strip().lower()
        for line in journal_conf.splitlines()
        if line.strip().lower().startswith("storage=")
    ]
    storage_volatile = service_manager_known and (not journal_active or (storage_values and storage_values[-1] == "volatile"))

    active_services = []
    for service in ("udisks2.service", "ModemManager.service", "apport.service", "whoopsie.service", "rsyslog.service"):
        rc, value = _run("systemctl", "is-active", service)
        if rc == 0 and value == "active":
            active_services.append(service)

    swaps = _read("/proc/swaps").splitlines()
    swap_active = len(swaps) > 1
    return {
        "qdb": qdb,
        "os_id": _os_id(),
        "root_mount": root_mount,
        "mounts": all_mounts,
        "swap_active": swap_active,
        # Without active swap there is nowhere to write a hibernation image. Treat
        # the kernel merely advertising "disk" as capability, not enabled policy.
        "hibernate_enabled": swap_active and "disk" in _read("/sys/power/state").split(),
        "journal_volatile": storage_volatile,
        "service_manager_known": service_manager_known,
        "active_unsafe_services": active_services,
        "epoch": int(time.time()),
        "rtc_epoch": _rtc_epoch(),
    }


def _os_id() -> str:
    for line in _read("/etc/os-release").splitlines():
        if line.startswith("ID="):
            return line[3:].strip('"')
    return ""


def _rtc_epoch() -> int | None:
    value = _read("/sys/class/rtc/rtc0/since_epoch")
    try:
        return int(value)
    except ValueError:
        return None


def detect_profile(snapshot: dict[str, object]) -> str | None:
    qdb = snapshot.get("qdb") or {}
    if isinstance(qdb, dict) and qdb:
        persistence = qdb.get("/qubes-vm-persistence")
        if persistence == "none":
            return "qubes-disposable"
        if persistence == "rw-only" and qdb.get("/qubes-vm-type") == "AppVM":
            return "qubes-vault"
        return None

    root = snapshot.get("root_mount") or {}
    if snapshot.get("os_id") == "debian" and isinstance(root, dict):
        fstype = str(root.get("fstype", ""))
        options = str(root.get("options", ""))
        source = str(root.get("source", ""))
        if fstype in {"overlay", "aufs"} and (
            "lowerdir=" in options or "filesystem.squashfs" in source or Path("/run/live/medium").exists()
        ):
            return "debian-live"
    return None


def evaluate(snapshot: dict[str, object]) -> tuple[str | None, list[str], list[str]]:
    failures: list[str] = []
    notes: list[str] = []
    profile = detect_profile(snapshot)
    if profile not in ALLOWED_PROFILES:
        failures.append(
            "unsupported or unprovable environment; use a Qubes VM with QubesDB evidence "
            "or Debian live media with an overlay root"
        )
        return profile, failures, notes

    if snapshot.get("swap_active") is not False:
        failures.append("swap is active or could not be proved inactive")
    if snapshot.get("hibernate_enabled") is not False:
        failures.append("kernel advertises disk hibernation; boot with noresume and disable sleep targets")
    if snapshot.get("journal_volatile") is not True:
        failures.append("journald is persistent; set Storage=volatile and restart it before attaching tokens")
    if snapshot.get("service_manager_known") is not True:
        failures.append("service state could not be inspected with systemctl")
    unsafe = snapshot.get("active_unsafe_services")
    if not isinstance(unsafe, list) or unsafe:
        failures.append("automount/telemetry services active or unknown: " + ", ".join(unsafe or ["unknown"]))

    epoch = snapshot.get("epoch")
    rtc_epoch = snapshot.get("rtc_epoch")
    if not isinstance(epoch, int) or epoch < 1_735_689_600:  # 2025-01-01
        failures.append("system clock is implausible; establish the offline RTC before creating evidence")
    if rtc_epoch is None:
        notes.append("RTC comparison unavailable; record the operator-verified offline time in ceremony evidence")
    elif not isinstance(rtc_epoch, int) or abs(epoch - rtc_epoch) > 300:
        failures.append("system clock differs from hardware RTC by more than five minutes")

    mounts = snapshot.get("mounts")
    if not isinstance(mounts, list):
        failures.append("mounted storage could not be enumerated")
    else:
        allowed_rw = {"/", "/dev", "/dev/shm", "/run", "/tmp"}
        qubes_rw_prefixes = ("/rw", "/home", "/usr/local") if profile.startswith("qubes-") else ()
        for mount in mounts:
            if not isinstance(mount, dict):
                failures.append("malformed mount evidence")
                continue
            target = str(mount.get("target", ""))
            opts = str(mount.get("options", ""))
            fstype = str(mount.get("fstype", ""))
            expected_qubes_mount = any(target == prefix or target.startswith(prefix + "/") for prefix in qubes_rw_prefixes)
            if "rw" in opts.split(",") and target not in allowed_rw and not expected_qubes_mount and fstype not in {
                "proc", "sysfs", "cgroup", "cgroup2", "devpts", "tmpfs", "securityfs", "pstore", "efivarfs"
            }:
                failures.append(f"unexpected writable persistent mount: {target or '<unknown>'}")

    if profile == "qubes-vault":
        notes.append("persistent Qubes AppVM: teardown scan and explicit qube destruction are mandatory")
    return profile, failures, notes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, help="test-only JSON probe snapshot")
    args = parser.parse_args()
    if args.snapshot:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    else:
        snapshot = inspect_host()
    profile, failures, notes = evaluate(snapshot)
    print(f"PROFILE {profile or 'unsupported'}")
    for note in notes:
        print(f"WARN {note}")
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        print("ENVIRONMENT PREFLIGHT FAILED")
        return 1
    print("ENVIRONMENT PREFLIGHT OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
