#!/usr/bin/env python3
"""Remove ceremony state and prove a canary did not reach retained files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


MAX_SCAN_FILE = 16 * 1024 * 1024
MAX_SCAN_FILES = 100_000


def mounts() -> set[str]:
    try:
        result = subprocess.run(
            ["findmnt", "-rn", "-o", "TARGET"], check=False, capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return {line for line in result.stdout.splitlines() if line.startswith("/")} if result.returncode == 0 else set()


def scan(root: Path, needle: bytes, excluded: Path) -> tuple[list[str], list[str], int]:
    hits: list[str] = []
    errors: list[str] = []
    count = 0
    if not root.exists():
        return hits, errors, count

    def onerror(error: OSError) -> None:
        errors.append(f"cannot inspect {error.filename}")

    for base, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        base_path = Path(base)
        dirs[:] = [d for d in dirs if not (base_path / d).is_symlink()]
        try:
            if base_path == excluded or excluded in base_path.parents:
                dirs[:] = []
                continue
        except (OSError, RuntimeError):
            pass
        for name in files:
            path = base_path / name
            count += 1
            if count > MAX_SCAN_FILES:
                errors.append(f"scan limit exceeded under {root}")
                return hits, errors, count
            try:
                if path.is_symlink() or path.stat().st_size > MAX_SCAN_FILE:
                    continue
                if needle in path.read_bytes():
                    hits.append(str(path))
            except (OSError, PermissionError):
                errors.append(f"cannot inspect {path}")
    return hits, errors, count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--canary", type=Path, required=True)
    parser.add_argument("--mount-baseline", type=Path, required=True)
    parser.add_argument("--scan-root", action="append", type=Path, default=[])
    parser.add_argument("--report", type=Path)
    parser.add_argument("--allow-nontmpfs-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    workdir = args.workdir.resolve()
    if not args.allow_nontmpfs_test and not str(workdir).startswith("/dev/shm/ceremony."):
        print("FAIL refusing teardown for a workdir outside /dev/shm", file=sys.stderr)
        return 2
    if args.report:
        report_path = args.report.resolve()
        if report_path == workdir or workdir in report_path.parents:
            print("FAIL teardown report must be retained outside the secret workdir", file=sys.stderr)
            return 2
    try:
        canary = args.canary.read_bytes()
    except OSError as exc:
        print(f"FAIL cannot read residue canary: {exc}", file=sys.stderr)
        return 2
    if len(canary) != 32:
        print("FAIL residue canary must be exactly 32 bytes", file=sys.stderr)
        return 2
    try:
        baseline = {line for line in args.mount_baseline.read_text(encoding="utf-8").splitlines() if line}
    except OSError as exc:
        print(f"FAIL cannot read mount baseline: {exc}", file=sys.stderr)
        return 2

    # tmpfs is the erasure control. unlink every name, then remove the directory;
    # do not claim that shred overwrites RAM or copy-on-write storage.
    failures: list[str] = []
    try:
        shutil.rmtree(workdir)
    except OSError as exc:
        failures.append(f"could not remove secret workdir: {exc}")
    if workdir.exists():
        failures.append("secret workdir still exists")

    now_mounts = mounts()
    if not now_mounts:
        failures.append("cannot enumerate mounts during teardown")
    new_mounts = sorted(now_mounts - baseline)
    if new_mounts:
        failures.append("unexpected mounts remain: " + ", ".join(new_mounts))

    hits: list[str] = []
    scan_errors: list[str] = []
    scanned = 0
    for root in args.scan_root:
        root_hits, root_errors, root_count = scan(root.resolve(), canary, workdir)
        hits.extend(root_hits)
        scan_errors.extend(root_errors)
        scanned += root_count
    if hits:
        failures.append("canary found in retained artifacts: " + ", ".join(hits))
    if scan_errors:
        failures.append("retained-artifact scan incomplete: " + "; ".join(scan_errors[:20]))

    report = {
        "schema": "regalia.ceremony-teardown/v1",
        "timestamp": int(time.time()),
        "workdir_removed": not workdir.exists(),
        "canary_sha256": hashlib.sha256(canary).hexdigest(),
        "scan_roots": [str(p.resolve()) for p in args.scan_root],
        "files_scanned": scanned,
        "unexpected_mounts": new_mounts,
        "canary_hits": hits,
        "scan_errors": scan_errors,
        "status": "pass" if not failures else "fail",
        "limitations": [
            "absence from readable files does not prove erasure from RAM, SSD wear-leveling, printer memory, or optical media",
            "power off and destroy the disposable VM; power-cycle and physically dispose of media per the runbook",
        ],
    }
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(encoded)
        except OSError as exc:
            print(f"FAIL cannot write teardown evidence: {exc}", file=sys.stderr)
            return 2
    else:
        print(encoded, end="")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
