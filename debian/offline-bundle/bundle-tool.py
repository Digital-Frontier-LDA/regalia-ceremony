#!/usr/bin/env python3
"""Create and verify deterministic metadata for the Debian ceremony bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import zipfile


MANIFEST = "MANIFEST.sha256"
GENERATED = {MANIFEST, "package-lock.json", "provenance.json", "sbom.spdx.json"}
LICENSE_NAME = re.compile(r"(^|/)(licen[cs]e|copying|notice|authors?)(\.|$)", re.IGNORECASE)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def files(root: Path, exclude_manifest: bool = True) -> list[Path]:
    result = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"symlink is prohibited in bundle: {path.relative_to(root)}")
        if path.is_file() and (not exclude_manifest or path.name != MANIFEST):
            result.append(path)
    return sorted(result, key=lambda p: p.relative_to(root).as_posix())


def package_lock(root: Path) -> dict[str, object]:
    packages = []
    for path in sorted((root / "apt").glob("*.deb")):
        fields = subprocess.run(
            ["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"],
            check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        if len(fields) != 3:
            raise ValueError(f"cannot read package identity: {path.name}")
        packages.append({
            "ecosystem": "deb", "name": fields[0], "version": fields[1],
            "architecture": fields[2], "file": path.relative_to(root).as_posix(), "sha256": digest(path),
        })
    for path in sorted((root / "wheels").glob("*")):
        if path.is_file():
            name_version = re.split(r"-(?=\d)", path.name, maxsplit=1)
            packages.append({
                "ecosystem": "python", "name": name_version[0].replace("_", "-"),
                "version": name_version[1].split("-")[0] if len(name_version) == 2 else "unknown",
                "architecture": "wheel-or-sdist", "file": path.relative_to(root).as_posix(), "sha256": digest(path),
            })
    for path, name, version in (
        (root / "bin/sops", "sops", "3.13.1"),
    ):
        packages.append({
            "ecosystem": "standalone", "name": name, "version": version,
            "architecture": "linux-amd64", "file": path.relative_to(root).as_posix(), "sha256": digest(path),
        })
    return {"schema": "regalia.offline-package-lock/v1", "packages": packages}


def extract_python_licenses(root: Path) -> None:
    destination = root / "licenses"
    destination.mkdir(exist_ok=True)
    for archive in sorted((root / "wheels").glob("*")):
        found: list[tuple[str, bytes]] = []
        metadata: list[bytes] = []
        try:
            if zipfile.is_zipfile(archive):
                with zipfile.ZipFile(archive) as package:
                    for name in package.namelist():
                        info = package.getinfo(name)
                        if LICENSE_NAME.search(name) and not info.is_dir() and info.file_size <= 1024 * 1024:
                            found.append((name, package.read(name)))
                        if name.endswith(".dist-info/METADATA") and info.file_size <= 1024 * 1024:
                            metadata.append(package.read(name))
            elif tarfile.is_tarfile(archive):
                with tarfile.open(archive, "r:*") as package:
                    for member in package.getmembers():
                        if LICENSE_NAME.search(member.name) and member.isfile() and member.size <= 1024 * 1024:
                            handle = package.extractfile(member)
                            if handle:
                                found.append((member.name, handle.read()))
                        if member.name.endswith(("/PKG-INFO", ".dist-info/METADATA")) and member.isfile() and member.size <= 1024 * 1024:
                            handle = package.extractfile(member)
                            if handle:
                                metadata.append(handle.read())
        except (OSError, KeyError, tarfile.TarError, zipfile.BadZipFile) as exc:
            raise ValueError(f"cannot inspect Python package licenses in {archive.name}: {exc}") from exc
        declarations = []
        for raw in metadata:
            declarations.extend(
                line for line in raw.decode("utf-8", "replace").splitlines()
                if line.startswith(("License:", "License-Expression:", "License-File:", "Classifier: License ::"))
            )
        if declarations:
            found.append(("METADATA-LICENSE.txt", ("\n".join(sorted(set(declarations))) + "\n").encode()))
        if not found:
            raise ValueError(f"Python package has no embedded license/notice text: {archive.name}")
        for index, (name, content) in enumerate(found):
            safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(name).name)
            (destination / f"python_{archive.name}_{index}_{safe_name}").write_bytes(content)


def create(root: Path, epoch: int, source_commit: str, builder_image: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("source commit must be a full SHA-1")
    if not builder_image.startswith("sha256:") or len(builder_image) != 71:
        raise ValueError("builder image must be a sha256 digest")
    extract_python_licenses(root)
    lock = package_lock(root)
    (root / "package-lock.json").write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    provenance = {
        "schema": "regalia.offline-provenance/v1",
        "source_commit": source_commit,
        "source_date_epoch": epoch,
        "builder_image_digest": builder_image,
        "debian_release": "12",
        "architecture": "amd64",
        "reproducibility": {
            "normalized_tar_owner": 0,
            "normalized_mtime": epoch,
            "expected_variance": "none when source, snapshot, architecture, and builder image digest match",
        },
    }
    (root / "provenance.json").write_text(json.dumps(provenance, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    spdx_packages = []
    for index, item in enumerate(lock["packages"]):
        spdx_packages.append({
            "SPDXID": f"SPDXRef-Package-{index}", "name": item["name"], "versionInfo": item["version"],
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": item["sha256"]}],
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": f"pkg:generic/{item['name']}@{item['version']}"}],
        })
    spdx = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "regalia-offline-ceremony-bundle", "documentNamespace": f"urn:regalia:{source_commit}:{epoch}",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: regalia-bundle-tool-v1"]},
        "packages": spdx_packages,
        "documentDescribes": [item["SPDXID"] for item in spdx_packages],
        "annotations": [{"annotationType": "OTHER", "annotator": "Tool: regalia-bundle-tool-v1",
                         "annotationDate": "1970-01-01T00:00:00Z",
                         "comment": "Dependency license texts are under licenses/. NOASSERTION requires human license review before redistribution."}],
    }
    (root / "sbom.spdx.json").write_text(json.dumps(spdx, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    lines = [f"{digest(path)}  {path.relative_to(root).as_posix()}" for path in files(root)]
    (root / MANIFEST).write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify(root: Path) -> None:
    for name in (MANIFEST, "package-lock.json", "provenance.json", "sbom.spdx.json", "install.sh"):
        if not (root / name).is_file():
            raise ValueError(f"required bundle file missing: {name}")
    expected: dict[str, str] = {}
    for line in (root / MANIFEST).read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("malformed checksum manifest")
        rel = PurePosixPath(match.group(2))
        if rel.is_absolute() or ".." in rel.parts or rel.as_posix() in expected:
            raise ValueError(f"unsafe or duplicate manifest path: {rel}")
        expected[rel.as_posix()] = match.group(1)
    actual = {path.relative_to(root).as_posix() for path in files(root)}
    if set(expected) != actual:
        raise ValueError(f"manifest coverage mismatch: missing={sorted(actual-set(expected))} extra={sorted(set(expected)-actual)}")
    for rel, wanted in expected.items():
        if digest(root / rel) != wanted:
            raise ValueError(f"checksum mismatch: {rel}")
    provenance = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
    if provenance.get("schema") != "regalia.offline-provenance/v1" or provenance.get("debian_release") != "12":
        raise ValueError("invalid provenance")
    lock = json.loads((root / "package-lock.json").read_text(encoding="utf-8"))
    if lock.get("schema") != "regalia.offline-package-lock/v1" or not lock.get("packages"):
        raise ValueError("empty or invalid package lock")
    spdx = json.loads((root / "sbom.spdx.json").read_text(encoding="utf-8"))
    if spdx.get("spdxVersion") != "SPDX-2.3" or len(spdx.get("packages", [])) != len(lock["packages"]):
        raise ValueError("SBOM does not cover the package lock")


def release_manifest(artifact: Path, output: Path, source_commit: str, epoch: int, snapshot: str) -> None:
    document = {
        "schema": "regalia.offline-release/v1", "artifact": artifact.name,
        "artifact_sha256": digest(artifact), "source_commit": source_commit,
        "source_date_epoch": epoch, "debian_snapshot": snapshot,
    }
    output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    create_parser = sub.add_parser("create")
    create_parser.add_argument("root", type=Path)
    create_parser.add_argument("--epoch", required=True, type=int)
    create_parser.add_argument("--source-commit", required=True)
    create_parser.add_argument("--builder-image", required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("root", type=Path)
    release_parser = sub.add_parser("release")
    release_parser.add_argument("artifact", type=Path)
    release_parser.add_argument("output", type=Path)
    release_parser.add_argument("--source-commit", required=True)
    release_parser.add_argument("--epoch", required=True, type=int)
    release_parser.add_argument("--snapshot", required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            create(args.root.resolve(), args.epoch, args.source_commit, args.builder_image)
        elif args.command == "verify":
            verify(args.root.resolve())
        else:
            release_manifest(args.artifact.resolve(), args.output.resolve(), args.source_commit, args.epoch, args.snapshot)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print("VALID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
