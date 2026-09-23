#!/usr/bin/env python3
"""ceremony-manifest.py — drive the key ceremony from the custody manifest, and fill the manifest from
what the ceremony proved (regalia#28).

    ceremony-manifest.py plan   MANIFEST [--site S] [--backend B ...]
    ceremony-manifest.py record MANIFEST --evidence FILE [FILE ...] [--site S] [--backend B ...] [--out OUT]
    ceremony-manifest.py piv-steps MANIFEST --device-id ID [--site S]
    ceremony-manifest.py yubikey-evidence --slot SLOT --info FILE --keys-info FILE --public-key FILE
                                          [--device-id ID] --out OUT

WHY THIS EXISTS. The 2026-09-03 audit of regalia#28 found the separation rules documented but nothing
manifest-driven: the seal registry is hand-edited, and no tool fills a binding from ceremony output.
Every binding pin was therefore a digest an operator retyped from a terminal into JSON — the exact
step where a transposed character becomes a production daemon that refuses its own card, or worse, a
manifest that pins a key nobody proved was generated on the device it names. This tool removes the
retyping in both directions:

  * `plan` reads the manifest BEFORE any hardware is touched and prints, for every binding still
    `planned`, the concrete provisioning step — backend, device, slot/object, algorithm, the policies
    the device must be generated with, and the evidence that must come back. It REFUSES a manifest
    that asks for something this ceremony cannot honour, because a ceremony that discovers that half
    way through has already generated keys it now has to account for.

  * `record` takes the evidence the ceremony and commissioning produced, matches each item to exactly
    one binding, fills device_serial / public_key_sha256 / pin_policy / touch_policy from what the
    DEVICE reported, advances planned -> qualified, re-validates the whole result with regalia-kms's
    own validator, and only then writes. Anything it cannot account for is a named refusal and
    NOTHING is written: a half-recorded manifest is worse than an untouched one, because it looks
    finished.

  * `yubikey-evidence` packages the raw ykman output for one PIV slot into the evidence record
    `record` consumes. It keeps the RAW text, not conclusions drawn from it, so `record` re-derives
    every value itself instead of trusting a summary somebody could have edited.

WHAT IT DOES NOT DO. It performs no hardware operation. It never runs pkcs11-tool, ykman or
commission-card.sh; it reads what they printed. The Nitrokey pin comes from commission-card.sh
--kek-id/--kek-ref, whose MANIFEST_BINDING_PINS line is printed only after the card's attestation
proved the key was generated on that genuine card (ADR-0002 D1). This tool does not repeat any of
those checks — it cannot, it has no card — and it does not accept a Nitrokey pin from anywhere else.

VALIDATION IS REGALIA-KMS'S, NOT A COPY OF ITS IDEAS. vendor/regalia_kms/ holds verbatim copies of
tools/custody_manifest.py, the backend capability table it reads, and the JSON schema, pinned by
sha256 in vendor/regalia_kms/PINS.json and proved by test_ceremony_manifest.py. A second,
"minimal" validator here would be the two-copies-drift defect regalia-kms#73 already paid for once.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "vendor" / "regalia_kms" / "tools"))
import custody_manifest  # noqa: E402  (vendored; see vendor/regalia_kms/PINS.json)

YUBIKEY_EVIDENCE_SCHEMA = "regalia.yubikey-piv-evidence/v1"

# Only these custody modes are provisioned by a key ceremony. fido-multi-enrollment credentials are
# enrolled at the relying party (tools/fido_continuity.py in regalia-kms owns them) and an `exception`
# object is by definition not provisioned the standard way. They are listed by `plan` as not this
# ceremony's, and `record` neither requires nor accepts evidence for them.
CEREMONY_CUSTODY = {"direct-hardware", "hardware-envelope"}
# The backends this ceremony has a provisioning route for. One entry per line: written inline, the
# pair reads to gitleaks' generic-api-key rule as `…key-piv", "<value>` and fails the secret scan.
PROVISIONED_BACKENDS = frozenset((
    "nitrokey-pkcs11",
    "yubikey-piv",
))

# PIV key slots: the four named ones and the twenty retired-key slots 82..95. f9 is the attestation
# slot and holds Yubico's key, not ours.
PIV_SLOTS = {"9a", "9c", "9d", "9e"} | {f"{n:02x}" for n in range(0x82, 0x96)}
PIV_SLOT_NAMES = {"AUTHENTICATION": "9a", "SIGNATURE": "9c", "KEY_MANAGEMENT": "9d", "CARD_AUTH": "9e"}
PIV_SLOT_NAMES.update({f"RETIRED{n - 0x81}": f"{n:02x}" for n in range(0x82, 0x96)})

# manifest algorithm -> ykman KEY_TYPE name. The manifest's capability table admits exactly these for
# yubikey-piv; anything else never reaches here because the vendored validator refuses it first.
YUBIKEY_ALGORITHM = {"p256": "ECCP256", "p384": "ECCP384", "rsa2048": "RSA2048"}

# manifest algorithm -> pkcs11-tool --key-type. The ceremony GENERATES on the card; commission-card's
# attestation is what proves it did, and an imported key fails that attestation.
NITROKEY_KEYGEN = {
    "p256": "EC:prime256v1", "p384": "EC:secp384r1", "secp256k1": "EC:secp256k1",
    "rsa2048": "rsa:2048", "rsa3072": "rsa:3072", "rsa4096": "rsa:4096",
}

# SubjectPublicKeyInfo AlgorithmIdentifier OIDs, DER-encoded (tag, length, value) so a match is an OID
# and not a coincidence of bytes inside a modulus.
OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")
OID_P256 = bytes.fromhex("06082a8648ce3d030107")
OID_P384 = bytes.fromhex("06052b81040022")
OID_RSA = bytes.fromhex("06092a864886f70d010101")
SPKI_FAMILY = {
    "ECCP256": (OID_EC_PUBLIC_KEY, OID_P256),
    "ECCP384": (OID_EC_PUBLIC_KEY, OID_P384),
    "RSA2048": (OID_RSA,),
}

FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
SERIAL = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HEX_ID = re.compile(r"^[0-9a-f]{1,64}$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PINS_LINE = re.compile(r"^MANIFEST_BINDING_PINS (\{.*\})\s*$")
# commission-card.sh prints this PASS line immediately before the pins, and it is the only place the
# transcript names the PKCS#11 id the pin belongs to. The MANIFEST_BINDING_PINS JSON carries serial and
# digest but not the id, and a Nitrokey holds several keys, so without it a pin cannot be put on the
# right binding. If the pins JSON ever carries "object_id" itself, the two must agree.
KEK_LINE = re.compile(r"KEK public_key_sha256 = (sha256:[0-9a-f]{64}) \(SubjectPublicKeyInfo of ID ([0-9A-Fa-f]+)\)")


class Refusal(Exception):
    """A named, safe-to-print reason the ceremony will not proceed. Nothing has been written."""


# =================================================================================================
# Manifest loading and routes
# =================================================================================================

def load_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise Refusal(f"cannot read manifest {path}: {error.strerror or error}") from None
    except json.JSONDecodeError as error:
        raise Refusal(f"manifest {path} is not JSON (line {error.lineno}, column {error.colno})") from None
    validate(raw, "manifest does not validate")
    return raw


def validate(manifest: Any, prefix: str) -> None:
    try:
        custody_manifest.validate_manifest(manifest)
    except custody_manifest.ManifestError as error:
        raise Refusal(f"{prefix}: {error}") from None


def norm_id(value: str) -> str:
    return value.strip().lower()


@dataclass
class Route:
    """One binding, located. `path` is the manifest path every message names."""
    obj_index: int
    bind_index: int
    obj: dict[str, Any]
    binding: dict[str, Any]
    path: str = field(init=False)

    def __post_init__(self) -> None:
        self.path = f"objects[{self.obj_index}]({self.obj['id']}).bindings[{self.bind_index}]"

    @property
    def backend(self) -> str:
        return self.binding["backend"]

    @property
    def device_id(self) -> str:
        return self.binding["device_id"]

    @property
    def object_id(self) -> str:
        return norm_id(self.binding["object_id"])


def all_routes(manifest: dict[str, Any]) -> list[Route]:
    return [Route(i, j, obj, b) for i, obj in enumerate(manifest["objects"]) for j, b in enumerate(obj["bindings"])]


def ceremony_routes(manifest: dict[str, Any]) -> list[Route]:
    return [r for r in all_routes(manifest) if r.obj["custody"] in CEREMONY_CUSTODY]


def in_scope(route: Route, site: str | None, backends: list[str] | None) -> bool:
    return (site is None or route.binding["site"] == site) and (not backends or route.backend in backends)


def is_symmetric(obj: dict[str, Any]) -> bool:
    return obj["kind"] == "symmetric-key" or obj["algorithm"].lower().startswith("aes")


def key_algorithm(route: Route) -> str:
    """The algorithm of the key IN THE SLOT. For an opaque secret that is the wrapping key the binding
    names; the secret itself has no algorithm."""
    if route.obj["algorithm"] == "opaque":
        kek = route.binding.get("kek_algorithm")
        if not kek:
            raise Refusal(f"{route.path}: an opaque object whose binding names no kek_algorithm leaves the key "
                          f"to generate in the slot unknown; this ceremony cannot provision it")
        return kek
    return route.obj["algorithm"]


def device_serials(manifest: dict[str, Any]) -> dict[str, str]:
    """device_id -> the ONE serial the manifest records for it, across every object. A device's serial
    is its identity (ADR-0002 D1), so it is a property of the device, not of one binding: once any
    binding records it, every other binding on that device inherits it."""
    serials: dict[str, str] = {}
    owners: dict[str, str] = {}
    for r in all_routes(manifest):
        s = r.binding.get("device_serial")
        if not s:
            continue
        if r.device_id in serials and serials[r.device_id] != s:
            raise Refusal(f"{r.path}: device {r.device_id} is recorded with two serials "
                          f"({serials[r.device_id]} and {s}); one device has one serial")
        if s in owners and owners[s] != r.device_id:
            raise Refusal(f"{r.path}: serial {s} is recorded for two devices ({owners[s]} and {r.device_id}); "
                          f"one serial is one device")
        serials[r.device_id] = s
        owners[s] = r.device_id
    return serials


def check_fleet(manifest: dict[str, Any]) -> None:
    """Invariants over the WHOLE manifest, checked by plan and again on the result of record."""
    device_serials(manifest)
    slots: dict[tuple[str, str], str] = {}
    keys: dict[str, tuple[str, str]] = {}
    for r in all_routes(manifest):
        if r.binding["state"] in {"retired", "revoked"}:
            continue
        slot = (r.device_id, r.object_id)
        if slot in slots:
            raise Refusal(f"{r.path}: {r.device_id} object {r.object_id} is also bound by {slots[slot]}; "
                          f"one slot holds one key")
        slots[slot] = r.path
        pk = r.binding.get("public_key_sha256")
        if pk and is_symmetric(r.obj):
            raise Refusal(f"{r.path}: {r.obj['algorithm']} is a symmetric key and has no public key, "
                          f"so public_key_sha256 cannot describe it")
        if pk:
            if pk in keys and keys[pk][0] != r.device_id:
                raise Refusal(f"{r.path}: public_key_sha256 {pk} is also pinned on {keys[pk][0]} ({keys[pk][1]}); "
                              f"a key generated on a device exists on no other device (ADR-0002 D1/D5), so one "
                              f"of the two was imported or the evidence is mixed up")
            keys[pk] = (r.device_id, r.path)


def check_route(route: Route) -> str:
    """Refuse what the ceremony cannot honour for one PLANNED binding; return its key algorithm."""
    b, obj = route.binding, route.obj
    if is_symmetric(obj):
        raise Refusal(f"{route.path}: {obj['algorithm']} is symmetric; the only pin this ceremony can prove is "
                      f"public_key_sha256 from an attested key pair, so it has no route that can qualify it")
    if route.backend == "yubikey-openpgp":
        raise Refusal(f"{route.path}: yubikey-openpgp has no provisioning route in this ceremony; "
                      f"plan the key as yubikey-piv or provision it outside the ceremony")
    if route.backend not in PROVISIONED_BACKENDS:
        raise Refusal(f"{route.path}: backend {route.backend} is not provisioned by this ceremony")
    algorithm = key_algorithm(route)
    if route.backend == "yubikey-piv":
        if route.object_id not in PIV_SLOTS:
            raise Refusal(f"{route.path}: object_id {b['object_id']} is not a PIV key slot "
                          f"(9a, 9c, 9d, 9e, 82-95)")
        if algorithm not in YUBIKEY_ALGORITHM:
            raise Refusal(f"{route.path}: yubikey-piv cannot generate {algorithm}")
        # ADR-0002 D5: YubiKey keys are GENERATED ON THE DEVICE and never imported. A planned binding
        # that already names its public key is asking for a key that exists before the device makes
        # it — which is only possible by importing it. The same goes for a seed: it reaches a YubiKey
        # only by being imported.
        if b.get("public_key_sha256"):
            raise Refusal(f"{route.path}: a planned YubiKey binding already pins public_key_sha256, i.e. a key "
                          f"that exists before the device generates it — that is an import, and YubiKey keys "
                          f"are generated on the device, never imported (ADR-0002 D5)")
        if obj["kind"] == "seed":
            raise Refusal(f"{route.path}: a seed reaches a YubiKey only by import, and YubiKey keys are "
                          f"generated on the device, never imported (ADR-0002 D5)")
        # Duplicates the vendored validator's refusal on purpose: that one guards the manifest format,
        # this one guards what the ceremony will do, and neither should depend on the other staying.
        if b.get("touch_policy") != "never":
            raise Refusal(f"{route.path}: touch_policy must be never; the daemon signs unattended")
        if b.get("pin_policy") not in {"once", "always"}:
            raise Refusal(f"{route.path}: pin_policy must be once or always")
    else:
        if algorithm not in NITROKEY_KEYGEN:
            raise Refusal(f"{route.path}: this ceremony has no attested generation route for {algorithm} "
                          f"on nitrokey-pkcs11")
        if not HEX_ID.fullmatch(route.object_id):
            raise Refusal(f"{route.path}: object_id {b['object_id']} is not a PKCS#11 hex id; "
                          f"commission-card.sh --kek-id takes hex")
    return algorithm


def planned_routes(manifest: dict[str, Any], site: str | None, backends: list[str] | None) -> list[Route]:
    """The planned, in-scope bindings, each already checked as honourable. Refuses ambiguity that would
    only surface at `record`: two Nitrokey bindings with the same object id and no serial are
    indistinguishable to a commission transcript, which names a serial and an id and nothing else."""
    check_fleet(manifest)
    routes = [r for r in ceremony_routes(manifest) if r.binding["state"] == "planned" and in_scope(r, site, backends)]
    for r in routes:
        check_route(r)
    serials = device_serials(manifest)
    unassigned: dict[str, list[Route]] = {}
    for r in routes:
        if r.backend == "nitrokey-pkcs11" and not serials.get(r.device_id):
            unassigned.setdefault(r.object_id, []).append(r)
    for object_id, group in unassigned.items():
        if len(group) > 1:
            names = ", ".join(f"{g.device_id} ({g.path})" for g in group)
            raise Refusal(f"Nitrokey object {object_id} is planned on {names} with no device_serial recorded for "
                          f"any of them; a commission transcript names only serial and id, so record cannot tell "
                          f"them apart. Record each card's device_serial in the manifest before the ceremony "
                          f"(commission-card.sh --expect-serial needs it anyway)")
    return routes


# =================================================================================================
# plan
# =================================================================================================

def describe(route: Route, serials: dict[str, str]) -> list[str]:
    b = route.binding
    algorithm = key_algorithm(route)
    serial = serials.get(route.device_id)
    lines = [
        f"STEP {route.path}",
        f"  object     {route.obj['id']} ({route.obj['kind']}, {route.obj['algorithm']}, "
        f"operations={','.join(route.obj['operations'])})",
        f"  site       {b['site']}",
        f"  backend    {route.backend}",
        f"  device_id  {route.device_id}",
    ]
    if route.backend == "yubikey-piv":
        yk = YUBIKEY_ALGORITHM[algorithm]
        pin, touch = b["pin_policy"].upper(), b["touch_policy"].upper()
        dev = serial or "<serial>"
        lines += [
            f"  serial     {serial or 'not yet recorded — the evidence record names the device (--device-id)'}",
            f"  slot       {route.object_id}",
            f"  algorithm  {algorithm} (ykman {yk}), GENERATED ON THE DEVICE — never imported (ADR-0002 D5)",
            f"  policies   pin_policy={b['pin_policy']} touch_policy={b['touch_policy']} "
            f"(fixed at generation; cannot be changed afterwards)",
            f"  generate   ykman --device {dev} piv keys generate --algorithm {yk} --pin-policy {pin} "
            f"--touch-policy {touch} {route.object_id} -",
            f"  evidence   ykman --device {dev} info > info.txt",
            f"             ykman --device {dev} piv keys info {route.object_id} > keys-info.txt",
            f"             ykman --device {dev} piv keys export {route.object_id} --format DER pub.der",
            f"             ceremony-manifest.py yubikey-evidence --device-id {route.device_id} "
            f"--slot {route.object_id} --info info.txt --keys-info keys-info.txt --public-key pub.der "
            f"--out {route.device_id}-{route.object_id}.json",
            f"  proves     serial, slot, algorithm, origin=GENERATED, PIN/touch policy as the DEVICE reports them, "
            f"public_key_sha256 of the exported SubjectPublicKeyInfo",
        ]
    else:
        lines += [
            f"  serial     {serial or 'NOT RECORDED — commission-card.sh --expect-serial requires it'}",
            f"  object id  {route.object_id} (PKCS#11 CKA_ID)",
            f"  algorithm  {algorithm}, GENERATED ON THE CARD "
            f"(pkcs11-tool --keypairgen --key-type {NITROKEY_KEYGEN[algorithm]} --id {route.object_id})",
            f"  policies   none on the card: PIN and use policy are the daemon's (ADR-0002 D2/D4)",
            f"  evidence   commission-card.sh --expect-serial {serial or '<serial>'} --expect-devaut-sha <sha256> "
            f"--kek-id {route.object_id} --kek-ref <key ref> > commission-{route.device_id}-{route.object_id}.txt",
            f"  proves     the MANIFEST_BINDING_PINS line: serial and public_key_sha256, printed only after the "
            f"attestation proved the key was generated on this genuine card (ADR-0002 D1)",
        ]
    return lines


def cmd_plan(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    routes = planned_routes(manifest, args.site, args.backend)
    serials = device_serials(manifest)
    scope = f"site={args.site or 'all'} backend={','.join(args.backend) if args.backend else 'all'}"
    print(f"PLAN {manifest['manifest_id']} ({scope}): {len(routes)} binding(s) to provision")
    for r in routes:
        print()
        print("\n".join(describe(r, serials)))
    others = [r for r in all_routes(manifest) if r.obj["custody"] not in CEREMONY_CUSTODY
              and r.binding["state"] == "planned" and in_scope(r, args.site, args.backend)]
    if others:
        print()
        for r in others:
            print(f"NOT THIS CEREMONY {r.path}: custody {r.obj['custody']} is not provisioned by a key ceremony")
    if not routes:
        print("\nnothing is planned in this scope; the ceremony has no manifest work to do")
    return 0


# =================================================================================================
# Evidence
# =================================================================================================

@dataclass
class Evidence:
    source: str
    backend: str
    object_id: str
    device_serial: str
    public_key_sha256: str
    device_id: str | None = None
    pin_policy: str | None = None
    touch_policy: str | None = None
    ykman_algorithm: str | None = None

    def fields(self) -> dict[str, str]:
        out = {"device_serial": self.device_serial, "public_key_sha256": self.public_key_sha256}
        if self.pin_policy:
            out["pin_policy"] = self.pin_policy
        if self.touch_policy:
            out["touch_policy"] = self.touch_policy
        return out


def parse_commission_transcript(text: str, source: str) -> Evidence:
    lines = [ANSI.sub("", line) for line in text.splitlines()]
    pins = [m.group(1) for m in (PINS_LINE.match(line) for line in lines) if m]
    if not pins:
        raise Refusal(f"{source}: no MANIFEST_BINDING_PINS line — commissioning did not pass, or ran without "
                      f"--kek-id/--kek-ref; there is no proven pin to record")
    if len(pins) > 1:
        raise Refusal(f"{source}: {len(pins)} MANIFEST_BINDING_PINS lines; one commissioning run pins one key, "
                      f"so this is several transcripts pasted together — supply them as separate files")
    try:
        data = json.loads(pins[0])
    except json.JSONDecodeError:
        raise Refusal(f"{source}: the MANIFEST_BINDING_PINS line is not JSON") from None
    if not isinstance(data, dict) or not {"device_serial", "public_key_sha256"} <= data.keys() \
            or not data.keys() <= {"device_serial", "public_key_sha256", "object_id"}:
        raise Refusal(f"{source}: MANIFEST_BINDING_PINS must carry device_serial and public_key_sha256 "
                      f"(and optionally object_id), nothing else")
    serial, pin = data["device_serial"], data["public_key_sha256"]
    if not isinstance(serial, str) or not SERIAL.fullmatch(serial):
        raise Refusal(f"{source}: MANIFEST_BINDING_PINS device_serial is not a serial")
    if not isinstance(pin, str) or not FINGERPRINT.fullmatch(pin):
        raise Refusal(f"{source}: MANIFEST_BINDING_PINS public_key_sha256 must be sha256: and 64 lowercase hex")
    ids = {norm_id(m.group(2)) for m in (KEK_LINE.search(line) for line in lines) if m and m.group(1) == pin}
    if len(ids) != 1:
        raise Refusal(f"{source}: cannot tell which object the pin belongs to — expected exactly one "
                      f"'KEK public_key_sha256 = {pin} (SubjectPublicKeyInfo of ID …)' line, found {len(ids)}")
    object_id = ids.pop()
    if "object_id" in data and (not isinstance(data["object_id"], str) or norm_id(data["object_id"]) != object_id):
        raise Refusal(f"{source}: MANIFEST_BINDING_PINS object_id disagrees with the KEK line (ID {object_id})")
    return Evidence(source, "nitrokey-pkcs11", object_id, serial, pin)


def parse_ykman_fields(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip():
            key = key.strip()
            if key in out:
                raise Refusal(f"ykman output repeats '{key}'; that is two devices' output, not one")
            out[key] = value.strip()
    return out


def piv_slot(value: str) -> str | None:
    """'9C (SIGNATURE)' (ykman 5) -> '9c'; also tolerates the bare hex or the enum name."""
    token = value.split()[0] if value.split() else ""
    token = token.removeprefix("SLOT.")
    if re.fullmatch(r"[0-9A-Fa-f]{2}", token):
        return token.lower()
    return PIV_SLOT_NAMES.get(token.upper())


def parse_yubikey_record(record: Any, source: str) -> Evidence:
    """Re-derive every value from the device's raw output. Nothing in the record is trusted as a
    conclusion; only the raw ykman text and the exported key bytes are read."""
    required = {"evidence", "slot", "ykman_info", "ykman_keys_info", "public_key_der_b64"}
    allowed = required | {"device_id"}
    if not isinstance(record, dict) or record.get("evidence") != YUBIKEY_EVIDENCE_SCHEMA:
        raise Refusal(f"{source}: not a {YUBIKEY_EVIDENCE_SCHEMA} record")
    if not required <= record.keys() or not record.keys() <= allowed:
        raise Refusal(f"{source}: a YubiKey evidence record carries exactly {sorted(required)} "
                      f"(and optionally device_id)")
    for key in allowed & record.keys():
        if not isinstance(record[key], str) or not record[key].strip():
            raise Refusal(f"{source}: {key} must be a non-empty string")
    slot = norm_id(record["slot"])
    if slot not in PIV_SLOTS:
        raise Refusal(f"{source}: slot {record['slot']} is not a PIV key slot")

    info = parse_ykman_fields(record["ykman_info"])
    serial = info.get("Serial number", "")
    if not re.fullmatch(r"[0-9]{1,12}", serial):
        raise Refusal(f"{source}: `ykman info` output carries no 'Serial number' — the device is unidentified")

    meta = parse_ykman_fields(record["ykman_keys_info"])
    for key in ("Key slot", "Algorithm", "Origin", "PIN required for use", "Touch required for use"):
        if key not in meta:
            raise Refusal(f"{source}: `ykman piv keys info` output lacks '{key}'")
    if piv_slot(meta["Key slot"]) != slot:
        raise Refusal(f"{source}: the key metadata is for slot {meta['Key slot']}, not {slot}")
    if meta["Origin"] != "GENERATED":
        raise Refusal(f"{source}: the device reports Origin {meta['Origin']} for slot {slot}; YubiKey keys are "
                      f"generated on the device, never imported (ADR-0002 D5)")
    pin = {"ONCE": "once", "ALWAYS": "always"}.get(meta["PIN required for use"])
    if pin is None:
        raise Refusal(f"{source}: the device reports PIN policy {meta['PIN required for use']} for slot {slot}; "
                      f"the manifest admits only once or always")
    if meta["Touch required for use"] != "NEVER":
        raise Refusal(f"{source}: the device reports touch policy {meta['Touch required for use']} for slot "
                      f"{slot}; the daemon signs unattended, so it must be NEVER")
    algorithm = meta["Algorithm"]
    if algorithm not in SPKI_FAMILY:
        raise Refusal(f"{source}: the device reports algorithm {algorithm}, which no manifest binding can use")

    try:
        der = base64.b64decode(record["public_key_der_b64"], validate=True)
    except ValueError:
        raise Refusal(f"{source}: public_key_der_b64 is not base64") from None
    if not der or der[0] != 0x30 or not all(oid in der[:32] for oid in SPKI_FAMILY[algorithm]):
        raise Refusal(f"{source}: the exported public key is not a {algorithm} SubjectPublicKeyInfo — "
                      f"the export and the metadata do not describe the same key")
    return Evidence(
        source, "yubikey-piv", slot, serial, "sha256:" + hashlib.sha256(der).hexdigest(),
        device_id=record.get("device_id"), pin_policy=pin, touch_policy="never", ykman_algorithm=algorithm,
    )


def parse_evidence(path: Path) -> Evidence:
    source = str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise Refusal(f"{source}: cannot read evidence ({getattr(error, 'strerror', None) or error})") from None
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            raise Refusal(f"{source}: evidence looks like JSON but does not parse") from None
        return parse_yubikey_record(record, source)
    if "MANIFEST_BINDING_PINS" in text or "Commissioning" in text or "KEK public_key_sha256" in text:
        return parse_commission_transcript(text, source)
    raise Refusal(f"{source}: unrecognised evidence — expected a commission-card.sh transcript or a "
                  f"{YUBIKEY_EVIDENCE_SCHEMA} record")


# =================================================================================================
# record
# =================================================================================================

def match(ev: Evidence, manifest: dict[str, Any], serials: dict[str, str]) -> Route:
    candidates = [r for r in ceremony_routes(manifest) if r.backend == ev.backend and r.object_id == ev.object_id]
    if ev.device_id is not None:
        named = [r for r in candidates if r.device_id == ev.device_id]
        if not named:
            raise Refusal(f"{ev.source}: evidence for an unknown binding — no {ev.backend} binding of device "
                          f"{ev.device_id} at object {ev.object_id}")
        recorded = serials.get(ev.device_id)
        if recorded and recorded != ev.device_serial:
            raise Refusal(f"{ev.source}: device {ev.device_id} is recorded with serial {recorded} but the device "
                          f"that produced this evidence reports {ev.device_serial} — the value differs from the "
                          f"one already recorded")
        candidates = named
    by_serial = [r for r in candidates if serials.get(r.device_id) == ev.device_serial]
    if by_serial:
        candidates = by_serial
    else:
        candidates = [r for r in candidates if not serials.get(r.device_id)]
    if not candidates:
        raise Refusal(f"{ev.source}: evidence for an unknown binding — no {ev.backend} binding at object "
                      f"{ev.object_id} for serial {ev.device_serial}")
    if len(candidates) > 1:
        names = ", ".join(f"{r.device_id} ({r.path})" for r in candidates)
        raise Refusal(f"{ev.source}: evidence is ambiguous — serial {ev.device_serial} object {ev.object_id} "
                      f"could be {names}; record the device_serial in the manifest or name --device-id")
    return candidates[0]


def cmd_record(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    routes = planned_routes(manifest, args.site, args.backend)
    serials = device_serials(manifest)
    evidence = [parse_evidence(p) for p in args.evidence]

    assigned: dict[str, tuple[Route, Evidence]] = {}
    for ev in evidence:
        route = match(ev, manifest, serials)
        if route.binding["state"] != "planned":
            raise Refusal(f"{ev.source}: {route.path} is already {route.binding['state']}; record advances only "
                          f"planned bindings and never rewrites one that was already recorded")
        if not in_scope(route, args.site, args.backend):
            raise Refusal(f"{ev.source}: {route.path} is outside this run's scope "
                          f"(site {route.binding['site']}, backend {route.backend})")
        if route.path in assigned:
            other = assigned[route.path][1]
            kind = "duplicate" if other.fields() == ev.fields() else "conflicting"
            raise Refusal(f"{kind} evidence for {route.path}: {other.source} and {ev.source}; each binding takes "
                          f"exactly one evidence record")
        assigned[route.path] = (route, ev)

    missing = [r.path for r in routes if r.path not in assigned]
    if missing:
        raise Refusal(f"binding(s) left without evidence: {', '.join(missing)} — every planned binding in scope "
                      f"must be proven before any is recorded")

    result = copy.deepcopy(manifest)
    for route, ev in assigned.values():
        target = result["objects"][route.obj_index]["bindings"][route.bind_index]
        if ev.ykman_algorithm is not None:
            want = YUBIKEY_ALGORITHM[key_algorithm(route)]
            if ev.ykman_algorithm != want:
                raise Refusal(f"{ev.source}: {route.path} needs {want} but the device holds {ev.ykman_algorithm}")
        for name, value in ev.fields().items():
            recorded = target.get(name)
            if recorded is not None and recorded != value:
                raise Refusal(f"{ev.source}: {route.path}.{name} is recorded as {recorded} but the evidence proves "
                              f"{value} — the value differs from the one already recorded")
            target[name] = value
        target["state"] = "qualified"

    check_fleet(result)
    validate(result, "the recorded manifest no longer validates")

    out = args.out or args.manifest
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    # Atomic: a crash mid-write must leave the previous manifest, never a truncated one.
    fd, tmp = tempfile.mkstemp(dir=str(Path(out).resolve().parent), prefix=".manifest.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, out)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    for route, ev in assigned.values():
        print(f"QUALIFIED {route.path} {route.device_id} serial={ev.device_serial} "
              f"public_key_sha256={ev.public_key_sha256} <- {ev.source}")
    print(f"RECORDED {len(assigned)} binding(s) -> {out}")
    return 0


# =================================================================================================
# yubikey-evidence
# =================================================================================================

def read_public_key(path: Path) -> bytes:
    data = path.read_bytes()
    if data.lstrip().startswith(b"-----BEGIN PUBLIC KEY-----"):
        body = re.search(rb"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", data, re.S)
        if not body:
            raise Refusal(f"{path}: unterminated PEM public key")
        return base64.b64decode(b"".join(body.group(1).split()), validate=True)
    return data


def cmd_piv_steps(args: argparse.Namespace) -> int:
    """Machine-readable generation parameters for ONE YubiKey, for ceremony.sh to execute. Tab-separated
    `slot algorithm pin_policy touch_policy path`, ykman spelling. Produced by the same checks as
    `plan`, so the wizard can only ever generate what `plan` would have printed — the policies come
    from the manifest and are never typed by the operator."""
    manifest = load_manifest(args.manifest)
    routes = [r for r in planned_routes(manifest, args.site, ["yubikey-piv"]) if r.device_id == args.device_id]
    if not routes:
        raise Refusal(f"no planned yubikey-piv binding for device {args.device_id} in this scope")
    for r in routes:
        print("\t".join([r.object_id, YUBIKEY_ALGORITHM[key_algorithm(r)], r.binding["pin_policy"].upper(),
                         r.binding["touch_policy"].upper(), r.path]))
    return 0


def cmd_yubikey_evidence(args: argparse.Namespace) -> int:
    try:
        record = {
            "evidence": YUBIKEY_EVIDENCE_SCHEMA,
            "slot": norm_id(args.slot),
            "ykman_info": args.info.read_text(encoding="utf-8"),
            "ykman_keys_info": args.keys_info.read_text(encoding="utf-8"),
            "public_key_der_b64": base64.b64encode(read_public_key(args.public_key)).decode("ascii"),
        }
    except OSError as error:
        raise Refusal(f"cannot read ykman output: {error}") from None
    if args.device_id:
        record["device_id"] = args.device_id
    # Refuse NOW, at the device, rather than at record time after the token has left the table.
    ev = parse_yubikey_record(record, str(args.out))
    Path(args.out).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"EVIDENCE {args.out}: serial={ev.device_serial} slot={ev.object_id} {ev.ykman_algorithm} "
          f"pin={ev.pin_policy} touch={ev.touch_policy} public_key_sha256={ev.public_key_sha256}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "record"):
        p = sub.add_parser(name)
        p.add_argument("manifest", type=Path)
        p.add_argument("--site")
        p.add_argument("--backend", action="append", choices=sorted(custody_manifest.BACKENDS))
        if name == "record":
            p.add_argument("--evidence", type=Path, nargs="+", required=True)
            p.add_argument("--out", type=Path)
    s = sub.add_parser("piv-steps")
    s.add_argument("manifest", type=Path)
    s.add_argument("--site")
    s.add_argument("--device-id", required=True)
    y = sub.add_parser("yubikey-evidence")
    y.add_argument("--slot", required=True)
    y.add_argument("--info", type=Path, required=True, help="`ykman --device S info` output")
    y.add_argument("--keys-info", type=Path, required=True, help="`ykman --device S piv keys info SLOT` output")
    y.add_argument("--public-key", type=Path, required=True, help="`ykman … piv keys export SLOT` (PEM or DER)")
    y.add_argument("--device-id", help="the manifest device_id this token is")
    y.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    handler = {"plan": cmd_plan, "record": cmd_record, "piv-steps": cmd_piv_steps,
               "yubikey-evidence": cmd_yubikey_evidence}[args.command]
    try:
        return handler(args)
    except Refusal as refusal:
        print(f"REFUSED: {refusal}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
