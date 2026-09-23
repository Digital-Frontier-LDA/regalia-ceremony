#!/usr/bin/env python3
"""test_ceremony_manifest.py — the manifest-driven ceremony (regalia#28), with no hardware.

What is proven here:
  * the vendored regalia-kms validator, capability table and schema are byte-identical to the pinned
    copies (and, when REGALIA_KMS_DIR names a checkout, to upstream) — the drift tripwire;
  * `plan` on a mixed fleet (one Nitrokey, two YubiKeys) prints each concrete provisioning step;
  * `plan` refuses each thing the ceremony cannot honour, BY MESSAGE;
  * `record` round-trips: commission-card.sh transcript + two YubiKey evidence records in, a manifest
    out whose three bindings are qualified with the device-reported values, and which the regalia-kms
    validator accepts;
  * `record` refuses unknown, missing, duplicate, conflicting, already-recorded and differing evidence
    and a result that no longer validates — BY MESSAGE, and with the output file never written.

Every refusal asserts its message, not just a non-zero exit. A refusal that fires for the wrong
reason passes an exit-code test while the guard it was meant to prove is broken.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPTS = HERE.parent.parent / "scripts"
SCRIPT = SCRIPTS / "ceremony-manifest.py"
VENDOR = SCRIPTS / "vendor" / "regalia_kms"

NK_SERIAL = "DENK0404144"
YK_A, YK_B = "36345471", "25923905"
PIN_NK = "sha256:" + "1" * 64


def spki(curve: str = "prime256v1") -> bytes:
    """A real SubjectPublicKeyInfo from openssl, so the OID checks see what ykman would export."""
    key = subprocess.run(["openssl", "ecparam", "-genkey", "-name", curve, "-noout"],
                         check=True, capture_output=True).stdout
    return subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=key,
                          check=True, capture_output=True).stdout


def load_tool():
    """Import the hyphenated script in-process. Registered in sys.modules first: its dataclasses look
    their module up by name while the class is being built."""
    spec = importlib.util.spec_from_file_location("ceremony_manifest_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def binding(site, backend, device, object_id, **extra):
    b = {"site": site, "backend": backend, "device_id": device, "object_id": object_id,
         "public_fingerprint": "sha256:" + "b" * 64, "state": "planned"}
    b.update(extra)
    return b


def fleet_manifest() -> dict:
    """One object held by a Nitrokey and two YubiKeys at two sites, plus a FIDO object the ceremony
    must leave alone."""
    common = {
        "classification": "restricted", "environment": "production", "owner": "release-engineering",
        "recovery": {"mode": "shamir-4-of-6", "authority_id": "company-root-2026", "minimum_replicas": 2,
                     "status": "planned"},
        "rotation": {"maximum_age_days": 365, "last_rotated": None},
        "migration": {"status": "planned", "source": "organization:release-pipelines"},
        "verification": {"status": "planned", "last_verified": None, "evidence": "regalia#28"},
    }
    signer = dict(common, id="release-signing-key", name="Release signing key", kind="asymmetric-key",
                  purpose="release-artifact", custody="direct-hardware", algorithm="p256", operations=["sign"],
                  policy_id="release-signing", bindings=[
                      binding("sitea", "nitrokey-pkcs11", "nitrokey-sitea", "0a", device_serial=NK_SERIAL),
                      binding("sitea", "yubikey-piv", "yubikey-sitea", "9c", pin_policy="once", touch_policy="never"),
                      binding("siteb", "yubikey-piv", "yubikey-siteb", "9c", pin_policy="always", touch_policy="never"),
                  ])
    fido = dict(common, id="github-org-admin-fido", name="GitHub admin", kind="fido-credential",
                purpose="github-admin-login", custody="fido-multi-enrollment", algorithm="device-managed",
                operations=["authenticate"], policy_id="github-org-admin",
                recovery={"mode": "multi-enrollment", "minimum_replicas": 2, "status": "planned"}, bindings=[
                    binding("custodian-a", "fido2", "fido-admin-a", "enrollment-a"),
                    binding("custodian-b", "fido2", "fido-admin-b", "enrollment-b"),
                ])
    return {"schema_version": 1, "manifest_id": "regalia-test-fleet", "generated_at": "2026-09-23T00:00:00Z",
            "objects": [signer, fido]}


def commission_transcript(serial=NK_SERIAL, pin=PIN_NK, kek_id="0A", pins_line=True) -> str:
    """The tail commission-card.sh --kek-id/--kek-ref prints on a pass, colours included."""
    lines = [
        "\n\x1b[1m### KEK provenance (ADR-0002 D1)\x1b[0m",
        f"  \x1b[32mPASS\x1b[0m EF CE01 is signed by this device and attests the key at ID {kek_id} — generated on this card",
        f"  \x1b[32mPASS\x1b[0m KEK public_key_sha256 = {pin} (SubjectPublicKeyInfo of ID {kek_id})",
        "\n\x1b[1m### RESULT\x1b[0m", "  9 passed, 0 failed",
        "\n  Commissioning PASSED. Record the serial, CHR and counter baseline in the fleet log.",
    ]
    if pins_line:
        lines += ["\n  Custody manifest binding pins for the KEK (ADR-0002 D1) — copy this line:",
                  f'MANIFEST_BINDING_PINS {{"device_serial":"{serial}","public_key_sha256":"{pin}"}}']
    return "\n".join(lines) + "\n"


def keys_info(slot="9C (SIGNATURE)", algorithm="ECCP256", origin="GENERATED", pin="ONCE", touch="NEVER") -> str:
    # The exact layout ykman 5.6 prints (ykman._cli.util.pretty_print).
    return (f"Key slot:               {slot}\nAlgorithm:              {algorithm}\nOrigin:                 {origin}\n"
            f"PIN required for use:   {pin}\nTouch required for use: {touch}\n")


def yubikey_record(serial, der, device_id=None, slot="9c", **info) -> dict:
    record = {
        "evidence": "regalia.yubikey-piv-evidence/v1", "slot": slot,
        "ykman_info": f"Device type: YubiKey 5 NFC\nSerial number: {serial}\nFirmware version: 5.7.1\n",
        "ykman_keys_info": keys_info(**info),
        "public_key_der_b64": base64.b64encode(der).decode(),
    }
    if device_id:
        record["device_id"] = device_id
    return record


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.manifest = self.dir / "manifest.json"
        self.write_manifest(fleet_manifest())
        self.der_a, self.der_b = spki(), spki()

    def write_manifest(self, manifest):
        self.manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def file(self, name, content):
        path = self.dir / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return path

    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)

    def standard_evidence(self):
        return [
            self.file("nk.txt", commission_transcript()),
            self.file("yka.json", yubikey_record(YK_A, self.der_a, "yubikey-sitea")),
            self.file("ykb.json", yubikey_record(YK_B, self.der_b, "yubikey-siteb", pin="ALWAYS")),
        ]

    def refuses(self, result, *fragments):
        self.assertNotEqual(result.returncode, 0, f"expected a refusal, got success:\n{result.stdout}")
        self.assertIn("REFUSED:", result.stderr)
        for fragment in fragments:
            self.assertIn(fragment, result.stderr)

    def record_refuses(self, evidence, *fragments, manifest=None, extra=()):
        if manifest is not None:
            self.write_manifest(manifest)
        before = self.manifest.read_bytes()
        out = self.dir / "out.json"
        result = self.run_tool("record", self.manifest, "--evidence", *evidence, "--out", out, *extra)
        self.refuses(result, *fragments)
        self.assertFalse(out.exists(), "a refused record wrote its output anyway")
        self.assertEqual(self.manifest.read_bytes(), before, "a refused record touched the input manifest")


class VendoredContract(unittest.TestCase):
    """The drift tripwire. The ceremony validates with regalia-kms's own code; if the copy here stops
    being that code, the ceremony can write manifests the daemon refuses."""

    def test_vendored_files_match_their_pins(self):
        pins = json.loads((VENDOR / "PINS.json").read_text(encoding="utf-8"))
        self.assertEqual(set(pins["files"]), {"tools/custody_manifest.py", "config/backend-capabilities.json",
                                              "config/custody-manifest.schema.json"})
        for rel, want in pins["files"].items():
            got = "sha256:" + hashlib.sha256((VENDOR / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"vendored {rel} drifted from its recorded sha256 — re-vendor from "
                                        f"regalia-kms and update PINS.json, never edit the copy")

    def test_vendored_files_match_upstream_when_available(self):
        upstream = os.environ.get("REGALIA_KMS_DIR")
        if not upstream:
            self.skipTest("REGALIA_KMS_DIR not set; upstream comparison needs a regalia-kms checkout")
        pins = json.loads((VENDOR / "PINS.json").read_text(encoding="utf-8"))
        for rel, want in pins["files"].items():
            got = "sha256:" + hashlib.sha256((pathlib.Path(upstream) / rel).read_bytes()).hexdigest()
            self.assertEqual(got, want, f"regalia-kms {rel} has moved on from the vendored copy")

    def test_the_tool_validates_with_the_vendored_copy(self):
        module = load_tool()
        self.assertEqual(pathlib.Path(module.custody_manifest.__file__).resolve(),
                         (VENDOR / "tools" / "custody_manifest.py").resolve())


class Plan(Case):
    def test_mixed_fleet_plan_names_every_step(self):
        result = self.run_tool("plan", self.manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        self.assertIn("3 binding(s) to provision", out)
        self.assertIn(f"commission-card.sh --expect-serial {NK_SERIAL} --expect-devaut-sha <sha256> --kek-id 0a", out)
        self.assertIn("pkcs11-tool --keypairgen --key-type EC:prime256v1 --id 0a", out)
        self.assertIn("piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy NEVER 9c", out)
        self.assertIn("piv keys generate --algorithm ECCP256 --pin-policy ALWAYS --touch-policy NEVER 9c", out)
        self.assertIn("yubikey-evidence --device-id yubikey-siteb --slot 9c", out)
        self.assertIn("never imported (ADR-0002 D5)", out)
        self.assertIn("NOT THIS CEREMONY objects[1](github-org-admin-fido).bindings[0]", out)

    def test_site_filter(self):
        result = self.run_tool("plan", self.manifest, "--site", "siteb")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 binding(s) to provision", result.stdout)
        self.assertIn("yubikey-siteb", result.stdout)
        self.assertNotIn("nitrokey-sitea", result.stdout)

    def test_refuses_an_invalid_manifest(self):
        m = fleet_manifest()
        del m["objects"][0]["policy_id"]
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "manifest does not validate", "policy_id")

    def test_refuses_yubikey_touch_other_than_never(self):
        m = fleet_manifest()
        m["objects"][0]["bindings"][1]["touch_policy"] = "always"
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "touch_policy=never")

    def test_refuses_a_yubikey_import(self):
        m = fleet_manifest()
        m["objects"][0]["bindings"][2]["public_key_sha256"] = "sha256:" + "c" * 64
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "that is an import", "never imported (ADR-0002 D5)")

    def test_refuses_a_seed_on_a_yubikey(self):
        m = fleet_manifest()
        m["objects"][0]["kind"] = "seed"
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "a seed reaches a YubiKey only by import")

    def test_refuses_an_aes_key_with_public_key_sha256(self):
        m = fleet_manifest()
        aes = copy.deepcopy(m["objects"][0])
        aes.update(id="storage-wrap-key", kind="symmetric-key", algorithm="aes-256", operations=["unwrap"],
                   bindings=[binding("sitea", "nitrokey-pkcs11", "nitrokey-sitea", "30", state="qualified",
                                     device_serial=NK_SERIAL, public_key_sha256="sha256:" + "d" * 64),
                             binding("siteb", "nitrokey-pkcs11", "nitrokey-siteb", "30", state="retired")])
        m["objects"].append(aes)
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "aes-256 is a symmetric key and has no public key")

    def test_refuses_a_planned_symmetric_key(self):
        m = fleet_manifest()
        aes = copy.deepcopy(m["objects"][0])
        aes.update(id="storage-wrap-key", kind="symmetric-key", algorithm="aes-256", operations=["unwrap"],
                   bindings=[binding("sitea", "nitrokey-pkcs11", "nitrokey-sitea", "30", device_serial=NK_SERIAL),
                             binding("siteb", "nitrokey-pkcs11", "nitrokey-siteb", "30")])
        m["objects"].append(aes)
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "is symmetric", "no route that can qualify it")

    def test_refuses_openpgp(self):
        m = fleet_manifest()
        m["objects"][0]["algorithm"] = "rsa2048"
        m["objects"][0]["bindings"][1].update(backend="yubikey-openpgp", object_id="sig")
        m["objects"][0]["bindings"][2]["object_id"] = "9a"
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "yubikey-openpgp has no provisioning route")

    def test_refuses_a_slot_that_is_not_a_piv_key_slot(self):
        m = fleet_manifest()
        m["objects"][0]["bindings"][1]["object_id"] = "f9"
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "object_id f9 is not a PIV key slot")

    def test_refuses_indistinguishable_nitrokeys(self):
        m = fleet_manifest()
        del m["objects"][0]["bindings"][0]["device_serial"]
        m["objects"][0]["bindings"].append(binding("siteb", "nitrokey-pkcs11", "nitrokey-siteb", "0a"))
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "record cannot tell them apart")

    def test_refuses_one_device_with_two_serials(self):
        m = fleet_manifest()
        m["objects"][0]["bindings"][1]["device_serial"] = YK_A
        other = copy.deepcopy(m["objects"][0])
        other.update(id="second-signer", bindings=[
            binding("sitea", "yubikey-piv", "yubikey-sitea", "9a", pin_policy="once", touch_policy="never",
                    device_serial=YK_B),
            binding("siteb", "yubikey-piv", "yubikey-siteb", "9a", pin_policy="once", touch_policy="never")])
        m["objects"].append(other)
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "is recorded with two serials")

    def test_the_ceremony_refuses_touch_even_if_the_validator_did_not(self):
        """The same rule as the vendored validator's, held independently: the validator guards the
        manifest FORMAT, this guards what the ceremony will generate. Through the CLI the validator
        always refuses first, so this is proven in-process on a binding that bypassed it."""
        module = load_tool()
        m = fleet_manifest()
        for touch, pin, why in (("cached", "once", "touch_policy must be never"),
                                ("never", "never", "pin_policy must be once or always")):
            b = dict(m["objects"][0]["bindings"][1], touch_policy=touch, pin_policy=pin)
            with self.assertRaises(module.Refusal) as caught:
                module.check_route(module.Route(0, 1, m["objects"][0], b))
            self.assertIn(why, str(caught.exception))

    def test_refuses_one_slot_bound_twice(self):
        m = fleet_manifest()
        other = copy.deepcopy(m["objects"][0])
        other["id"] = "second-signer"
        m["objects"].append(other)
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "one slot holds one key")


class Record(Case):
    def test_round_trip_on_a_mixed_fleet(self):
        out = self.dir / "qualified.json"
        result = self.run_tool("record", self.manifest, "--evidence", *self.standard_evidence(), "--out", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RECORDED 3 binding(s)", result.stdout)
        got = json.loads(out.read_text(encoding="utf-8"))
        nk, yka, ykb = got["objects"][0]["bindings"]
        self.assertEqual((nk["state"], nk["device_serial"], nk["public_key_sha256"]), ("qualified", NK_SERIAL, PIN_NK))
        self.assertEqual((yka["state"], yka["device_serial"]), ("qualified", YK_A))
        self.assertEqual(yka["public_key_sha256"], "sha256:" + hashlib.sha256(self.der_a).hexdigest())
        self.assertEqual((yka["pin_policy"], yka["touch_policy"]), ("once", "never"))
        self.assertEqual((ykb["device_serial"], ykb["pin_policy"]), (YK_B, "always"))
        self.assertEqual(ykb["public_key_sha256"], "sha256:" + hashlib.sha256(self.der_b).hexdigest())
        self.assertEqual([b["state"] for b in got["objects"][1]["bindings"]], ["planned", "planned"],
                         "the FIDO object is not the ceremony's and must be left alone")
        # The output is a manifest regalia-kms accepts, and a plan over it has nothing left to do.
        again = self.run_tool("plan", out)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("0 binding(s) to provision", again.stdout)
        # ...and recording the same evidence again is refused, not silently re-applied.
        self.refuses(self.run_tool("record", out, "--evidence", self.standard_evidence()[0], "--site", "sitea",
                                   "--backend", "nitrokey-pkcs11"), "is already qualified")

    def test_in_place_by_default(self):
        result = self.run_tool("record", self.manifest, "--evidence", *self.standard_evidence())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.manifest.read_text())["objects"][0]["bindings"][0]["state"], "qualified")

    def test_scope_limits_what_must_be_proven(self):
        nk = self.standard_evidence()[0]
        out = self.dir / "out.json"
        result = self.run_tool("record", self.manifest, "--evidence", nk, "--backend", "nitrokey-pkcs11", "--out", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        states = [b["state"] for b in json.loads(out.read_text())["objects"][0]["bindings"]]
        self.assertEqual(states, ["qualified", "planned", "planned"])

    def test_yubikey_record_produced_by_the_tool_round_trips(self):
        (self.dir / "info.txt").write_text(f"Device type: YubiKey 5 NFC\nSerial number: {YK_A}\n")
        (self.dir / "keys.txt").write_text(keys_info())
        pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(self.der_a) + b"-----END PUBLIC KEY-----\n"
        (self.dir / "pub.pem").write_bytes(pem)
        out = self.dir / "made.json"
        result = self.run_tool("yubikey-evidence", "--device-id", "yubikey-sitea", "--slot", "9C",
                               "--info", self.dir / "info.txt", "--keys-info", self.dir / "keys.txt",
                               "--public-key", self.dir / "pub.pem", "--out", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(out.read_text())["public_key_der_b64"], base64.b64encode(self.der_a).decode())
        ev = self.standard_evidence()
        result = self.run_tool("record", self.manifest, "--evidence", ev[0], out, ev[2], "--out", self.dir / "o.json")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_yubikey_evidence_refuses_an_imported_key_at_the_device(self):
        (self.dir / "info.txt").write_text(f"Serial number: {YK_A}\n")
        (self.dir / "keys.txt").write_text(keys_info(origin="IMPORTED"))
        (self.dir / "pub.der").write_bytes(self.der_a)
        out = self.dir / "made.json"
        result = self.run_tool("yubikey-evidence", "--slot", "9c", "--info", self.dir / "info.txt",
                               "--keys-info", self.dir / "keys.txt", "--public-key", self.dir / "pub.der",
                               "--out", out)
        self.refuses(result, "reports Origin IMPORTED", "never imported (ADR-0002 D5)")
        self.assertFalse(out.exists())

    # ---- refusals -----------------------------------------------------------------------------------

    def test_refuses_evidence_for_an_unknown_binding(self):
        ev = self.standard_evidence()
        stray = self.file("stray.txt", commission_transcript(kek_id="0b", pin="sha256:" + "2" * 64))
        self.record_refuses([*ev, stray], "evidence for an unknown binding", "object 0b")

    def test_refuses_a_yubikey_named_for_an_unknown_device(self):
        ev = self.standard_evidence()
        ev[2] = self.file("ykb.json", yubikey_record(YK_B, self.der_b, "yubikey-sitec", pin="ALWAYS"))
        self.record_refuses(ev, "evidence for an unknown binding", "device yubikey-sitec")

    def test_refuses_a_binding_left_without_evidence(self):
        ev = self.standard_evidence()
        self.record_refuses(ev[:2], "left without evidence", "objects[0](release-signing-key).bindings[2]")

    def test_refuses_conflicting_evidence(self):
        ev = self.standard_evidence()
        other = self.file("ykb2.json", yubikey_record(YK_B, spki(), "yubikey-siteb", pin="ALWAYS"))
        self.record_refuses([*ev, other], "conflicting evidence for objects[0](release-signing-key).bindings[2]")

    def test_refuses_duplicate_evidence(self):
        ev = self.standard_evidence()
        again = self.file("nk-again.txt", commission_transcript())
        self.record_refuses([*ev, again], "duplicate evidence for objects[0](release-signing-key).bindings[0]")

    def test_refuses_ambiguous_yubikey_evidence(self):
        ev = self.standard_evidence()
        ev[1] = self.file("yka.json", yubikey_record(YK_A, self.der_a))  # no --device-id, no recorded serial
        self.record_refuses(ev, "evidence is ambiguous")

    def test_refuses_a_serial_that_differs_from_the_recorded_one(self):
        m = fleet_manifest()
        m["objects"][0]["bindings"][1]["device_serial"] = "11111111"
        ev = self.standard_evidence()
        self.record_refuses(ev, "recorded with serial 11111111", "differs from the one already recorded", manifest=m)

    def test_refuses_a_nitrokey_serial_that_differs_from_the_recorded_one(self):
        ev = self.standard_evidence()
        ev[0] = self.file("nk.txt", commission_transcript(serial="DENK0000001"))
        m = fleet_manifest()
        m["objects"][0]["bindings"].append(binding("siteb", "nitrokey-pkcs11", "nitrokey-siteb", "0b",
                                                   device_serial="DENK0000002"))
        self.record_refuses(ev, "evidence for an unknown binding", "serial DENK0000001", manifest=m)

    def test_refuses_a_pin_policy_that_differs_from_the_plan(self):
        ev = self.standard_evidence()
        ev[2] = self.file("ykb.json", yubikey_record(YK_B, self.der_b, "yubikey-siteb", pin="ONCE"))
        self.record_refuses(ev, "pin_policy is recorded as always but the evidence proves once")

    def test_refuses_a_device_reported_touch_policy(self):
        ev = self.standard_evidence()
        ev[1] = self.file("yka.json", yubikey_record(YK_A, self.der_a, "yubikey-sitea", touch="CACHED"))
        self.record_refuses(ev, "reports touch policy CACHED")

    def test_refuses_an_imported_yubikey_key(self):
        ev = self.standard_evidence()
        ev[1] = self.file("yka.json", yubikey_record(YK_A, self.der_a, "yubikey-sitea", origin="IMPORTED"))
        self.record_refuses(ev, "reports Origin IMPORTED")

    def test_refuses_the_wrong_algorithm(self):
        ev = self.standard_evidence()
        ev[1] = self.file("yka.json", yubikey_record(YK_A, spki("secp384r1"), "yubikey-sitea", algorithm="ECCP384"))
        self.record_refuses(ev, "needs ECCP256 but the device holds ECCP384")

    def test_refuses_an_export_that_is_not_the_reported_key_type(self):
        ev = self.standard_evidence()
        ev[1] = self.file("yka.json", yubikey_record(YK_A, spki("secp384r1"), "yubikey-sitea"))
        self.record_refuses(ev, "is not a ECCP256 SubjectPublicKeyInfo")

    def test_refuses_the_same_key_on_two_devices(self):
        ev = self.standard_evidence()
        ev[2] = self.file("ykb.json", yubikey_record(YK_B, self.der_a, "yubikey-siteb", pin="ALWAYS"))
        self.record_refuses(ev, "is also pinned on yubikey-sitea")

    def test_refuses_a_transcript_without_pins(self):
        ev = self.standard_evidence()
        ev[0] = self.file("nk.txt", commission_transcript(pins_line=False))
        self.record_refuses(ev, "no MANIFEST_BINDING_PINS line")

    def test_refuses_two_transcripts_pasted_together(self):
        ev = self.standard_evidence()
        ev[0] = self.file("nk.txt", commission_transcript() + commission_transcript())
        self.record_refuses(ev, "2 MANIFEST_BINDING_PINS lines")

    def test_refuses_a_pin_the_kek_line_does_not_carry(self):
        ev = self.standard_evidence()
        text = commission_transcript().replace(f"KEK public_key_sha256 = {PIN_NK}",
                                               "KEK public_key_sha256 = sha256:" + "3" * 64)
        ev[0] = self.file("nk.txt", text)
        self.record_refuses(ev, "cannot tell which object the pin belongs to")

    def test_refuses_evidence_for_an_already_recorded_binding(self):
        m = fleet_manifest()
        m["objects"][0]["bindings"][0].update(state="qualified", public_key_sha256=PIN_NK)
        self.record_refuses(self.standard_evidence(), "is already qualified", manifest=m)

    def test_refuses_evidence_outside_the_scope(self):
        # The siteb YubiKey's evidence, supplied to a --site sitea run.
        self.record_refuses(self.standard_evidence(), "outside this run's scope", "site siteb",
                            extra=("--site", "sitea"))

    def test_refuses_unrecognised_evidence(self):
        ev = self.standard_evidence()
        self.record_refuses([*ev, self.file("notes.txt", "the card looked fine\n")], "unrecognised evidence")

    def test_refuses_a_result_that_no_longer_validates(self):
        """No input reaches this today: every value record writes is shape-checked before it is written.
        The guard exists for the day the validator gains a rule the evidence does not know about, so it
        is proven by substituting a validator that accepts the input and refuses the result."""
        module = load_tool()
        real = module.custody_manifest.validate_manifest

        def strict(manifest):
            real(manifest)
            if any(b.get("state") == "qualified" for o in manifest["objects"] for b in o["bindings"]):
                raise module.custody_manifest.ManifestError("objects[0].bindings[0]: a rule the evidence cannot meet")
            return manifest

        module.custody_manifest.validate_manifest = strict
        out = self.dir / "out.json"
        stderr = self.dir / "stderr"
        saved = sys.stderr
        try:
            with open(stderr, "w", encoding="utf-8") as sys.stderr:
                rc = module.main(["record", str(self.manifest), "--evidence",
                                  *map(str, self.standard_evidence()), "--out", str(out)])
        finally:
            sys.stderr = saved
            module.custody_manifest.validate_manifest = real
        self.assertEqual(rc, 1)
        self.assertIn("the recorded manifest no longer validates", stderr.read_text())
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
