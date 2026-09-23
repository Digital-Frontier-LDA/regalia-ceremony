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
    and a result that no longer validates — BY MESSAGE, and with the output file never written;
  * the operation-behaviour control (regalia#28 criterion 3): a binding qualifies only with a proof that
    its key signed a fresh challenge, which `record` re-verifies itself — and a missing proof, a bad
    signature, a proof over a different key, a reused, empty or short challenge, a stray proof and an
    operation no signature can show are each refused by message.

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


def keypair(curve: str = "prime256v1") -> tuple[bytes, bytes]:
    """A real key from openssl: (private PEM, SubjectPublicKeyInfo DER). `curve` may also be rsa2048."""
    if curve.startswith("rsa"):
        key = subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{curve[3:]}"],
                             check=True, capture_output=True).stdout
    else:
        key = subprocess.run(["openssl", "ecparam", "-genkey", "-name", curve, "-noout"],
                             check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=key,
                         check=True, capture_output=True).stdout
    return key, der


def spki(curve: str = "prime256v1") -> bytes:
    """A real SubjectPublicKeyInfo from openssl, so the OID checks see what ykman would export."""
    return keypair(curve)[1]


def sign(key: bytes, data: bytes, digest: str = "sha256") -> bytes:
    """What the token does for the operation proof, done in software: a DER ECDSA / PKCS#1 v1.5 signature
    over `data` with `digest` — exactly the signature `openssl dgst -verify` accepts."""
    with tempfile.TemporaryDirectory() as work:
        path = pathlib.Path(work, "key.pem")
        path.write_bytes(key)
        return subprocess.run(["openssl", "dgst", f"-{digest}", "-sign", str(path)], input=data,
                              check=True, capture_output=True).stdout


def operation_proof(backend, serial, object_id, key, der, challenge=None, signature=None, device_id=None,
                    digest="sha256", **override) -> dict:
    """A regalia.operation-proof/v1 record, signed for real unless a test substitutes a part."""
    challenge = os.urandom(32) if challenge is None else challenge
    signature = sign(key, challenge, digest) if signature is None else signature
    record = {"evidence": "regalia.operation-proof/v1", "backend": backend, "device_serial": serial,
              "object_id": object_id, "operation": "sign",
              "challenge_b64": base64.b64encode(challenge).decode(),
              "signature_b64": base64.b64encode(signature).decode(),
              "public_key_der_b64": base64.b64encode(der).decode()}
    if device_id:
        record["device_id"] = device_id
    record.update(override)
    return record


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
        (self.key_nk, self.der_nk), (self.key_a, self.der_a), (self.key_b, self.der_b) = keypair(), keypair(), keypair()
        self.pin_nk = "sha256:" + hashlib.sha256(self.der_nk).hexdigest()

    def write_manifest(self, manifest):
        self.manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def file(self, name, content):
        path = self.dir / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return path

    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)

    def standard_evidence(self):
        """[0..2] the three bindings' device evidence, [3..5] their operation proofs, in the same order."""
        return [
            self.file("nk.txt", commission_transcript(pin=self.pin_nk)),
            self.file("yka.json", yubikey_record(YK_A, self.der_a, "yubikey-sitea")),
            self.file("ykb.json", yubikey_record(YK_B, self.der_b, "yubikey-siteb", pin="ALWAYS")),
            *self.standard_proofs(),
        ]

    def standard_proofs(self):
        return [
            self.file("op-nk.json", operation_proof("nitrokey-pkcs11", NK_SERIAL, "0a", self.key_nk, self.der_nk,
                                                    device_id="nitrokey-sitea")),
            self.file("op-yka.json", operation_proof("yubikey-piv", YK_A, "9c", self.key_a, self.der_a,
                                                     device_id="yubikey-sitea")),
            self.file("op-ykb.json", operation_proof("yubikey-piv", YK_B, "9c", self.key_b, self.der_b)),
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

    def test_a_yubikey_pair_may_declare_multi_enrollment_recovery(self):
        """ADR-0002 D5 made representable (regalia-kms#29): an object held ONLY on YubiKeys, generated
        on each device, recovers by multi-enrollment, not Shamir. Before that fix the vendored
        validator refused every such manifest, so the ceremony could not plan the D5 case at all."""
        m = fleet_manifest()
        signer = m["objects"][0]
        signer["bindings"] = [b for b in signer["bindings"] if b["backend"] == "yubikey-piv"]
        signer["recovery"] = {"mode": "multi-enrollment", "status": "planned"}
        self.write_manifest(m)
        result = self.run_tool("plan", self.manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 binding(s) to provision", result.stdout)
        self.assertIn("never imported (ADR-0002 D5)", result.stdout)

    def test_multi_enrollment_does_not_excuse_a_nitrokey_from_shamir(self):
        m = fleet_manifest()
        m["objects"][0]["recovery"] = {"mode": "multi-enrollment", "status": "planned"}
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "only for YubiKey PIV keys generated on the device")

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
        self.assertEqual((nk["state"], nk["device_serial"], nk["public_key_sha256"]), ("qualified", NK_SERIAL, self.pin_nk))
        self.assertEqual(result.stdout.count("OPERATION VERIFIED"), 3, "every binding must report its verified proof")
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
        ev = self.standard_evidence()
        out = self.dir / "out.json"
        result = self.run_tool("record", self.manifest, "--evidence", ev[0], ev[3], "--backend", "nitrokey-pkcs11",
                               "--out", out)
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
        result = self.run_tool("record", self.manifest, "--evidence", ev[0], out, ev[2], *ev[3:],
                               "--out", self.dir / "o.json")
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
        again = self.file("nk-again.txt", commission_transcript(pin=self.pin_nk))
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
        ev[0] = self.file("nk.txt", commission_transcript(serial="DENK0000001", pin=self.pin_nk))
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
        ev[0] = self.file("nk.txt", commission_transcript(pin=self.pin_nk, pins_line=False))
        self.record_refuses(ev, "no MANIFEST_BINDING_PINS line")

    def test_refuses_two_transcripts_pasted_together(self):
        ev = self.standard_evidence()
        ev[0] = self.file("nk.txt", commission_transcript(pin=self.pin_nk) + commission_transcript(pin=self.pin_nk))
        self.record_refuses(ev, "2 MANIFEST_BINDING_PINS lines")

    def test_refuses_a_pin_the_kek_line_does_not_carry(self):
        ev = self.standard_evidence()
        text = commission_transcript(pin=self.pin_nk).replace(f"KEK public_key_sha256 = {self.pin_nk}",
                                               "KEK public_key_sha256 = sha256:" + "3" * 64)
        ev[0] = self.file("nk.txt", text)
        self.record_refuses(ev, "cannot tell which object the pin belongs to")

    def test_refuses_evidence_for_an_already_recorded_binding(self):
        m = fleet_manifest()
        m["objects"][0]["bindings"][0].update(state="qualified", public_key_sha256=self.pin_nk)
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


class OperationBehaviour(Case):
    """regalia#28 criterion 3: a binding is qualified only when its key has been seen to sign a fresh
    challenge, and `record` re-verifies that signature itself against the key being pinned. Each refusal
    is asserted by message, with nothing written."""

    def proof_file(self, name, *args, **kwargs):
        return self.file(name, operation_proof(*args, **kwargs))

    def test_a_binding_without_a_proof_is_refused(self):
        ev = self.standard_evidence()
        del ev[4]
        self.record_refuses(ev, "no operation proof for objects[0](release-signing-key).bindings[1]",
                            "regalia#28 criterion 3")

    def test_a_signature_that_does_not_verify_is_refused(self):
        ev = self.standard_evidence()
        # Signed by another key, but presenting the right one: the proof claims yka's key.
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_b, self.der_a)
        self.record_refuses(ev, "op-yka.json: the operation proof's signature does not verify",
                            "objects[0](release-signing-key).bindings[1]")

    def test_a_signature_over_another_challenge_is_refused(self):
        ev = self.standard_evidence()
        sig = sign(self.key_nk, os.urandom(32))
        ev[3] = self.proof_file("op-nk.json", "nitrokey-pkcs11", NK_SERIAL, "0a", self.key_nk, self.der_nk,
                                signature=sig)
        self.record_refuses(ev, "op-nk.json: the operation proof's signature does not verify")

    def test_a_verdict_in_the_proof_is_not_trusted(self):
        """Even with a claimed verdict the record is refused, and a well-formed proof carrying a BAD signature
        cannot be rescued by adding one: the field itself is refused."""
        ev = self.standard_evidence()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_b, self.der_a, verified="true")
        self.record_refuses(ev, "in particular no verdict")

    def test_a_proof_over_a_different_key_is_refused(self):
        ev = self.standard_evidence()
        other_key, other_der = keypair()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", other_key, other_der)
        self.record_refuses(ev, "op-yka.json: the operation proof is over a different key",
                            "objects[0](release-signing-key).bindings[1] is being pinned to",
                            "sha256:" + hashlib.sha256(self.der_a).hexdigest())

    def test_a_nitrokey_proof_over_a_key_other_than_the_attested_pin_is_refused(self):
        ev = self.standard_evidence()
        ev[3] = self.proof_file("op-nk.json", "nitrokey-pkcs11", NK_SERIAL, "0a", self.key_a, self.der_a)
        self.record_refuses(ev, "op-nk.json: the operation proof is over a different key", self.pin_nk)

    def test_a_reused_challenge_is_refused(self):
        ev = self.standard_evidence()
        challenge = os.urandom(32)
        ev[3] = self.proof_file("op-nk.json", "nitrokey-pkcs11", NK_SERIAL, "0a", self.key_nk, self.der_nk,
                                challenge=challenge)
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_a, self.der_a,
                                challenge=challenge)
        self.record_refuses(ev, "reused challenge", "op-nk.json signed the same challenge")

    def test_an_empty_challenge_is_refused(self):
        ev = self.standard_evidence()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_a, self.der_a, challenge=b"")
        self.record_refuses(ev, "op-yka.json: the operation proof's challenge is empty")

    def test_a_short_challenge_is_refused(self):
        ev = self.standard_evidence()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_a, self.der_a,
                                challenge=os.urandom(16))
        self.record_refuses(ev, "challenge is 16 bytes", "at least 32 random bytes")

    def test_an_empty_signature_is_refused(self):
        ev = self.standard_evidence()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_a, self.der_a, signature=b"")
        self.record_refuses(ev, "op-yka.json: the operation proof carries no signature")

    def test_a_proof_field_that_is_not_a_string_is_refused(self):
        ev = self.standard_evidence()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_a, self.der_a, signature_b64=12345)
        self.record_refuses(ev, "op-yka.json: signature_b64 must be a string")

    def test_a_proof_object_id_the_backend_cannot_have_is_refused(self):
        ev = self.standard_evidence()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "f9", self.key_a, self.der_a)
        self.record_refuses(ev, "op-yka.json: object_id f9 is not a yubikey-piv object id")
        ev[3] = self.proof_file("op-nk.json", "nitrokey-pkcs11", NK_SERIAL, "key-0a", self.key_nk, self.der_nk)
        self.record_refuses(ev, "op-nk.json: object_id key-0a is not a nitrokey-pkcs11 object id")

    def test_a_proof_for_no_binding_is_refused(self):
        ev = self.standard_evidence()
        stray = self.proof_file("op-stray.json", "yubikey-piv", "99999999", "9c", *keypair())
        self.record_refuses([*ev, stray], "operation proof(s) for no binding recorded in this run", "op-stray.json")

    def test_two_proofs_for_one_binding_are_refused(self):
        ev = self.standard_evidence()
        again = self.proof_file("op-yka-2.json", "yubikey-piv", YK_A, "9c", self.key_a, self.der_a)
        self.record_refuses([*ev, again], "two operation proofs for yubikey-piv serial 36345471 object 9c")

    def test_a_proof_naming_another_device_is_refused(self):
        ev = self.standard_evidence()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_a, self.der_a,
                                device_id="yubikey-siteb")
        self.record_refuses(ev, "the operation proof names device yubikey-siteb", "is yubikey-sitea")

    def test_a_nitrokey_key_of_the_wrong_algorithm_is_refused(self):
        """The commission transcript carries only a digest, so without the proof nothing checked the
        Nitrokey key's ALGORITHM against the manifest. The proof's key is parsed structurally."""
        key, der = keypair("secp256k1")
        ev = self.standard_evidence()
        ev[0] = self.file("nk.txt", commission_transcript(pin="sha256:" + hashlib.sha256(der).hexdigest()))
        ev[3] = self.proof_file("op-nk.json", "nitrokey-pkcs11", NK_SERIAL, "0a", key, der)
        self.record_refuses(ev, "plans p256 but the key that signed is secp256k1")

    def test_a_proof_for_an_unprovable_operation_is_refused(self):
        ev = self.standard_evidence()
        ev[4] = self.proof_file("op-yka.json", "yubikey-piv", YK_A, "9c", self.key_a, self.der_a, operation="unwrap")
        self.record_refuses(ev, "operation 'unwrap' is not a proof record can re-verify")

    def test_without_openssl_record_refuses_rather_than_passes(self):
        before = self.manifest.read_bytes()
        out = self.dir / "out.json"
        empty = self.dir / "empty-path"
        empty.mkdir()
        result = subprocess.run([sys.executable, str(SCRIPT), "record", str(self.manifest), "--evidence",
                                 *map(str, self.standard_evidence()), "--out", str(out)],
                                capture_output=True, text=True, env=dict(os.environ, PATH=str(empty)))
        self.refuses(result, "cannot re-verify the operation proof — openssl did not run")
        self.assertFalse(out.exists())
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_plan_refuses_an_operation_no_proof_can_show(self):
        m = fleet_manifest()
        ka = copy.deepcopy(m["objects"][0])
        ka.update(id="session-agreement-key", operations=["key-agreement"],
                  bindings=[binding("sitea", "nitrokey-pkcs11", "nitrokey-sitea", "0b", device_serial=NK_SERIAL),
                            binding("siteb", "nitrokey-pkcs11", "nitrokey-siteb", "0b", device_serial="DENK0000009")])
        m["objects"].append(ka)
        self.write_manifest(m)
        self.refuses(self.run_tool("plan", self.manifest), "objects[2](session-agreement-key).bindings[0]",
                     "operation(s) key-agreement have no operation proof record can re-verify")

    def test_plan_names_the_operation_proof_step(self):
        out = self.run_tool("plan", self.manifest).stdout
        self.assertIn(f"operation-proof.sh --backend nitrokey-pkcs11 --serial {NK_SERIAL} --object-id 0a", out)
        self.assertIn("operation-proof.sh --backend yubikey-piv --serial <serial> --object-id 9c "
                      "--device-id yubikey-siteb", out)

    def test_certificate_sign_is_provable(self):
        m = fleet_manifest()
        m["objects"][0]["operations"] = ["certificate-sign", "sign"]
        self.write_manifest(m)
        result = self.run_tool("record", self.manifest, "--evidence", *self.standard_evidence(),
                               "--out", self.dir / "o.json")
        self.assertEqual(result.returncode, 0, result.stderr)


class ProofDeviceSide(Case):
    """proof-prepare and operation-proof: the halves operation-proof.sh drives at the token."""

    def prepare(self, der):
        (self.dir / "pub.der").write_bytes(der)
        result = self.run_tool("proof-prepare", "--public-key", self.dir / "pub.der",
                               "--challenge-out", self.dir / "chal", "--to-sign-out", self.dir / "tosign")
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip(), (self.dir / "chal").read_bytes(), (self.dir / "tosign").read_bytes()

    def token_sign(self, key, mechanism, to_sign):
        """What pkcs11-tool --sign -m MECHANISM --signature-format openssl returns, done in software."""
        (self.dir / "key.pem").write_bytes(key)
        if mechanism == "ECDSA":   # raw ECDSA over the prepared digest, DER-encoded
            cmd = ["openssl", "pkeyutl", "-sign", "-inkey", str(self.dir / "key.pem")]
        else:
            cmd = ["openssl", "dgst", "-sha256", "-sign", str(self.dir / "key.pem")]
        return subprocess.run(cmd, input=to_sign, check=True, capture_output=True).stdout

    def seal(self, der, sig, out, backend="yubikey-piv", object_id="9c"):
        (self.dir / "sig").write_bytes(sig)
        return self.run_tool("operation-proof", "--backend", backend, "--serial", YK_A, "--object-id", object_id,
                             "--device-id", "yubikey-sitea", "--challenge", self.dir / "chal",
                             "--signature", self.dir / "sig", "--public-key", self.dir / "pub.der", "--out", out)

    def test_every_provisioned_algorithm_round_trips(self):
        for curve, mechanism, digest in (("prime256v1", "ECDSA", "sha256"), ("secp384r1", "ECDSA", "sha384"),
                                         ("secp256k1", "ECDSA", "sha256"), ("rsa2048", "SHA256-RSA-PKCS", None)):
            with self.subTest(curve=curve):
                key, der = keypair(curve)
                got, challenge, to_sign = self.prepare(der)
                self.assertEqual(got, mechanism)
                self.assertEqual(len(challenge), 32)
                self.assertEqual(to_sign, hashlib.new(digest, challenge).digest() if digest else challenge)
                out = self.dir / f"proof-{curve}.json"
                result = self.seal(der, self.token_sign(key, mechanism, to_sign), out,
                                   backend="nitrokey-pkcs11" if curve == "secp256k1" else "yubikey-piv",
                                   object_id="01" if curve == "secp256k1" else "9c")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("OPERATION PROOF", result.stdout)
                record = json.loads(out.read_text())
                self.assertNotIn("verified", json.dumps(record).lower().replace("regalia.operation-proof", ""))
                self.assertEqual(base64.b64decode(record["challenge_b64"]), challenge)

    def test_two_prepares_draw_different_challenges(self):
        _, first, _ = self.prepare(self.der_a)
        _, second, _ = self.prepare(self.der_a)
        self.assertNotEqual(first, second)

    def test_a_bad_signature_is_refused_at_the_token(self):
        mechanism, _, to_sign = self.prepare(self.der_a)
        out = self.dir / "proof.json"
        result = self.seal(self.der_a, self.token_sign(self.key_b, mechanism, to_sign), out)
        self.refuses(result, "the token's signature does not verify", "NOTHING WRITTEN")
        self.assertFalse(out.exists())

    def test_prepare_refuses_a_key_the_ceremony_does_not_provision(self):
        self.refuses(self.run_tool("proof-prepare", "--public-key", self.file("junk.der", "not a key"),
                                   "--challenge-out", self.dir / "c", "--to-sign-out", self.dir / "t"),
                     "is not a SubjectPublicKeyInfo of any algorithm this ceremony provisions")
        _, rsa1024 = keypair("rsa1024")
        (self.dir / "small.der").write_bytes(rsa1024)
        self.refuses(self.run_tool("proof-prepare", "--public-key", self.dir / "small.der",
                                   "--challenge-out", self.dir / "c", "--to-sign-out", self.dir / "t"),
                     "is not a SubjectPublicKeyInfo of any algorithm this ceremony provisions")
        self.assertFalse((self.dir / "c").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
