#!/usr/bin/env python3
"""Submit an artifact digest to the centralized KMS and save a DER P-256 signature."""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import urllib.request
import urllib.parse
import uuid


def der_integer(value: bytes) -> bytes:
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return b"\x02" + bytes([len(value)]) + value


def raw_p256_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError("KMS release signature must be raw 64-byte P-256 r||s")
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < order and 0 < s < order):
        raise ValueError("KMS returned an invalid P-256 signature scalar")
    body = der_integer(signature[:32]) + der_integer(signature[32:])
    return b"\x30" + bytes([len(body)]) + body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_manifest", type=Path)
    parser.add_argument("--kms-url", required=True)
    parser.add_argument("--object-id", required=True)
    parser.add_argument("--client-cert", type=Path, required=True)
    parser.add_argument("--client-key", type=Path, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.receipt.exists():
        print("refusing to overwrite release evidence", file=sys.stderr)
        return 2
    parsed_url = urllib.parse.urlparse(args.kms_url)
    if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password:
        raise ValueError("KMS URL must be an HTTPS origin without userinfo")
    manifest = args.release_manifest.read_bytes()
    release = json.loads(manifest)
    if release.get("schema") != "regalia.offline-release/v1":
        raise ValueError("invalid release manifest")
    digest = hashlib.sha256(manifest).digest()
    request_id = str(uuid.uuid4())
    nonce = uuid.uuid4().hex
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    body = {
        "object_id": args.object_id,
        "context": {"environment": "production", "purpose": "release-signing",
                    "expires_at": expires.isoformat().replace("+00:00", "Z"), "nonce": nonce,
                    "subject": release["artifact"]},
        "content_type": "application/vnd.regalia.release-manifest+json",
        "payload_base64": base64.b64encode(digest).decode("ascii"),
    }
    context = ssl.create_default_context(cafile=str(args.ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(args.client_cert), str(args.client_key))
    request = urllib.request.Request(
        args.kms_url.rstrip("/") + "/v1/operations/sign", data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Request-ID": request_id, "Idempotency-Key": nonce},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError(f"KMS returned HTTP {response.status}")
        response_body = response.read(2 * 1024 * 1024 + 1)
        if len(response_body) > 2 * 1024 * 1024:
            raise ValueError("KMS response exceeds 2 MiB")
        result = json.loads(response_body)
    if (result.get("request_id") != request_id or result.get("object_id") != args.object_id
            or result.get("content_type") != "application/vnd.regalia.release-manifest+json"):
        raise ValueError("KMS response binding mismatch")
    der = raw_p256_to_der(base64.b64decode(result["result_base64"], validate=True))
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(der)
    check = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(args.public_key), "-signature", str(args.output), str(args.release_manifest)],
        check=False, capture_output=True, text=True,
    )
    if check.returncode != 0:
        args.output.unlink()
        raise ValueError("KMS signature does not match the commissioned release public key")
    receipt = {
        "schema": "regalia.release-signature/v1", "artifact": release["artifact"],
        "artifact_sha256": release["artifact_sha256"], "release_manifest_sha256": digest.hex(), "kms_object_id": args.object_id,
        "request_id": request_id, "operation_id": result.get("operation_id"),
        "signature_file": args.output.name, "algorithm": "p256-sha256",
    }
    fd = os.open(args.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(receipt, handle, sort_keys=True, indent=2)
        handle.write("\n")
    print(f"SIGNED: {args.output} via KMS operation {result.get('operation_id')}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"SIGNING FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
