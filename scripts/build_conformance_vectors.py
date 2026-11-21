"""Regenerate public, test-only NRAI v1 conformance fixtures."""

import base64
import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nrai.crypto import canonical_json, sign_manifest


ROOT = Path(__file__).parents[1]
VECTOR_DIR = ROOT / "tests" / "vectors" / "v1"
MAGIC = b"NRAI\r\n\x1a\n"
PREFIX = struct.Struct(">Q")
# This public test key is intentionally deterministic and must never be used to
# sign real files. Its seed is public so every implementation can reproduce
# the valid signature fixture.
TEST_ONLY_PRIVATE_SEED = bytes(range(32))
ASSET_ID = "550e8400-e29b-41d4-a716-446655440000"
CREATED_AT = "2025-01-02T03:04:05Z"


def encode_container(manifest_bytes, payload):
    return MAGIC + PREFIX.pack(len(manifest_bytes)) + manifest_bytes + payload


def main():
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    payload = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAFUlEQVR4nGNUSFjwn4GBgYEJRIAwAB+oAiM3hxFcAAAAAElFTkSuQmCC"
    )
    unsigned = {
        "format": "NRAI",
        "version": 1,
        "asset_id": ASSET_ID,
        "created_at": CREATED_AT,
        "media_type": "image/png",
        "payload": {"length": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
        "rights": {
            "ai_training": "deny",
            "ai_finetuning": "deny",
            "ai_inference": "ask",
            "ai_analysis": "unspecified",
            "screenshot": "deny",
            "redistribution": "ask",
        },
        "creator": "NRAI v1 conformance fixture",
        "lineage": {
            "parent_asset_id": "550e8400-e29b-41d4-a716-446655440001",
            "parent_payload_sha256": "0" * 64,
            "operation": "fixture:create",
            "recorded_at": CREATED_AT,
        },
        # These keys exercise non-ASCII sorting and string escaping across runtimes.
        "x-test-extension": {"\ue000": "line one\nline two", "𐀀": "café"},
    }
    key = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_PRIVATE_SEED)
    manifest = sign_manifest(unsigned, key)
    manifest_bytes = canonical_json(manifest)

    vectors = {
        "valid.nrai": encode_container(manifest_bytes, payload),
        "bad-payload-length.nrai": encode_container(manifest_bytes, payload + b"x"),
    }

    changed_signature = dict(manifest)
    changed_signature["signature"] = dict(manifest["signature"])
    signature_bytes = bytearray(base64.b64decode(changed_signature["signature"]["value"]))
    signature_bytes[0] ^= 1
    changed_signature["signature"]["value"] = base64.b64encode(signature_bytes).decode("ascii")
    vectors["bad-signature.nrai"] = encode_container(canonical_json(changed_signature), payload)

    future_manifest = dict(manifest)
    future_manifest["version"] = 2
    future_manifest = sign_manifest({key: value for key, value in future_manifest.items() if key != "signature"}, key)
    vectors["unsupported-version.nrai"] = encode_container(canonical_json(future_manifest), payload)

    float_extension = dict(unsigned)
    float_extension["x-test-float"] = 1.25
    vectors["float-extension.nrai"] = encode_container(canonical_json(sign_manifest(float_extension, key)), payload)

    duplicate_json = manifest_bytes.replace(b'"version":1', b'"version":1,"version":1', 1)
    vectors["duplicate-key.nrai"] = encode_container(duplicate_json, payload)
    vectors["utf8-bom.nrai"] = encode_container(b"\xef\xbb\xbf" + manifest_bytes, payload)
    vectors["truncated-header.nrai"] = MAGIC + PREFIX.pack(len(manifest_bytes))[:4]
    vectors["wrong-magic.nrai"] = b"NOTNRAI!" + PREFIX.pack(len(manifest_bytes)) + manifest_bytes + payload

    for name, data in vectors.items():
        (VECTOR_DIR / name).write_bytes(data)
    (VECTOR_DIR / "valid-manifest.json").write_bytes(canonical_json(manifest) + b"\n")
    catalog = {
        "suite": "NRAI Container Format 1.0",
        "test_key_note": "The fixture signing seed is public and test-only.",
        "vectors": [
            {"file": "valid.nrai", "stage": "verify", "expected": "accept", "reason": "valid signature and payload digest"},
            {"file": "bad-payload-length.nrai", "stage": "verify", "expected": "reject", "reason": "payload length mismatch"},
            {"file": "bad-signature.nrai", "stage": "verify", "expected": "reject", "reason": "signature invalid"},
            {"file": "unsupported-version.nrai", "stage": "load", "expected": "reject", "reason": "unsupported manifest version"},
            {"file": "float-extension.nrai", "stage": "load", "expected": "reject", "reason": "floating-point JSON number"},
            {"file": "duplicate-key.nrai", "stage": "load", "expected": "reject", "reason": "duplicate json object key"},
            {"file": "utf8-bom.nrai", "stage": "load", "expected": "reject", "reason": "UTF-8 BOM"},
            {"file": "truncated-header.nrai", "stage": "load", "expected": "reject", "reason": "truncated header"},
            {"file": "wrong-magic.nrai", "stage": "load", "expected": "reject", "reason": "wrong magic"},
        ],
    }
    (VECTOR_DIR / "catalog.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
