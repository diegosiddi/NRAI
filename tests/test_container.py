import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nrai.container import create_document, derive_document, load_document, save_document, verify_document
from nrai.crypto import verify_manifest


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.payload = b"\x89PNG\r\nprototype-original-bytes"

    def test_round_trip_preserves_exact_payload_bytes(self):
        doc = create_document(self.payload, "image/png", {"ai_training": "deny"}, self.key)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.nrai"
            save_document(doc, path)
            loaded = load_document(path)
        self.assertEqual(loaded.payload, self.payload)
        self.assertTrue(verify_document(loaded)[0])
        self.assertEqual(loaded.manifest["rights"]["ai_training"], "deny")

    def test_payload_tampering_fails_integrity(self):
        doc = create_document(self.payload, "image/png", {}, self.key)
        changed = type(doc)(doc.manifest, doc.payload + b"x")
        ok, reason = verify_document(changed)
        self.assertFalse(ok)
        self.assertIn("length", reason)

    def test_manifest_tampering_fails_signature(self):
        doc = create_document(self.payload, "image/png", {"redistribution": "deny"}, self.key)
        manifest = dict(doc.manifest)
        manifest["rights"] = dict(manifest["rights"])
        manifest["rights"]["redistribution"] = "allow"
        self.assertFalse(verify_manifest(manifest)[0])

    def test_derivative_carries_rights_and_parent_digest(self):
        parent = create_document(self.payload, "image/png", {"ai_training": "deny", "screenshot": "ask"}, self.key)
        child = derive_document(parent, b"converted bytes", "image/jpeg", self.key, "convert:jpeg")
        self.assertEqual(child.manifest["rights"], parent.manifest["rights"])
        self.assertEqual(child.manifest["lineage"]["parent_payload_sha256"], parent.manifest["payload"]["sha256"])
        self.assertTrue(verify_document(child)[0])

    def test_unknown_right_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown rights"):
            create_document(self.payload, "image/png", {"train": "deny"}, self.key)


if __name__ == "__main__":
    unittest.main()
