import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nrai.container import (
    create_document, decrypt_document, derive_document, load_document,
    save_document, verify_document,
)
from nrai.crypto import sign_manifest, verify_manifest


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

    def test_encrypted_round_trip_keeps_pixels_out_of_container(self):
        password = "a very long sample passphrase"
        doc = create_document(self.payload, "image/png", {"ai_training": "deny"}, self.key,
                              encryption_password=password)
        self.assertNotIn(self.payload, doc.payload)
        self.assertTrue(verify_document(doc)[0])
        self.assertEqual(decrypt_document(doc, password), self.payload)

    def test_wrong_password_and_ciphertext_tampering_fail_closed(self):
        doc = create_document(self.payload, "image/png", {}, self.key,
                              encryption_password="a very long sample passphrase")
        with self.assertRaisesRegex(ValueError, "Could not decrypt"):
            decrypt_document(doc, "incorrect password")
        changed = type(doc)(doc.manifest, doc.payload[:-1] + bytes([doc.payload[-1] ^ 1]))
        self.assertFalse(verify_document(changed)[0])

    def test_encryption_is_bound_to_author_key_and_rights(self):
        password = "a very long sample passphrase"
        doc = create_document(self.payload, "image/png", {"ai_training": "deny"}, self.key,
                              encryption_password=password)
        altered = dict(doc.manifest)
        altered["rights"] = dict(altered["rights"])
        altered["rights"]["ai_training"] = "allow"
        attacker_signed = sign_manifest(altered, Ed25519PrivateKey.generate())
        forged = type(doc)(attacker_signed, doc.payload)
        self.assertTrue(verify_document(forged)[0])
        with self.assertRaisesRegex(ValueError, "Could not decrypt"):
            decrypt_document(forged, password)

    def test_encryption_rejects_short_passphrase(self):
        with self.assertRaisesRegex(ValueError, "at least 12 characters"):
            create_document(self.payload, "image/png", {}, self.key, encryption_password="short")

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
