import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image

from nrai.container import create_document, save_document
from nrai.viewer import load_verified_image


def tiny_png():
    output = BytesIO()
    Image.new("RGB", (3, 2), color=(30, 90, 180)).save(output, format="PNG")
    return output.getvalue()


class ViewerTests(unittest.TestCase):
    def test_viewer_verifies_and_decodes_signed_payload(self):
        key = Ed25519PrivateKey.generate()
        doc = create_document(tiny_png(), "image/png", {"screenshot": "deny"}, key)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "valid.nrai"
            save_document(doc, path)
            loaded, image, reason = load_verified_image(path)

        self.assertEqual(image.size, (3, 2))
        self.assertEqual(loaded.manifest["rights"]["screenshot"], "deny")
        self.assertIn("signature valid", reason)

    def test_viewer_decrypts_only_with_the_passphrase(self):
        key = Ed25519PrivateKey.generate()
        password = "a very long sample passphrase"
        doc = create_document(tiny_png(), "image/png", {}, key, encryption_password=password)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "encrypted.nrai"
            save_document(doc, path)
            with self.assertRaisesRegex(ValueError, "Could not decrypt"):
                load_verified_image(path, encryption_password="incorrect password")
            _loaded, image, _reason = load_verified_image(path, encryption_password=password)
        self.assertEqual(image.size, (3, 2))

    def test_viewer_refuses_payload_tampering(self):
        doc = create_document(tiny_png(), "image/png", {}, Ed25519PrivateKey.generate())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tampered.nrai"
            save_document(doc, path)
            with path.open("ab") as handle:
                handle.write(b"tamper")
            with self.assertRaisesRegex(ValueError, "payload length mismatch"):
                load_verified_image(path)


if __name__ == "__main__":
    unittest.main()
