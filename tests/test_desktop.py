import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nrai.container import RIGHTS, load_document, verify_document
from nrai.desktop import create_image_container


class DesktopCreatorTests(unittest.TestCase):
    def test_creator_wraps_original_bytes_and_selected_rights(self):
        payload = b"original image bytes, unchanged"
        choices = {right: "unspecified" for right in RIGHTS}
        choices.update({"ai_training": "deny", "screenshot": "ask", "redistribution": "allow"})
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.png"
            output = Path(folder) / "protected.nrai"
            source.write_bytes(payload)

            created = create_image_container(
                source, output, choices, Ed25519PrivateKey.generate(), "Test creator"
            )
            loaded = load_document(output)

        self.assertEqual(loaded.payload, payload)
        self.assertEqual(loaded.manifest["rights"], choices)
        self.assertEqual(loaded.manifest["creator"], "Test creator")
        self.assertTrue(verify_document(loaded)[0])
        self.assertEqual(created.payload, payload)

    def test_creator_rejects_output_over_source(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.png"
            source.write_bytes(b"image")
            with self.assertRaisesRegex(ValueError, "different from the source"):
                create_image_container(source, source, {}, Ed25519PrivateKey.generate())

    def test_creator_rejects_non_image_file(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "notes.txt"
            source.write_text("not an image")
            output = Path(folder) / "notes.nrai"
            with self.assertRaisesRegex(ValueError, "not recognized as an image"):
                create_image_container(source, output, {}, Ed25519PrivateKey.generate())


if __name__ == "__main__":
    unittest.main()
