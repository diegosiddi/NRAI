from pathlib import Path
from unittest.mock import patch

from nrai.cli import main
from nrai.container import decrypt_document, load_document
from nrai.crypto import generate_keypair


def test_cli_creates_and_exports_encrypted_file(tmp_path):
    source = tmp_path / "source.png"
    output = tmp_path / "protected.nrai"
    exported = tmp_path / "exported.png"
    private = tmp_path / "author.private.pem"
    public = tmp_path / "author.public.pem"
    contents = b"private source image bytes"
    password = "a sufficiently long test passphrase"
    source.write_bytes(contents)
    generate_keypair(private, public)

    with patch("nrai.cli.getpass.getpass", side_effect=[password, password]):
        assert main(["create", str(source), str(output), "--private-key", str(private), "--encrypt"]) == 0

    document = load_document(output)
    assert document.manifest["encryption"]["algorithm"] == "AES-256-GCM"
    assert decrypt_document(document, password) == contents

    with patch("nrai.cli.getpass.getpass", return_value=password):
        assert main(["export", str(output), str(exported)]) == 0
    assert Path(exported).read_bytes() == contents
