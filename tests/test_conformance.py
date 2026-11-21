import json
from pathlib import Path

from nrai.container import load_document, verify_document


VECTOR_DIR = Path(__file__).parent / "vectors" / "v1"


def test_published_nrai_v1_conformance_vectors():
    catalog = json.loads((VECTOR_DIR / "catalog.json").read_text(encoding="utf-8"))
    for vector in catalog["vectors"]:
        path = VECTOR_DIR / vector["file"]
        if vector["stage"] == "load":
            try:
                load_document(path)
            except ValueError:
                continue
            raise AssertionError("expected load rejection for %s" % vector["file"])

        document = load_document(path)
        valid, reason = verify_document(document)
        if vector["expected"] == "accept":
            assert valid, "%s: %s" % (vector["file"], reason)
        else:
            assert not valid, "expected verification rejection for %s" % vector["file"]
            assert vector["reason"] in reason.lower(), "%s: %s" % (vector["file"], reason)


def test_conformance_fixture_manifest_matches_embedded_manifest():
    document = load_document(VECTOR_DIR / "valid.nrai")
    expected = json.loads((VECTOR_DIR / "valid-manifest.json").read_text(encoding="utf-8"))
    assert document.manifest == expected
    assert document.manifest["x-test-extension"] == {"\ue000": "line one\nline two", "𐀀": "café"}
