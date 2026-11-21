import importlib.util
import plistlib
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "register_macos_bundle.py"
SPEC = importlib.util.spec_from_file_location("register_macos_bundle", SCRIPT)
MACOS_REGISTRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MACOS_REGISTRATION)


def test_macos_registration_adds_nrai_document_type_once(tmp_path):
    bundle = tmp_path / "NRAI Viewer.app"
    contents = bundle / "Contents"
    contents.mkdir(parents=True)
    info_path = contents / "Info.plist"
    info_path.write_bytes(plistlib.dumps({"CFBundleName": "NRAI Viewer"}))

    MACOS_REGISTRATION.register_bundle(bundle)
    MACOS_REGISTRATION.register_bundle(bundle)
    info = plistlib.loads(info_path.read_bytes())

    assert info["CFBundleIdentifier"] == "com.diegosiddi.nrai.viewer"
    assert len(info["UTExportedTypeDeclarations"]) == 1
    assert info["UTExportedTypeDeclarations"][0]["UTTypeIdentifier"] == "com.diegosiddi.nrai"
    assert len(info["CFBundleDocumentTypes"]) == 1
    assert info["CFBundleDocumentTypes"][0]["LSItemContentTypes"] == ["com.diegosiddi.nrai"]
