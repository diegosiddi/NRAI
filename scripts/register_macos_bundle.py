"""Add Finder document-type metadata to a PyInstaller macOS app bundle."""

import plistlib
import sys
from pathlib import Path


UTI = "com.diegosiddi.nrai"


def register_bundle(bundle_path):
    bundle = Path(bundle_path)
    info_path = bundle / "Contents" / "Info.plist"
    if not info_path.is_file():
        raise FileNotFoundError("Not a macOS application bundle: %s" % bundle)
    with info_path.open("rb") as source:
        info = plistlib.load(source)

    info.setdefault("CFBundleIdentifier", "com.diegosiddi.nrai.viewer")
    types = info.setdefault("UTExportedTypeDeclarations", [])
    if not any(item.get("UTTypeIdentifier") == UTI for item in types):
        types.append(
            {
                "UTTypeIdentifier": UTI,
                "UTTypeDescription": "NRAI protected image",
                "UTTypeConformsTo": ["public.data", "public.content"],
                "UTTypeTagSpecification": {
                    "public.filename-extension": ["nrai"],
                    "public.mime-type": "application/vnd.nrai",
                },
            }
        )

    document_types = info.setdefault("CFBundleDocumentTypes", [])
    if not any(UTI in item.get("LSItemContentTypes", []) for item in document_types):
        document_types.append(
            {
                "CFBundleTypeName": "NRAI protected image",
                "CFBundleTypeRole": "Viewer",
                "LSHandlerRank": "Owner",
                "LSItemContentTypes": [UTI],
            }
        )

    info["NSHighResolutionCapable"] = True
    with info_path.open("wb") as target:
        plistlib.dump(info, target, sort_keys=False)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: register_macos_bundle.py APP_BUNDLE")
    register_bundle(sys.argv[1])
