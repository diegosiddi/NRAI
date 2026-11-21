"""Add Finder document-type metadata to a PyInstaller macOS app bundle."""

import plistlib
import argparse
import shutil
import sys
from pathlib import Path


UTI = "com.diegosiddi.nrai"


def register_bundle(bundle_path, thumbnail_extension=None):
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

    if thumbnail_extension:
        extension = Path(thumbnail_extension)
        if not extension.is_dir() or extension.suffix != ".appex":
            raise ValueError("Quick Look thumbnail extension must be a built .appex bundle")
        plugins = bundle / "Contents" / "PlugIns"
        plugins.mkdir(parents=True, exist_ok=True)
        destination = plugins / extension.name
        if destination.exists():
            raise FileExistsError("Quick Look extension already exists in app bundle: %s" % destination)
        shutil.copytree(extension, destination, symlinks=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app_bundle")
    parser.add_argument("--thumbnail-extension")
    args = parser.parse_args()
    register_bundle(args.app_bundle, args.thumbnail_extension)
