"""Command line interface for NRAI files."""

import argparse
import json
import sys
from pathlib import Path

from .container import (
    create_document, derive_document, load_document, media_type_for,
    save_document, converted_payload, verify_document,
)
from .crypto import generate_keypair, load_private_key, load_public_key


def _parser():
    parser = argparse.ArgumentParser(prog="nrai", description="Create and inspect signed NRAI image containers")
    sub = parser.add_subparsers(dest="command", required=True)
    keys = sub.add_parser("keygen", help="create an Ed25519 signing key pair")
    keys.add_argument("--private", required=True)
    keys.add_argument("--public", required=True)
    create = sub.add_parser("create", help="wrap image bytes in a signed .nrai container")
    create.add_argument("input")
    create.add_argument("output")
    create.add_argument("--private-key", required=True)
    create.add_argument("--rights", help="JSON file containing per-purpose rights")
    create.add_argument("--creator")
    inspect = sub.add_parser("inspect", help="print the manifest")
    inspect.add_argument("file")
    verify = sub.add_parser("verify", help="check payload integrity and manifest signature")
    verify.add_argument("file")
    verify.add_argument("--trusted-key", help="optional public key to establish signer identity")
    export = sub.add_parser("export", help="extract original payload and write a rights sidecar")
    export.add_argument("file")
    export.add_argument("output")
    convert = sub.add_parser("convert", help="convert an image and preserve rights in a new signed container")
    convert.add_argument("file")
    convert.add_argument("output", help="output .nrai path")
    convert.add_argument("--to", required=True, choices=("png", "jpeg", "webp", "bmp", "tiff"))
    convert.add_argument("--private-key", required=True)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.command == "keygen":
            kid = generate_keypair(args.private, args.public)
            print("Created Ed25519 key pair; key id: " + kid)
        elif args.command == "create":
            rights = json.loads(Path(args.rights).read_text("utf-8")) if args.rights else {}
            payload = Path(args.input).read_bytes()
            doc = create_document(payload, media_type_for(args.input), rights,
                                  load_private_key(args.private_key), args.creator)
            save_document(doc, args.output)
            print("Created %s (%d payload bytes)" % (args.output, len(payload)))
        elif args.command == "inspect":
            doc = load_document(args.file)
            print(json.dumps(doc.manifest, indent=2, ensure_ascii=False))
        elif args.command == "verify":
            doc = load_document(args.file)
            trusted = load_public_key(args.trusted_key) if args.trusted_key else None
            ok, message = verify_document(doc, trusted)
            print(("OK: " if ok else "FAIL: ") + message)
            return 0 if ok else 2
        elif args.command == "export":
            doc = load_document(args.file)
            Path(args.output).write_bytes(doc.payload)
            sidecar = dict(doc.manifest)
            Path(args.output + ".rights.json").write_text(json.dumps(sidecar, indent=2) + "\n", "utf-8")
            print("Exported payload and rights sidecar; exported bytes no longer enforce NRAI policy")
        elif args.command == "convert":
            parent = load_document(args.file)
            output = converted_payload(parent.payload, args.to)
            mime = "image/jpeg" if args.to == "jpeg" else "image/" + args.to
            doc = derive_document(parent, output, mime, load_private_key(args.private_key), "convert:" + args.to)
            save_document(doc, args.output)
            print("Created converted NRAI file; rights copied and parent digest recorded")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print("nrai: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
