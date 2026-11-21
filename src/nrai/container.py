"""Binary container framing and manifest operations."""

import hashlib
import json
import mimetypes
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .crypto import canonical_json, load_private_key, sign_manifest, verify_manifest

MAGIC = b"NRAI\r\n\x1a\n"
PREFIX = struct.Struct(">Q")
MAX_HEADER_BYTES = 4 * 1024 * 1024
RIGHTS = ("ai_training", "ai_finetuning", "ai_inference", "ai_analysis", "screenshot", "redistribution")
RIGHTS_VALUES = ("allow", "deny", "ask", "unspecified")


@dataclass
class NraiDocument:
    manifest: dict
    payload: bytes


def _validate_rights(rights):
    if not isinstance(rights, dict):
        raise ValueError("rights must be an object")
    unknown = set(rights) - set(RIGHTS)
    if unknown:
        raise ValueError("unknown rights: " + ", ".join(sorted(unknown)))
    for name, value in rights.items():
        if value not in RIGHTS_VALUES:
            raise ValueError("right %s must be one of: %s" % (name, ", ".join(RIGHTS_VALUES)))
    return {name: rights.get(name, "unspecified") for name in RIGHTS}


def create_document(payload, media_type=None, rights=None, private_key=None, creator=None, lineage=None):
    payload = bytes(payload)
    if private_key is None:
        raise ValueError("a signing key is required")
    manifest = {
        "format": "NRAI",
        "version": 1,
        "asset_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "media_type": media_type or "application/octet-stream",
        "payload": {"length": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
        "rights": _validate_rights({} if rights is None else rights),
    }
    if creator:
        manifest["creator"] = creator
    if lineage:
        manifest["lineage"] = lineage
    return NraiDocument(sign_manifest(manifest, private_key), payload)


def save_document(document, path):
    header = canonical_json(document.manifest)
    if len(header) > MAX_HEADER_BYTES:
        raise ValueError("manifest exceeds maximum header size")
    Path(path).write_bytes(MAGIC + PREFIX.pack(len(header)) + header + document.payload)


def load_document(path):
    raw = Path(path).read_bytes()
    if len(raw) < len(MAGIC) + PREFIX.size or not raw.startswith(MAGIC):
        raise ValueError("not an NRAI v1 container")
    header_size = PREFIX.unpack(raw[len(MAGIC):len(MAGIC) + PREFIX.size])[0]
    if header_size > MAX_HEADER_BYTES:
        raise ValueError("manifest exceeds maximum header size")
    start = len(MAGIC) + PREFIX.size
    end = start + header_size
    if end > len(raw):
        raise ValueError("truncated NRAI manifest")
    try:
        manifest = json.loads(raw[start:end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid NRAI manifest JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != "NRAI" or manifest.get("version") != 1:
        raise ValueError("unsupported NRAI manifest")
    return NraiDocument(manifest, raw[end:])


def verify_document(document, trusted_public_key=None):
    manifest = document.manifest
    payload_info = manifest.get("payload")
    if not isinstance(payload_info, dict):
        return False, "missing payload descriptor"
    if payload_info.get("length") != len(document.payload):
        return False, "payload length mismatch"
    if payload_info.get("sha256") != hashlib.sha256(document.payload).hexdigest():
        return False, "payload digest mismatch"
    return verify_manifest(manifest, trusted_public_key)


def make_lineage(parent, operation):
    return {
        "parent_asset_id": parent.manifest.get("asset_id"),
        "parent_payload_sha256": parent.manifest.get("payload", {}).get("sha256"),
        "operation": operation,
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def media_type_for(path):
    return mimetypes.guess_type(str(path))[0] or "application/octet-stream"


def converted_payload(payload, target_format):
    try:
        from PIL import Image
        from io import BytesIO
    except ImportError as exc:
        raise RuntimeError("image conversion requires the optional Pillow dependency") from exc
    source = Image.open(BytesIO(payload))
    out = BytesIO()
    fmt = target_format.upper()
    if fmt == "JPG":
        fmt = "JPEG"
    if fmt in ("JPEG", "WEBP") and source.mode not in ("RGB", "L"):
        source = source.convert("RGB")
    source.save(out, format=fmt)
    return out.getvalue()


def derive_document(parent, payload, media_type, private_key, operation):
    rights = dict(parent.manifest.get("rights", {}))
    creator = parent.manifest.get("creator")
    return create_document(payload, media_type, rights, private_key, creator, make_lineage(parent, operation))
