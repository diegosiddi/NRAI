"""Binary container framing and manifest operations."""

import hashlib
import json
import mimetypes
import re
import struct
import uuid
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization

from .crypto import (
    canonical_json, decrypt_payload, encrypt_payload, load_private_key,
    sign_manifest, verify_manifest,
)

MAGIC = b"NRAI\r\n\x1a\n"
PREFIX = struct.Struct(">Q")
MAX_HEADER_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
RIGHTS = ("ai_training", "ai_finetuning", "ai_inference", "ai_analysis", "screenshot", "redistribution")
RIGHTS_VALUES = ("allow", "deny", "ask", "unspecified")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_MEDIA_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
_RFC3339_UTC_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


@dataclass
class NraiDocument:
    manifest: dict
    payload: bytes


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key: " + key)
        result[key] = value
    return result


def _reject_json_number(value):
    raise ValueError("floating-point and non-finite JSON numbers are not supported")


def _strict_json_loads(text):
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_float=_reject_json_number,
        parse_constant=_reject_json_number,
    )


def _validate_timestamp(value, field):
    if not isinstance(value, str) or not _RFC3339_UTC_RE.fullmatch(value):
        raise ValueError("%s must be a UTC RFC 3339 timestamp ending in Z" % field)
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("%s is not a valid timestamp" % field) from exc


def _validate_uuid(value, field):
    if not isinstance(value, str):
        raise ValueError("%s must be a UUID string" % field)
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise ValueError("%s must be a canonical lowercase UUID" % field) from exc
    if value != canonical:
        raise ValueError("%s must be a canonical lowercase UUID" % field)


def _reject_floats(value, depth=0):
    if depth > MAX_JSON_DEPTH:
        raise ValueError("NRAI JSON nesting depth exceeds 64")
    if isinstance(value, float):
        raise ValueError("floating-point JSON values are not supported in NRAI v1")
    if type(value) is int and not -(2**63) <= value <= 2**64 - 1:
        raise ValueError("NRAI JSON integers must fit in signed or unsigned 64-bit range")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            _reject_floats(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item, depth + 1)


def validate_manifest(manifest):
    """Validate the required NRAI v1 fields without discarding extensions."""
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    _reject_floats(manifest)
    if manifest.get("format") != "NRAI":
        raise ValueError("unsupported NRAI manifest format")
    if type(manifest.get("version")) is not int or manifest["version"] != 1:
        raise ValueError("unsupported NRAI manifest version")
    _validate_uuid(manifest.get("asset_id"), "asset_id")
    _validate_timestamp(manifest.get("created_at"), "created_at")
    media_type = manifest.get("media_type")
    if not isinstance(media_type, str) or not _MEDIA_TYPE_RE.fullmatch(media_type):
        raise ValueError("media_type must be a type/subtype token")

    payload = manifest.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    length = payload.get("length")
    if type(length) is not int or not 0 <= length <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("payload.length must be an unsigned 64-bit integer")
    if not isinstance(payload.get("sha256"), str) or not _SHA256_RE.fullmatch(payload["sha256"]):
        raise ValueError("payload.sha256 must be 64 lowercase hexadecimal characters")

    rights = manifest.get("rights")
    if not isinstance(rights, dict) or set(rights) != set(RIGHTS):
        raise ValueError("rights must contain exactly the six NRAI v1 rights")
    for name, value in rights.items():
        if value not in RIGHTS_VALUES:
            raise ValueError("right %s must be one of: %s" % (name, ", ".join(RIGHTS_VALUES)))

    if "creator" in manifest and not isinstance(manifest["creator"], str):
        raise ValueError("creator must be a string")
    if "lineage" in manifest:
        lineage = manifest["lineage"]
        required = {"parent_asset_id", "parent_payload_sha256", "operation", "recorded_at"}
        if not isinstance(lineage, dict) or set(lineage) != required:
            raise ValueError("lineage must contain exactly the four NRAI v1 lineage fields")
        _validate_uuid(lineage["parent_asset_id"], "lineage.parent_asset_id")
        if not isinstance(lineage["parent_payload_sha256"], str) or not _SHA256_RE.fullmatch(lineage["parent_payload_sha256"]):
            raise ValueError("lineage.parent_payload_sha256 must be a SHA-256 hex digest")
        if not isinstance(lineage["operation"], str) or not lineage["operation"]:
            raise ValueError("lineage.operation must be a non-empty string")
        _validate_timestamp(lineage["recorded_at"], "lineage.recorded_at")

    signature = manifest.get("signature")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "public_key", "value"}:
        raise ValueError("signature must contain the four NRAI v1 signature fields")
    if signature["algorithm"] != "Ed25519":
        raise ValueError("unsupported signature algorithm")
    if not isinstance(signature["key_id"], str) or not _KEY_ID_RE.fullmatch(signature["key_id"]):
        raise ValueError("signature.key_id must be 32 lowercase hexadecimal characters")
    if not isinstance(signature["public_key"], str) or not isinstance(signature["value"], str):
        raise ValueError("signature key and value must be base64 strings")

    if "encryption" in manifest:
        encryption = manifest["encryption"]
        fields = {
            "algorithm", "kdf", "salt", "nonce", "scrypt_n", "scrypt_r",
            "scrypt_p", "plaintext_length", "plaintext_sha256",
        }
        if not isinstance(encryption, dict) or set(encryption) != fields:
            raise ValueError("encryption descriptor has invalid fields")
        if encryption["algorithm"] != "AES-256-GCM" or encryption["kdf"] != "scrypt":
            raise ValueError("unsupported NRAI payload encryption")
        if (type(encryption["scrypt_n"]) is not int or encryption["scrypt_n"] != 32768 or
                type(encryption["scrypt_r"]) is not int or encryption["scrypt_r"] != 8 or
                type(encryption["scrypt_p"]) is not int or encryption["scrypt_p"] != 1):
            raise ValueError("unsupported NRAI scrypt parameters")
        if (type(encryption["plaintext_length"]) is not int or
                not 0 <= encryption["plaintext_length"] <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("encryption.plaintext_length must be an unsigned 64-bit integer")
        if (not isinstance(encryption["plaintext_sha256"], str) or
                not _SHA256_RE.fullmatch(encryption["plaintext_sha256"])):
            raise ValueError("encryption.plaintext_sha256 must be a SHA-256 hex digest")
        try:
            salt = base64.b64decode(encryption["salt"], validate=True)
            nonce = base64.b64decode(encryption["nonce"], validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("encryption salt and nonce must be base64 strings") from exc
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError("encryption salt or nonce has an invalid length")
        if base64.b64encode(salt).decode("ascii") != encryption["salt"] or base64.b64encode(nonce).decode("ascii") != encryption["nonce"]:
            raise ValueError("encryption salt and nonce must use canonical base64")

    # Ensure all extension values are representable in the canonical encoding.
    from .crypto import canonical_json

    try:
        canonical_json(manifest)
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("manifest cannot be represented as canonical NRAI JSON") from exc
    return manifest


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


def create_document(payload, media_type=None, rights=None, private_key=None, creator=None, lineage=None, encryption_password=None):
    payload = bytes(payload)
    if private_key is None:
        raise ValueError("a signing key is required")
    asset_id = str(uuid.uuid4())
    media_type = media_type or "application/octet-stream"
    normalized_rights = _validate_rights({} if rights is None else rights)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    manifest = {
        "format": "NRAI",
        "version": 1,
        "asset_id": asset_id,
        "created_at": created_at,
        "media_type": media_type,
        "payload": {"length": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
        "rights": normalized_rights,
    }
    if creator:
        manifest["creator"] = creator
    if lineage:
        manifest["lineage"] = lineage
    if encryption_password is not None:
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        signer_public_key = base64.b64encode(public_raw).decode("ascii")
        payload, encryption = encrypt_payload(payload, encryption_password, manifest, signer_public_key)
        manifest["payload"] = {"length": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        manifest["encryption"] = encryption
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
        manifest = _strict_json_loads(raw[start:end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid NRAI manifest JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != "NRAI" or type(manifest.get("version")) is not int or manifest.get("version") != 1:
        raise ValueError("unsupported NRAI manifest")
    return NraiDocument(manifest, raw[end:])


def verify_document(document, trusted_public_key=None):
    manifest = document.manifest
    try:
        validate_manifest(manifest)
    except (ValueError, TypeError) as exc:
        return False, str(exc)
    payload_info = manifest.get("payload")
    if not isinstance(payload_info, dict):
        return False, "missing payload descriptor"
    if payload_info.get("length") != len(document.payload):
        return False, "payload length mismatch"
    if payload_info.get("sha256") != hashlib.sha256(document.payload).hexdigest():
        return False, "payload digest mismatch"
    return verify_manifest(manifest, trusted_public_key)


def decrypt_document(document, password, trusted_public_key=None):
    """Verify, decrypt, and validate an encrypted NRAI payload."""
    valid, reason = verify_document(document, trusted_public_key)
    if not valid:
        raise ValueError("Refusing to decrypt an invalid NRAI file: " + reason)
    encryption = document.manifest.get("encryption")
    if encryption is None:
        return document.payload
    return decrypt_payload(document.payload, encryption, password, document.manifest)


def make_lineage(parent, operation):
    return {
        "parent_asset_id": parent.manifest.get("asset_id"),
        "parent_payload_sha256": parent.manifest.get("payload", {}).get("sha256"),
        "operation": operation,
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def media_type_for(path):
    detected = mimetypes.guess_type(str(path))[0]
    if detected:
        return detected
    image_types = {
        ".avif": "image/avif",
        ".heic": "image/heic",
        ".heif": "image/heif",
        ".svg": "image/svg+xml",
    }
    return image_types.get(Path(path).suffix.lower(), "application/octet-stream")


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


def derive_document(parent, payload, media_type, private_key, operation, encryption_password=None):
    rights = dict(parent.manifest.get("rights", {}))
    creator = parent.manifest.get("creator")
    return create_document(
        payload, media_type, rights, private_key, creator,
        make_lineage(parent, operation), encryption_password,
    )
