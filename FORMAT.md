# NRAI v1 Container Format

This document specifies the experimental version 1 binary container. Integers are unsigned big-endian. The payload is embedded as-is; wrapping does not rewrite, decode, or recompress it.

## Binary layout

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 bytes | Magic: `4e 52 41 49 0d 0a 1a 0a` (`NRAI\r\n\x1a\n`) |
| 8 | 8 bytes | Manifest byte length, unsigned 64-bit big-endian |
| 16 | N bytes | UTF-8 JSON manifest |
| 16 + N | remainder | Original image payload bytes |

The v1 reader accepts manifests up to 4 MiB and rejects wrong magic, unsupported versions, malformed JSON, truncated headers, digest mismatches, and invalid signatures. There is no padding or trailing data outside the declared payload. The payload may be any media type, though image software should accept only supported image encodings.

## Manifest

The JSON object has these required fields:

```json
{
  "format": "NRAI",
  "version": 1,
  "asset_id": "UUID",
  "created_at": "UTC RFC 3339 timestamp",
  "media_type": "image/jpeg",
  "payload": {
    "length": 12345,
    "sha256": "64 lowercase hexadecimal characters"
  },
  "rights": {
    "ai_training": "deny",
    "ai_finetuning": "deny",
    "ai_inference": "ask",
    "ai_analysis": "unspecified",
    "screenshot": "deny",
    "redistribution": "ask"
  },
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "first 32 hex chars of SHA-256(raw public key)",
    "public_key": "base64 encoded 32-byte Ed25519 public key",
    "value": "base64 encoded 64-byte Ed25519 signature"
  }
}
```

Rights are independent. Allowed values are `allow`, `deny`, `ask`, and `unspecified`. Readers must preserve unknown extension fields when forwarding a manifest and must not treat missing or `unspecified` rights as `allow`. This prototype validates the six listed keys and emits all six.

Optional fields include `creator` (a display label; not a verified identity) and `lineage`:

```json
{
  "parent_asset_id": "UUID",
  "parent_payload_sha256": "...",
  "operation": "convert:webp",
  "recorded_at": "UTC RFC 3339 timestamp"
}
```

## Signature and integrity

To verify the signature, remove the `signature` field, serialize the remaining JSON object with UTF-8, sorted keys, no insignificant spaces, and unescaped Unicode, then verify the Ed25519 signature over those bytes. The signature object embeds the raw public key. `key_id` is SHA-256 of that key, truncated to the first 32 lowercase hex characters. Trust in the key must be established separately.

The SHA-256 hash is computed over the exact payload bytes and its byte count is signed. A container is valid only when both signature verification and payload length/hash checks pass. This detects edits; it does not prevent them.

## Derivatives

A compatible converter decodes the parent payload, performs its documented transformation, creates a new asset ID, hashes the resulting encoded bytes, copies the parent's rights, records the parent asset ID and payload hash, and signs the new manifest with the converter's signing key. The derivative signature identifies the signer of the new statement, not necessarily the original creator. This protocol cannot make arbitrary third-party conversions inherit metadata.
