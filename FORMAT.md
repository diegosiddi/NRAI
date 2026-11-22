# NRAI Container Format 1.1

**Status:** stable format revision 1.1 for manifest version 1. The container
framing and unencrypted representation are unchanged. This revision defines
an optional encrypted-payload profile. Implementations that support the profile
must follow section 3. Future incompatible format changes require a new
manifest `version` value.

Revision 1.1 defines an optional encrypted-payload profile for v1 containers.
Unencrypted v1 files retain their exact prior representation. The profile is
indicated by a signed top-level `encryption` descriptor; legacy readers can
verify the signed ciphertext but cannot render it as an image.

The recommended extension is `.nrai`. The project currently uses
`application/vnd.nrai` as a provisional media-type label; it is not an IANA
registration. The macOS Uniform Type Identifier is `com.diegosiddi.nrai`.
These labels help desktop software route files but are not proof that a file is
valid NRAI. The eight-byte magic is the format discriminator.

## 1. Container framing

All integers in the binary header are unsigned, big-endian.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 bytes | Magic: `4e 52 41 49 0d 0a 1a 0a` (`NRAI\r\n\x1a\n`) |
| 8 | 8 bytes | Manifest length `N`, unsigned 64-bit big-endian |
| 16 | `N` bytes | UTF-8 JSON manifest |
| `16 + N` | remainder | Payload bytes, copied without transformation |

Readers must reject a file shorter than 16 bytes, incorrect magic, a manifest
length greater than 4,194,304 bytes, a truncated manifest, invalid UTF-8 or
JSON, a UTF-8 BOM, duplicate object keys, nesting deeper than 64 levels,
unsupported manifest versions, or a payload that
does not satisfy the signed length and digest. There is no padding or separate
trailer. The payload is exactly every byte after the manifest.

The container layer accepts any payload media type. Image viewers must only
decode encodings they support, and must verify the manifest and payload before
decoding.

## 2. Manifest

The manifest is a UTF-8 JSON object. The following fields are required:

```json
{
  "format": "NRAI",
  "version": 1,
  "asset_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2025-01-02T03:04:05Z",
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
    "key_id": "first 32 lowercase hex characters of SHA-256(raw public key)",
    "public_key": "base64 encoded 32-byte Ed25519 public key",
    "value": "base64 encoded 64-byte Ed25519 signature"
  }
}
```

`asset_id` is a canonical lowercase UUID string. `created_at` is a UTC RFC 3339
date-time with whole-second precision and the exact form `YYYY-MM-DDTHH:MM:SSZ`.
`media_type` is a syntactically valid type and
subtype separated by `/`. `payload.length` is an unsigned 64-bit integer and
must equal the exact number of payload bytes. `payload.sha256` is SHA-256 of
those bytes, represented by exactly 64 lowercase hexadecimal characters. For
encrypted files, these refer to ciphertext bytes, including the AEAD tag.

The six `rights` keys above are required in v1. Each value is exactly one of
`allow`, `deny`, `ask`, or `unspecified`. Missing rights are not allowed and
must never be interpreted as `allow`.

Optional fields are `creator` (a display string, not a verified identity) and
`lineage`:

```json
{
  "parent_asset_id": "550e8400-e29b-41d4-a716-446655440000",
  "parent_payload_sha256": "64 lowercase hexadecimal characters",
  "operation": "convert:webp",
  "recorded_at": "2025-01-02T03:04:05Z"
}
```

Readers must preserve unknown top-level extension fields when forwarding a
manifest. They are covered by the signature. A reader must not assign meaning
to an unknown field unless an applicable extension specification defines it.
Unknown keys inside the v1 `rights` and `lineage` objects are invalid.

## 3. Encrypted-payload profile

An encrypted file has this additional signed top-level object:

```json
{
  "encryption": {
    "algorithm": "AES-256-GCM",
    "kdf": "scrypt",
    "salt": "base64 of 16 random bytes",
    "nonce": "base64 of 12 random bytes",
    "scrypt_n": 32768,
    "scrypt_r": 8,
    "scrypt_p": 1,
    "plaintext_length": 12345,
    "plaintext_sha256": "64 lowercase hexadecimal characters"
  }
}
```

The encryption descriptor has exactly these fields and values. The payload is
AES-256-GCM ciphertext with its 16-byte authentication tag appended. A 32-byte
key is derived from the UTF-8 passphrase and 16-byte random salt using scrypt
with the parameters shown. The implementation requires a passphrase of at
least 12 characters; users should choose a longer, unique passphrase. The
12-byte nonce must be newly generated for each encryption operation. The AEAD
associated data is `NRAI\0v1\0` followed by canonical JSON for an object with
two fields: `metadata` and `signing_public_key`. `metadata` contains every
manifest field except `payload`, `encryption`, and `signature`; the second field
is the same base64 public key embedded in the Ed25519 signature descriptor.
This binds the ciphertext to the rights and metadata and to the signing key.

The signed payload descriptor hashes and counts the ciphertext. The signed
encryption descriptor records the expected plaintext length and SHA-256 digest;
after decryption, readers must verify both. A reader must verify the manifest
signature and ciphertext digest before attempting decryption, then fail closed
on an incorrect passphrase, invalid authentication tag, or plaintext digest
mismatch. The passphrase and derived key are never stored in the file. The
signature key and encryption passphrase serve different purposes.

This profile uses a shared passphrase rather than recipient-specific key
envelopes. Anyone who knows the passphrase can decrypt and copy the image. The
salt and ciphertext permit offline passphrase guessing, so a weak passphrase is
not safe. Losing the passphrase makes the image unrecoverable. Changing or
revoking access requires re-encrypting the payload with a new passphrase and
redistributing it. The rights manifest remains readable without the passphrase.
Native file-browser thumbnail extensions in this prototype do not decrypt files
and must suppress their thumbnails.

## 4. Canonical JSON and signature

To verify the signature:

1. Copy the manifest object and remove its `signature` member.
2. Serialize as UTF-8 JSON with object keys sorted by Unicode code point,
   arrays in their existing order, no insignificant whitespace, and Unicode
   characters emitted directly except JSON-required escapes for quotation
   marks, backslashes, and control characters.
3. Reject duplicate keys, floating-point numbers, `NaN`, and infinity. JSON
   integers must fit in signed or unsigned 64-bit range and use decimal
   notation; booleans and `null` retain their JSON spellings.
4. Verify the Ed25519 signature over the resulting bytes.

The signature embeds the raw 32-byte public key as base64. `key_id` is the
first 32 lowercase hexadecimal characters of SHA-256 over that raw key. The
embedded key permits integrity verification; it does not establish who owns
the key. Applications need a separate trust store or other verified identity
binding for that claim.

## 5. Rights and derivatives

Rights are signed declarations. NRAI does not itself enforce them. Compatible
software should communicate and follow them, but arbitrary software, exports,
screenshots, or re-encoding can discard the wrapper and manifest.

A compatible converter may create a derivative by decoding the parent payload,
performing a documented operation, assigning a new asset ID, hashing the new
payload, copying the rights, recording the parent asset ID and digest in
`lineage`, and signing the new manifest. The derivative signature identifies
the signer of the new statement, not necessarily the original creator. Lineage
is only available when the conversion tool records it; it is not guaranteed
across unrelated software.

## 6. Conformance vectors

The machine-readable catalog and binary fixtures in
[`tests/vectors/v1/`](tests/vectors/v1/) define positive and negative v1.0
cases. An implementation conforms to this prototype suite when it accepts the
valid vector and rejects each invalid vector for the specified reason. New
implementations should add their own results without changing the frozen
fixture bytes.
