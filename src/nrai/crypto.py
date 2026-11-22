"""Ed25519 signing helpers for NRAI manifests."""

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 1


def _derive_payload_key(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Encryption passphrase must be at least 12 characters")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def _payload_aad(manifest, signer_public_key):
    bound_metadata = {
        key: value for key, value in manifest.items()
        if key not in {"payload", "encryption", "signature"}
    }
    binding = {"metadata": bound_metadata, "signing_public_key": signer_public_key}
    return b"NRAI\x00v1\x00" + canonical_json(binding)


def encrypt_payload(plaintext, password, manifest, signer_public_key):
    """Encrypt payload bytes with password-derived AES-256-GCM key."""
    plaintext = bytes(plaintext)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_payload_key(password, salt)
    aad = _payload_aad(manifest, signer_public_key)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    descriptor = {
        "algorithm": "AES-256-GCM",
        "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "scrypt_n": SCRYPT_N,
        "scrypt_r": SCRYPT_R,
        "scrypt_p": SCRYPT_P,
        "plaintext_length": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
    }
    return ciphertext, descriptor


def decrypt_payload(ciphertext, descriptor, password, manifest):
    """Decrypt and authenticate a payload; bad passwords fail closed."""
    try:
        salt = base64.b64decode(descriptor["salt"], validate=True)
        nonce = base64.b64decode(descriptor["nonce"], validate=True)
        key = _derive_payload_key(
            password, salt, descriptor["scrypt_n"], descriptor["scrypt_r"], descriptor["scrypt_p"]
        )
        signer_public_key = manifest["signature"]["public_key"]
        aad = _payload_aad(manifest, signer_public_key)
        plaintext = AESGCM(key).decrypt(nonce, bytes(ciphertext), aad)
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Could not decrypt this NRAI file; check the passphrase and file integrity") from exc
    if len(plaintext) != descriptor["plaintext_length"]:
        raise ValueError("Decrypted NRAI payload length does not match its signed descriptor")
    if hashlib.sha256(plaintext).hexdigest() != descriptor["plaintext_sha256"]:
        raise ValueError("Decrypted NRAI payload digest does not match its signed descriptor")
    return plaintext


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def key_id(public_bytes):
    return hashlib.sha256(public_bytes).hexdigest()[:32]


def generate_keypair(private_path, public_path):
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(private_path).write_bytes(private_bytes)
    Path(private_path).chmod(0o600)
    Path(public_path).write_bytes(public_bytes)
    return key_id(private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ))


def load_private_key(path):
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key must be Ed25519 PEM")
    return key


def load_public_key(path):
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key must be Ed25519 PEM")
    return key


def sign_manifest(manifest, private_key):
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    sig = private_key.sign(canonical_json(unsigned))
    unsigned["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id(public_raw),
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "value": base64.b64encode(sig).decode("ascii"),
    }
    return unsigned


def verify_manifest(manifest, trusted_public_key=None):
    signature = manifest.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
        return False, "missing or unsupported signature"
    try:
        embedded = base64.b64decode(signature["public_key"], validate=True)
        sig = base64.b64decode(signature["value"], validate=True)
        pub = trusted_public_key or Ed25519PublicKey.from_public_bytes(embedded)
        actual_raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        if key_id(actual_raw) != signature.get("key_id"):
            return False, "signing key id does not match"
        if trusted_public_key is not None and actual_raw != embedded:
            return False, "embedded key does not match trusted key"
        unsigned = dict(manifest)
        unsigned.pop("signature", None)
        pub.verify(sig, canonical_json(unsigned))
        return True, "signature valid (signer identity is not established unless the key is trusted)"
    except (ValueError, KeyError, InvalidSignature):
        return False, "signature invalid"
