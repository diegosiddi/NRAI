# NRAI — Protected Image Rights Protocol

NRAI is a prototype image container for carrying an unchanged source image byte stream alongside a signed, machine-readable rights manifest. It gives compatible software a common way to inspect rights, verify integrity, and record supported derivative operations.

**NRAI is a declaration and interoperability prototype, not DRM.** A manifest cannot force an uncooperative program to honor it, stop an image from being copied, or guarantee that rights survive arbitrary edits, screenshots, re-encoding, or third-party conversion. The viewer and SDK demonstrate cooperative behavior only.

## What is included

- Version 1 container specification in [FORMAT.md](FORMAT.md).
- Python SDK and `nrai` CLI for key generation, creation, inspection, verification, export, and converted derivatives.
- A small desktop viewer that refuses invalid signatures and displays the declared screenshot policy.
- Android `FLAG_SECURE` integration sketch in [examples/android/ProtectedImageActivity.kt](examples/android/ProtectedImageActivity.kt).
- Tests and a sample independently configured rights file.

## Install

Python 3.9 or later is required. Install the package and optional image conversion/viewer dependencies:

```sh
python -m pip install '.[images]'
```

## Quick start

```sh
nrai keygen --private creator.private.pem --public creator.public.pem
nrai create photo.jpg photo.nrai --private-key creator.private.pem \
  --rights examples/rights.json --creator 'Example creator'
nrai inspect photo.nrai
nrai verify photo.nrai --trusted-key creator.public.pem
nrai-viewer photo.nrai
```

`verify` checks the payload digest and Ed25519 signature. With `--trusted-key`, it also checks that the signer matches the supplied key. Without a trusted key, a valid signature proves only that the embedded key signed the manifest; it does not establish who controls that key.

Convert to another image encoding while carrying rights into a newly signed NRAI file:

```sh
nrai convert photo.nrai photo-small.nrai --to webp --private-key creator.private.pem
```

The conversion records the parent asset ID and payload digest. It copies rights because this SDK controls the conversion path. If you export raw image bytes, a JSON sidecar is written next to them, but the exported image itself has no NRAI enforcement:

```sh
nrai export photo.nrai exported-photo.jpg
```

## Rights model

Each right has its own `allow`, `deny`, `ask`, or `unspecified` value. Supported keys are `ai_training`, `ai_finetuning`, `ai_inference`, `ai_analysis`, `screenshot`, and `redistribution`. Missing keys become `unspecified`; software should not interpret that as permission. The manifest is signed as a whole, so changing any policy requires a new signature.

## Viewer and screenshot behavior

The desktop demo can display a valid image and show the `screenshot` declaration. Tkinter does not provide a portable way to stop OS screenshots, screen recording, remote desktop capture, cameras, or another program from reading pixels. It does not pretend to block screenshots.

The Android example shows how an application can set `WindowManager.LayoutParams.FLAG_SECURE` for the Activity window after validating the NRAI file and seeing `screenshot: deny`. Android documents this as preventing that window from appearing in screenshots and non-secure displays. It applies only when the image is displayed in that protected application window; it does not protect exported files, other apps, external cameras, rooted or compromised devices, or every device/vendor capture path. See the official [Android `FLAG_SECURE` reference](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE).

No general desktop OS integration is included. Protecting arbitrary files system-wide would require OS-level support and cooperation from image decoders, display servers, and capture paths. A file extension or file association alone cannot make screenshots white.

## Threat model and limits

NRAI is designed to detect accidental corruption and communicate a creator's declaration to software that chooses to cooperate.

- Ed25519 signatures cover all manifest fields, including each rights choice and the SHA-256 digest and length of the exact payload bytes.
- Signatures do not establish legal ownership or identity. Applications need an out-of-band trusted-key policy to associate a public key with a creator.
- A recipient can remove the wrapper, copy pixels, alter content, or create a new file. Cryptographic verification will detect edits to an existing NRAI file, but cannot stop a determined user from making an unmarked copy.
- Derivative lineage is recorded only when a compatible tool performs the operation and signs the resulting container. It is not guaranteed across unrelated software.
- A screenshot restriction is an instruction. Enforcement depends on a host platform's capture controls and application integration.
- Rights declarations are not legal advice and do not themselves amend a license or contract.

## Development

```sh
python -m pip install '.[test]'
python -m pytest
```

## Repository status

This is an experimental 0.1 format. The v1 framing is intentionally small and specified in [FORMAT.md](FORMAT.md). Treat new versions as distinct protocol revisions; do not silently reinterpret signed fields.

## License

The repository software is available under the custom [NRAI End-User,
Non-Commercial License](LICENSE). It permits free, unmodified, non-commercial
end-user use; alterations and commercial use require separate written
permission from the copyright holder. This is source-available software, not
open source under the [Open Source Definition](https://opensource.org/osd),
which requires allowing derived works and use across fields of endeavor,
including business use. This license covers repository software, not image
assets or NRAI rights declarations created by users.
