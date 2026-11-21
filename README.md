# NRAI — Protected Image Rights Protocol

NRAI is a prototype image container for carrying an unchanged source image byte stream alongside a signed, machine-readable rights manifest. It gives compatible software a common way to inspect rights, verify integrity, and record supported derivative operations.

**NRAI is a declaration and interoperability prototype, not DRM.** A manifest cannot force an uncooperative program to honor it, stop an image from being copied, or guarantee that rights survive arbitrary edits, screenshots, re-encoding, or third-party conversion. The viewer and SDK demonstrate cooperative behavior only.

## What is included

- Version 1 container specification in [FORMAT.md](FORMAT.md).
- Python SDK and 0nrai0 CLI for key generation, creation, inspection, verification, export, and converted derivatives.
- A cross-platform desktop app for importing an image, configuring all six rights, and creating a signed 0.nrai0 file.
- A small desktop viewer that refuses invalid signatures and displays the declared screenshot policy.
- Android 0FLAG_SECURE0 integration sketch in [examples/android/ProtectedImageActivity.kt](examples/android/ProtectedImageActivity.kt).
- Tests and a sample independently configured rights file.

## Install

Python 3.9 or later is required. Install the package:

`sh
python -m pip install .
`

Tkinter is included with most standard Python distributions. On Linux, you may need to install your distribution's Tk package separately. The image creator does not re-encode the selected file; the exact source bytes are carried into the NRAI container.

## Desktop app

Launch the creator with:

`sh
nrai-desktop
`

Choose an image, set each rights value, optionally enter a creator name, and choose where to save the `.nrai0 file. The app creates an Ed25519 signing key on first launch in the current user's application-data directory and reuses it for future files. The private key stays on that computer and is not embedded in the NRAI file. Back it up securely if you need to sign future files with the same key; anyone who obtains it can sign as that key. The app also saves the matching public key next to it.

To build a native app for the current platform, install PyInstaller and run:

`sh
python -m pip install '.[build-desktop]'
python -m PyInstaller --noconfirm --clean --windowed --name NRAI --paths src nrai_desktop.py
`

On macOS this creates `dist/NRAI.app0; on Windows it creates `dist/NRAI.exe0. Build on each target platform. These development builds are not code-signed or notarized, so macOS may show its normal warning for apps from an unidentified developer. The **desktop builds** GitHub Actions workflow can build both platforms on demand or when a `v*0 tag is pushed, then attach the files as workflow artifacts; it does not create a GitHub Release.

## Quick start

`sh
nrai keygen --private creator.private.pem --public creator.public.pem
nrai create photo.jpg photo.nrai --private-key creator.private.pem   --rights examples/rights.json --creator 'Example creator'
nrai inspect photo.nrai
nrai verify photo.nrai --trusted-key creator.public.pem
nrai-viewer photo.nrai
`

`verify0 checks the payload digest and Ed25519 signature. With `--trusted-key0, it also checks that the signer matches the supplied key. Without a trusted key, a valid signature proves only that the embedded key signed the manifest; it does not establish who controls that key.

Convert to another image encoding while carrying rights into a newly signed NRAI file:

`sh
nrai convert photo.nrai photo-small.nrai --to webp --private-key creator.private.pem
`

The conversion records the parent asset ID and payload digest. It copies rights because this SDK controls the conversion path. If you export raw image bytes, a JSON sidecar is written next to them, but the exported image itself has no NRAI enforcement:

`sh
nrai export photo.nrai exported-photo.jpg
`

## Rights model

Each right has its own `allow0, `deny0, `ask0, or `unspecified0 value. Supported keys are `ai_training0, `ai_finetuning0, `ai_inference0, `ai_analysis0, `screenshot0, and `redistribution0. Missing keys become `unspecified0; software should not interpret that as permission. The manifest is signed as a whole, so changing any policy requires a new signature.

## Viewer and screenshot behavior

The desktop viewer demo can display a valid image and show the `screenshot0 declaration. Tkinter does not provide a portable way to stop OS screenshots, screen recording, remote desktop capture, cameras, or another program from reading pixels. It does not pretend to block screenshots.

The Android example shows how an application can set `WindowManager.LayoutParams.FLAG_SECURE0 for the Activity window after validating the NRAI file and seeing `screenshot: deny0. Android documents this as preventing that window from appearing in screenshots and non-secure displays. It applies only when the image is displayed in that protected application window; it does not protect exported files, other apps, external cameras, rooted or compromised devices, or every device/vendor capture path. See the official [Android `FLAG_SECURE0 reference](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE).

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

`sh
python -m pip install '.[test]'
python -m pytest
`

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

This repository is public. GitHub's terms allow other GitHub users to view and
fork public repositories, and changing a repository to private later does not
remove existing forks or local copies. See [GitHub's repository licensing
guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository).
The custom license states the permitted uses; it cannot technically prevent
copies or forks from being made.
