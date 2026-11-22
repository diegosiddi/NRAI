# NRAI — Protected Image Rights Protocol

NRAI is a prototype image container for carrying an unchanged source image byte stream alongside a signed, machine-readable rights manifest. It gives compatible software a common way to inspect rights, verify integrity, and record supported derivative operations.

**NRAI is a declaration and interoperability prototype, not DRM.** Unencrypted files carry signed rights declarations; optional encryption keeps the image payload unreadable without its passphrase. A recipient who can decrypt and display an image can still copy it, and a manifest cannot force uncooperative software to honor its rights declarations or guarantee that rights survive arbitrary edits, screenshots, re-encoding, or third-party conversion.

## What is included

- NRAI v1 container specification, revision 1.1, in [FORMAT.md](FORMAT.md), with binary interoperability vectors and an optional encrypted-payload profile.
- Python SDK and `nrai` CLI for key generation, creation, inspection, verification, export, and converted derivatives.
- A cross-platform desktop app for importing an image, configuring all six rights, and creating a signed `.nrai` file.
- An optional encrypted-payload profile using AES-256-GCM with a passphrase-derived key, so removing the NRAI wrapper leaves ciphertext.
- A companion desktop viewer that verifies `.nrai` files, requests a passphrase for encrypted images, displays their rights, and reports the declared screenshot policy.
- Platform file-type registration assets for macOS, Windows, and Linux so compatible desktop environments can identify and open `.nrai` files.
- Finder Quick Look and Windows Explorer thumbnail providers. Both verify the v1 manifest before decoding and suppress thumbnails for invalid files, encrypted payloads, or `screenshot: deny`.
- Android `FLAG_SECURE` integration sketch in [examples/android/ProtectedImageActivity.kt](examples/android/ProtectedImageActivity.kt).
- Tests and a sample independently configured rights file.

## Install

Python 3.9 or later is required. Install the package:

```sh
python -m pip install .
```

Tkinter is included with most standard Python distributions. On Linux, you may need to install your distribution's Tk package separately. The image creator does not re-encode the selected file; the exact source bytes are carried into the NRAI container.

The viewer needs Pillow when running from Python. Install it with `python -m pip install '.[images]'`.

## Desktop app

Launch the creator with:

```sh
nrai-desktop
```

Choose an image, set each rights value, optionally enter a creator name, and choose whether to encrypt the image with a passphrase. The image payload is encrypted before it is placed in the `.nrai` file; anyone who removes the wrapper without the passphrase gets ciphertext. Use a long, unique passphrase and share it only with intended viewers. Anyone who receives it can decrypt and copy the image, and losing it makes the image unrecoverable. Rights metadata remains readable without it.

The app creates an Ed25519 signing key on first launch in the current user's application-data directory and reuses it for future files. The private signing key stays on that computer and is not embedded in the NRAI file. It is currently stored as an unencrypted PEM file, so protect access to your computer and back it up securely if you need to sign future files with the same key; anyone who obtains it can sign files as that key. This signing key is separate from the image-encryption passphrase.

Launch **NRAI Viewer** to choose and inspect an existing `.nrai` file, or pass the path to `nrai-viewer`. The viewer checks the payload digest and signature before decoding the image and requests the passphrase for encrypted files. A valid signature without a trusted key confirms that the embedded key signed the manifest but does not identify its owner. Screenshot policy is displayed as a declaration; the viewer cannot block OS screenshots or screen recording.

To build a native app for the current platform, install PyInstaller and run:

```sh
python -m pip install '.[build-desktop]'
python -m PyInstaller --noconfirm --clean --windowed --name "NRAI Creator" --paths src nrai_desktop.py
python -m PyInstaller --noconfirm --clean --windowed --name "NRAI Viewer" --paths src nrai_viewer_desktop.py
```

On macOS this creates `dist/NRAI Creator.app` and `dist/NRAI Viewer.app`; on Windows, both app folders with their bundled dependencies appear under `dist/`. Build on each target platform. These development builds are not code-signed or notarized, so macOS may show its normal warning for apps from an unidentified developer. The **desktop builds** GitHub Actions workflow can build both apps for each platform on demand or when a `v*` tag is pushed, then attach them as workflow artifacts; it does not create a GitHub Release.

For a local macOS build, build the Quick Look extension in Xcode and bundle it with the Viewer:

```sh
xcodebuild -project platform/macos/NRAIQuickLook/NRAIQuickLook.xcodeproj \
  -scheme NRAIQuickLookExtension -configuration Release \
  -derivedDataPath build/macos-quicklook CODE_SIGNING_ALLOWED=NO build
python scripts/register_macos_bundle.py "dist/NRAI Viewer.app" \
  --thumbnail-extension "build/macos-quicklook/Build/Products/Release/NRAIQuickLookExtension.appex"
```

The desktop workflow builds and embeds this extension automatically. Its artifacts are ad-hoc signed, not Developer ID signed or notarized; distribution outside development may require signing and notarization for consistent Quick Look registration.

## Register the file type on desktop systems

- **macOS:** the Viewer declares `com.diegosiddi.nrai`, and its Quick Look Thumbnail Extension provides image thumbnails to Finder and other Quick Look clients. The extension verifies the signature and payload before decoding.
- **Windows:** the desktop artifact includes the Explorer handler and install/uninstall scripts. After extracting the Viewer build to a stable folder, open PowerShell there and run `./install-nrai.ps1 -ViewerExe './NRAI Viewer.exe' -ThumbnailHandlerDll './NraiThumbnailHandler.dll'`. This registers the file association and Explorer thumbnail provider for the current user. Windows Settings remains the place to change the preferred app. Run `./uninstall-nrai.ps1` to remove the association and handler.
- **Linux desktops using shared-mime-info:** install `platform/linux/application-x-nrai.xml` into the system or user MIME package directory and refresh the desktop MIME database. Install `platform/linux/nrai-viewer.desktop` and make it the preferred handler for `application/vnd.nrai`.

The native extensions produce thumbnails, not an editable view of rights. They decline to create thumbnails when verification fails, `screenshot: deny` is present, or the payload is encrypted. This avoids creating new cached preview pixels for those files, but cannot erase existing caches, prevent screenshots of the full viewer, or enforce policy system-wide. The Linux metadata currently enables open-with integration; no Linux thumbnailer is included.

## Quick start

```sh
nrai keygen --private creator.private.pem --public creator.public.pem
nrai create photo.jpg photo.nrai --private-key creator.private.pem \
  --rights examples/rights.json --creator 'Example creator'
nrai create confidential.jpg confidential.nrai --private-key creator.private.pem --encrypt
nrai inspect photo.nrai
nrai verify photo.nrai --trusted-key creator.public.pem
nrai-viewer photo.nrai
```

`verify` checks the payload digest and Ed25519 signature, including for encrypted files. With `--trusted-key`, it also checks that the signer matches the supplied key. Without a trusted key, a valid signature proves only that the embedded key signed the manifest; it does not establish who controls that key. `create --encrypt` prompts for a passphrase without echoing it. `export` prompts before decrypting encrypted files. Converting an encrypted file prompts for its current passphrase and carries encryption forward to the derivative.

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

The desktop viewer demo can display a valid image and show the `screenshot` declaration. Tkinter does not provide a portable way to stop OS screenshots, screen recording, remote desktop capture, cameras, or another program from reading pixels. It does not pretend to block screenshots.

The Android example shows how an application can set `WindowManager.LayoutParams.FLAG_SECURE` for the Activity window after validating the NRAI file and seeing `screenshot: deny`. Android documents this as preventing that window from appearing in screenshots and non-secure displays. It applies only when the image is displayed in that protected application window; it does not protect exported files, other apps, external cameras, rooted or compromised devices, or every device/vendor capture path. See the official [Android `FLAG_SECURE` reference](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE).

File-type associations and verified thumbnail handlers are included for macOS and Windows, but they do not enforce rights. Protecting arbitrary files system-wide would require OS-level support and cooperation from image decoders, display servers, and capture paths. A file extension, thumbnail handler, or file association alone cannot make screenshots white.

## Threat model and limits

NRAI is designed to detect accidental corruption and communicate a creator's declaration to software that chooses to cooperate.

- Ed25519 signatures cover all manifest fields, including each rights choice and the SHA-256 digest and length of the exact payload bytes.
- Signatures do not establish legal ownership or identity. Applications need an out-of-band trusted-key policy to associate a public key with a creator.
- Unencrypted NRAI payloads can be extracted directly. Encrypted payloads require the passphrase to recover the image after stripping, but any recipient who can decrypt and display the image can copy it. This passphrase profile does not provide per-recipient revocation, secure hardware playback, or screenshot prevention.
- The passphrase is not stored in the file; losing it means losing access to the image. The signed rights manifest remains visible, and the stored salt/ciphertext allow offline guessing of weak passphrases.
- Cryptographic verification detects edits to an existing NRAI file, but cannot stop a determined user from making an unmarked copy or a new file signed with their own key.
- Derivative lineage is recorded only when a compatible tool performs the operation and signs the resulting container. It is not guaranteed across unrelated software.
- A screenshot restriction is an instruction. Enforcement depends on a host platform's capture controls and application integration.
- Rights declarations are not legal advice and do not themselves amend a license or contract.

## Development

```sh
python -m pip install '.[test]'
python -m pytest
```

The frozen interoperability vectors are in `tests/vectors/v1/`; regenerate them with `PYTHONPATH=src python scripts/build_conformance_vectors.py`. The Swift thumbnail verifier is tested against the same catalog on macOS CI. The Windows Explorer handler is compiled on Windows CI. Native thumbnails are deliberately unavailable for encrypted files.

## Repository status

NRAI v1 remains the container revision specified in [FORMAT.md](FORMAT.md); revision 1.1 defines the optional encrypted-payload profile. The SDK and desktop apps remain prototype software. Treat incompatible changes as a new protocol version and do not silently reinterpret signed fields. `application/vnd.nrai` is currently a project media-type label, not an IANA registration.

## License

The repository software is licensed under the [Apache License, Version 2.0](LICENSE). It permits use, modification, redistribution, and commercial use, subject to its terms. The [NOTICE](NOTICE) credits Diego Siddi and asks users to provide attribution. Apache 2.0 does not require attribution just for using the software internally; when distributing derivative works, its section 4(d) requires preserving the attribution notice in one of the allowed locations. The request to credit Diego for other uses is informational, not an additional license condition.

The public repository can be forked and copied. Apache 2.0 grants the permissions described in the license, and GitHub repository visibility settings do not add restrictions to those permissions.
