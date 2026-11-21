# NRAI — Protected Image Rights Protocol

NRAI is a prototype image container for carrying an unchanged source image byte stream alongside a signed, machine-readable rights manifest. It gives compatible software a common way to inspect rights, verify integrity, and record supported derivative operations.

**NRAI is a declaration and interoperability prototype, not DRM.** A manifest cannot force an uncooperative program to honor it, stop an image from being copied, or guarantee that rights survive arbitrary edits, screenshots, re-encoding, or third-party conversion. The viewer and SDK demonstrate cooperative behavior only.

## What is included

- Version 1 container specification in [FORMAT.md](FORMAT.md).
- Python SDK and `nrai` CLI for key generation, creation, inspection, verification, export, and converted derivatives.
- A cross-platform desktop app for importing an image, configuring all six rights, and creating a signed `.nrai` file.
- A companion desktop viewer that verifies `.nrai` files, displays their images and rights, and reports the declared screenshot policy.
- Platform file-type registration assets for macOS, Windows, and Linux so compatible desktop environments can identify and open `.nrai` files.
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

Choose an image, set each rights value, optionally enter a creator name, and choose where to save the `.nrai` file. The app creates an Ed25519 signing key on first launch in the current user's application-data directory and reuses it for future files. The private key stays on that computer and is not embedded in the NRAI file. Back it up securely if you need to sign future files with the same key; anyone who obtains it can sign as that key. The app also saves the matching public key next to it.

Launch **NRAI Viewer** to choose and inspect an existing `.nrai` file, or pass the path to `nrai-viewer`. The viewer checks the payload digest and signature before decoding the image, displays all six rights, and can optionally verify against a trusted public key. A valid signature without a trusted key confirms that the embedded key signed the manifest but does not identify its owner. Screenshot policy is displayed as a declaration; the viewer cannot block OS screenshots or screen recording.

To build a native app for the current platform, install PyInstaller and run:

```sh
python -m pip install '.[build-desktop]'
python -m PyInstaller --noconfirm --clean --windowed --name "NRAI Creator" --paths src nrai_desktop.py
python -m PyInstaller --noconfirm --clean --windowed --name "NRAI Viewer" --paths src nrai_viewer_desktop.py
```

On macOS this creates `dist/NRAI Creator.app` and `dist/NRAI Viewer.app`; on Windows, both app folders with their bundled dependencies appear under `dist/`. Build on each target platform. These development builds are not code-signed or notarized, so macOS may show its normal warning for apps from an unidentified developer. The **desktop builds** GitHub Actions workflow can build both apps for each platform on demand or when a `v*` tag is pushed, then attach them as workflow artifacts; it does not create a GitHub Release.

For a local macOS build, add the file-type declaration to the Viewer bundle with `python scripts/register_macos_bundle.py "dist/NRAI Viewer.app"`. The desktop workflow runs this step automatically for its macOS artifact.

## Register the file type on desktop systems

- **macOS:** the Viewer app bundle declares the exported `com.diegosiddi.nrai` Uniform Type Identifier and handles `.nrai` documents. Finder can then open selected files in NRAI Viewer. This does not add an operating-system Quick Look thumbnail or system image decoder.
- **Windows:** after extracting the Viewer build to a stable folder, run `platform/windows/install-nrai.ps1 -ViewerExe 'C:\path\to\NRAI Viewer.exe'` in PowerShell. This registers the file association for the current Windows user. Windows Settings remains the place to change the preferred app. Run `platform/windows/uninstall-nrai.ps1` to remove the association.
- **Linux desktops using shared-mime-info:** install `platform/linux/application-x-nrai.xml` into the system or user MIME package directory and refresh the desktop MIME database. Install `platform/linux/nrai-viewer.desktop` and make it the preferred handler for `application/vnd.nrai`.

These integrations make compatible desktop shells recognize and open NRAI files. Image preview remains inside NRAI Viewer; native Finder Quick Look and Windows Explorer thumbnail or preview handlers are not included in this prototype. Those need dedicated platform extensions and additional signing, packaging, and validation work.

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

The desktop viewer demo can display a valid image and show the `screenshot` declaration. Tkinter does not provide a portable way to stop OS screenshots, screen recording, remote desktop capture, cameras, or another program from reading pixels. It does not pretend to block screenshots.

The Android example shows how an application can set `WindowManager.LayoutParams.FLAG_SECURE` for the Activity window after validating the NRAI file and seeing `screenshot: deny`. Android documents this as preventing that window from appearing in screenshots and non-secure displays. It applies only when the image is displayed in that protected application window; it does not protect exported files, other apps, external cameras, rooted or compromised devices, or every device/vendor capture path. See the official [Android `FLAG_SECURE` reference](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE).

File-type open associations are included for desktop platforms, but they do not enforce rights. Protecting arbitrary files system-wide would require OS-level support and cooperation from image decoders, display servers, and capture paths. A file extension or file association alone cannot make screenshots white.

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

This repository is public. GitHub's terms allow other GitHub users to view and
fork public repositories, and changing a repository to private later does not
remove existing forks or local copies. See [GitHub's repository licensing
guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository).
The custom license states the permitted uses; it cannot technically prevent
copies or forks from being made.
