"""Desktop viewer for signed NRAI image containers."""

import argparse
import io
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .container import RIGHTS, load_document, verify_document
from .crypto import load_public_key

RIGHT_LABELS = {
    "ai_training": "AI training",
    "ai_finetuning": "AI fine-tuning",
    "ai_inference": "AI inference",
    "ai_analysis": "AI analysis",
    "screenshot": "Screenshots",
    "redistribution": "Redistribution",
}


def load_verified_image(file_path, trusted_key_path=None):
    """Verify an NRAI document, then decode its image payload for display."""
    doc = load_document(file_path)
    trusted_key = load_public_key(trusted_key_path) if trusted_key_path else None
    valid, reason = verify_document(doc, trusted_key)
    if not valid:
        raise ValueError("Refusing to display an invalid NRAI file: " + reason)
    try:
        from PIL import Image
    except ImportError as exc:
        raise RuntimeError("Install Pillow to display NRAI images") from exc
    try:
        with Image.open(io.BytesIO(doc.payload)) as source:
            source.load()
            image = source.copy()
    except Exception as exc:
        raise ValueError("The verified NRAI payload is not a readable image: %s" % exc) from exc
    return doc, image, reason


class NraiViewerApp:
    def __init__(self, root, initial_file=None):
        self.root = root
        self.root.title("NRAI Viewer")
        self.root.minsize(760, 620)
        self.trusted_key_path = None
        self.image_ref = None

        toolbar = ttk.Frame(root, padding=(12, 10))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Open .nrai…", command=self.choose_file).pack(side="left")
        ttk.Button(toolbar, text="Choose trusted public key…", command=self.choose_trusted_key).pack(
            side="left", padx=(8, 0)
        )
        self.key_status = tk.StringVar(value="Signer identity not independently confirmed")
        ttk.Label(toolbar, textvariable=self.key_status).pack(side="left", padx=(12, 0))

        self.status = tk.StringVar(value="Open a signed NRAI image to verify and display it.")
        ttk.Label(root, textvariable=self.status, wraplength=900, padding=(12, 4)).pack(fill="x")

        content = ttk.Panedwindow(root, orient="horizontal")
        content.pack(fill="both", expand=True, padx=12, pady=8)
        preview_frame = ttk.LabelFrame(content, text="Image", padding=8)
        details_frame = ttk.LabelFrame(content, text="Declared rights", padding=12)
        content.add(preview_frame, weight=4)
        content.add(details_frame, weight=2)
        self.preview = ttk.Label(preview_frame, text="No image open", anchor="center")
        self.preview.pack(fill="both", expand=True)
        self.rights_text = tk.StringVar(value="Rights appear here after the file is verified.")
        ttk.Label(details_frame, textvariable=self.rights_text, justify="left", wraplength=250).pack(anchor="nw")
        self.screenshot_note = tk.StringVar(value="")
        ttk.Label(
            details_frame,
            textvariable=self.screenshot_note,
            wraplength=250,
            foreground="#8a3b12",
        ).pack(anchor="nw", pady=(12, 0))

        self.root.bind("<Configure>", self._resize_image)
        self.current_path = None
        self.current_image = None
        self.current_document = None
        if initial_file:
            self.open_file(initial_file)

    def choose_file(self):
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Open an NRAI image",
            filetypes=[("NRAI files", "*.nrai"), ("All files", "*")],
        )
        if path:
            self.open_file(path)

    def choose_trusted_key(self):
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Choose a trusted Ed25519 public key",
            filetypes=[("PEM public keys", "*.pem"), ("All files", "*")],
        )
        if not path:
            return
        self.trusted_key_path = path
        self.key_status.set("Trusted key selected: %s" % Path(path).name)
        if self.current_path:
            self.open_file(self.current_path)

    def open_file(self, path):
        try:
            doc, image, reason = load_verified_image(path, self.trusted_key_path)
            from PIL import ImageTk
            photo = ImageTk.PhotoImage(image)
        except (OSError, ValueError, RuntimeError) as exc:
            self.status.set("Could not open this NRAI file.")
            messagebox.showerror("NRAI Viewer", str(exc), parent=self.root)
            return
        self.current_path = str(path)
        self.current_document = doc
        self.current_image = image
        self.image_ref = photo
        self.preview.configure(image=photo, text="")
        signer = "signature valid; signer identity unverified" if not self.trusted_key_path else "signature valid with selected trusted key"
        self.status.set("%s — %s" % (Path(path).name, signer))
        self._show_rights(doc)
        self.root.title("NRAI Viewer — " + Path(path).name)
        self._resize_image()

    def _show_rights(self, doc):
        rights = doc.manifest.get("rights", {})
        self.rights_text.set(
            "\n".join("%s: %s" % (RIGHT_LABELS[name], rights.get(name, "unspecified")) for name in RIGHTS)
        )
        if rights.get("screenshot", "unspecified") == "deny":
            self.screenshot_note.set(
                "Screenshot use is marked deny. This app cannot block OS screenshots, recording, or external capture."
            )
        else:
            self.screenshot_note.set("Screenshot policy: %s" % rights.get("screenshot", "unspecified"))

    def _resize_image(self, _event=None):
        if self.current_image is None:
            return
        from PIL import ImageTk

        width = max(120, self.preview.winfo_width() - 20)
        height = max(120, self.preview.winfo_height() - 20)
        display = self.current_image.copy()
        display.thumbnail((width, height))
        self.image_ref = ImageTk.PhotoImage(display)
        self.preview.configure(image=self.image_ref)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Open and verify signed NRAI image containers")
    parser.add_argument("file", nargs="?", help="optional .nrai file to open")
    parser.add_argument("--trusted-key", help="optional trusted Ed25519 public key PEM")
    args = parser.parse_args(argv)
    root = tk.Tk()
    app = NraiViewerApp(root)
    if args.trusted_key:
        app.trusted_key_path = args.trusted_key
        app.key_status.set("Trusted key selected: %s" % Path(args.trusted_key).name)
    if args.file:
        app.open_file(args.file)
    else:
        root.after(100, app.choose_file)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
