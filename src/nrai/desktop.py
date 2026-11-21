"""Cross-platform desktop app for creating signed NRAI image containers."""

import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .container import RIGHTS, RIGHTS_VALUES, create_document, media_type_for, save_document
from .crypto import generate_keypair, load_private_key

RIGHT_LABELS = {
    "ai_training": "AI training",
    "ai_finetuning": "AI fine-tuning",
    "ai_inference": "AI inference",
    "ai_analysis": "AI analysis",
    "screenshot": "Screenshots",
    "redistribution": "Redistribution",
}
RIGHT_HELP = {
    "allow": "Allow",
    "deny": "Deny",
    "ask": "Ask first",
    "unspecified": "Unspecified",
}


def key_directory():
    """Return the per-user NRAI key directory for the current platform."""
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "NRAI" / "keys"


def ensure_default_key():
    """Load or create this user's default Ed25519 signing key pair."""
    directory = key_directory()
    private_path = directory / "creator.private.pem"
    public_path = directory / "creator.public.pem"
    directory.mkdir(parents=True, exist_ok=True)
    if not private_path.exists():
        generate_keypair(private_path, public_path)
    elif not public_path.exists():
        # Reconstruct the public half if it was removed; the private key remains
        # the source of truth and is never written into an output .nrai file.
        from cryptography.hazmat.primitives import serialization

        public = load_private_key(private_path).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_path.write_bytes(public)
    return private_path


def create_image_container(image_path, output_path, rights, private_key, creator=""):
    """Wrap unchanged source image bytes in a signed NRAI file."""
    source = Path(image_path)
    target = Path(output_path)
    if not source.is_file():
        raise ValueError("Choose an existing image file.")
    if source.resolve() == target.resolve():
        raise ValueError("The output file must be different from the source image.")
    mime_type = media_type_for(source)
    if not mime_type.startswith("image/"):
        raise ValueError("The selected file type is not recognized as an image.")
    payload = source.read_bytes()
    document = create_document(payload, mime_type, rights, private_key, creator.strip() or None)
    save_document(document, target)
    return document


class NraiDesktopApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NRAI Image Rights")
        self.root.minsize(620, 660)
        self.source_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.creator = tk.StringVar()
        self.status = tk.StringVar(value="Choose an image to get started.")
        self.rights = {name: tk.StringVar(value="unspecified") for name in RIGHTS}

        try:
            self.private_key_path = ensure_default_key()
            self.private_key = load_private_key(self.private_key_path)
        except (OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror("Signing key unavailable", str(exc), parent=root)
            raise

        self._build_ui()

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=20)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Create an NRAI image", font=("TkDefaultFont", 18, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text="Keep the image bytes intact and attach your signed rights choices.",
            wraplength=570,
        ).pack(anchor="w", pady=(4, 16))

        source_frame = ttk.LabelFrame(outer, text="1. Image", padding=12)
        source_frame.pack(fill="x", pady=(0, 12))
        source_row = ttk.Frame(source_frame)
        source_row.pack(fill="x")
        ttk.Entry(source_row, textvariable=self.source_path, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(source_row, text="Choose image…", command=self.choose_image).pack(side="left", padx=(8, 0))
        ttk.Label(source_frame, text="The original image file bytes are stored unchanged.").pack(anchor="w", pady=(8, 0))

        creator_frame = ttk.LabelFrame(outer, text="2. Creator (optional)", padding=12)
        creator_frame.pack(fill="x", pady=(0, 12))
        ttk.Entry(creator_frame, textvariable=self.creator).pack(fill="x")

        rights_frame = ttk.LabelFrame(outer, text="3. Rights manifest", padding=12)
        rights_frame.pack(fill="both", expand=True, pady=(0, 12))
        ttk.Label(rights_frame, text="Choose a value for each use. Unspecified does not mean allowed.").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )
        for row, name in enumerate(RIGHTS, start=1):
            ttk.Label(rights_frame, text=RIGHT_LABELS[name]).grid(row=row, column=0, sticky="w", padx=(0, 24), pady=4)
            combo = ttk.Combobox(
                rights_frame,
                textvariable=self.rights[name],
                values=RIGHTS_VALUES,
                state="readonly",
                width=18,
            )
            combo.grid(row=row, column=1, sticky="w", pady=4)
            combo.set("unspecified")
        rights_frame.columnconfigure(1, weight=1)

        output_frame = ttk.LabelFrame(outer, text="4. Save NRAI file", padding=12)
        output_frame.pack(fill="x", pady=(0, 12))
        output_row = ttk.Frame(output_frame)
        output_row.pack(fill="x")
        ttk.Entry(output_row, textvariable=self.output_path, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(output_row, text="Choose location…", command=self.choose_output).pack(side="left", padx=(8, 0))

        key_note = "Signing key: %s\nKeep this key private. Anyone with it can sign files as this key." % self.private_key_path
        ttk.Label(outer, text=key_note, wraplength=570, foreground="#555555").pack(anchor="w", pady=(0, 10))

        footer = ttk.Frame(outer)
        footer.pack(fill="x")
        ttk.Label(footer, textvariable=self.status, wraplength=400).pack(side="left", fill="x", expand=True)
        ttk.Button(footer, text="Create .nrai", command=self.create_file).pack(side="right")

    def choose_image(self):
        selected = filedialog.askopenfilename(
            parent=self.root,
            title="Choose an image",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.gif *.webp *.bmp *.tif *.tiff *.heic *.avif"),
                ("All files", "*"),
            ],
        )
        if not selected:
            return
        self.source_path.set(selected)
        self.output_path.set(str(Path(selected).with_suffix(".nrai")))
        self.status.set("Image selected. Choose rights and save the NRAI file.")

    def choose_output(self):
        initial = self.output_path.get() or "image.nrai"
        selected = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save NRAI file",
            defaultextension=".nrai",
            initialfile=Path(initial).name,
            initialdir=str(Path(initial).parent) if Path(initial).parent.exists() else None,
            filetypes=[("NRAI files", "*.nrai")],
        )
        if selected:
            if not selected.lower().endswith(".nrai"):
                selected += ".nrai"
            self.output_path.set(selected)

    def create_file(self):
        source = self.source_path.get()
        output = self.output_path.get()
        if not source:
            messagebox.showinfo("Choose an image", "Choose an image file first.", parent=self.root)
            return
        if not output:
            self.choose_output()
            output = self.output_path.get()
        if not output:
            return
        choices = {name: value.get() for name, value in self.rights.items()}
        try:
            create_image_container(source, output, choices, self.private_key, self.creator.get())
        except (OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror("Could not create NRAI file", str(exc), parent=self.root)
            self.status.set("Could not create the file.")
            return
        self.status.set("Created %s" % output)
        messagebox.showinfo(
            "NRAI file created",
            "Saved the signed rights manifest and original image bytes to:\n%s" % output,
            parent=self.root,
        )


def main():
    root = tk.Tk()
    try:
        NraiDesktopApp(root)
    except (OSError, ValueError, RuntimeError):
        root.destroy()
        return 1
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
