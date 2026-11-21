"""Small desktop viewer that respects NRAI's screenshot=deny declaration within its own UI."""

import argparse
import io
import tkinter as tk

from .container import load_document, verify_document


def main(argv=None):
    parser = argparse.ArgumentParser(description="NRAI cooperative viewer demonstration")
    parser.add_argument("file")
    args = parser.parse_args(argv)
    doc = load_document(args.file)
    valid, reason = verify_document(doc)
    if not valid:
        raise SystemExit("Refusing to display invalid container: " + reason)
    try:
        from PIL import Image, ImageTk
    except ImportError:
        raise SystemExit("Install the optional Pillow dependency to run the viewer")
    image = Image.open(io.BytesIO(doc.payload))
    root = tk.Tk()
    root.title("NRAI cooperative viewer — " + args.file)
    screenshot_denied = doc.manifest.get("rights", {}).get("screenshot") == "deny"
    note = "Screenshot denied by manifest. This demo cannot block OS screenshots or external capture." if screenshot_denied else "Screenshot policy: " + str(doc.manifest.get("rights", {}).get("screenshot", "unspecified"))
    tk.Label(root, text=note, wraplength=700, padx=12, pady=8).pack()
    preview = ImageTk.PhotoImage(image)
    label = tk.Label(root, image=preview)
    label.image = preview
    label.pack()
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
