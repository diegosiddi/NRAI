"""NRAI Protected Image Rights Protocol prototype."""

__version__ = "0.1.0"

from .container import NraiDocument, create_document, load_document, save_document, verify_document
from .crypto import generate_keypair

__all__ = [
    "NraiDocument", "create_document", "load_document", "save_document",
    "generate_keypair", "verify_document", "__version__",
]
