# NRAI v1.0 compatibility vectors

`catalog.json` lists signed valid and malformed binary samples with their
expected acceptance result. `valid.nrai` is a deterministic 2×2 PNG example;
the fixed test signing seed is intentionally public and must never be used for
real NRAI files. `valid-manifest.json` is the manifest embedded in that file.

Regenerate the fixture files from the repository root with:

```sh
PYTHONPATH=src python scripts/build_conformance_vectors.py
```

Implementations should consume the frozen binary files and catalog directly.
Regeneration is for maintainers; do not replace the valid fixture with a
production signing key.
