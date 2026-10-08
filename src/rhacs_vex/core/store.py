"""Reading Red Hat VEX documents from the local mirror (data/vex/CVE-*.json).

Fetching and syncing the mirror lives in rhacs_vex.mirror; this is only the
read side the engine needs.
"""
from __future__ import annotations

import functools
import json
import logging
import os
from typing import Optional

BASE_DIR = "data"
VEX_DIR = os.path.join(BASE_DIR, "vex")


def vex_path(cve_id: str) -> str:
    return os.path.join(VEX_DIR, f"{cve_id}.json")


def read_vex(cve_id: str) -> Optional[dict]:
    """Parse one VEX document, uncached — the caller owns its lifetime.

    A parsed document runs ~5x its file size, so a batch driver walking the work
    CVE-major reads each once and drops it.  A corrupt file is deleted so the
    next sync re-downloads it.
    """
    path = vex_path(cve_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as exc:
        logging.warning("Corrupt VEX file %s: %s — deleting to allow re-download", path, exc)
        try:
            os.unlink(path)
        except OSError:
            pass
        return None


def load_document(cve_id: str):
    """The parsed VexDocument for a CVE (None without a VEX file).

    The raw JSON is dropped as soon as the lookup tables are built, so a caller
    holds only the compact form.
    """
    from .vexdoc import VexDocument
    data = read_vex(cve_id)
    return VexDocument(data) if data is not None else None


@functools.lru_cache(maxsize=int(os.environ.get('VEX_CACHE_SIZE', '16')))
def load_vex(cve_id: str):
    """load_document behind a small LRU, for per-row callers."""
    return load_document(cve_id)
