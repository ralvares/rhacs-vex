"""One finding, one verdict — the engine's per-row entry point.

    audit_row_detailed(row, ctx) -> pd.Series([verdict, fix, justification,
                                               severity, state, stated])

Batch callers use audit.py (CVE-major, one document read per CVE).  The
implementation lives in core/: csaf (one CSAF-VEX document as statements),
judge (the verdict), versions (rpm arithmetic, dist-tags, module streams),
workload (the scanned image), store (the local mirror).
"""
from __future__ import annotations

import pandas as pd

from .core.csaf import Document
from .core.judge import judge
from .core.store import load_vex as _load_vex      # module-level so tests can patch it
from .core.workload import (WorkloadContext,  # noqa: F401  (re-exports)
                            parse_context_from_labels, parse_image_ref)

__all__ = ['audit_row_detailed', 'WorkloadContext', 'parse_context_from_labels', 'parse_image_ref']


def audit_row_detailed(row, ctx: WorkloadContext) -> pd.Series:
    """The six verdict values for one finding, on the mirrored document."""
    cve = str(row['CVE']).strip().upper()
    doc = _load_vex(cve)
    if isinstance(doc, dict):
        doc = Document(doc)
    return pd.Series(judge(row, ctx, doc).as_list())
