"""Public engine API — a stable facade over rhacs_vex.core.

    audit_row_detailed(row, ctx) -> pd.Series([verdict, fix, justification,
                                               severity, state, stated])

The implementation lives in core/:
    versions.py  rpm version arithmetic, dist-tags, module streams
    vexdoc.py    one CSAF-VEX document parsed into lookup tables
    workload.py  the scanned image's identity (WorkloadContext)
    scope.py     is a VEX product this workload's product
    decide.py    the decision ladder, severity, state
    store.py     reading the local VEX mirror
"""
from __future__ import annotations

from typing import Optional

from .core.decide import triage, vex_product
from .core.store import load_vex as _load_vex      # module-level so tests can patch it
from .core.workload import (WorkloadContext, context_for_image,  # noqa: F401  (re-exports)
                            parse_context_from_labels, parse_image_ref)


def audit_row_with_doc(row, ctx: WorkloadContext, data: Optional[dict]) -> list:
    """The six verdict values for one finding, on a document the caller holds."""
    return triage(row, ctx, data).as_list()


def audit_row_detailed(row, ctx: WorkloadContext):
    """audit_row_with_doc on the mirrored document, as a pandas Series."""
    import pandas as pd
    cve = str(row['CVE']).strip().upper()
    return pd.Series(audit_row_with_doc(row, ctx, _load_vex(cve)))


def _vex_product_with_doc(row, ctx, data) -> str:
    return vex_product(data, str(row.get('COMPONENT', '')), ctx)


def _vex_product_for_row(row, ctx) -> str:
    cve = str(row.get('CVE', '')).strip().upper()
    return _vex_product_with_doc(row, ctx, _load_vex(cve))
