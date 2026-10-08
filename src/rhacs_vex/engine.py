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

from .core.decide import (FP, POS, SEVERITY_FROM_SCANNER as _RHACS_SEVERITY_MAP,  # noqa: F401
                          UNSTATED_KINDS, triage, vex_product)
from .core.store import BASE_DIR, VEX_DIR, load_vex as _load_vex, read_vex as _read_vex  # noqa: F401
from .core.vexdoc import NOT_AFFECTED_FLAGS as _NOT_AFFECTED_FLAGS                # noqa: F401
from .core.versions import align_epochs as _normalize_epoch                        # noqa: F401
from .core.versions import evr_compare as compare_versions                         # noqa: F401
from .core.workload import (WorkloadContext, context_for_image,                    # noqa: F401
                            parse_context_from_labels, parse_image_ref)
from .sbom import (rpm_file_owners_from_sbom, rpm_source_map_from_sbom,            # noqa: F401
                   wire_rpm_owners)


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
