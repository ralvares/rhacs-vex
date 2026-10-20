"""Red Hat CSAF-VEX → OpenVEX, per image, from a syft SBOM.

    syft SBOM → candidates (VEX index + OSV, optionally grype) → engine → OpenVEX

No vulnerability scanner is required: the candidate pairs come from the two
data sets that name components (candidates.py) and the verdict is always Red
Hat's, through the same engine every triage path uses.  Every false positive is
published so a scanner drops what triage drops; the ones the engine inferred
rather than read off a statement about this build say so in their
impact_statement (`stated_only=True` publishes only the others).

Every subcomponent `@id` is the purl syft recorded for that artifact, reduced
to the cross-scanner form proven in docs/OPENVEX-SPIKE-RESULTS.md.
"""
from __future__ import annotations

from typing import Optional

import pandas as pd

from . import candidates, openvex
from .audit import audit_frame
from .core.workload import context_for_image
from .sbom import SyftSBOM


def triage_sbom(image_ref: str, sbom: SyftSBOM, index, *, ocp_release: Optional[str] = None,
                findings: Optional[pd.DataFrame] = None, use_osv: bool = True,
                vex_product: bool = False):
    """(context, triage result) for every candidate pair of one image's SBOM.

    vex_product adds the VEX_PRODUCT column (the triage table shows it; the
    OpenVEX path does not need it and skips the lookup).
    """
    df = candidates.merge(candidates.from_sbom(sbom, index, image_ref=image_ref,
                                               use_osv=use_osv), findings)
    ctx = context_for_image(image_ref, os_hint=sbom.os_hint(), labels=sbom.labels or {},
                            digests=sbom.digests, ocp_release=ocp_release)
    if df.empty:
        return ctx, df
    sbom.enrich(df, ctx)
    return ctx, audit_frame(df, ctx, vex_product=vex_product)


def generate(image_ref: str, sbom: SyftSBOM, index, *, ocp_release: Optional[str] = None,
             findings: Optional[pd.DataFrame] = None, use_osv: bool = True,
             stated_only: bool = False):
    """(statements, triage result) for one digest-pinned image."""
    _ctx, result = triage_sbom(image_ref, sbom, index, ocp_release=ocp_release,
                               findings=findings, use_osv=use_osv)
    if result.empty:
        return [], result
    return openvex.statements_from_df(result, image_ref, stated_only=stated_only), result
