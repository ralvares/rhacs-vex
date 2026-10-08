"""Red Hat CSAF-VEX → OpenVEX, per image, from a syft SBOM.

    syft SBOM ─┬─ rpm artifacts ─────── VEX index (rpm purl → CVEs)    ┐
               ├─ the image itself ──── VEX index (oci repo → CVEs)    ├→ engine → OpenVEX
               ├─ go/pypi/npm/maven ─── OSV (package+version → CVEs)   │   (every false
               └─ (optional) grype findings                            ┘    positive)

No vulnerability scanner is required.  The candidate (component, CVE) pairs
come from the two data sets that name components: Red Hat's own VEX for rpms
and the image, and OSV for the language packages Red Hat never names as purls.
The verdict is always Red Hat's, through the same engine every triage path
uses.  Every false positive is published so a scanner drops what triage drops;
the ones the engine inferred rather than read off a statement about this build
say so in their impact_statement (`stated_only=True` publishes only the others).

Every subcomponent `@id` is the purl syft recorded for that artifact, reduced
to the cross-scanner form proven in docs/OPENVEX-SPIKE-RESULTS.md (bare purl,
no qualifiers; golang in both `v` and non-`v` versions).
"""
from __future__ import annotations

import os
import re
from typing import Optional

import pandas as pd

from . import openvex, osvdb, scanfree
from .audit import audit_frame
from .core.store import vex_path
from .core.workload import context_for_image
from .sbom import SyftSBOM, srpm_from_purl

ROW_COLUMNS = ['COMPONENT', 'VERSION', 'CVE', 'SEVERITY', 'CVSS', 'LINK', 'FIXED_VERSION',
               'SOURCE', 'LOCATION', 'ADVISORY', 'ADVISORY_LINK', 'SRPM', 'PURL']

# syft artifact type → the SOURCE vocabulary the engine and emitter use
_SOURCE = {'rpm': 'OS', 'go-module': 'GO', 'python': 'PYTHON', 'npm': 'NODEJS',
           'java-archive': 'JAVA'}


def _row(comp, ver, cve, source, location='', srpm='', purl=''):
    return {'COMPONENT': comp, 'VERSION': ver, 'CVE': cve, 'SEVERITY': '', 'CVSS': 0,
            'LINK': '', 'FIXED_VERSION': '', 'SOURCE': source, 'LOCATION': location,
            'ADVISORY': '', 'ADVISORY_LINK': '', 'SRPM': srpm, 'PURL': purl}


def _component_name(art: dict) -> str:
    """The name the engine matches on: Maven as group:artifact, others as-is."""
    if art.get('type') == 'java-archive':
        m = re.match(r'pkg:maven/([^/]+)/([^@?]+)', art.get('purl') or '')
        if m:
            return f"{m.group(1)}:{m.group(2)}"
    return art.get('name', '')


def candidates(sbom: SyftSBOM, index: dict, *, image_ref: str = '',
               use_osv: bool = True) -> pd.DataFrame:
    """Every (component, CVE) pair Red Hat's VEX could decide for this image."""
    rpm_idx, oci_idx = index.get('rpm') or {}, index.get('oci') or {}
    rows, seen = [], set()

    def add(comp, ver, cve, *a, **kw):
        if (comp, ver, cve) not in seen and os.path.exists(vex_path(cve)):
            seen.add((comp, ver, cve))
            rows.append(_row(comp, ver, cve, *a, **kw))

    for art in sbom.artifacts:
        kind, name, ver = art.get('type'), art.get('name', ''), str(art.get('version', ''))
        purl = art.get('purl') or ''
        if not (name and ver):
            continue
        loc = ((art.get('locations') or [{}])[0] or {}).get('path', '')
        if kind == 'rpm':
            srpm = srpm_from_purl(purl)
            cves = set(rpm_idx.get(scanfree.rpm_purl_name(purl) if purl else name, ()))
            if srpm:
                cves |= set(rpm_idx.get(srpm, ()))
            for cve in sorted(cves):
                add(name, ver, cve, 'OS', 'var/lib/rpm', srpm, purl)
        elif use_osv and osvdb.ecosystem_of(kind):
            for cve in osvdb.cves_for(osvdb.ecosystem_of(kind), name, ver, index):
                add(_component_name(art), ver, cve, _SOURCE[kind], loc, '', purl)

    keys, comp, ver = scanfree.image_identity(
        scanfree.repo_from_ref(image_ref) if image_ref else '', sbom.labels)
    for key in keys:
        for cve in oci_idx.get(key, ()):
            add(comp, ver, cve, scanfree.IMAGE_SOURCE, 'root/buildinfo/labels.json')
    return pd.DataFrame(rows, columns=ROW_COLUMNS)


def merge_findings(base: pd.DataFrame, findings: Optional[pd.DataFrame]) -> pd.DataFrame:
    """Union scanner findings (e.g. grype) into the candidates; scanner rows win."""
    if findings is None or findings.empty:
        return base
    findings = findings.copy()
    for col in ROW_COLUMNS:
        if col not in findings.columns:
            findings[col] = ''
    have = set(zip(findings['COMPONENT'], findings['VERSION'], findings['CVE']))
    extra = base[[k not in have for k in zip(base['COMPONENT'], base['VERSION'], base['CVE'])]]
    return pd.concat([findings[ROW_COLUMNS], extra], ignore_index=True)


def generate(image_ref: str, sbom: SyftSBOM, index: dict, *, ocp_release: Optional[str] = None,
             findings: Optional[pd.DataFrame] = None, use_osv: bool = True,
             stated_only: bool = False):
    """(statements, triage result) for one digest-pinned image."""
    df = merge_findings(candidates(sbom, index, image_ref=image_ref, use_osv=use_osv),
                        findings)
    ctx = context_for_image(image_ref, os_hint=sbom.os_hint(), labels=sbom.labels or {},
                            digests=sbom.digests, ocp_release=ocp_release)
    if df.empty:
        return [], df
    sbom.enrich(df, ctx)
    result = audit_frame(df, ctx, vex_product=False)
    return openvex.statements_from_df(result, image_ref, stated_only=stated_only), result
