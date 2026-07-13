"""trivy adapter — trivy image scan → triage DataFrame.

trivy is fed the live image (or its own JSON report): it skips the OCI root
of syft-SPDX SBOMs ("unsupported type"), so cross-feeding it syft output
loses the image identity (docs/OPENVEX-SPIKE-RESULTS.md).  Vulnerability ids
that are not CVEs (GHSA-…) are kept out — Red Hat VEX is CVE-keyed.
"""
from __future__ import annotations

import json
import os
import subprocess

import pandas as pd

# purl type → engine SOURCE vocabulary (same table shape as the grype adapter).
_PURL_TO_SOURCE = {
    'pkg:rpm':    'OS',
    'pkg:golang': 'GO',
    'pkg:pypi':   'PYTHON',
    'pkg:npm':    'NODEJS',
    'pkg:maven':  'JAVA',
}

_SEVERITY = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
             'low': 'LOW', 'unknown': ''}


def trivy_scan(target: str, *, platform: str = 'linux/amd64') -> dict:
    """Run trivy on an image ref, or load an existing trivy JSON report."""
    if os.path.exists(target):
        with open(target) as fh:
            return json.load(fh)
    proc = subprocess.run(
        ['trivy', 'image', target, '--platform', platform, '-f', 'json', '-q'],
        capture_output=True, text=True)
    if proc.returncode != 0:
        tail = (proc.stderr or '').strip().splitlines()[-3:]
        raise RuntimeError(f"trivy failed ({proc.returncode}): " + ' / '.join(tail))
    return json.loads(proc.stdout)


def _source_for(purl: str) -> str:
    for prefix, src in _PURL_TO_SOURCE.items():
        if str(purl).startswith(prefix):
            return src
    return ''


def to_df(trivy_doc: dict) -> pd.DataFrame:
    """Flatten trivy Results into the triage DataFrame shape (rhacs_to_df)."""
    rows, seen = [], set()
    for res in trivy_doc.get('Results', []):
        for v in res.get('Vulnerabilities') or []:
            cve = str(v.get('VulnerabilityID', '')).upper().strip()
            if not cve.startswith('CVE-'):
                continue
            cname, cver = v.get('PkgName', ''), v.get('InstalledVersion', '')
            key = (cname, cver, cve)
            if key in seen:
                continue
            seen.add(key)
            purl = (v.get('PkgIdentifier') or {}).get('PURL', '')
            rows.append({
                'COMPONENT':     cname,
                'VERSION':       cver,
                'CVE':           cve,
                'SEVERITY':      _SEVERITY.get(str(v.get('Severity', '')).lower(), ''),
                'CVSS':          0,
                'LINK':          v.get('PrimaryURL', ''),
                'FIXED_VERSION': v.get('FixedVersion', ''),
                'SOURCE':        _source_for(purl),
                'LOCATION':      res.get('Target', ''),
                'ADVISORY':      '',
                'ADVISORY_LINK': '',
                'SRPM':          v.get('SrcName', '') if v.get('SrcName') != cname else '',
            })
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=['COMPONENT', 'VERSION', 'CVE', 'SEVERITY', 'CVSS', 'LINK',
                 'FIXED_VERSION', 'SOURCE', 'LOCATION', 'ADVISORY', 'ADVISORY_LINK'])


def os_hint(trivy_doc: dict) -> str:
    """OS family:name string from trivy metadata (refines ctx.rhel_ver)."""
    md = (trivy_doc.get('Metadata') or {}).get('OS') or {}
    return f"{md.get('Family', '')}:{md.get('Name', '')}"
