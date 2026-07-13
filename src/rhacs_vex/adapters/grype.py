"""grype adapter — syft SBOM generation + grype scan → triage DataFrame.

Flow (docs/OPENVEX-SPIKE-RESULTS.md): syft must emit **syft-json** (the SPDX
export drops repoDigests and grype then has no image identity to match VEX
products against); grype runs with --by-cve so GHSA aliases collapse onto the
CVE ids the Red Hat VEX files are keyed by.
"""
from __future__ import annotations

import json
import os
import re
import subprocess

import pandas as pd

SYFT_DIR = os.path.join('data', 'syft')

# grype artifact type → the SOURCE vocabulary the engine already knows from
# RHACS scans (GO/OS/PYTHON/...).  Unknown types stay unmapped and their rows
# are still triaged; they just mint no subcomponent purl on export.
_TYPE_TO_SOURCE = {
    'rpm':          'OS',
    'go-module':    'GO',
    'python':       'PYTHON',
    'npm':          'NODEJS',
    'java-archive': 'JAVA',
}

_SEVERITY = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
             'low': 'LOW', 'negligible': 'LOW'}


def _run(cmd: list, what: str) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        tail = (proc.stderr or '').strip().splitlines()[-3:]
        raise RuntimeError(f"{what} failed ({proc.returncode}): " + ' / '.join(tail))
    return proc


def syft_sbom(image_ref: str, *, platform: str = 'linux/amd64',
              force: bool = False) -> str:
    """Generate (or reuse) the syft-json SBOM for an image ref; returns path."""
    os.makedirs(SYFT_DIR, exist_ok=True)
    path = os.path.join(SYFT_DIR, image_ref.replace('/', '_') + '.json')
    if not force and os.path.exists(path) and os.path.getsize(path) > 0:
        return path
    _run(['syft', f'registry:{image_ref}', '--platform', platform,
          '-o', f'syft-json={path}'], 'syft')
    return path


def grype_scan(target: str) -> dict:
    """Run grype (CVE-normalized ids) on an SBOM path or image ref."""
    src = f'sbom:{target}' if os.path.exists(target) else f'registry:{target}'
    proc = _run(['grype', src, '--by-cve', '-o', 'json'], 'grype')
    return json.loads(proc.stdout)


def sbom_labels(sbom_path: str) -> dict:
    """Image labels recorded in the syft-json SBOM (source.metadata.labels).

    Saves a skopeo inspect per image — the SBOM already carries the OCI config.
    {} when absent (e.g. scratch images), letting callers fall back.
    """
    try:
        with open(sbom_path) as fh:
            doc = json.load(fh)
        return (doc.get('source', {}).get('metadata') or {}).get('labels') or {}
    except Exception:
        return {}


def to_df(grype_doc: dict) -> pd.DataFrame:
    """Flatten grype matches into the triage DataFrame shape (rhacs_to_df)."""
    rows, seen = [], set()
    for m in grype_doc.get('matches', []):
        vuln, art = m.get('vulnerability', {}), m.get('artifact', {})
        cve = str(vuln.get('id', '')).upper().strip()
        if not cve.startswith('CVE-'):
            continue
        cname, cver = art.get('name', ''), art.get('version', '')
        key = (cname, cver, cve)
        if key in seen:
            continue
        seen.add(key)
        locations = art.get('locations') or [{}]
        fix = (vuln.get('fix') or {}).get('versions') or []
        # source-rpm name from the purl's upstream qualifier — Red Hat verdicts
        # are per source package, so the emitter extends rpm statements to it.
        srpm = ''
        m_up = re.search(r'upstream=([^&]+?)-[^-]+-[^-]+\.src\.rpm', art.get('purl', ''))
        if m_up:
            srpm = m_up.group(1)
        rows.append({
            'COMPONENT':     cname,
            'VERSION':       cver,
            'CVE':           cve,
            'SEVERITY':      _SEVERITY.get(str(vuln.get('severity', '')).lower(), ''),
            'CVSS':          0,
            'LINK':          vuln.get('dataSource', ''),
            'FIXED_VERSION': fix[0] if fix else '',
            'SOURCE':        _TYPE_TO_SOURCE.get(art.get('type', ''), ''),
            'LOCATION':      locations[0].get('path', ''),
            'ADVISORY':      '',
            'ADVISORY_LINK': '',
            'SRPM':          srpm,
        })
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=['COMPONENT', 'VERSION', 'CVE', 'SEVERITY', 'CVSS', 'LINK',
                 'FIXED_VERSION', 'SOURCE', 'LOCATION', 'ADVISORY', 'ADVISORY_LINK'])


def os_hint(grype_doc: dict) -> str:
    """Distro string from the grype document (refines ctx.rhel_ver)."""
    d = grype_doc.get('distro') or {}
    return f"{d.get('name', '')}:{d.get('version', '')}"
