"""Candidate (component, CVE) pairs: what Red Hat's VEX could decide for an image.

A scanner, the VEX index and OSV only *propose* pairs; the engine decides them.
Every path builds its rows here, so a pair carries the same columns and the
same identity whichever source proposed it:

    syft SBOM ─┬─ rpm artifacts ─────── VEX index (rpm purl → CVEs)
               ├─ the image itself ──── VEX index (oci repo → CVEs)
               └─ go/pypi/npm/maven ─── OSV (package + version → CVEs)
    scanner findings (RHACS, grype, trivy) + the same index lookups

Coverage of the index is the mirror image of a scanner's: rpms and images are
complete (Red Hat enumerates every binary subpackage and the syft purl and the
VEX purl agree on name, version-release, arch and epoch), while vendored Go and
Python are assessed at the image, never at the module purl, so OSV or a scanner
supplies those.  Identity comes from the purl throughout.
"""
from __future__ import annotations

import os
import re
from typing import Optional

import pandas as pd

from . import osv
from .core.store import vex_path
from .core.versions import sbom_module
from .sbom import SyftSBOM, srpm_from_purl
from .vexindex import rpm_purl_name

ROW_COLUMNS = ['COMPONENT', 'VERSION', 'CVE', 'SEVERITY', 'CVSS', 'LINK', 'FIXED_VERSION',
               'SOURCE', 'LOCATION', 'ADVISORY', 'ADVISORY_LINK', 'SRPM', 'PURL', 'MODULE']

# syft / grype artifact type → the SOURCE vocabulary the engine and emitter use
SOURCE_OF_TYPE = {'rpm': 'OS', 'go-module': 'GO', 'python': 'PYTHON', 'npm': 'NODEJS',
                  'java-archive': 'JAVA'}

# Rows minted for the image itself use SOURCE='IMAGE' rather than 'OS': an
# image-identity pseudo-component carries a path ('openshift/ose-cli-rhel9'),
# and minted as an rpm purl it would be an identity no scanner emits.
IMAGE_SOURCE = 'IMAGE'
IMAGE_LOCATION = 'root/buildinfo/labels.json'
RPM_LOCATION = 'var/lib/rpm'


def row(comp, ver, cve, source, location='', srpm='', purl='', module='') -> dict:
    """One candidate.  MODULE: an rpm's module stream ('nodejs:20'), 'non-modular' when
    the SBOM says it is not modular, '' when unknown."""
    return {'COMPONENT': comp, 'VERSION': ver, 'CVE': cve, 'SEVERITY': '', 'CVSS': 0,
            'LINK': '', 'FIXED_VERSION': '', 'SOURCE': source, 'LOCATION': location,
            'ADVISORY': '', 'ADVISORY_LINK': '', 'SRPM': srpm, 'PURL': purl, 'MODULE': module}


def empty_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=ROW_COLUMNS)


# ── the image's own identity ─────────────────────────────────────────────────

def repo_from_ref(image_ref: str) -> str:
    """Repo path of an image reference, digest and tag dropped."""
    ref = (image_ref or '').split('@')[0]
    head, _, tail = ref.rpartition('/')
    return f"{head}/{tail.partition(':')[0]}" if head else tail.partition(':')[0]


def image_identity(repo: str, labels) -> tuple:
    """(index keys, pseudo-component, version) for the image's own identity.

    Both the repo path as pulled and the `name` label are looked up: the two
    purl eras index the image under either form (§4a), and an art-dev build
    carries no labels at all.
    """
    labels = labels or {}
    label_name = labels.get('name') or ''
    keys = {repo, repo.split('/')[-1]} if repo else set()
    if label_name:
        keys |= {label_name, label_name.split('/')[-1]}
    comp = label_name or (repo.split('/')[-1] if repo else '')
    return {k for k in keys if k}, comp, labels.get('release') or labels.get('version') or ''


# ── lookups ──────────────────────────────────────────────────────────────────

def _rpm_cves(index, name: str, srpm: str = '') -> set:
    """CVEs whose VEX names the binary rpm or its source rpm (Red Hat often tracks
    a subpackage under its source, so a binary-only lookup would miss candidates)."""
    rpm_idx = index.get('rpm') or {}
    cves = set(rpm_idx.get(name, ()))
    if srpm:
        cves |= set(rpm_idx.get(srpm, ()))
    return cves


def _image_rows(index, image_ref: str, labels) -> list:
    oci_idx = index.get('oci') or {}
    keys, comp, ver = image_identity(repo_from_ref(image_ref), labels)
    if not comp:
        return []
    cves = set()
    for key in keys:
        cves |= set(oci_idx.get(key, ()))
    return [row(comp, ver, cve, IMAGE_SOURCE, IMAGE_LOCATION) for cve in sorted(cves)]


class _Rows:
    """Rows keyed (component, version, CVE), first one wins."""

    def __init__(self, have=()):
        self.seen, self.rows = set(have), []

    def add(self, r: dict, *, need_vex: bool = False) -> None:
        """need_vex: keep the pair only when Red Hat publishes VEX for the CVE.
        Index CVEs always have a document; OSV proposes many that have none,
        and those could only come back as "no VEX file" noise."""
        key = (r['COMPONENT'], r['VERSION'], r['CVE'])
        if key not in self.seen and (not need_vex or os.path.exists(vex_path(r['CVE']))):
            self.seen.add(key)
            self.rows.append(r)


def _component_name(art: dict) -> str:
    """The name the engine matches on: Maven as group:artifact, others as-is."""
    if art.get('type') == 'java-archive':
        m = re.match(r'pkg:maven/([^/]+)/([^@?]+)', art.get('purl') or '')
        if m:
            return f"{m.group(1)}:{m.group(2)}"
    return art.get('name', '')


# ── builders ─────────────────────────────────────────────────────────────────

def from_sbom(sbom: SyftSBOM, index, *, image_ref: str = '', use_osv: bool = True) -> pd.DataFrame:
    """Every pair the VEX index (rpm + image) and OSV (language packages) propose."""
    out = _Rows()
    for art in sbom.artifacts:
        kind, name, ver = art.get('type'), art.get('name', ''), str(art.get('version', ''))
        purl = art.get('purl') or ''
        if not (name and ver):
            continue
        if kind == 'rpm':
            srpm = srpm_from_purl(purl)
            module = sbom_module((art.get('metadata') or {}).get('modularityLabel'))
            for cve in sorted(_rpm_cves(index, rpm_purl_name(purl) if purl else name, srpm)):
                out.add(row(name, ver, cve, 'OS', RPM_LOCATION, srpm, purl, module))
        elif use_osv and osv.ecosystem_of(kind):
            loc = ((art.get('locations') or [{}])[0] or {}).get('path', '')
            for cve in osv.cves_for(osv.ecosystem_of(kind), name, ver, index):
                out.add(row(_component_name(art), ver, cve, SOURCE_OF_TYPE[kind], loc, '', purl),
                        need_vex=True)
    for r in _image_rows(index, image_ref, sbom.labels):
        out.add(r)
    return pd.DataFrame(out.rows, columns=ROW_COLUMNS)


def osv_evidence(sbom: SyftSBOM, index):
    """osv.Evidence over the SBOM's language packages (None without OSV data)."""
    if index is None or not hasattr(index, 'osv_packages'):
        return None
    owners = sbom.file_owners()
    mods = []
    for art in sbom.artifacts:
        eco = osv.ecosystem_of(art.get('type'))
        name, ver = _component_name(art), str(art.get('version', ''))
        if not (eco and name and ver):
            continue
        loc = ((art.get('locations') or [{}])[0] or {}).get('path', '')
        owner = owners.get(loc) or owners.get('/' + loc.lstrip('/'))
        mods.append((eco, name, ver, owner[0] if owner else ''))
    return osv.Evidence(index, mods) if mods else None


def add_to_findings(df: pd.DataFrame, index, *, image_ref: str = '', labels=None) -> tuple:
    """Scanner findings plus every pair the VEX index can decide; (df, added).

    The two sources are complements: a scanner enumerates the classes Red Hat
    publishes no purls for, the index the classes it does.  Scanner rows win on
    collision (their severity, fix and location are richer); rpm candidates
    come from the rpms the scanner reported, plus the image's own identity.
    """
    if df is None or not index or not {'COMPONENT', 'VERSION', 'CVE', 'SOURCE'} <= set(df.columns):
        return df, 0
    out = _Rows(zip(df['COMPONENT'], df['VERSION'], df['CVE']) if len(df) else ())
    if len(df):
        os_rows = df[df['SOURCE'].astype(str).str.upper() == 'OS']
        srpms = os_rows['SRPM'] if 'SRPM' in os_rows else [''] * len(os_rows)
        for comp, ver, srpm in sorted({(str(c), str(v), str(s or '')) for c, v, s in
                                       zip(os_rows['COMPONENT'], os_rows['VERSION'], srpms)}):
            if '/' in comp:          # an image pseudo-component, not an rpm name
                continue
            srpm = '' if srpm.lower() in ('nan', 'none') else srpm
            for cve in sorted(_rpm_cves(index, comp, srpm)):
                out.add(row(comp, ver, cve, 'OS', RPM_LOCATION, srpm))
    for r in _image_rows(index, image_ref, labels):
        out.add(r)
    if not out.rows:
        return df, 0
    # added rows take the frame's columns: nothing invented, nothing it lacks
    extra = pd.DataFrame(out.rows).reindex(columns=df.columns, fill_value='')
    return pd.concat([df, extra], ignore_index=True), len(out.rows)


def merge(candidates: pd.DataFrame, findings: Optional[pd.DataFrame]) -> pd.DataFrame:
    """Union scanner findings into the candidates; scanner rows win."""
    if findings is None or findings.empty:
        return candidates
    findings = findings.reindex(columns=ROW_COLUMNS, fill_value='')
    have = set(zip(findings['COMPONENT'], findings['VERSION'], findings['CVE']))
    extra = candidates[[k not in have for k in
                        zip(candidates['COMPONENT'], candidates['VERSION'], candidates['CVE'])]]
    return pd.concat([findings, extra], ignore_index=True)
