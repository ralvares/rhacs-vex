"""grype and trivy JSON → the scanned Image and its findings.

A syft SBOM of the same image, when given, is the better inventory: findings
are joined to its packages (module streams, rpm vendors, file ownership).
"""
from __future__ import annotations

import json
import re
from typing import Optional

from .model import Finding, Image, Package
from .rpm import source_name
from .sbom import _KIND, image_from_source, package_name, settle_stream, split_ref

_CVE = re.compile(r'^CVE-\d{4}-\d+$', re.I)


def _load(doc):
    if isinstance(doc, str):
        with open(doc) as fh:
            return json.load(fh)
    return doc


def detect(doc: dict) -> str:
    """'syft' | 'grype' | 'trivy' | '' — what produced a JSON document."""
    if 'matches' in doc and 'source' in doc:
        return 'grype'
    if 'Results' in doc or 'SchemaVersion' in doc:
        return 'trivy'
    if 'artifacts' in doc and 'source' in doc:
        return 'syft'
    return ''


def _split_epoch(version: str) -> tuple:
    m = re.match(r'^(\d+):(.+)$', version or '')
    return (int(m.group(1)), m.group(2)) if m else (None, version or '')


# ── grype ───────────────────────────────────────────────────────────────────

def read_grype(doc) -> tuple:
    """→ (Image, [Finding]). One finding per (CVE, package)."""
    doc = _load(doc)
    src = doc.get('source') or {}
    d = doc.get('distro') or {}
    img = image_from_source(src.get('target') if isinstance(src.get('target'), dict) else {},
                            {'id': d.get('name', ''), 'versionID': d.get('version', '')})
    packages, findings, seen = {}, [], set()
    for m in doc.get('matches') or []:
        v, a = m.get('vulnerability') or {}, m.get('artifact') or {}
        cve = _cve_of(v.get('id', ''), [r.get('id', '') for r in m.get('relatedVulnerabilities') or []])
        if not cve:
            continue
        aid = a.get('id') or f"{a.get('name')}@{a.get('version')}"
        if aid not in packages:
            packages[aid] = _grype_package(a)
            img.packages.append(packages[aid])
        if (cve, aid) in seen:
            continue
        seen.add((cve, aid))
        fix = (v.get('fix') or {}).get('versions') or []
        findings.append(Finding(cve, packages[aid], 'grype', '' if _CVE.match(v.get('id', '')) else v.get('id', ''),
                                fix[0] if fix else '', v.get('severity', '')))
    settle_stream(img)
    return img, findings


def _cve_of(vid: str, related: list) -> str:
    if _CVE.match(vid or ''):
        return vid.upper()
    for r in related:
        if _CVE.match(r or ''):
            return r.upper()
    return ''


def _grype_package(a: dict) -> Package:
    kind = _KIND.get(a.get('type', ''), 'other')
    meta = a.get('metadata') or {}
    locs = tuple(l.get('accessPath') or l.get('path', '') for l in a.get('locations') or [])
    p = Package(kind, package_name(kind, a.get('name', ''), a.get('purl', '')), a.get('version', ''),
                purl=a.get('purl', ''), id=a.get('id', ''), locations=locs)
    if kind == 'rpm':
        p.epoch, p.version = _split_epoch(p.version)
        if meta.get('epoch') is not None:
            p.epoch = meta.get('epoch')
        ml = meta.get('modularityLabel')
        p.module = ':'.join(ml.split(':')[:2]) if ml else ('' if ml is not None else None)
        ups = a.get('upstreams') or []
        if ups:
            p.source = ups[0].get('name', '')
        else:
            m = re.search(r'[?&]upstream=([^&]+)', p.purl)
            p.source = source_name(m.group(1).replace('%2B', '+')) if m else ''
        m = re.search(r'[?&]arch=([^&]+)', p.purl)
        p.arch = m.group(1) if m else ''
    return p


# ── trivy ───────────────────────────────────────────────────────────────────

_TRIVY_KIND = {'gobinary': 'go', 'gomod': 'go', 'jar': 'java', 'pom': 'java', 'gradle': 'java',
               'node-pkg': 'npm', 'npm': 'npm', 'yarn': 'npm', 'pnpm': 'npm', 'python-pkg': 'python',
               'pip': 'python', 'pipenv': 'python', 'poetry': 'python', 'gemspec': 'gem', 'bundler': 'gem',
               'cargo': 'rust', 'rustbinary': 'rust', 'nuget': 'dotnet', 'dotnet-core': 'dotnet',
               'composer': 'php'}


def read_trivy(doc) -> tuple:
    """→ (Image, [Finding])."""
    doc = _load(doc)
    meta = doc.get('Metadata') or {}
    cfg = ((meta.get('ImageConfig') or {}).get('config') or {})
    os_ = meta.get('OS') or {}
    target = {'userInput': doc.get('ArtifactName', '') if doc.get('ArtifactType') == 'container_image' else '',
              'repoDigests': meta.get('RepoDigests') or [], 'labels': cfg.get('Labels') or {},
              'architecture': (meta.get('ImageConfig') or {}).get('architecture', '')}
    if meta.get('ImageID'):
        target['manifestDigest'] = ''
    family = (os_.get('Family') or '').lower()
    img = image_from_source(target, {'id': 'rhel' if family in ('redhat', 'rhel') else family,
                                     'versionID': os_.get('Name', '')})
    packages, findings, seen = {}, [], set()
    for res in doc.get('Results') or []:
        cls, typ = res.get('Class', ''), res.get('Type', '')
        kind = 'rpm' if cls == 'os-pkgs' and typ in ('redhat', 'centos', 'rocky', 'alma', 'oracle', 'fedora',
                                                     'amazon', 'photon', 'suse') else \
            ('other' if cls == 'os-pkgs' else _TRIVY_KIND.get(typ, 'other'))
        for v in res.get('Vulnerabilities') or []:
            cve = _cve_of(v.get('VulnerabilityID', ''), v.get('VendorIDs') or [])
            if not cve:
                continue
            p = _trivy_package(kind, v, res.get('Target', ''))
            key = (p.kind, p.name, p.version, p.locations[:1], p.arch)
            p = packages.setdefault(key, p)
            if p not in img.packages:
                img.packages.append(p)
            if (cve, key) in seen:
                continue
            seen.add((cve, key))
            findings.append(Finding(cve, p, 'trivy', '' if _CVE.match(v.get('VulnerabilityID', '')) else
                                    v.get('VulnerabilityID', ''), v.get('FixedVersion', ''), v.get('Severity', '')))
    settle_stream(img)
    return img, findings


def _trivy_package(kind: str, v: dict, target: str) -> Package:
    purl = (v.get('PkgIdentifier') or {}).get('PURL', '')
    name = v.get('PkgName', '')
    if kind == 'python':
        name = package_name('python', name, purl)
    loc = v.get('PkgPath') or ''
    p = Package(kind, name, v.get('InstalledVersion', ''), purl=purl,
                id=(v.get('PkgIdentifier') or {}).get('UID', ''), locations=(('/' + loc.lstrip('/')),) if loc else ())
    if kind == 'rpm':
        p.epoch, p.version = _split_epoch(p.version)
        m = re.search(r'[?&]epoch=(\d+)', purl)
        if m and p.epoch is None:
            p.epoch = int(m.group(1))
        m = re.search(r'[?&]arch=([^&]+)', purl)
        p.arch = m.group(1) if m else ''
        p.source = v.get('SrcName', '') or ''
    return p


# ── joining to an SBOM ──────────────────────────────────────────────────────

def join(findings: list, sbom: Image, scanned: Optional[Image] = None) -> list:
    """Point each finding at the SBOM's package for it (same id, else same kind,
    name and version, at the same location when several). Keeps the scanner's
    package when the SBOM has no match."""
    by_id = {p.id: p for p in sbom.packages if p.id}
    by_nv: dict = {}
    for p in sbom.packages:
        by_nv.setdefault((p.kind, p.name, p.version), []).append(p)
    for f in findings:
        q = f.package
        hit = by_id.get(q.id) if q.id else None
        if hit is None or (hit.kind, hit.name) != (q.kind, q.name):
            cands = by_nv.get((q.kind, q.name, q.version), [])
            if len(cands) > 1 and q.locations:
                cands = [c for c in cands if set(c.locations) & set(q.locations)] or cands
            hit = cands[0] if cands else None
        if hit is not None:
            f.package = hit
    return findings
