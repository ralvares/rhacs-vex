"""CVE ↔ upstream package, for the components Red Hat never names.

Red Hat assesses vendored Go / Python / npm / Java code at the IMAGE (or the
rpm that ships the binary), so its VEX says "image X is not affected by CVE-Y"
without naming the module.  To put a real subcomponent purl on that statement —
the identity grype and trivy match on — we need to know which packages CVE-Y is
about.  The OSV dataset says exactly that, per ecosystem, with affected ranges.

Data: the OSV bulk exports, one zip per ecosystem, under data/osv/, loaded
into the on-disk index by `vextriage sync` (vexindex.build_osv) and queried one
package at a time.  Fully offline once downloaded.
"""
from __future__ import annotations

import os
import re
from typing import List, Optional

OSV_DIR = os.path.join('data', 'osv')
OSV_BUCKET = 'https://storage.googleapis.com/osv-vulnerabilities'

# syft artifact type → OSV ecosystem
ECOSYSTEMS = {
    'go-module': 'Go',
    'python': 'PyPI',
    'npm': 'npm',
    'java-archive': 'Maven',
}


def download(ecosystems=None, console=None) -> list:
    """Fetch each ecosystem's OSV bulk export into data/osv/ — only when it changed.

    The ETag of the copy on disk is sent back (If-None-Match); an unchanged
    export answers 304 and costs nothing.  Returns the ecosystems that changed.
    """
    import requests
    os.makedirs(OSV_DIR, exist_ok=True)
    changed = []
    for eco in ecosystems or ECOSYSTEMS.values():
        url = f'{OSV_BUCKET}/{eco}/all.zip'
        path = os.path.join(OSV_DIR, f'{eco}.zip')
        tag_path = path + '.etag'
        headers = {}
        if os.path.exists(path) and os.path.exists(tag_path):
            with open(tag_path) as fh:
                headers['If-None-Match'] = fh.read().strip()
        with requests.get(url, stream=True, timeout=600, headers=headers) as res:
            if res.status_code == 304:
                if console:
                    console.print(f"   {eco}: unchanged")
                continue
            res.raise_for_status()
            with open(path + '.part', 'wb') as fh:
                for blk in res.iter_content(1 << 20):
                    fh.write(blk)
            os.replace(path + '.part', path)
            if res.headers.get('ETag'):
                with open(tag_path, 'w') as fh:
                    fh.write(res.headers['ETag'])
        changed.append(eco)
        if console:
            console.print(f"   {eco}: {os.path.getsize(path) / 1e6:.0f} MB (updated)")
    return changed


def available(ecosystem: str, index=None) -> bool:
    return bool(index is not None and hasattr(index, 'has_osv') and index.has_osv(ecosystem))


def cves_for(ecosystem: str, name: str, version: str, index=None) -> List[str]:
    """CVEs whose OSV record lists this package version as affected.

    Reads the package's records from the on-disk index (vexindex.py) — nothing
    is held in memory.  A record with no usable range counts as affected: the
    candidate only proposes a pair, the Red Hat VEX decides.
    """
    if index is None or not hasattr(index, 'osv'):
        return []
    hits = set()
    for cves, ranges, versions in index.osv(ecosystem, name):
        if _affected(ecosystem, version, ranges, versions):
            hits.update(cves)
    return sorted(hits)


# ── version ranges ───────────────────────────────────────────────────────────

def _affected(eco, version, ranges, versions) -> bool:
    if versions and version in versions:
        return True
    evaluable = [r for r in ranges if r.get('type') in ('SEMVER', 'ECOSYSTEM')]
    if not evaluable:
        return not versions             # nothing to evaluate → propose it
    v = _norm(eco, version)
    for r in evaluable:
        try:
            if _in_range(eco, v, r.get('events', [])):
                return True
        except Exception:
            return True                 # unparseable version → let the VEX decide
    return False


def _in_range(eco, v, events) -> bool:
    """OSV semantics: v is affected if some introduced ≤ v and no fixed/last
    bound between that introduced and v."""
    intro = [e['introduced'] for e in events if 'introduced' in e]
    bounds = [(e.get('fixed'), e.get('last_affected')) for e in events
              if 'fixed' in e or 'last_affected' in e]
    for i in intro:
        if i != '0' and _cmp(eco, v, i) < 0:
            continue
        closed = False
        for fixed, last in bounds:
            if fixed and (i == '0' or _cmp(eco, fixed, i) > 0) and _cmp(eco, v, fixed) >= 0:
                closed = True
            if last and (i == '0' or _cmp(eco, last, i) >= 0) and _cmp(eco, v, last) > 0:
                closed = True
        if not closed:
            return True
    return False


def _norm(eco: str, version: str) -> str:
    v = str(version or '').strip()
    if eco == 'Go':
        v = re.sub(r'^go', '', v)        # stdlib: go1.21.3
        v = v[1:] if v.startswith('v') else v
        v = v.split('+')[0]
    return v


def _cmp(eco: str, a: str, b: str) -> int:
    a, b = _norm(eco, a), _norm(eco, b)
    if eco == 'PyPI':
        from packaging.version import Version
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    return _semverish(a, b)


def _semverish(a: str, b: str) -> int:
    """Semver-like compare (Go pseudo-versions, npm, Maven dotted versions)."""
    def split(v):
        core, _, pre = v.partition('-')
        nums = [int(x) if x.isdigit() else x for x in re.split(r'[.]', core)]
        return nums, pre

    (na, pa), (nb, pb) = split(a), split(b)
    for x, y in zip(na + [0] * (len(nb) - len(na)), nb + [0] * (len(na) - len(nb))):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return 1 if x > y else -1
        return 1 if str(x) > str(y) else -1
    if pa == pb:
        return 0
    if not pa:
        return 1                         # release > pre-release
    if not pb:
        return -1
    return 1 if pa > pb else -1


def ecosystem_of(artifact_type: str) -> Optional[str]:
    return ECOSYSTEMS.get(artifact_type)
