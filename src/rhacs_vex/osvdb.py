"""CVE ↔ upstream package, for the components Red Hat never names.

Red Hat assesses vendored Go / Python / npm / Java code at the IMAGE (or the
rpm that ships the binary), so its VEX says "image X is not affected by CVE-Y"
without naming the module.  To put a real subcomponent purl on that statement —
the identity grype and trivy match on — we need to know which packages CVE-Y is
about.  The OSV dataset says exactly that, per ecosystem, with affected ranges.

Data: the OSV bulk exports, one zip per ecosystem, under data/osv/
(`vextriage osv-sync`, or https://storage.googleapis.com/osv-vulnerabilities/
<Ecosystem>/all.zip).  Fully offline once downloaded.
"""
from __future__ import annotations

import functools
import json
import os
import re
import zipfile
from typing import Dict, List, Optional

OSV_DIR = os.path.join('data', 'osv')
OSV_BUCKET = 'https://storage.googleapis.com/osv-vulnerabilities'

# syft artifact type → OSV ecosystem
ECOSYSTEMS = {
    'go-module': 'Go',
    'python': 'PyPI',
    'npm': 'npm',
    'java-archive': 'Maven',
}


def download(ecosystems=None, console=None) -> None:
    """Fetch the OSV bulk export for each ecosystem into data/osv/."""
    import requests
    os.makedirs(OSV_DIR, exist_ok=True)
    for eco in ecosystems or ECOSYSTEMS.values():
        url = f'{OSV_BUCKET}/{eco}/all.zip'
        path = os.path.join(OSV_DIR, f'{eco}.zip')
        with requests.get(url, stream=True, timeout=600) as res:
            res.raise_for_status()
            with open(path + '.part', 'wb') as fh:
                for blk in res.iter_content(1 << 20):
                    fh.write(blk)
        os.replace(path + '.part', path)
        if console:
            console.print(f"   {eco}: {os.path.getsize(path) / 1e6:.0f} MB")
    _load.cache_clear()


@functools.lru_cache(maxsize=None)
def _load(ecosystem: str) -> Dict[str, List[tuple]]:
    """package name → [(CVE ids, ranges, versions)] for one ecosystem."""
    path = os.path.join(OSV_DIR, f'{ecosystem}.zip')
    out: Dict[str, List[tuple]] = {}
    if not os.path.exists(path):
        return out
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            try:
                rec = json.loads(z.read(name))
            except Exception:
                continue
            cves = tuple(sorted({a for a in [rec.get('id', ''), *rec.get('aliases', [])]
                                 if a.startswith('CVE-')}))
            if not cves or rec.get('withdrawn'):
                continue
            for aff in rec.get('affected', []):
                pkg = aff.get('package') or {}
                if pkg.get('ecosystem', '').split(':')[0] != ecosystem or not pkg.get('name'):
                    continue
                out.setdefault(_key(ecosystem, pkg['name']), []).append(
                    (cves, aff.get('ranges') or [], tuple(aff.get('versions') or ())))
    return out


def available(ecosystem: str) -> bool:
    return os.path.exists(os.path.join(OSV_DIR, f'{ecosystem}.zip'))


def _key(ecosystem: str, name: str) -> str:
    if ecosystem == 'PyPI':
        return re.sub(r'[-_.]+', '-', name).lower()
    return name


def cves_for(ecosystem: str, name: str, version: str) -> List[str]:
    """CVEs whose OSV record lists this package version as affected.

    A record with no usable range (or a range type we cannot evaluate) counts
    as affected: the candidate only proposes a pair, the Red Hat VEX decides.
    """
    hits = set()
    for cves, ranges, versions in _load(ecosystem).get(_key(ecosystem, name), ()):
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
