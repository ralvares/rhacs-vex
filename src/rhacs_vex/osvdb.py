"""CVE ↔ upstream package, for the components Red Hat never names.

Red Hat assesses vendored Go / Python / npm / Java code at the IMAGE (or the
rpm that ships the binary), so its VEX says "image X is not affected by CVE-Y"
without naming the module.  To put a real subcomponent purl on that statement —
the identity grype and trivy match on — we need to know which packages CVE-Y is
about.  The OSV dataset says exactly that, per ecosystem, with affected ranges.

Data: OSV's per-ecosystem exports, imported into the on-disk index by
`vextriage sync` (`sync` below) and queried one package at a time — only the
records that carry a CVE alias, about 49 MB of the 245 MB the four exports
weigh (npm is 97% `MAL-` malware reports).  After the first import a sync
fetches just the records changed since, from OSV's `modified_id.csv`.  Nothing
is kept on disk but the index; fully offline once synced.
"""
from __future__ import annotations

import os
import re
import tempfile
import time
from datetime import datetime, timezone
from typing import List, Optional

OSV_BUCKET = 'https://storage.googleapis.com/osv-vulnerabilities'
DELTA_LIMIT = 5000           # more changed records than this → re-import the export
LEGACY_DIR = os.path.join('data', 'osv')     # where older versions kept the exports

# syft artifact type → OSV ecosystem
ECOSYSTEMS = {
    'go-module': 'Go',
    'python': 'PyPI',
    'npm': 'npm',
    'java-archive': 'Maven',
}


def sync(index_path: str, ecosystems=None, console=None, workers: int = 8,
         full_threshold: int = DELTA_LIMIT) -> dict:
    """Bring the index's OSV tables level with OSV — fetching only what changed.

    First run per ecosystem: the bulk export is streamed to a temporary file,
    imported (CVE-aliased records only) and deleted.  After that, OSV's
    `modified_id.csv` (newest first) is read down to the last import and only
    those records are fetched one by one — `MAL-` malware reports are skipped
    unread, so npm's 8 MB change list costs a few records, not 218 MB.
    Returns {ecosystem: 'full N' | 'delta N' | 'current'}.
    """
    import requests
    from . import vexindex
    out = {}
    for eco in ecosystems or ECOSYSTEMS.values():
        have = vexindex.osv_stamp(eco, index_path)
        newest, changed = _changes_since(eco, have, full_threshold)
        if have and changed is not None:
            if not changed:
                out[eco] = 'current'
            else:
                recs, gone = _fetch_records(eco, changed, workers)
                n = vexindex.upsert_osv(eco, recs, index_path, stamp=newest, removed=gone)
                out[eco] = f'delta {len(changed):,} record(s) → {n:,} row(s)'
        elif not have and os.path.exists(os.path.join(LEGACY_DIR, f'{eco}.zip')):
            # an export a previous version kept on disk: import it once, from
            # its download time on, then free the space
            old = os.path.join(LEGACY_DIR, f'{eco}.zip')
            since = datetime.fromtimestamp(os.path.getmtime(old), timezone.utc) \
                .strftime('%Y-%m-%dT%H:%M:%S.000000000Z')
            n = vexindex.import_osv_zip(old, eco, index_path, stamp=since)
            os.unlink(old)
            for leftover in (old + '.etag', old + '.part'):
                if os.path.exists(leftover):
                    os.unlink(leftover)
            out[eco] = f'imported the local export → {n:,} row(s); next sync fetches changes'
        else:
            fd, tmp = tempfile.mkstemp(suffix=f'.{eco}.zip')
            os.close(fd)
            try:
                with requests.get(f'{OSV_BUCKET}/{eco}/all.zip', stream=True, timeout=600) as res:
                    res.raise_for_status()
                    with open(tmp, 'wb') as fh:
                        for blk in res.iter_content(1 << 20):
                            fh.write(blk)
                size = os.path.getsize(tmp)
                n = vexindex.import_osv_zip(tmp, eco, index_path, stamp=newest)
                out[eco] = f'full {size / 1e6:.0f} MB → {n:,} row(s)'
            finally:
                os.unlink(tmp)
        if console:
            console.print(f"   {eco}: {out[eco]}")
    return out


def _changes_since(eco: str, stamp: str, limit: int):
    """(newest modified time, [changed non-MAL ids]) from modified_id.csv.

    The list is None when there is no stamp or more than *limit* records
    changed — the bulk export is cheaper then.
    """
    import requests
    newest, ids = '', []
    with requests.get(f'{OSV_BUCKET}/{eco}/modified_id.csv', stream=True, timeout=120) as res:
        res.raise_for_status()
        for line in res.iter_lines(decode_unicode=True):
            if not line or ',' not in line:
                continue
            modified, rid = line.split(',', 1)
            newest = newest or modified
            if not stamp:
                break                        # only the newest time is needed
            if modified <= stamp:
                break                        # sorted newest first
            if rid.startswith('MAL-'):
                continue
            ids.append(rid.strip())
            if len(ids) > limit:
                return newest, None
    return newest, (ids if stamp else None)


def _fetch_records(eco: str, ids, workers: int):
    """([record], [ids that no longer exist]) — one GET per changed record."""
    import requests
    from concurrent.futures import ThreadPoolExecutor
    session = requests.Session()

    def get(rid):
        for attempt in range(5):
            try:
                r = session.get(f'{OSV_BUCKET}/{eco}/{rid}.json', timeout=60)
                if r.status_code == 404:
                    return rid, None
                if r.status_code < 500:
                    r.raise_for_status()
                    return rid, r.json()
            except requests.ConnectionError:
                pass
            time.sleep(2 ** attempt)
        raise RuntimeError(f'could not fetch OSV record {eco}/{rid}')

    recs, gone = [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for rid, rec in ex.map(get, ids):
            (recs.append(rec) if rec is not None else gone.append(rid))
    return recs, gone


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
