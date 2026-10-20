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

It also maps scanner advisory IDs (`GHSA-…`, `GO-…`) to the CVE Red Hat
publishes VEX under (`resolve`): from the same index first, and only for an ID
it does not hold from api.osv.dev (never with VEX_OFFLINE set).  Unresolved IDs
stay as they were — "no VEX file" is the right answer when no CVE exists.
"""
from __future__ import annotations

import functools
import json
import os
import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import List, Optional

import requests

from .core import versions as V

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


class Evidence:
    """What OSV says about the modules an image's SBOM lists, per CVE.

    modules: [(eco, name, version, owner_rpm)] — every Go / PyPI / npm / Maven
    package syft found, with the rpm whose file carries it ('' if none).
    judge() answers for one CVE and a scope of those modules (one rpm's, or the
    whole image's):

      ('affected', mods)  a module of the scope is in the CVE's vulnerable range
      ('clear', mods)     the CVE's packages are in the scope, all past the fix
      None                no evidence: OSV does not know the CVE, the scope is
                          empty, or none of the CVE's packages is in it

    Absence is never evidence: syft lists a fork or a replace target under its
    own name (the jwt code of golang-jwt/jwt ships as dgrijalva/jwt-go or
    form3tech-oss/jwt-go), and code bundled into a binary (undici in node,
    pip's _vendor, Red Hat's FIPS Go toolchain) is not listed at all.
    """

    def __init__(self, index, modules):
        self.index, self.modules = index, list(modules)
        self._rev = None

    def _packages(self, cve) -> set:
        if self._rev is None:
            rev: dict = {}
            for eco, pkg, cves in self.index.osv_packages():
                for c in cves.split():
                    rev.setdefault(c, set()).add((eco, pkg))
            self._rev = rev
        return self._rev.get(cve, set())

    def judge(self, cve, owner=None, module=None):
        """owner: only that rpm's modules; module: only (name, version)."""
        from .vexindex import package_key
        scope = [m for m in self.modules if (owner is None or m[3] == owner)
                 and (module is None or (m[1], m[2]) == module)]
        pkgs = self._packages(cve)
        if not scope or not pkgs:
            return None
        rel = [m for m in scope if (m[0], package_key(m[0], m[1])) in pkgs]
        if not rel:
            return None
        hit = [m for m in rel if any(cve in cves and _affected(m[0], m[2], ranges, versions)
                                     for cves, ranges, versions in self.index.osv(m[0], m[1]))]
        return ('affected', hit) if hit else ('clear', rel)


# ── version ranges ───────────────────────────────────────────────────────────

def _affected(eco, version, ranges, versions) -> bool:
    v = _norm(eco, version)
    if not re.match(r'\d', v):
        return True                     # syft's UNKNOWN, a branch name: cannot clear
    if versions and (version in versions or v in {_norm(eco, x) for x in versions}):
        return True
    evaluable = [r for r in ranges if r.get('type') in ('SEMVER', 'ECOSYSTEM')]
    if not evaluable:
        return not versions             # nothing to evaluate → propose it
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


_MAVEN_PRE = re.compile(r'[.-]?(alpha|a|beta|b|milestone|m|rc|cr|snapshot)[.-]?(\d*)$', re.I)


def _maven(v: str) -> str:
    """Maven qualifiers as a semver pre-release: 2.0.0.RC1 / 2.0.0-RC1 sort
    before 2.0.0; .Final / .RELEASE / .GA are the release itself."""
    v = re.sub(r'[.-](final|release|ga)$', '', v, flags=re.I)
    m = _MAVEN_PRE.search(v)
    if m and m.start() > 0:
        return f"{v[:m.start()]}-{m.group(1).lower()}.{m.group(2) or 0}"
    return v


def _cmp(eco: str, a: str, b: str) -> int:
    a, b = _norm(eco, a), _norm(eco, b)
    if eco == 'PyPI':
        from packaging.version import Version
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    if eco == 'Maven':
        a, b = _maven(a), _maven(b)
    return V.pkg_cmp(a, b)


def ecosystem_of(artifact_type: str) -> Optional[str]:
    return ECOSYSTEMS.get(artifact_type)


# ── advisory ID → CVE ────────────────────────────────────────────────────────

_API = 'https://api.osv.dev/v1/vulns/'
_WORKERS = int(os.environ.get('OSV_WORKERS', '8'))

# Memoised per process, never written to disk.  A scan carries a handful of
# advisory IDs (14 on the largest RHOAI workbench measured), so one lookup each
# per run costs a second and leaves nothing behind to go stale or to be mistaken
# for part of the VEX mirror.


def is_advisory_id(vuln_id: str) -> bool:
    """True for an ecosystem advisory ID — anything that is not a CVE."""
    v = str(vuln_id or '').strip()
    return bool(v) and not v.upper().startswith('CVE-')


def _canonical(vuln_id: str) -> str:
    """OSV's exact spelling, which the API matches literally.

    A GHSA is an upper-case prefix over a lower-case base32 suffix, and OSV
    404s on any other casing — `GHSA-mv93-w799-cj2w` serves, `GHSA-MV93-…` and
    `ghsa-mv93-…` do not.  RHACS reports the ID upper-cased throughout, so this
    is not a theoretical case.  Everything else (`GO-`, `PYSEC-`, `RUSTSEC-`)
    is upper.
    """
    v = str(vuln_id or '').strip()
    prefix, sep, rest = v.partition('-')
    if not sep:
        return v.upper()
    return (f'{prefix.upper()}-{rest.lower()}' if prefix.upper() == 'GHSA'
            else v.upper())


@functools.lru_cache(maxsize=4096)
def resolve(vuln_id: str):
    """The CVE this advisory aliases, or None.  Never raises, never blocks long.

    A network failure returns None and the caller keeps the original ID (no
    VEX file under it → POSITIVE, as the tool would say without OSV).
    """
    if not is_advisory_id(vuln_id):
        return None
    local = _index()
    if local is not None:
        cve = local.osv_cve(_canonical(vuln_id))
        if cve:
            return cve
    if os.environ.get('VEX_OFFLINE'):
        return None
    try:
        res = requests.get(_API + _canonical(vuln_id), timeout=15)
        if res.status_code != 200:          # 404 = OSV does not know the ID
            return None
        # OSV serves records with raw newlines inside `details`, which strict
        # JSON rejects; the payload is otherwise well formed.
        doc = json.loads(res.text, strict=False)
    except Exception:
        return None
    cves = sorted(a for a in (doc.get('aliases') or []) + (doc.get('upstream') or [])
                  if str(a).upper().startswith('CVE-'))
    return cves[0] if cves else None


@functools.lru_cache(maxsize=1)
def _index():
    from . import vexindex
    return vexindex.open_index()


def resolve_many(vuln_ids, workers: int = 0) -> dict:
    """{advisory_id: CVE} for the IDs that resolve; unresolved ones are absent."""
    ids = [i for i in dict.fromkeys(vuln_ids) if is_advisory_id(i)]
    if not ids:
        return {}
    with ThreadPoolExecutor(max_workers=max(1, workers or _WORKERS)) as ex:
        found = list(ex.map(resolve, ids))
    return {i: c for i, c in zip(ids, found) if c}
