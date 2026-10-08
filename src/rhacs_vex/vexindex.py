"""The local lookup index — one SQLite file, built by streaming, queried per key.

Nothing here loads a dataset into memory.  Building reads one VEX document (or
one OSV record) at a time and inserts its keys; querying asks for one rpm
name, one image key or one package at a time.  That keeps `vextriage openvex`
usable on a small machine while the corpus itself is tens of GB.

    rpm(name, cve)        rpm package name → CVEs whose Red Hat VEX names it
    oci(key, cve)         image repo / name → CVEs whose Red Hat VEX names it
    osv(eco, pkg, cves, ranges, versions)
                          upstream package → OSV records (CVE aliases, ranges)

Code that expects the old in-memory shape keeps working: `index.get('rpm')`
returns a table object with `.get(name, default)`, like the dict it replaces.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sqlite3
import threading
import zipfile
from typing import Optional
from urllib.parse import unquote

from .core.store import BASE_DIR, VEX_DIR

INDEX_PATH = os.path.join(BASE_DIR, 'vex-index.sqlite')

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rpm (name TEXT NOT NULL, cve TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oci (key  TEXT NOT NULL, cve TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS osv (eco TEXT NOT NULL, pkg TEXT NOT NULL, cves TEXT NOT NULL,
                                ranges TEXT NOT NULL, versions TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""
_INDEXES = """
CREATE INDEX IF NOT EXISTS rpm_name ON rpm(name);
CREATE INDEX IF NOT EXISTS oci_key  ON oci(key);
CREATE INDEX IF NOT EXISTS osv_pkg  ON osv(eco, pkg);
"""


# ── identity helpers (VEX purls) ─────────────────────────────────────────────

def rpm_purl_name(purl: str) -> str:
    """Package name of an rpm purl: vendor namespace dropped, deeper path kept
    (`pkg:rpm/redhat/openshift4/ose-cli` routes to the image ladder by its '/')."""
    body = unquote(purl.partition('?')[0][len('pkg:rpm/'):]).partition('@')[0]
    return body.partition('/')[2] or body


def oci_repo_keys(purl: str) -> list:
    """Effective repo and bare image name of an oci purl (both purl eras)."""
    body = purl.partition('?')[0][len('pkg:oci/'):]
    tail = body.split('@')[0].split('/')[-1]
    m = re.search(r'repository_url=([^&]+)', purl)
    repo = m.group(1) if m else ''
    if repo and not (repo.endswith('/' + tail) or repo.endswith(tail)):
        repo = repo.rstrip('/') + '/' + tail
    return [k for k in (repo, tail) if k]


def _doc_keys(doc: dict):
    """(rpm names, oci keys) named by any status or flag of one VEX document."""
    pid2purl: dict = {}

    def walk(branches):
        for b in branches or []:
            p = b.get('product') or {}
            h = p.get('product_identification_helper') or {}
            if p.get('product_id') and h.get('purl'):
                pid2purl[p['product_id']] = h['purl']
            walk(b.get('branches'))

    pt = doc.get('product_tree') or {}
    walk(pt.get('branches'))
    comp = {(r.get('full_product_name') or {}).get('product_id'): r.get('product_reference')
            for r in pt.get('relationships') or []}
    rpms, ocis = set(), set()
    for vuln in doc.get('vulnerabilities') or []:
        pids = set()
        for ids in (vuln.get('product_status') or {}).values():
            pids.update(ids)
        for flag in vuln.get('flags') or []:
            pids.update(flag.get('product_ids', []))
        for pid in pids:
            purl = pid2purl.get(comp.get(pid, pid)) or pid2purl.get(pid)
            if not purl:
                continue
            if purl.startswith('pkg:rpm/'):
                rpms.add(rpm_purl_name(purl))
            elif purl.startswith('pkg:oci/'):
                ocis.update(oci_repo_keys(purl))
    return rpms, ocis


# ── build ────────────────────────────────────────────────────────────────────

def _connect_write(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    con = sqlite3.connect(path)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=OFF')
    con.executescript(_SCHEMA)
    return con


def build_vex(vex_dir: str = VEX_DIR, path: str = INDEX_PATH, progress=None) -> dict:
    """(Re)build the rpm/oci tables from the mirror, one document at a time."""
    files = sorted(glob.glob(os.path.join(vex_dir, 'CVE-*.json')))
    con = _connect_write(path)
    with con:
        con.execute('DELETE FROM rpm')
        con.execute('DELETE FROM oci')
    batch_r, batch_o = [], []
    for i, fp in enumerate(files):
        if progress and i % 2000 == 0:
            progress(i, len(files))
        try:
            with open(fp) as fh:
                doc = json.load(fh)
        except Exception:
            continue
        cve = os.path.basename(fp)[:-5]
        rpms, ocis = _doc_keys(doc)
        del doc
        batch_r += [(n, cve) for n in rpms]
        batch_o += [(k, cve) for k in ocis]
        if len(batch_r) + len(batch_o) > 50_000:
            _flush(con, batch_r, batch_o)
    _flush(con, batch_r, batch_o)
    with con:
        con.executescript(_INDEXES)
        con.execute("INSERT OR REPLACE INTO meta VALUES ('vex_files', ?)", (str(len(files)),))
    stats = {'files': len(files),
             'rpm': con.execute('SELECT COUNT(DISTINCT name) FROM rpm').fetchone()[0],
             'oci': con.execute('SELECT COUNT(DISTINCT key) FROM oci').fetchone()[0]}
    con.close()
    return stats


def _flush(con, batch_r, batch_o):
    with con:
        con.executemany('INSERT INTO rpm VALUES (?, ?)', batch_r)
        con.executemany('INSERT INTO oci VALUES (?, ?)', batch_o)
    batch_r.clear()
    batch_o.clear()


def build_osv(osv_dir: str, path: str = INDEX_PATH, ecosystems=None) -> dict:
    """(Re)build the osv table from the OSV bulk zips, one record at a time."""
    con = _connect_write(path)
    counts = {}
    for zpath in sorted(glob.glob(os.path.join(osv_dir, '*.zip'))):
        eco = os.path.splitext(os.path.basename(zpath))[0]
        if ecosystems and eco not in ecosystems:
            continue
        with con:
            con.execute('DELETE FROM osv WHERE eco = ?', (eco,))
        rows, n = [], 0
        with zipfile.ZipFile(zpath) as z:
            for name in z.namelist():
                try:
                    rec = json.loads(z.read(name))
                except Exception:
                    continue
                if rec.get('withdrawn'):
                    continue
                cves = sorted({a for a in [rec.get('id', ''), *rec.get('aliases', [])]
                               if a.startswith('CVE-')})
                if not cves:
                    continue
                for aff in rec.get('affected', []):
                    pkg = aff.get('package') or {}
                    if pkg.get('ecosystem', '').split(':')[0] != eco or not pkg.get('name'):
                        continue
                    rows.append((eco, package_key(eco, pkg['name']), ' '.join(cves),
                                 json.dumps(aff.get('ranges') or []),
                                 json.dumps(aff.get('versions') or [])))
                    n += 1
                if len(rows) > 20_000:
                    with con:
                        con.executemany('INSERT INTO osv VALUES (?, ?, ?, ?, ?)', rows)
                    rows.clear()
        with con:
            con.executemany('INSERT INTO osv VALUES (?, ?, ?, ?, ?)', rows)
        counts[eco] = n
    with con:
        con.executescript(_INDEXES)
    con.close()
    return counts


def package_key(eco: str, name: str) -> str:
    """OSV package names as compared: PyPI is PEP 503-normalised."""
    return re.sub(r'[-_.]+', '-', name).lower() if eco == 'PyPI' else name


# ── query ────────────────────────────────────────────────────────────────────

class _Table:
    """Read-only, dict-like view of one key → [CVE] table."""

    def __init__(self, index: "VexIndex", table: str, col: str):
        self._ix, self._sql = index, f'SELECT cve FROM {table} WHERE {col} = ? ORDER BY cve'
        self._any = f'SELECT 1 FROM {table} LIMIT 1'

    def get(self, key, default=()):
        rows = self._ix._con().execute(self._sql, (key,)).fetchall()
        return [r[0] for r in rows] if rows else default

    def __bool__(self):
        return self._ix._con().execute(self._any).fetchone() is not None


class VexIndex:
    """Handle on the SQLite index; one connection per thread, opened lazily."""

    def __init__(self, path: str = INDEX_PATH):
        self.path = path
        self._local = threading.local()

    def _con(self) -> sqlite3.Connection:
        con = getattr(self._local, 'con', None)
        if con is None:
            con = sqlite3.connect(f'file:{self.path}?mode=ro', uri=True)
            self._local.con = con
        return con

    def get(self, kind, default=None):
        if kind == 'rpm':
            return _Table(self, 'rpm', 'name')
        if kind == 'oci':
            return _Table(self, 'oci', 'key')
        return default

    def osv(self, eco: str, name: str) -> list:
        """[(cves, ranges, versions)] for one package."""
        rows = self._con().execute('SELECT cves, ranges, versions FROM osv WHERE eco = ? AND pkg = ?',
                                   (eco, package_key(eco, name))).fetchall()
        return [(c.split(), json.loads(r), tuple(json.loads(v))) for c, r, v in rows]

    def has_osv(self, eco: str) -> bool:
        return self._con().execute('SELECT 1 FROM osv WHERE eco = ? LIMIT 1',
                                   (eco,)).fetchone() is not None

    def __bool__(self):
        return bool(self.get('rpm')) or bool(self.get('oci'))

    def __getstate__(self):                 # picklable for worker processes
        return {'path': self.path}

    def __setstate__(self, state):
        self.__init__(state['path'])


def open_index(path: str = INDEX_PATH) -> Optional[VexIndex]:
    """The index at *path*, or None when it has not been built."""
    if not os.path.exists(path):
        return None
    try:
        ix = VexIndex(path)
        ix._con().execute('SELECT 1 FROM meta LIMIT 1')
        return ix
    except sqlite3.Error:
        return None
