"""The local index of the Red Hat VEX mirror (SQLite).

    doc(id, cve, mtime, blob)       each document, parsed and compacted (csaf.encode), zlib
    name(kind, name, doc)           rpm / maven / npm / … names → the documents naming them
    image(path, doc, product)       image paths (namespace/name) → documents, naming products
    digest(d64, doc)                image build digests (first 64 bits) → documents
    product(id, pid, name, cpe)     every product node
    meta(key, value)

Built from data/vex/CVE-*.json by `vextriage sync`, re-reading only the
documents whose file changed.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import zlib
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
from typing import Iterable, Optional

from . import csaf

VERSION = '3'
SCHEMA = """
CREATE TABLE IF NOT EXISTS doc (id INTEGER PRIMARY KEY, cve TEXT UNIQUE, mtime REAL, blob BLOB);
CREATE TABLE IF NOT EXISTS name (kind TEXT, name TEXT, doc INTEGER);
CREATE TABLE IF NOT EXISTS image (path TEXT, doc INTEGER, product INTEGER);
CREATE TABLE IF NOT EXISTS digest (d64 INTEGER, doc INTEGER);
CREATE TABLE IF NOT EXISTS product (id INTEGER PRIMARY KEY, pid TEXT UNIQUE, name TEXT, cpe TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS name_key ON name(kind, name);
CREATE INDEX IF NOT EXISTS name_doc ON name(doc);
CREATE INDEX IF NOT EXISTS image_path ON image(path);
CREATE INDEX IF NOT EXISTS image_doc ON image(doc);
CREATE INDEX IF NOT EXISTS digest_key ON digest(d64);
CREATE INDEX IF NOT EXISTS digest_doc ON digest(doc);
"""


def d64(digest_hex: str) -> int:
    """The first 64 bits of a sha256, as a signed integer key."""
    v = int(digest_hex[:16], 16)
    return v - (1 << 64) if v >= 1 << 63 else v


def _read(path: str):
    """One mirror file → (cve, mtime, blob, names, images, digests), or None."""
    cve = os.path.basename(path)[:-5].upper()
    try:
        mtime = os.path.getmtime(path)
        with open(path, 'rb') as fh:
            doc = csaf.parse(json.load(fh), cve)
    except (OSError, ValueError):
        return None
    names, images, digests = set(), set(), set()
    for s in doc.statements:
        c = s.comp
        if c is None:
            continue
        if c.kind == 'image':
            if c.name:
                images.add((c.name, s.product.id, s.product.name, s.product.cpe))
            if c.digest:
                digests.add(d64(c.digest))
        elif c.name:
            names.add((c.kind, c.name))
    blob = zlib.compress(json.dumps(csaf.encode(doc), separators=(',', ':')).encode(), 9)
    return cve, mtime, blob, names, images, digests


class Index:
    def __init__(self, path: str):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self._doc = lru_cache(maxsize=256)(self._load)
        self._products: dict = {}

    # ── building ────────────────────────────────────────────────────────────
    def update(self, vex_dir: str, workers: int = 0, full: bool = False, progress=None) -> dict:
        """Re-read the mirror files whose mtime changed (every file with full=True
        or when the index format changed); drop documents whose file is gone."""
        if self.meta('version') != VERSION:
            full = True
        files = {f[:-5].upper(): os.path.join(vex_dir, f) for f in os.listdir(vex_dir)
                 if f.upper().startswith('CVE-') and f.endswith('.json')}
        have = dict(self.db.execute('SELECT cve, mtime FROM doc'))
        if full and have:
            for t in ('name', 'image', 'digest', 'doc', 'product'):
                self.db.execute(f'DELETE FROM {t}')
            have = {}
        todo = [p for cve, p in files.items() if have.get(cve) != os.path.getmtime(p)]
        gone = [cve for cve in have if cve not in files]
        t0, done = time.time(), 0
        self._delete(gone)
        if todo:
            with ProcessPoolExecutor(workers or max(1, (os.cpu_count() or 2) - 1)) as ex:
                batch = []
                for res in ex.map(_read, sorted(todo), chunksize=8):
                    done += 1
                    if res is not None:
                        batch.append(res)
                    if len(batch) >= 100:
                        self._write(batch)
                        batch = []
                    if progress and done % 1000 == 0:
                        progress(done, len(todo))
                self._write(batch)
        self.db.execute("INSERT OR REPLACE INTO meta VALUES ('version', ?)", (VERSION,))
        self.db.execute("INSERT OR REPLACE INTO meta VALUES ('updated', ?)",
                        (time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),))
        self.db.commit()
        if full:
            self.db.execute('VACUUM')
        self._doc.cache_clear()
        return {'read': len(todo), 'removed': len(gone), 'documents': self.count(),
                'seconds': round(time.time() - t0)}

    def _delete(self, cves: Iterable[str]):
        for cve in cves:
            row = self.db.execute('SELECT id FROM doc WHERE cve = ?', (cve,)).fetchone()
            if row:
                for t in ('name', 'image', 'digest'):
                    self.db.execute(f'DELETE FROM {t} WHERE doc = ?', row)
                self.db.execute('DELETE FROM doc WHERE id = ?', row)

    def _product_id(self, pid: str, name: str, cpe: str) -> int:
        if pid not in self._products:
            self.db.execute('INSERT OR IGNORE INTO product (pid, name, cpe) VALUES (?,?,?)', (pid, name, cpe))
            self._products[pid] = self.db.execute('SELECT id FROM product WHERE pid = ?', (pid,)).fetchone()[0]
        return self._products[pid]

    def _write(self, batch):
        if not batch:
            return
        self._delete(r[0] for r in batch)
        for cve, mtime, blob, names, images, digests in batch:
            doc = self.db.execute('INSERT INTO doc (cve, mtime, blob) VALUES (?,?,?)', (cve, mtime, blob)).lastrowid
            self.db.executemany('INSERT INTO name VALUES (?,?,?)', [(k, n, doc) for k, n in names])
            self.db.executemany('INSERT INTO image VALUES (?,?,?)',
                                [(p, doc, self._product_id(pid, n, c)) for p, pid, n, c in images])
            self.db.executemany('INSERT INTO digest VALUES (?,?)', [(d, doc) for d in digests])
        self.db.commit()

    # ── reading ─────────────────────────────────────────────────────────────
    def count(self) -> int:
        return self.db.execute('SELECT COUNT(*) FROM doc').fetchone()[0]

    def meta(self, key: str) -> str:
        row = self.db.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
        return row[0] if row else ''

    def has(self, cve: str) -> bool:
        return self.db.execute('SELECT 1 FROM doc WHERE cve = ?', (cve.upper(),)).fetchone() is not None

    def doc(self, cve: str) -> Optional[csaf.Document]:
        """The parsed document for a CVE, or None when Red Hat publishes none."""
        return self._doc(cve.upper())

    def _load(self, cve: str) -> Optional[csaf.Document]:
        row = self.db.execute('SELECT blob FROM doc WHERE cve = ?', (cve,)).fetchone()
        return csaf.decode(json.loads(zlib.decompress(row[0])), cve) if row else None

    def cves_naming(self, kind: str, names: Iterable[str]) -> dict:
        """{name: {cve, …}}: the documents whose statements name each (kind, name)."""
        out: dict = {}
        for n in set(names):
            rows = self.db.execute('SELECT DISTINCT d.cve FROM name n JOIN doc d ON d.id = n.doc '
                                   'WHERE n.kind = ? AND n.name = ?', (kind, n)).fetchall()
            if rows:
                out[n] = {r[0] for r in rows}
        return out

    def cves_for_image(self, paths: Iterable[str], digests: Iterable[str]) -> set:
        out = set()
        for p in set(paths):
            out.update(c for (c,) in self.db.execute(
                'SELECT DISTINCT d.cve FROM image i JOIN doc d ON d.id = i.doc WHERE i.path = ?', (p,)))
        for dg in set(digests):
            out.update(c for (c,) in self.db.execute(
                'SELECT DISTINCT d.cve FROM digest g JOIN doc d ON d.id = g.doc WHERE g.d64 = ?', (d64(dg),)))
        return out

    def products_naming(self, paths: Iterable[str]) -> dict:
        """{path: [Product, …]}: the products whose statements name each image path."""
        out: dict = {}
        for p in set(paths):
            rows = self.db.execute('SELECT DISTINCT p.pid, p.name, p.cpe FROM image i '
                                   'JOIN product p ON p.id = i.product WHERE i.path = ?', (p,)).fetchall()
            if rows:
                out[p] = [csaf.classify(*r) for r in rows]
        return out

    def products_with_digest(self, digests: Iterable[str]) -> list:
        """The (path, Product) pairs of statements naming any of these builds."""
        out = set()
        for dg in set(digests):
            for (cve,) in self.db.execute('SELECT d.cve FROM digest g JOIN doc d ON d.id = g.doc '
                                          'WHERE g.d64 = ? LIMIT 3', (d64(dg),)):
                for s in self.doc(cve).by_digest({dg}):
                    out.add((s.comp.name, s.product))
        return sorted(out, key=lambda x: (x[0], x[1].id))

    def paths_ending(self, name: str) -> list:
        """Image paths whose last segment is `name`, in any namespace."""
        return sorted(p for (p,) in self.db.execute('SELECT DISTINCT path FROM image WHERE path LIKE ?',
                                                    ('%/' + name,)) if p.rsplit('/', 1)[-1] == name)
