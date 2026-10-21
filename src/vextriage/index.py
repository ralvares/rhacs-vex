"""The local index of the Red Hat VEX mirror (SQLite): one row per statement.

    doc(id, cve, mtime, title, severity, kev)
    product(id, pid, name, cpe)            every product node named by a statement
    comp(id, h, pid, kind, name, version, epoch, arch, module, digest, d64, stamp, tag)
                                           every component node, shared across documents
                                           (h: hash of the row; id 0 = no component)
    remedy(id, h, body)                    a statement's remediations, JSON, shared
    stmt(comp, doc, seq, product, status, flag, remedy, severity)
                                           seq: the statement's place in its document (the
                                           engine cites the first matching statement)
    image(path, doc, product)              which products name an image path (scope)
    node(doc, product, clear_seq, path_seq)
                                           per OpenShift / layered product node: its first
                                           cleared statement, and its first cleared image whose
                                           path it does not also list open (errata assumption)
    meta(key, value)

A scan asks for the statements about its packages, image paths and digests
(comp by kind + name, or by digest) — a few indexed queries — instead of
reading whole documents. Built from the mirror (sync.Mirror) by `vextriage
sync`, re-reading only the documents whose change time moved.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
import time
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor
from typing import Iterable, Optional

from . import csaf
from .csaf import STATUSES, Comp, Document, Remedy, Statement
from .rpm import parse_evr

VERSION = '7'
SCHEMA = """
CREATE TABLE IF NOT EXISTS doc (id INTEGER PRIMARY KEY, cve TEXT UNIQUE, mtime REAL, title TEXT,
                                severity TEXT, kev INTEGER);
CREATE TABLE IF NOT EXISTS product (id INTEGER PRIMARY KEY, pid TEXT UNIQUE, name TEXT, cpe TEXT);
CREATE TABLE IF NOT EXISTS comp (id INTEGER PRIMARY KEY, h INTEGER UNIQUE, pid TEXT, kind TEXT, name TEXT,
                                 version TEXT, epoch INTEGER, arch TEXT, module TEXT, digest TEXT,
                                 d64 INTEGER, stamp INTEGER, tag TEXT);
CREATE TABLE IF NOT EXISTS remedy (id INTEGER PRIMARY KEY, h INTEGER UNIQUE, body TEXT);
CREATE TABLE IF NOT EXISTS stmt (comp INTEGER, doc INTEGER, seq INTEGER, product INTEGER, status INTEGER,
                                 flag TEXT, remedy INTEGER, severity TEXT);
CREATE TABLE IF NOT EXISTS image (path TEXT, doc INTEGER, product INTEGER);
CREATE TABLE IF NOT EXISTS node (doc INTEGER, product INTEGER, clear_seq INTEGER, path_seq INTEGER);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS comp_name ON comp(kind, name);
CREATE INDEX IF NOT EXISTS comp_d64 ON comp(d64);
"""
STMT_INDEXES = """
CREATE INDEX IF NOT EXISTS stmt_comp ON stmt(comp);
CREATE INDEX IF NOT EXISTS stmt_doc ON stmt(doc, product, seq);
CREATE INDEX IF NOT EXISTS node_doc ON node(doc, product);
CREATE INDEX IF NOT EXISTS image_path ON image(path);
CREATE INDEX IF NOT EXISTS image_doc ON image(doc);
"""
CHUNK = 900                                         # SQLite's bound-parameter limit is 999


def d64(digest_hex: str) -> int:
    """The first 64 bits of a sha256, as a signed integer key."""
    v = int(digest_hex[:16], 16)
    return v - (1 << 64) if v >= 1 << 63 else v


def _h(row) -> int:
    v = int.from_bytes(hashlib.blake2b(json.dumps(row, separators=(',', ':')).encode(), digest_size=8).digest(),
                       'big')
    return v - (1 << 64) if v >= 1 << 63 else v


def _chunks(items):
    items = list(items)
    for i in range(0, len(items), CHUNK):
        yield items[i:i + CHUNK]


def _q(n: int) -> str:
    return ','.join('?' * n)


def _read(row):
    """(cve, mtime, gz) → the document, compacted (csaf.encode), or None."""
    cve, mtime, gz = row
    try:
        doc = csaf.parse(json.loads(gzip.decompress(gz)), cve)
    except (OSError, ValueError, EOFError):
        return None
    return cve, mtime, csaf.encode(doc)


def _nodes(enc: dict, doc: int, P: list) -> list:
    """(doc, product, clear_seq, path_seq) for each OpenShift / layered product node of a
    document: its first cleared statement (any component), and its first cleared image
    whose path it does not also list open — all the errata assumption needs of what a
    node cleared (engine._errata_assumed)."""
    fam = {}
    for pi, (pid, name, cpe) in enumerate(enc['P']):
        fam[pi] = csaf.classify(pid, name, cpe).family in ('ocp', 'layered')
    open_paths: dict = {}
    for st, pi, ci, *_ in enc['S']:
        if fam[pi] and ci >= 0 and enc['C'][ci][1] == 'image' and st in (1, 2):
            open_paths.setdefault(pi, set()).add(enc['C'][ci][2])
    out: dict = {}
    for seq, (st, pi, ci, *_) in enumerate(enc['S']):
        if not fam[pi] or st not in (0, 3):
            continue
        n = out.setdefault(pi, [seq, None])
        if n[1] is None and ci >= 0 and enc['C'][ci][1] == 'image' \
                and enc['C'][ci][2] not in open_paths.get(pi, ()):
            n[1] = seq
    return [(doc, P[pi], c, p) for pi, (c, p) in out.items()]


class Index:
    def __init__(self, path: str, readonly: bool = False):
        self.path = path
        if readonly:
            self.db = sqlite3.connect(f'file:{path}?mode=ro', uri=True, check_same_thread=False)
        else:
            self.db = sqlite3.connect(path, check_same_thread=False)
            self.db.executescript(SCHEMA)
        self._ids: dict = {}                        # building: product pid / comp h / remedy h → id
        self._prod: Optional[dict] = None           # reading: product id → Product
        self._comp: dict = {}                       # reading: comp id → Comp
        self._rem: dict = {}                        # reading: remedy id → (Remedy, …)
        self._docs: OrderedDict = OrderedDict()     # full documents, most recent last

    # ── building ────────────────────────────────────────────────────────────
    def update(self, mirror, workers: int = 0, full: bool = False, progress=None) -> dict:
        """Re-read the documents whose change time moved (every one with full=True
        or when the index format changed); drop those the mirror no longer has."""
        if self.meta('version') != VERSION:
            full = True
        stamps = mirror.stamps()
        if full:
            self._reset()
        have = dict(self.db.execute('SELECT cve, mtime FROM doc'))
        todo = sorted(cve for cve, t in stamps.items() if have.get(cve) != t)
        gone = [cve for cve in have if cve not in stamps]
        t0, done = time.time(), 0
        self._delete(gone + [c for c in todo if c in have])
        if full:
            self.db.executescript('DROP INDEX IF EXISTS stmt_comp; DROP INDEX IF EXISTS stmt_doc;'
                                  'DROP INDEX IF EXISTS image_path; DROP INDEX IF EXISTS image_doc;'
                                  'DROP INDEX IF EXISTS node_doc; DROP INDEX IF EXISTS stmt_open;')
        if todo:
            with ProcessPoolExecutor(workers or max(1, (os.cpu_count() or 2) - 1)) as ex:
                for i in range(0, len(todo), 2000):     # bounded: map queues its whole input
                    for res in ex.map(_read, list(mirror.rows(todo[i:i + 2000])), chunksize=16):
                        done += 1
                        if res is not None:
                            self._write(*res)
                    self.db.commit()
                    if progress:
                        progress(done, len(todo))
        self.db.executescript(STMT_INDEXES)
        self.db.execute("INSERT OR REPLACE INTO meta VALUES ('version', ?)", (VERSION,))
        self.db.execute("INSERT OR REPLACE INTO meta VALUES ('updated', ?)",
                        (time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),))
        self.db.commit()
        if full:
            self.db.execute('VACUUM')
        self._ids.clear()
        self._prod, self._comp, self._rem = None, {}, {}
        self._docs.clear()
        return {'read': len(todo), 'removed': len(gone), 'documents': self.count(),
                'seconds': round(time.time() - t0)}

    def _reset(self):
        """Drop every table (an older format has other columns) and start over."""
        for (t,) in self.db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
            self.db.execute(f'DROP TABLE IF EXISTS {t}')
        self.db.executescript(SCHEMA)
        self.db.commit()

    def _delete(self, cves: Iterable[str]):
        for cve in cves:
            row = self.db.execute('SELECT id FROM doc WHERE cve = ?', (cve,)).fetchone()
            if row:
                self.db.execute('DELETE FROM stmt WHERE doc = ?', row)
                self.db.execute('DELETE FROM image WHERE doc = ?', row)
                self.db.execute('DELETE FROM node WHERE doc = ?', row)
                self.db.execute('DELETE FROM doc WHERE id = ?', row)
        self.db.commit()

    def _id(self, table: str, key, insert) -> int:
        k = (table, key)
        if k not in self._ids:
            col = 'pid' if table == 'product' else 'h'
            row = self.db.execute(f'SELECT id FROM {table} WHERE {col} = ?', (key,)).fetchone()
            self._ids[k] = row[0] if row else insert()
        return self._ids[k]

    def _write(self, cve: str, mtime: float, enc: dict):
        db = self.db
        doc = db.execute('INSERT INTO doc (cve, mtime, title, severity, kev) VALUES (?,?,?,?,?)',
                         (cve, mtime, enc['t'], enc['s'], enc['k'])).lastrowid
        P = [self._id('product', pid, lambda pid=pid, n=n, c=c: db.execute(
            'INSERT INTO product (pid, name, cpe) VALUES (?,?,?)', (pid, n, c)).lastrowid)
            for pid, n, c in enc['P']]
        C = []
        for row in enc['C']:
            pid, kind, name, ver, ep, arch, mod, dg, st, tag = row
            C.append(self._id('comp', _h(row), lambda row=row, dg=dg: db.execute(
                'INSERT INTO comp (h, pid, kind, name, version, epoch, arch, module, digest, d64, stamp, tag) '
                'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (_h(row), pid, kind, name, ver, ep, arch, mod, dg,
                                                       d64(dg) if dg else None, st, tag)).lastrowid))
        rem_cache: dict = {}
        stmts, images = [], set()
        for seq, (st, pi, ci, flag, ri, sev) in enumerate(enc['S']):
            rem = 0
            if ri:
                body = [enc['R'][i] for i in ri]
                key = tuple(ri)
                if key not in rem_cache:
                    rem_cache[key] = self._id('remedy', _h(body), lambda body=body: db.execute(
                        'INSERT INTO remedy (h, body) VALUES (?,?)', (_h(body), json.dumps(body))).lastrowid)
                rem = rem_cache[key]
            comp = C[ci] if ci >= 0 else 0
            stmts.append((comp, doc, seq, P[pi], st, flag, rem, sev))
            if ci >= 0 and enc['C'][ci][1] == 'image' and enc['C'][ci][2]:
                images.add((enc['C'][ci][2], doc, P[pi]))
        db.executemany('INSERT INTO stmt VALUES (?,?,?,?,?,?,?,?)', stmts)
        db.executemany('INSERT INTO image VALUES (?,?,?)', images)
        db.executemany('INSERT INTO node VALUES (?,?,?,?)', _nodes(enc, doc, P))

    # ── reading: rows → statements ──────────────────────────────────────────
    def count(self) -> int:
        return self.db.execute('SELECT COUNT(*) FROM doc').fetchone()[0]

    def meta(self, key: str) -> str:
        row = self.db.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
        return row[0] if row else ''

    def has(self, cve: str) -> bool:
        return self.db.execute('SELECT 1 FROM doc WHERE cve = ?', (cve.upper(),)).fetchone() is not None

    def products(self) -> dict:
        """{product id: Product} — every product node (a few thousand)."""
        if self._prod is None:
            self._prod = {i: csaf.classify(pid, n, c) for i, pid, n, c in
                          self.db.execute('SELECT id, pid, name, cpe FROM product')}
        return self._prod

    def _comps(self, ids):
        miss = [i for i in set(ids) if i and i not in self._comp]
        for ch in _chunks(miss):
            for i, pid, kind, name, ver, ep, arch, mod, dg, st, tag in self.db.execute(
                    f'SELECT id, pid, kind, name, version, epoch, arch, module, digest, stamp, tag FROM comp '
                    f'WHERE id IN ({_q(len(ch))})', ch):
                self._comp[i] = Comp(kind, name, ver, parse_evr(ver, ep) if kind == 'rpm' and ver else None,
                                     arch, mod, dg, st, tag, pid)

    def _rems(self, ids):
        miss = [i for i in set(ids) if i and i not in self._rem]
        for ch in _chunks(miss):
            for i, body in self.db.execute(f'SELECT id, body FROM remedy WHERE id IN ({_q(len(ch))})', ch):
                self._rem[i] = tuple(Remedy(*r) for r in json.loads(body))

    def _assemble(self, rows, doc_ids) -> dict:
        """stmt rows (comp, doc, seq, product, status, flag, remedy, severity) → {cve: Document},
        each document's statements in their order in the document."""
        rows = sorted(set(rows), key=lambda r: (r[1], r[2]))
        self._comps(r[0] for r in rows)
        self._rems(r[6] for r in rows)
        prods = self.products()
        docs: dict = {}
        for ch in _chunks(set(doc_ids) | {r[1] for r in rows}):
            for i, cve, title, sev, kev in self.db.execute(
                    f'SELECT id, cve, title, severity, kev FROM doc WHERE id IN ({_q(len(ch))})', ch):
                docs[i] = Document(cve, title or '', sev or '', kev=bool(kev))
        for comp, doc, seq, prod, st, flag, rem, sev in rows:
            p, c = prods[prod], self._comp.get(comp)
            docs[doc].statements.append(Statement(STATUSES[st], p, c, f'{p.id}:{c.pid}' if c else p.id,
                                                  flag or '', self._rem.get(rem, ()), sev or ''))
        return {d.cve: d for d in docs.values()}

    def doc(self, cve: str) -> Optional[Document]:
        """Every statement of a CVE's document, or None when Red Hat publishes none."""
        cve = cve.upper()
        if cve in self._docs:
            self._docs.move_to_end(cve)
            return self._docs[cve]
        row = self.db.execute('SELECT id FROM doc WHERE cve = ?', (cve,)).fetchone()
        if not row:
            return None
        rows = self.db.execute('SELECT comp, doc, seq, product, status, flag, remedy, severity FROM stmt '
                               'WHERE doc = ?', row).fetchall()
        d = self._assemble(rows, [row[0]])[cve]
        self._docs[cve] = d
        if len(self._docs) > 64:
            self._docs.popitem(last=False)
        return d

    # ── reading: what one image needs ───────────────────────────────────────
    def comp_ids(self, kind: str, names: Iterable[str]) -> dict:
        """{comp id: name} of the components of `kind` with these names."""
        out = {}
        for ch in _chunks(set(names)):
            out.update(self.db.execute(f'SELECT id, name FROM comp WHERE kind = ? AND name IN ({_q(len(ch))})',
                                       [kind] + ch))
        return out

    def digest_comp_ids(self, digests: Iterable[str]) -> set:
        out = set()
        for dg in set(digests):
            out.update(i for (i,) in self.db.execute('SELECT id FROM comp WHERE d64 = ? AND digest = ?',
                                                     (d64(dg), dg)))
        return out

    def select(self, comp_ids: Iterable[int], cves: Iterable[str] = (), product_ids: Iterable[int] = ()) -> dict:
        """{cve: Document} holding only: the statements about these components, the
        statements naming a product directly, and — for the documents involved —
        what the errata assumption reads of these products (below)."""
        q = 'SELECT comp, doc, seq, product, status, flag, remedy, severity FROM stmt'
        rows = []
        for ch in _chunks(set(comp_ids)):
            rows += self.db.execute(f'{q} WHERE comp IN ({_q(len(ch))})', ch).fetchall()
        doc_ids = {r[1] for r in rows}
        for ch in _chunks({c.upper() for c in cves}):
            doc_ids.update(i for (i,) in self.db.execute(f'SELECT id FROM doc WHERE cve IN ({_q(len(ch))})', ch))
        rows += [r for r in self.db.execute(f'{q} WHERE comp = 0') if r[1] in doc_ids]
        # the errata assumption reads, per node of the image's products: its open images,
        # whether it cleared anything, and whether it cleared an image path it does not
        # also list open — the node table names the first statement of each (_nodes)
        pids = list(set(product_ids))
        if pids and doc_ids:
            cols = 's.comp, s.doc, s.seq, s.product, s.status, s.flag, s.remedy, s.severity'
            for pch in _chunks(pids):              # its open images, few: read by product (stmt_open)
                rows += [r for r in self.db.execute(
                    f'SELECT {cols} FROM stmt s JOIN comp c ON c.id = s.comp WHERE s.product IN ({_q(len(pch))}) '
                    f'AND s.status IN (1, 2) AND +c.kind = ?', pch + ['image']) if r[1] in doc_ids]
            for ch in _chunks(doc_ids):            # what it cleared: one statement of each kind
                for pch in _chunks(pids):
                    rows += self.db.execute(
                        f'SELECT {cols} FROM node n JOIN stmt s ON s.doc = n.doc AND s.product = n.product '
                        f'AND s.seq IN (n.clear_seq, n.path_seq) '
                        f'WHERE n.doc IN ({_q(len(ch))}) AND n.product IN ({_q(len(pch))})', ch + pch).fetchall()
        return self._assemble(rows, doc_ids)

    def product_ids(self, keys: Iterable[str]) -> list:
        """The product nodes of these product keys ('openshift', 'openshift_gitops' …)."""
        keys = set(keys)
        return [i for i, p in self.products().items() if p.key in keys]

    def products_naming(self, paths: Iterable[str]) -> dict:
        """{path: [Product, …]}: the products whose statements name each image path."""
        out: dict = {}
        prods = self.products()
        for p in set(paths):
            ids = [i for (i,) in self.db.execute('SELECT DISTINCT product FROM image WHERE path = ?', (p,))]
            if ids:
                out[p] = [prods[i] for i in ids]
        return out

    def products_with_digest(self, digests: Iterable[str]) -> list:
        """The (path, Product) pairs of statements naming any of these builds."""
        ids = self.digest_comp_ids(digests)
        self._comps(ids)
        prods = self.products()
        out = set()
        for ch in _chunks(ids):
            for comp, prod in self.db.execute(f'SELECT DISTINCT comp, product FROM stmt '
                                              f'WHERE comp IN ({_q(len(ch))})', ch):
                out.add((self._comp[comp].name, prods[prod]))
        return sorted(out, key=lambda x: (x[0], x[1].id))

    def paths_ending(self, name: str) -> list:
        """Image paths whose last segment is `name`, in any namespace."""
        return sorted(p for (p,) in self.db.execute('SELECT DISTINCT path FROM image WHERE path LIKE ?',
                                                    ('%/' + name,)) if p.rsplit('/', 1)[-1] == name)
