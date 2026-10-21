#!/usr/bin/env python3
"""vex_graph.py — the whole Red Hat CSAF-VEX mirror as one queryable graph.

Every document, every product, every component and every status reference,
recorded as the documents state them (plus parsed purl / CPE fields), so any
rule or classification the engine uses can be checked against ALL of the data
with a query instead of a sample:

    product(pid, name, cpe, part, vendor, cpe_product, cpe_version, cpe_update,
            cpe_edition, family, major, minor, mainline, version, docs)
        one row per distinct (product id, name, cpe); family/major/minor/
        mainline/version are core/csaf.classify()'s reading, kept beside the
        raw fields so they can be audited
    component(cid, ref, purl, type, namespace, name, version, epoch, arch,
              rpmmod, repository_url, tag, digest, path, docs)
        one row per distinct (component product id, purl); path is the image
        identity (product id namespace/name) for images, else ''
    listing(cve, pid, cid, status, flag, remediations, severity)
        one row per status reference: pid is the product, cid the component
        (NULL when the status names a product directly), remediations every
        category given for it, in document order (JSON)
    document(cve, title, severity, products, components, listings)

    python3 tools/vex_graph.py [--vex data/vex.sqlite] [--out data/vex-graph.sqlite]

Example queries (sqlite3 data/vex-graph.sqlite):
    -- purl types per product family
    SELECT p.family, c.type, COUNT(*) FROM listing l JOIN product p USING(pid)
      LEFT JOIN component c USING(cid) GROUP BY 1, 2 ORDER BY 1, 3 DESC;
    -- CPE products classify() files as layered, by size
    SELECT cpe_product, COUNT(DISTINCT pid) FROM product WHERE family = 'layered'
      GROUP BY 1 ORDER BY 2 DESC;
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from urllib.parse import unquote

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))
from vextriage.sync import Mirror  # noqa: E402
from vextriage.csaf import STATUSES, classify   # noqa: E402

SCHEMA = """
CREATE TABLE product (pid TEXT, name TEXT, cpe TEXT, part TEXT, vendor TEXT, cpe_product TEXT,
                      cpe_version TEXT, cpe_update TEXT, cpe_edition TEXT, family TEXT, major TEXT,
                      minor INTEGER, mainline INTEGER, version TEXT, docs INTEGER);
CREATE TABLE component (cid INTEGER PRIMARY KEY, ref TEXT, purl TEXT, type TEXT, namespace TEXT,
                        name TEXT, version TEXT, epoch TEXT, arch TEXT, rpmmod TEXT,
                        repository_url TEXT, tag TEXT, digest TEXT, path TEXT, docs INTEGER);
CREATE TABLE listing (cve TEXT, pid TEXT, cid INTEGER, status TEXT, flag TEXT,
                      remediations TEXT, severity TEXT);
CREATE TABLE document (cve TEXT PRIMARY KEY, title TEXT, severity TEXT, products INTEGER,
                       components INTEGER, listings INTEGER);
"""
INDEXES = """
CREATE INDEX product_pid ON product(pid);
CREATE INDEX component_name ON component(type, name);
CREATE INDEX component_path ON component(path);
CREATE INDEX listing_cve ON listing(cve);
CREATE INDEX listing_pid ON listing(pid);
CREATE INDEX listing_cid ON listing(cid);
"""


def parse_purl(purl: str) -> dict:
    """pkg:type/namespace/name@version?qualifiers — every field, decoded."""
    out = dict(type='', namespace='', name='', version='', epoch='', arch='', rpmmod='',
               repository_url='', tag='', digest='')
    if not purl.startswith('pkg:'):
        return out
    body, _, query = purl[4:].partition('?')
    q = {k: unquote(v) for k, v in (kv.split('=', 1) for kv in query.split('&') if '=' in kv)}
    path, _, ver = body.partition('@')
    segs = [unquote(x) for x in path.split('/')]
    out['type'] = segs[0]
    out['name'] = segs[-1] if len(segs) > 1 else ''
    out['namespace'] = '/'.join(segs[1:-1])
    out['version'] = unquote(ver)
    out['epoch'] = q.get('epoch', '')
    out['arch'] = q.get('arch', '')
    out['rpmmod'] = q.get('rpmmod', '')
    out['repository_url'] = q.get('repository_url', '')
    out['tag'] = q.get('tag', '')
    m = re.search(r'sha256:([0-9a-f]{64})', out['version'])
    out['digest'] = m.group(1) if m else ''
    return out


def image_path(ref: str, purl: str) -> str:
    """The image identity: the product id's namespace/name — for oci purls and
    purl-less ids under a registry namespace (never a dotted Maven group)."""
    if purl and not purl.startswith('pkg:oci/'):
        return ''
    if not purl and '.' in ref.split('/')[0]:
        return ''
    parts = re.sub(r'@.*$', '', ref).split('/')
    if len(parts) > 2 and '.' in parts[0]:
        parts = parts[1:]
    return '/'.join(parts).lower() if len(parts) >= 2 and all(parts) else ''


def read_doc(row):
    """(cve, mtime, gz) → (cve, title, severity, products, components, listings)."""
    import gzip
    cve = row[0]
    try:
        d = json.loads(gzip.decompress(row[2]))
    except Exception:
        return None
    tree = d.get('product_tree') or {}
    nodes = {}

    def walk(branches):
        for b in branches or []:
            p = b.get('product')
            if p and p.get('product_id'):
                h = p.get('product_identification_helper') or {}
                nodes[p['product_id']] = (p.get('name', ''), h.get('purl', ''), h.get('cpe', ''))
            walk(b.get('branches'))
    walk(tree.get('branches'))
    rel = {}
    for r in tree.get('relationships') or []:
        full = (r.get('full_product_name') or {}).get('product_id')
        if full:
            rel[full] = (r.get('relates_to_product_reference', ''), r.get('product_reference', ''))
    products, components, listings = {}, {}, []

    def product(pid):
        name, _purl, cpe = nodes.get(pid, ('', '', ''))
        products[(pid, name, cpe)] = 1
        return pid

    for v in d.get('vulnerabilities') or []:
        status = {}
        for st in STATUSES:
            for pid in (v.get('product_status') or {}).get(st, []):
                status.setdefault(pid, st)
        flags = {}
        for f in v.get('flags') or []:
            for pid in f.get('product_ids') or []:
                flags.setdefault(pid, f.get('label', ''))
                status.setdefault(pid, 'known_not_affected')
        rems = {}
        for r in v.get('remediations') or []:
            for pid in r.get('product_ids') or []:
                rems.setdefault(pid, []).append(r.get('category', ''))
        sev = {}
        for t in v.get('threats') or []:
            if t.get('category') == 'impact':
                for pid in t.get('product_ids') or []:
                    sev[pid] = t.get('details', '')
        for pid, st in status.items():
            if pid in rel:
                parent, comp = rel[pid]
                purl = nodes.get(comp, ('', '', ''))[1]
                components[(comp, purl)] = 1
                key = (comp, purl)
            elif pid in nodes:
                parent, key = pid, None            # a product named directly
            else:
                parent, key = pid, ('?orphan', pid)   # no node, no relationship
                components[key] = 1
            listings.append((cve, product(parent), key, st, flags.get(pid, ''),
                             json.dumps(rems.get(pid, [])), sev.get(pid, '')))
    doc = d.get('document') or {}
    agg = (doc.get('aggregate_severity') or {}).get('text', '')
    return cve, doc.get('title', ''), agg, list(products), list(components), listings


def _rows(mirror: Mirror):
    cves = sorted(mirror.stamps())
    for i in range(0, len(cves), 2000):             # bounded: map queues its whole input
        yield list(mirror.rows(cves[i:i + 2000]))


def build(vex_db: str, out: str, workers: int) -> dict:
    mirror = Mirror(vex_db)
    tmp = out + '.tmp'
    if os.path.exists(tmp):
        os.unlink(tmp)
    con = sqlite3.connect(tmp)
    con.executescript('PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;' + SCHEMA)
    prod_docs, comp_id, comp_docs = {}, {}, {}
    t0, n = time.time(), 0
    with ProcessPoolExecutor(workers) as ex:
        for res in (r for batch in _rows(mirror) for r in ex.map(read_doc, batch, chunksize=40)):
            if res is None:
                continue
            cve, title, agg, products, components, listings = res
            for p in products:
                prod_docs[p] = prod_docs.get(p, 0) + 1
            rows = []
            for c in components:
                if c not in comp_id:
                    comp_id[c] = len(comp_id) + 1
                comp_docs[c] = comp_docs.get(c, 0) + 1
            for (cv, pid, key, st, flag, rem, sev) in listings:
                rows.append((cv, pid, comp_id[key] if key else None, st, flag, rem, sev))
            con.executemany('INSERT INTO listing VALUES (?,?,?,?,?,?,?)', rows)
            con.execute('INSERT INTO document VALUES (?,?,?,?,?,?)',
                        (cve, title, agg, len(products), len(components), len(listings)))
            n += 1
            if n % 2000 == 0:
                print(f'  {n:,}/{mirror.count():,} documents ({time.time() - t0:.0f}s)', flush=True)
    prows = []
    for (pid, name, cpe), docs in prod_docs.items():
        p = classify(pid, name, cpe)
        f = (cpe.replace('cpe:/', '').split(':') + [''] * 6)[:6] if cpe else [''] * 6
        prows.append((pid, name, cpe, f[0], f[1], f[2], f[3], f[4], f[5], p.family, p.major,
                      p.minor, int(p.mainline), p.version, docs))
    con.executemany('INSERT INTO product VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', prows)
    crows = []
    for (ref, purl), cid in comp_id.items():
        q = parse_purl(purl)
        crows.append((cid, ref, purl, q['type'] if purl else ('orphan' if ref == '?orphan' else 'none'),
                      q['namespace'], q['name'], q['version'], q['epoch'], q['arch'], q['rpmmod'],
                      q['repository_url'], q['tag'], q['digest'], image_path(ref, purl),
                      comp_docs[(ref, purl)]))
    con.executemany('INSERT INTO component VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', crows)
    con.executescript(INDEXES)
    con.commit()
    stats = {'documents': n, 'products': len(prows), 'components': len(crows),
             'listings': con.execute('SELECT COUNT(*) FROM listing').fetchone()[0],
             'seconds': round(time.time() - t0)}
    con.close()
    os.replace(tmp, out)
    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--vex', default=os.path.join('data', 'vex.sqlite'), help='the mirror (vextriage sync)')
    ap.add_argument('--out', default=os.path.join('data', 'vex-graph.sqlite'))
    ap.add_argument('--workers', type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()
    print(json.dumps(build(a.vex, a.out, a.workers)))


if __name__ == '__main__':
    main()
