"""Holdout calibration of the engine's inferred rules on the whole index.

For an (image or rpm, CVE) that Red Hat states, hide that statement, let the
engine infer, and compare with the hidden truth. Every rule that fires is
counted; the inferred ones are the point.

    python3 tools/holdout.py [--index data/vextriage.sqlite] [--sample N] [--cases rpm,foreign,image]
                             [--per-doc 40] [--out FILE.jsonl] [--report FILE.txt]

Cases (truth = the hidden statements):

  rpm_*    a RHEL binary rpm with statements in one minor stream: a fix or a
           not-affected build (x86_64/noarch), or open there (version-less).
           Hidden: every statement about the binary in that stream, and the
           stream's .src builds / version-less statements of its source.
           Installed: rpm_prefix — the fix's build with `~` appended (just
           before the fix: truth affected); rpm_atfix — the fix itself (truth
           clear: it carries the fix); rpm_clean — the not-affected build (truth not affected);
           rpm_open — just before the lowest fix elsewhere (truth affected).
  foreign  an rpm RHEL names and another product names too. Hidden: every
           RHEL statement about it. Truth: RHEL's (a fix → just before it).
  build    an image build (one tag, all its arch digests) of a product
           version that lists several builds. Hidden: that build. The image
           is that build (its digests hidden, its build time kept).
  version  an image under one product version. Hidden: every statement about
           it under that version. The line and the other versions stay.
  unnamed  an image under one product version (or only its line). Hidden:
           every statement naming the image path, in every product. The
           engine sees an image of that product it cannot find: the errata
           assumption or "not listed". Variants of the errata rule are scored
           on the same cases.

Truth classes: affected (open), fixed (a fix was needed: affected before it),
clear (not affected), absent (not affected only as component_not_present: a
scanner would not have reported the package there, so those cases say little
about a finding in a real scan). The holdout can only test where Red Hat
speaks: rules that read Red Hat's silence ("not listed") are scored against
cases where it did speak, a selection that is not the one a real scan meets.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import zlib
from collections import Counter, defaultdict
from functools import cmp_to_key
from multiprocessing import Pool

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))
from vextriage import csaf  # noqa: E402
from vextriage.csaf import FIXED, NOT_AFFECTED, OPEN, Document  # noqa: E402
from vextriage.engine import Engine, Scope, version_relation  # noqa: E402
from vextriage.model import Image, Package  # noqa: E402
from vextriage.rpm import EVR, evr_cmp  # noqa: E402

POS, FIX, CLEAR, ABSENT = 'affected', 'fixed', 'clear', 'absent'
MODULE = Package('go', 'example.invalid/holdout', 'v0.0.1', purl='pkg:golang/example.invalid/holdout@v0.0.1')
PER_DOC = 40


def sub(doc: Document, statements) -> Document:
    return Document(doc.cve, doc.title, doc.severity, list(statements), doc.kev)


def klass(status: str) -> str:
    return POS if status in ('affected', 'under_investigation') else CLEAR


def _pick(items, n, seed):
    items = list(items)
    if len(items) <= n:
        return items
    return random.Random(seed).sample(items, n)


# ── rpm cases ───────────────────────────────────────────────────────────────

def _minor(s):
    d = s.comp.dist
    return d.minor if s.comp.evr is not None and d.minor is not None else s.product.minor


def _sources(doc: Document) -> tuple:
    """(product id, version-release) → .src names; version-release → .src names."""
    by_p, by_vr = defaultdict(set), defaultdict(set)
    for x in doc.statements:
        if x.comp is not None and x.comp.kind == 'rpm' and x.comp.is_src and x.comp.version:
            by_p[(x.product.id, x.comp.version)].add(x.comp.name)
            by_vr[x.comp.version].add(x.comp.name)
    return by_p, by_vr


def _source_of(srcs, s) -> str:
    """The source package of a binary build: the .src build with the same
    version-release under the same product (else any product)."""
    by_p, by_vr = srcs
    same = by_p.get((s.product.id, s.comp.version)) or by_vr.get(s.comp.version) or set()
    if len(same) == 1:
        return next(iter(same))
    if s.comp.name in same:
        return s.comp.name
    pref = sorted((n for n in same if s.comp.name.startswith(n)), key=len, reverse=True)
    return pref[0] if pref else ''


def _rhel_image(major, minor):
    return Image(ref=f'registry.access.redhat.com/ubi{major}/ubi', registry='registry.access.redhat.com',
                 repo=f'ubi{major}/ubi', os_id='rhel', rhel_major=major, rhel_minor=minor)


def rpm_cases(doc: Document):
    rh = [s for s in doc.statements if s.product.family == 'rhel' and s.comp is not None
          and s.comp.kind == 'rpm' and s.product.major is not None and s.product.stream != 'line']
    groups = defaultdict(list)
    for s in rh:
        m = _minor(s)
        if m is None or s.comp.is_src:
            continue
        if s.comp.evr is not None and s.comp.arch not in ('x86_64', 'noarch'):
            continue
        groups[(s.comp.name, s.product.major, m)].append(s)
    if not groups:
        return
    srcs = _sources(doc)
    products = doc.products()
    for (name, major, M) in _pick(sorted(groups), PER_DOC, doc.cve):
        H = groups[(name, major, M)]
        builds = [s for s in H if s.comp.evr is not None]
        fixes = [s for s in builds if s.status == FIXED]
        clean = [s for s in builds if s.status == NOT_AFFECTED]
        opens = [s for s in H if s.status in OPEN and s.comp.evr is None]
        if fixes and clean:
            continue                                # mixed within the stream: no single truth
        ref = (fixes or clean or [None])[0]
        src = _source_of(srcs, ref) if ref is not None else ''
        if not src:
            any_b = next((s for s in rh if s.comp.name == name and s.comp.evr is not None), None)
            src = _source_of(srcs, any_b) if any_b is not None else ''
        src = src or name

        def hide(s):
            return (s.product.family == 'rhel' and s.product.major == major and s.product.stream != 'line'
                    and _minor(s) == M and (s.comp.name == name or s.comp.is_src or s.comp.evr is None))
        rel = doc.about('rpm', name) + (doc.about('rpm', src) if src != name else [])
        hd = sub(doc, products + [s for s in rel if not hide(s)])
        mod = ref.comp.module if ref is not None else ''
        installs = []
        for f in fixes[:1]:
            e = f.comp.evr
            installs.append(('rpm_prefix', EVR(e.epoch, e.version, e.release + '~'), POS, f.comp.arch))
            installs.append(('rpm_atfix', e, CLEAR, f.comp.arch))   # the fix itself: not affected
        for c in clean[:1]:
            installs.append(('rpm_clean', c.comp.evr, CLEAR, c.comp.arch))
        if opens and not builds:
            others = [s for s in hd.statements if s.comp is not None and s.comp.name == name
                      and s.status == FIXED and s.comp.evr is not None and s.product.major == major]
            if others:
                lo = min(others, key=lambda s: cmp_to_key(evr_cmp)(s.comp.evr)).comp.evr
                installs.append(('rpm_open', EVR(lo.epoch, lo.version, lo.release + '~'), POS, 'x86_64'))
        for case, evr, truth, arch in installs:
            pkg = Package('rpm', name, f'{evr.version}-{evr.release}', epoch=evr.epoch, arch=arch or 'x86_64',
                          source=src, vendor='Red Hat, Inc.',
                          module=mod if mod else ('' if not (ref and ref.comp.dist.module) else None))
            v = Engine(None, Scope(_rhel_image(major, M), major, M, rhel_image=True))._judge(pkg, hd)
            yield {'case': case, 'rule': v.rule, 'stated': v.stated, 'status': v.status, 'truth': truth,
                   'cve': doc.cve, 'what': f'{name} RHEL {major}.{M}', 'installed': str(evr)}


def foreign_cases(doc: Document):
    """An rpm named by RHEL and by another product: hide every RHEL statement
    about it. Does the other product's statement predict RHEL's?"""
    rh = defaultdict(list)
    other = set()
    for s in doc.statements:
        c = s.comp
        if c is None or c.kind != 'rpm' or c.is_src and c.evr is not None:
            continue
        if s.product.family == 'rhel' and s.product.major in (8, 9, 10):
            rh[(c.name, s.product.major)].append(s)
        elif s.product.family in ('ocp', 'layered'):
            other.add(c.name)
    products = doc.products()
    for (name, major) in _pick(sorted(k for k in rh if k[0] in other), PER_DOC, doc.cve):
        R = rh[(name, major)]
        fixes = [s for s in R if s.status == FIXED and s.comp.evr is not None and not s.comp.is_src]
        opens = [s for s in R if s.status in OPEN]
        clean = [s for s in R if s.status == NOT_AFFECTED]
        if fixes:
            e = fixes[0].comp.evr
            evr, M, truth = EVR(e.epoch, e.version, e.release + '~'), _minor(fixes[0]), POS
        elif opens:
            evr, M, truth = EVR(None, '0', f'0.el{major}'), None, POS
        elif clean:
            b = next((s for s in clean if s.comp.evr is not None), None)
            evr = b.comp.evr if b else EVR(None, '0', f'0.el{major}')
            M, truth = (_minor(b) if b else None), CLEAR
        else:
            continue
        hd = sub(doc, products + [s for s in doc.about('rpm', name) if s.product.family != 'rhel'])
        pkg = Package('rpm', name, f'{evr.version}-{evr.release}', epoch=evr.epoch, arch='x86_64', source=name,
                      vendor='Red Hat, Inc.', module='')
        v = Engine(None, Scope(_rhel_image(major, M), major, M, rhel_image=True))._judge(pkg, hd)
        ev = next((s for s in hd.statements if v.evidence and s.pid == v.evidence[0]), None)
        yield {'case': 'foreign', 'rule': v.rule, 'stated': v.stated, 'status': v.status, 'truth': truth,
               'cve': doc.cve, 'what': f'{name} RHEL {major}', 'installed': str(evr), 'product': v.product,
               'evidence_kind': '' if ev is None else ('build' if ev.comp.evr is not None else 'versionless'),
               'evidence_key': '' if ev is None else ev.product.key}


# ── image cases ─────────────────────────────────────────────────────────────

def _img(path: str, major, labels=None):
    return Image(ref=f'registry.redhat.io/{path}', registry='registry.redhat.io', repo=path,
                 labels=labels or {}, digests=set(), os_id='rhel', rhel_major=major or 9, rhel_minor=None)


def _truth(S: list) -> str:
    if any(s.status in OPEN for s in S):
        return POS
    if any(s.status == FIXED for s in S):
        return FIX
    if all(s.flag == 'component_not_present' for s in S if s.status == NOT_AFFECTED):
        return ABSENT
    return CLEAR


def _node_counts(statements, keys) -> dict:
    """{product id: Counter} of what each node of `keys` says, image and other."""
    nodes: dict = defaultdict(Counter)
    for s in statements:
        p = s.product
        if p.key not in keys or p.family not in ('ocp', 'layered'):
            continue
        c = s.comp
        n = nodes[p.id]
        if c is not None and c.kind == 'image':
            n['img_open' if s.status in OPEN else 'img_clear'] += 1
        elif s.status in OPEN:
            n['other_open'] += 1
        else:
            n['other_clear'] += 1
    return nodes


def _paths(statements) -> tuple:
    """{product id: open paths}, {product id: cleared paths} — distinct images per node."""
    op, cl = defaultdict(set), defaultdict(set)
    for s in statements:
        if s.comp is not None and s.comp.kind == 'image':
            (op if s.status in OPEN else cl)[s.product.id].add(s.comp.name)
    return op, cl


def errata_variants(nodes, versions, paths, version: str) -> dict:
    """What each variant of the errata assumption says for an unnamed image at
    `version`: True = assumed affected. nodes: {pid: Counter}; paths: {pid: (open, clear)}."""
    def rel(pid):
        return version_relation(version, versions[pid])
    sel = {pid: n for pid, n in nodes.items() if rel(pid) in ('own', 'line', 'newer')}
    ol = {pid: n for pid, n in sel.items() if rel(pid) in ('own', 'line')}
    out = {'current': any(n['img_open'] and not (n['img_clear'] or n['other_clear']) for n in sel.values()),
           'images_only': any(n['img_open'] and not n['img_clear'] for n in sel.values()),
           'never': False,
           'any_open': any(n['img_open'] for n in sel.values())}
    for t in (0.5, 0.75, 0.9):
        def frac(pid, t=t):
            o, c = len(paths[pid][0]), len(paths[pid][1] - paths[pid][0])
            return bool(o) and o / (o + c) > t
        out[f'paths>{t}'] = any(frac(pid) for pid in sel)
        out[f'own_line_paths>{t}'] = any(frac(pid) for pid in ol)
    out['current_own_line'] = any(n['img_open'] and not (n['img_clear'] or n['other_clear']) for n in ol.values())
    return out


def image_cases(doc: Document):
    imgs = [s for s in doc.statements if s.comp is not None and s.comp.kind == 'image' and s.comp.name
            and s.product.family in ('ocp', 'layered')]
    if not imgs:
        return
    by = defaultdict(list)
    for s in imgs:
        by[(s.comp.name, s.product.key)].append(s)
    # the engine reads, for an image: product statements, image statements and
    # (errata assumption) which product nodes cleared anything — one stand-in each
    stand: dict = {}
    for s in doc.statements:
        if s.comp is not None and s.comp.kind != 'image' and s.status in (FIXED, NOT_AFFECTED):
            stand.setdefault(s.product.id, s)
    base = doc.products() + list(stand.values())
    by_path = defaultdict(list)
    for s in doc.statements:
        if s.comp is not None and s.comp.kind == 'image':
            by_path[s.comp.name].append(s)
    versions = {s.product.id: s.product.version for s in doc.statements}
    targets = []
    for (path, key), S in by.items():
        vs = defaultdict(list)
        line = []
        for s in S:
            (line if s.product.is_line else vs[s.product.version]).append(s)
        major = next((s.product.major for s in S if s.product.major), 9)
        for ver, own in (list(vs.items()) or ([('', line)] if line else [])):
            targets.append((path, key, ver, own, major))
    counts: dict = {}
    for (path, key, ver, own, major) in _pick(sorted(targets, key=lambda t: t[:3]), PER_DOC, doc.cve):
        truth = _truth(own)
        rest = [s for p, ss in by_path.items() if p != path for s in ss]
        hd = sub(doc, base + rest)
        sc = Scope(_img(path, major), major, None, keys={key}, version=ver, paths=set())
        v = Engine(None, sc)._judge(MODULE, hd)
        if key not in counts:
            counts[key] = _node_counts(doc.statements, {key})
        nodes = {pid: Counter(n) for pid, n in counts[key].items()}
        for s in by_path[path]:
            if s.product.id in nodes:
                nodes[s.product.id]['img_open' if s.status in OPEN else 'img_clear'] -= 1
        nodes = {pid: n for pid, n in nodes.items() if sum(n.values()) > 0}
        op, cl = _paths(rest)
        paths = {pid: (op.get(pid, set()), cl.get(pid, set())) for pid in nodes}
        feats = [(version_relation(ver, versions[pid]), len(paths[pid][0]), len(paths[pid][1] - paths[pid][0]),
                  n['other_open'], n['other_clear']) for pid, n in nodes.items()]
        yield {'case': 'unnamed', 'rule': v.rule, 'stated': v.stated, 'status': v.status, 'truth': truth,
               'cve': doc.cve, 'what': f'{path} {key} {ver or "line"}', 'key': key, 'nodes': feats,
               'variants': errata_variants(nodes, versions, paths, ver)}
        if not ver:
            continue
        mine = [s for s in by_path[path]
                if not (s.product.key == key and version_relation(ver, s.product.version) == 'own')]
        sc = Scope(_img(path, major), major, None, keys={key}, version=ver, paths={path})
        v = Engine(None, sc)._judge(MODULE, sub(doc, base + rest + mine))
        seen = Counter(f'{version_relation(ver, s.product.version) if s.product.key == key else "foreign"}:'
                       f'{s.status}' for s in mine)
        yield {'case': 'version', 'rule': v.rule, 'stated': v.stated, 'status': v.status, 'truth': truth,
               'cve': doc.cve, 'what': f'{path} {key} {ver}', 'seen': dict(seen)}
        builds = defaultdict(list)
        for s in own:
            if s.comp.digest and s.comp.stamp:
                builds[s.comp.stamp].append(s)
        if len(builds) < 2:
            continue
        for stamp in _pick(sorted(builds), 5, doc.cve + path):
            B = builds[stamp]
            digs = {s.comp.digest for s in B}
            bt = _truth(B)
            sc = Scope(_img(path, major, {'release': str(stamp)}), major, None, keys={key}, version=ver,
                       paths={path})
            v = Engine(None, sc)._judge(MODULE, sub(doc, base + rest + [s for s in by_path[path]
                                                                        if s.comp.digest not in digs]))
            yield {'case': 'build', 'rule': v.rule, 'stated': v.stated, 'status': v.status,
                   'truth': CLEAR if bt in (FIX, ABSENT) else bt, 'cve': doc.cve,
                   'what': f'{path} {key} {ver} @{stamp}'}


# ── driver ──────────────────────────────────────────────────────────────────

_IX = None
CASES = ('rpm', 'foreign', 'image')


def _init(path, cases=CASES, per_doc=PER_DOC):
    global _IX, CASES, PER_DOC
    CASES, PER_DOC = cases, per_doc
    import sqlite3
    _IX = sqlite3.connect(f'file:{path}?mode=ro', uri=True)


def _work(cve):
    (blob,) = _IX.execute('SELECT blob FROM doc WHERE cve = ?', (cve,)).fetchone()
    doc = csaf.decode(json.loads(zlib.decompress(blob)), cve)
    out = []
    try:
        if 'rpm' in CASES:
            out += list(rpm_cases(doc))
        if 'foreign' in CASES:
            out += list(foreign_cases(doc))
        if 'image' in CASES:
            out += list(image_cases(doc))
    except Exception as e:                          # a case the tool cannot build: report, never hide
        out.append({'case': 'error', 'rule': type(e).__name__, 'status': '', 'truth': '', 'cve': cve,
                    'what': str(e)[:200], 'stated': False})
    return out


def _is_pos(truth):
    return truth in (POS, FIX)


def score(rows):
    t: dict = defaultdict(Counter)
    for r in rows:
        if r['case'] == 'error':
            t[('error', r['rule'], '')]['n'] += 1
            continue
        c = t[(r['case'], r['rule'], 'stated' if r['stated'] else 'inferred')]
        c['n'] += 1
        pred_pos = klass(r['status']) == POS
        c['truth_' + r['truth']] += 1
        c['correct'] += pred_pos == _is_pos(r['truth'])
        if r['truth'] in (POS, CLEAR):              # decisive: affected, or not affected with the component present
            c['decisive'] += 1
            c['decisive_correct'] += pred_pos == (r['truth'] == POS)
    return t


def report(rows, ndocs, out=sys.stdout):
    t = score(rows)

    def p(*a):
        print(*a, file=out)
    p(f'{ndocs:,} documents, {len(rows):,} cases (at most {PER_DOC} per document per kind)\n')
    p('accuracy: fixed counts as affected (a build before the fix). decisive: affected or clear only')
    p('(clear = not affected with the component present; absent = component_not_present only).\n')
    p(f'{"case":10} {"rule":26} {"":8} {"n":>8} {"accuracy":>9} {"decisive":>9}   '
      'truth affected / fixed / clear / absent')
    for k in sorted(t, key=lambda k: (k[0], -t[k]['n'])):
        c = t[k]
        if k[0] == 'error':
            p(f'error      {k[1]:26} {"":8} {c["n"]:8,}')
            continue
        dec = f'{c["decisive_correct"] / c["decisive"]:9.1%}' if c['decisive'] else f'{"-":>9}'
        p(f'{k[0]:10} {k[1]:26} {k[2]:8} {c["n"]:8,} {c["correct"] / c["n"]:9.1%} {dec}   '
          f'{c["truth_affected"]:,} / {c["truth_fixed"]:,} / {c["truth_clear"]:,} / {c["truth_absent"]:,}')
    un = [r for r in rows if r['case'] == 'unnamed']
    if un:
        p('\nerrata-assumption variants on the unnamed-image cases (fires = assumed affected)')
        p(f'truth: {dict(Counter(r["truth"] for r in un))}')
        p(f'{"variant":22} {"fires":>7} {"precision":>10} {"recall":>7} {"accuracy":>9} {"decisive":>9}')
        pos = sum(1 for r in un if _is_pos(r['truth']))
        dec = [r for r in un if r['truth'] in (POS, CLEAR)]
        for n in un[0]['variants']:
            fire = [r for r in un if r['variants'][n]]
            tp = sum(1 for r in fire if _is_pos(r['truth']))
            correct = sum(1 for r in un if r['variants'][n] == _is_pos(r['truth']))
            dcorrect = sum(1 for r in dec if r['variants'][n] == (r['truth'] == POS))
            p(f'{n:22} {len(fire):7,} {tp / len(fire) if fire else 0:10.1%} {tp / pos if pos else 0:7.1%} '
              f'{correct / len(un):9.1%} {dcorrect / len(dec) if dec else 0:9.1%}')


def main():
    global PER_DOC
    ap = argparse.ArgumentParser()
    ap.add_argument('--index', default=os.path.join('data', 'vextriage.sqlite'))
    ap.add_argument('--sample', type=int, default=0, help='only this many documents (random)')
    ap.add_argument('--out', help='write every case as JSON lines')
    ap.add_argument('--report', help='also write the report to this file')
    ap.add_argument('--workers', type=int, default=max(1, (os.cpu_count() or 2)))
    ap.add_argument('--cases', default=','.join(CASES), help='rpm,foreign,image')
    ap.add_argument('--per-doc', type=int, default=PER_DOC, help='cases of each kind per document, at most')
    a = ap.parse_args()
    PER_DOC = a.per_doc
    import sqlite3
    cves = [c for (c,) in sqlite3.connect(a.index).execute('SELECT cve FROM doc ORDER BY cve')]
    if a.sample:
        cves = random.Random(0).sample(cves, min(a.sample, len(cves)))
    rows = []
    with Pool(a.workers, _init, (a.index, tuple(a.cases.split(',')), a.per_doc)) as pool:
        for i, out in enumerate(pool.imap_unordered(_work, cves, chunksize=8), 1):
            rows += out
            if i % 5000 == 0:
                print(f'  {i:,}/{len(cves):,} documents, {len(rows):,} cases', file=sys.stderr)
    if a.out:
        with open(a.out, 'w') as fh:
            for r in rows:
                fh.write(json.dumps(r) + '\n')
    report(rows, len(cves))
    if a.report:
        with open(a.report, 'w') as fh:
            report(rows, len(cves), fh)


if __name__ == '__main__':
    main()
