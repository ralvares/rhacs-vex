#!/usr/bin/env python3
"""Legacy vs current engine on the real findings stored in data/parquet/.

The parquets hold RHACS findings for whole OCP releases and operator bundles
(component, version, CVE, source, image).  Every distinct finding is replayed
through both engines against the mirrored Red Hat VEX in data/vex/, with the
same workload context handed to each.  Exit 1 on any difference.

    python3 tests/diff_engines_parquet.py [--scope ocp|operators|all] [--show N]

The context is rebuilt from the image ref the way the offline retriage did
(release-pinned for OCP payload images); the RHEL major is taken from the
image's own rpm dist-tags, because the parquets do not keep the scanner's OS.
"""
import argparse
import collections
import glob
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))
sys.path.insert(0, ROOT)

import pyarrow.parquet as pq                    # noqa: E402

from tests.legacy import engine_legacy as old   # noqa: E402
from rhacs_vex import engine as new             # noqa: E402
from rhacs_vex.core.store import read_vex      # noqa: E402

KEEP = ['COMPONENT', 'VERSION', 'CVE', 'SOURCE', 'LOCATION', 'FIXED_VERSION',
        'RHACS_SEVERITY', 'IMAGE', 'OCP_COMPONENT', 'OCP_VERSION', 'AUDIT_RESULT']


def load(scope):
    pats = {'ocp': ['data/parquet/ocp/*.parquet'],
            'operators': ['data/parquet/operators/*.parquet']}
    files = sum((glob.glob(p) for s in (['ocp', 'operators'] if scope == 'all' else [scope])
                 for p in pats[s]), [])
    rows = {}
    for f in sorted(files):
        kind = 'ocp' if '/ocp/' in f else 'operator'
        t = pq.read_table(f)
        df = t.select([c for c in KEEP if c in t.column_names]).to_pandas()
        for rec in df.to_dict('records'):
            rec = {k: ('' if v is None or (isinstance(v, float) and v != v) else str(v))
                   for k, v in rec.items()}
            # Scope depends on the OCP minor only; patch releases of one minor
            # share images, so one representative patch per minor suffices.
            minor = '.'.join(rec.get('OCP_VERSION', '').split('.')[:2])
            key = (kind, rec['IMAGE'], rec.get('OCP_COMPONENT', ''), minor,
                   rec['COMPONENT'], rec['VERSION'], rec['CVE'].upper(), rec['SOURCE'],
                   rec['LOCATION'], rec['FIXED_VERSION'])
            rows.setdefault(key, rec)
    return rows


def os_hints(rows):
    """Most common .elN among an image's rpm versions → 'rhel:N'."""
    c = collections.defaultdict(collections.Counter)
    for (_k, img, *_), rec in rows.items():
        if rec['SOURCE'] == 'OS':
            m = re.search(r'[.+]el(\d+)', rec['VERSION'])
            if m:
                c[img][m.group(1)] += 1
    return {img: f"rhel:{cnt.most_common(1)[0][0]}" for img, cnt in c.items()}


def make_ctx(mod, kind, image, comp, ocp_version, hint):
    ctx = mod.parse_image_ref(image, os_hint=hint)
    if kind == 'ocp':
        minor = '.'.join(ocp_version.split('.')[:2])
        ctx.workload_type = 'ocp'
        ctx.ocp_ver = minor
        ctx.display_name = f'OpenShift {ocp_version}'
        ctx.extra_prefixes = []
        ctx.ocp_component = comp or None
    return ctx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scope', default='all', choices=['ocp', 'operators', 'all'])
    ap.add_argument('--show', type=int, default=15)
    ap.add_argument('--per-cve', type=int, default=0, metavar='K',
                    help='sample at most K findings per CVE, spread across distinct '
                         '(image, source, component) — 0 = every finding')
    ap.add_argument('--shard', default='0/1', metavar='I/N',
                    help='only CVEs whose position mod N == I (run N in parallel)')
    args = ap.parse_args()

    t0 = time.time()
    rows = load(args.scope)
    hints = os_hints(rows)
    by_cve = collections.defaultdict(list)
    for key, rec in rows.items():
        by_cve[key[6]].append((key, rec))
    print(f'{len(rows):,} distinct findings, {len(by_cve):,} CVEs '
          f'(loaded in {time.time() - t0:.0f}s)', file=sys.stderr)

    ctxs = {}
    total = diffs = shown = missing_doc = 0
    stored_agree = stored_total = 0
    verdicts = collections.Counter()
    diff_kinds = collections.Counter()
    if args.per_cve:
        for cve, items in by_cve.items():
            if len(items) > args.per_cve:
                seen, keep = set(), []
                for key, rec in items:          # one per (image, source, component)
                    k = (key[1], rec['SOURCE'], rec['COMPONENT'])
                    if k not in seen:
                        seen.add(k)
                        keep.append((key, rec))
                by_cve[cve] = keep[:args.per_cve]
        print(f'sampled to {sum(map(len, by_cve.values())):,} findings', file=sys.stderr)
    si, sn = (int(x) for x in args.shard.split('/'))
    todo = [kv for n, kv in enumerate(sorted(by_cve.items())) if n % sn == si]
    for i, (cve, items) in enumerate(todo, 1):
        data = read_vex(cve)
        if data is None:
            missing_doc += len(items)
        for key, rec in items:
            kind, image, comp, ocpv = key[:4]
            ck = (kind, image, comp, ocpv)
            if ck not in ctxs:
                h = hints.get(image, '')
                ctxs[ck] = (make_ctx(old, kind, image, comp, ocpv, h),
                            make_ctx(new, kind, image, comp, ocpv, h))
            c_old, c_new = ctxs[ck]
            row = {'COMPONENT': rec['COMPONENT'], 'VERSION': rec['VERSION'], 'CVE': cve,
                   'SOURCE': rec['SOURCE'], 'LOCATION': rec['LOCATION'],
                   'FIXED_VERSION': rec['FIXED_VERSION'],
                   'SEVERITY': rec.get('RHACS_SEVERITY', '').upper()}
            a = [str(x) for x in old.audit_row_with_doc(row, c_old, data)]
            b = [str(x) for x in new.audit_row_with_doc(row, c_new, data)]
            a.append(old._vex_product_with_doc(row, c_old, data))
            b.append(new._vex_product_with_doc(row, c_new, data))
            total += 1
            verdicts[b[0]] += 1
            if data is not None and rec.get('AUDIT_RESULT'):
                stored_total += 1
                stored_agree += rec['AUDIT_RESULT'] == b[0]
            if a != b:
                diffs += 1
                diff_kinds[tuple(k for k, (x, y) in enumerate(zip(a, b)) if x != y)] += 1
                if shown < args.show:
                    shown += 1
                    print(f'--- {kind} {image} [{comp}] {rec["COMPONENT"]} {rec["VERSION"]} {cve}')
                    for k, (x, y) in enumerate(zip(a, b)):
                        if x != y:
                            print(f'    [{k}] legacy={x!r}\n        new   ={y!r}')
        if i % 250 == 0:
            print(f'… {i:,}/{len(todo):,} CVEs, {total:,} rows, {diffs} diffs '
                  f'({time.time() - t0:.0f}s)', file=sys.stderr)

    print(f'\n{total:,} findings replayed ({missing_doc:,} with no VEX file), '
          f'{diffs} differences between legacy and new engine')
    if diff_kinds:
        print('  differing fields:', dict(diff_kinds))
    print(f'  verdicts: {dict(verdicts)}')
    if stored_total:
        print(f'  agreement with the verdict stored in the parquet (older engine, older '
              f'VEX): {stored_agree:,}/{stored_total:,} '
              f'({100 * stored_agree / stored_total:.1f}%)')
    print(f'  {time.time() - t0:.0f}s')
    sys.exit(1 if diffs else 0)


if __name__ == '__main__':
    main()
