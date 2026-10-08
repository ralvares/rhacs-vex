#!/usr/bin/env python3
"""Legacy vs current engine on REAL data: your VEX mirror + cached RHACS scans.

The fuzz test (tests/fuzz_engine_diff.py) proves the two engines agree on
synthetic documents; this runs them over the actual corpus.  Run from the repo
root after `vextriage sync` and at least one RHACS run (data/scans/*.json):

    python3 tests/diff_engines_corpus.py [--limit N] [--show N]

Exit status is 1 when any row differs.  Delete tests/legacy/ once this has been
clean on your data.
"""
import argparse
import copy
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))
sys.path.insert(0, ROOT)

from tests.legacy import engine_legacy as old   # noqa: E402
from rhacs_vex import engine as new             # noqa: E402
from rhacs_vex.core.store import read_vex      # noqa: E402
from rhacs_vex.triage import rhacs_to_df as scan_to_df  # noqa: E402


def contexts(scan: dict, ref: str):
    labels = (scan.get('metadata') or {}).get('v1', {}).get('labels') or {}
    os_info = (scan.get('scan') or {}).get('operatingSystem', '')
    out = []
    for mod in (old, new):
        out.append(mod.parse_context_from_labels(labels, ref, os_info) if labels
                   else mod.parse_image_ref(ref, os_hint=os_info))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scans', default='data/scans')
    ap.add_argument('--limit', type=int, default=0, help='images to check (0 = all)')
    ap.add_argument('--show', type=int, default=10)
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.scans, '*.json')))
    if args.limit:
        files = files[:args.limit]
    rows = diffs = shown = 0
    docs = {}
    for i, path in enumerate(files, 1):
        try:
            scan = json.load(open(path))
        except Exception:
            continue
        ref = ((scan.get('name') or {}).get('fullName')
               or os.path.basename(path)[:-5].replace('_', '/', 2))
        ctx_old, ctx_new = contexts(scan, ref)
        df = scan_to_df(scan)
        for rec in df.to_dict('records'):
            cve = str(rec['CVE']).upper()
            if cve not in docs:
                if len(docs) > 64:
                    docs.clear()
                docs[cve] = read_vex(cve)
            data = docs[cve]
            a = [str(x) for x in old.audit_row_with_doc(rec, ctx_old,
                                                        copy.deepcopy(data) if data else None)]
            b = [str(x) for x in new.audit_row_with_doc(rec, ctx_new, data)]
            rows += 1
            if a != b:
                diffs += 1
                if shown < args.show:
                    shown += 1
                    print(f'--- {ref}  {rec["COMPONENT"]} {rec["VERSION"]} {cve}')
                    for k, (x, y) in enumerate(zip(a, b)):
                        if x != y:
                            print(f'    [{k}] legacy={x!r}\n        new   ={y!r}')
        if i % 50 == 0:
            print(f'… {i}/{len(files)} images, {rows:,} rows, {diffs} diffs', file=sys.stderr)
    print(f'\n{len(files)} images, {rows:,} rows, {diffs} differences')
    sys.exit(1 if diffs else 0)


if __name__ == '__main__':
    main()
