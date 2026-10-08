"""Triage every operator's channel-head images (RHACS findings → engine).

    vextriage operators [--version 4.20,4.21] [--operator NAME,…] [--offline]

One CSV per unique bundle under data/reports/operators/
(`<operator>-<channel>-<bundle version>.csv`); which OCP minors' catalogs
reference each bundle is recorded in data/reports/operators_index.json.  A
bundle referenced by several minors is scanned and written once.

--offline re-triages from the cached RHACS scans only (no Central), which is
how verdicts are refreshed as Red Hat's VEX changes.
"""
from __future__ import annotations

import argparse
import json
import os
import re

import pandas as pd
from rich import box
from rich.console import Console
from rich.table import Table

from . import discovery, mirror, scan
from .adapters.rhacs import Central

REPORTS_DIR = os.path.join('data', 'reports')
OPERATOR_DIR = os.path.join(REPORTS_DIR, 'operators')
INDEX_PATH = os.path.join(REPORTS_DIR, 'operators_index.json')
FP, POS = '✅ FALSE POSITIVE', '❌ POSITIVE'


def report_path(operator: str, channel: str, bundle_version: str) -> str:
    clean = lambda s: re.sub(r'[/\\:*?"<>|]', '_', s)          # noqa: E731
    return os.path.join(OPERATOR_DIR, f"{operator}-{clean(channel)}-{clean(bundle_version)}.csv")


def collect(minors, op_filter=None, skip_existing=False):
    """(bundles to scan {basename: item}, {basename: {minors}}) across catalogs."""
    work, minors_of = {}, {}
    for minor in minors:
        path = discovery.catalog_path(minor)
        if not os.path.exists(path):
            continue
        for op, entries in discovery.channel_heads(path).items():
            if op_filter and op not in op_filter:
                continue
            for e in entries:
                bundle = e['head_bundle']
                version = discovery.bundle_version(op, bundle.get('name', ''))
                out = report_path(op, e['channel'], version)
                base = os.path.splitext(os.path.basename(out))[0]
                minors_of.setdefault(base, set()).add(minor)
                if base in work or (skip_existing and os.path.exists(out)):
                    continue
                work[base] = {'operator': op, 'channel': e['channel'], 'version': version,
                              'path': out, 'images': discovery.workload_images(bundle)}
    return work, minors_of


def write_index(minors_of: dict) -> None:
    """Union this run's bundle → minors map into operators_index.json."""
    try:
        with open(INDEX_PATH) as fh:
            index = {k: set(v) for k, v in json.load(fh).items()}
    except Exception:
        index = {}
    for base, minors in minors_of.items():
        index.setdefault(base, set()).update(minors)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(INDEX_PATH, 'w') as fh:
        json.dump({k: sorted(v) for k, v in sorted(index.items())}, fh, indent=2)


def assemble(item: dict, results: dict):
    """One bundle's report from its images' results (IMAGE, IMAGE_ROLE first)."""
    parts = []
    for role, img in item['images']:
        res = results.get(img) or {}
        if res.get('result_df') is not None:
            df = res['result_df'].copy()
            df.insert(0, 'IMAGE', img)
            df.insert(1, 'IMAGE_ROLE', role)
            parts.append(df)
    return pd.concat(parts, ignore_index=True) if parts else None


def run(minors, *, op_filter=None, workers=10, false_only=False, skip_existing=False,
        offline=False, console=None) -> int:
    console = console or Console()
    central = Central.from_env(offline=offline)
    if not (offline or central.configured):
        console.print('[red]ROX_ENDPOINT and ROX_API_TOKEN must be set (or use --offline).[/red]')
        return 1
    work, minors_of = collect(minors, op_filter, skip_existing)
    write_index(minors_of)
    images = sorted({img for item in work.values() for _r, img in item['images']})
    console.print(f"📊 {len(work)} bundles, {len(images)} unique images "
                  f"({'cached scans only' if offline else 'RHACS'})")
    if not images:
        return 0
    results = scan.rhacs_batch(central, [(img, img, None, None) for img in images],
                               workers=workers, false_only=false_only)
    os.makedirs(OPERATOR_DIR, exist_ok=True)
    rows = []
    for base, item in sorted(work.items()):
        df = assemble(item, results)
        counts = df['AUDIT_RESULT'].value_counts().to_dict() if df is not None else {}
        if df is not None:
            df.to_csv(item['path'], index=False)
        rows.append({**item, 'base': base, 'pos': counts.get(POS, 0), 'fp': counts.get(FP, 0),
                     'written': df is not None})
    for minor in minors:
        mine = [r for r in rows if minor in minors_of.get(r['base'], ())]
        if mine:
            summary(console, minor, mine)
    failed = sum(1 for r in results.values() if r.get('found') is None)
    return 2 if failed else 0


def summary(console, minor: str, rows: list) -> None:
    t = Table(title=f"OCP {minor} — operators", box=box.ROUNDED, header_style="bold")
    for col, kw in (('Operator', {'style': 'cyan'}), ('Channel', {'style': 'magenta'}),
                    ('Bundle', {'style': 'dim'}), ('Images', {'justify': 'right'}),
                    ('Positive', {'justify': 'right', 'style': 'bold red'}),
                    ('False positive', {'justify': 'right', 'style': 'bold green'})):
        t.add_column(col, **kw)
    for r in rows:
        t.add_row(r['operator'], r['channel'], r['version'], str(len(r['images'])),
                  str(r['pos'] or '-'), str(r['fp'] or '-'))
    console.print(t)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='vextriage operators', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--version', default=None, help='OCP minor(s), comma-separated '
                                                    '(default: every catalog on disk)')
    ap.add_argument('--operator', default=None, help='package name(s), comma-separated')
    ap.add_argument('--workers', type=int, default=10)
    ap.add_argument('--false-only', action='store_true')
    ap.add_argument('--skip-existing', action='store_true',
                    help='skip bundles whose report already exists')
    ap.add_argument('--offline', action='store_true',
                    help='cached RHACS scans only — refresh verdicts without Central')
    args = ap.parse_args(argv)
    console = Console()
    mirror.ensure_mirror(console)
    minors = ([v.strip() for v in args.version.split(',') if v.strip()] if args.version
              else discovery.catalog_versions())
    if not minors:
        console.print(f'[red]no catalogs under {discovery.CATALOG_DIR}[/red]')
        return 1
    ops = {o.strip() for o in args.operator.split(',')} if args.operator else None
    return run(minors, op_filter=ops, workers=args.workers, false_only=args.false_only,
               skip_existing=args.skip_existing, offline=args.offline, console=console)


if __name__ == '__main__':
    raise SystemExit(main())
