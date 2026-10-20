"""vextriage — triage grype / trivy / syft findings against Red Hat CSAF-VEX; publish OpenVEX.

    vextriage sync                                   mirror Red Hat VEX, build the index
    vextriage scan IMAGE                             syft → the free scan (no scanner)
    vextriage scan IMAGE --scanner grype|trivy       run the scanner, triage its findings
    vextriage scan --sbom s.json [--grype g.json | --trivy t.json]   from files
    vextriage openvex IMAGE|--sbom s.json -o out.openvex.json        Red Hat's verdicts as OpenVEX
    vextriage explain CVE IMAGE|--sbom s.json        the statements and how they decide
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from . import __version__

DATA = os.environ.get('VEXTRIAGE_DATA', 'data')


def _paths(args):
    vex = args.vex or os.path.join(DATA, 'vex')
    idx = args.index or os.path.join(DATA, 'vextriage.sqlite')
    return vex, idx


def _err(msg: str) -> int:
    print(f'vextriage: {msg}', file=sys.stderr)
    return 2


def _run(cmd: list, out: str) -> None:
    exe = shutil.which(cmd[0])
    if not exe:
        raise SystemExit(_err(f'{cmd[0]} is not installed (needed for: {" ".join(cmd)})'))
    with open(out, 'w') as fh:
        p = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise SystemExit(_err(f'{" ".join(cmd)} failed:\n{p.stderr[-2000:]}'))


def _index(args):
    from .index import Index
    vex, idx = _paths(args)
    if not os.path.exists(idx):
        raise SystemExit(_err(f'no index at {idx} — run `vextriage sync` first'))
    return Index(idx)


def _inputs(args, need_scanner: bool):
    """→ (Image, findings or None, tmpdir). Runs syft / grype / trivy as asked."""
    from .sbom import read_syft
    from .scanners import detect, join, read_grype, read_trivy
    tmp = tempfile.mkdtemp(prefix='vextriage-')
    sbom = args.sbom
    if not sbom and args.image:
        sbom = os.path.join(tmp, 'sbom.syft.json')
        print(f'syft {args.image} …', file=sys.stderr)
        _run(['syft', args.image, '-o', 'syft-json', '-q'], sbom)
    image = read_syft(sbom) if sbom else None
    findings = None
    report = getattr(args, 'grype', None) or getattr(args, 'trivy', None)
    scanner = getattr(args, 'scanner', None)
    if not report and scanner in ('grype', 'trivy'):
        report = os.path.join(tmp, f'{scanner}.json')
        print(f'{scanner} …', file=sys.stderr)
        if scanner == 'grype':
            _run(['grype', f'sbom:{sbom}' if sbom else args.image, '-o', 'json', '-q'], report)
        else:
            if not args.image:
                raise SystemExit(_err('trivy needs the image (it does not read syft SBOMs)'))
            _run(['trivy', 'image', '-q', '-f', 'json', args.image], report)
    if report:
        with open(report) as fh:
            doc = json.load(fh)
        kind = detect(doc)
        if kind == 'grype':
            scanned, findings = read_grype(doc)
        elif kind == 'trivy':
            scanned, findings = read_trivy(doc)
        else:
            raise SystemExit(_err(f'{report}: not a grype or trivy JSON report'))
        if image is None:
            image = scanned
        else:
            join(findings, image)
            if not image.digests:
                image.digests |= scanned.digests
    if image is None:
        raise SystemExit(_err('give an IMAGE, --sbom, --grype or --trivy'))
    return image, findings, tmp


def cmd_sync(args) -> int:
    from .index import Index
    from .sync import mirror
    vex, idx = _paths(args)
    if not args.offline:
        print(json.dumps(mirror(vex, full=args.full)))
    if not os.path.isdir(vex):
        return _err(f'no mirror at {vex}')
    os.makedirs(os.path.dirname(idx) or '.', exist_ok=True)
    ix = Index(idx)
    print(json.dumps(ix.update(vex, full=args.full,
                               progress=lambda d, n: print(f'  indexed {d:,}/{n:,}', file=sys.stderr))))
    return 0


def _triage(args):
    from .triage import triage
    image, findings, tmp = _inputs(args, need_scanner=False)
    ix = _index(args)
    scope, rows = triage(image, ix, findings)
    shutil.rmtree(tmp, ignore_errors=True)
    return image, scope, rows


def cmd_scan(args) -> int:
    from . import openvex, report
    image, scope, rows = _triage(args)
    recs = report.records(rows)
    if args.json:
        with open(args.json, 'w') as fh:
            report.write_json(recs, fh)
    if args.csv:
        with open(args.csv, 'w', newline='') as fh:
            report.write_csv(recs, fh)
    if args.openvex:
        doc = openvex.document(image, ((r.finding.cve, r.finding.package, r.verdict) for r in rows),
                               stated_only=args.stated_only)
        with open(args.openvex, 'w') as fh:
            json.dump(doc, fh, indent=1)
    if args.format == 'json':
        report.write_json(recs, sys.stdout)
    elif args.format == 'csv':
        report.write_csv(recs, sys.stdout)
    else:
        report.print_table(recs, scope, image, show_all=args.all)
    pos = sum(1 for r in recs if r['status'] in ('affected', 'under_investigation'))
    return 1 if (args.fail and pos) else 0


def cmd_openvex(args) -> int:
    from . import openvex
    image, scope, rows = _triage(args)
    doc = openvex.document(image, ((r.finding.cve, r.finding.package, r.verdict) for r in rows),
                           stated_only=args.stated_only)
    out = open(args.output, 'w') if args.output else sys.stdout
    json.dump(doc, out, indent=1)
    out.write('\n')
    if args.output:
        out.close()
        n = len(doc['statements'])
        print(f'{args.output}: {n} statements '
              f'({sum(1 for s in doc["statements"] if s["status"] in ("not_affected", "fixed"))} not affected or fixed)',
              file=sys.stderr)
    return 0


def cmd_explain(args) -> int:
    from .engine import Engine, resolve
    from .model import Finding
    from .triage import image_package
    image, findings, tmp = _inputs(args, need_scanner=False)
    shutil.rmtree(tmp, ignore_errors=True)
    ix = _index(args)
    scope = resolve(image, ix)
    cve = args.cve.upper()
    doc = ix.doc(cve)
    print(f'image     {image.ref or image.name_label}')
    print(f'RHEL      {scope.rhel}.{scope.minor}    product {sorted(scope.keys) or ("RHEL" if scope.rhel_image else "-")} '
          f'{scope.version}    red hat image: {image.red_hat}')
    print(f'paths     {sorted(scope.paths)}')
    if doc is None:
        print(f'{cve}: Red Hat publishes no VEX document')
        return 0
    print(f'{cve}     {doc.title}  [{doc.severity}]  {len(doc.statements)} statements')
    eng = Engine(ix, scope)
    pkgs = [p for p in image.packages if not args.package or p.name == args.package]
    names = {p.name for p in pkgs} | {p.source for p in pkgs if p.source}
    relevant = [s for s in doc.statements if s.comp is not None and
                ((s.comp.kind == 'rpm' and s.comp.name in names) or
                 (s.comp.kind == 'image' and s.comp.name in scope.paths) or
                 (s.comp.kind not in ('rpm', 'image') and s.comp.name in names))]
    rel_order = {'own': 0, 'rhel': 0, 'line': 1, 'newer': 2, 'older': 3, 'unordered': 4, 'vendor': 5, 'foreign': 6}
    print(f'\nstatements naming this image or its packages ({len(relevant)}):')
    for s in sorted(relevant, key=lambda s: (rel_order.get(scope.relation(s.product), 9), s.comp.name, s.product.id))[:args.limit]:
        c = s.comp
        what = f'{c.name} {c.version}' if c.kind != 'image' else f'{c.name} {c.digest[:12]} {c.tag}'
        print(f'  [{scope.relation(s.product):9}] {s.status:20} {s.product.id[:44]:44} {what} {s.flag}')
    print('\nverdicts:')
    judged = [p for p in pkgs if p.kind != 'rpm' or p.name in {s.comp.name for s in relevant} or p.source in {s.comp.name for s in relevant}]
    if not args.package:
        judged = judged[:args.limit]
    for p in judged + [image_package(image, scope)]:
        v = eng.judge(Finding(cve, p))
        print(f'  {p.name} {p.version}: {v.status}{"" if v.stated else " (inferred)"} [{v.rule}] {v.reason}')
    return 0


def cmd_doctor(args) -> int:
    vex, idx = _paths(args)
    for tool in ('syft', 'grype', 'trivy'):
        print(f'{tool:8} {shutil.which(tool) or "not installed"}')
    n = len([f for f in os.listdir(vex) if f.endswith('.json')]) if os.path.isdir(vex) else 0
    print(f'mirror   {vex}: {n:,} documents')
    if os.path.exists(idx):
        from .index import Index
        ix = Index(idx)
        print(f'index    {idx}: {ix.count():,} documents, updated {ix.meta("updated")}')
    else:
        print(f'index    {idx}: missing — run `vextriage sync`')
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='vextriage', description=__doc__.split('\n')[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument('--version', action='version', version=f'vextriage {__version__}')
    ap.add_argument('--vex', help='mirror directory (default data/vex)')
    ap.add_argument('--index', help='index file (default data/vextriage.sqlite)')
    sub = ap.add_subparsers(dest='cmd')

    p = sub.add_parser('sync', help='mirror Red Hat CSAF-VEX and update the index')
    p.add_argument('--full', action='store_true', help='re-download the archive and rebuild the index')
    p.add_argument('--offline', action='store_true', help='only (re)index the local mirror')
    p.set_defaults(fn=cmd_sync)

    def inputs(p):
        p.add_argument('image', nargs='?', help='image reference (syft and the scanner run on it)')
        p.add_argument('--sbom', help='syft JSON SBOM of the image')
        p.add_argument('--stated-only', action='store_true',
                       help='OpenVEX: only what Red Hat stated about this product and package')

    p = sub.add_parser('scan', help='triage an image: the free scan, or grype / trivy findings')
    inputs(p)
    p.add_argument('--scanner', choices=('grype', 'trivy', 'none'), default='none')
    p.add_argument('--grype', help='grype JSON report')
    p.add_argument('--trivy', help='trivy JSON report')
    p.add_argument('--openvex', help='also write the verdicts as OpenVEX')
    p.add_argument('--json', help='also write every row as JSON')
    p.add_argument('--csv', help='also write every row as CSV')
    p.add_argument('--format', choices=('table', 'json', 'csv'), default='table')
    p.add_argument('--all', action='store_true', help='show cleared rows too')
    p.add_argument('--fail', action='store_true', help='exit 1 when anything is left to act on')
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser('openvex', help="Red Hat's verdicts for an image as OpenVEX (the free scan)")
    inputs(p)
    p.add_argument('-o', '--output')
    p.set_defaults(fn=cmd_openvex)

    p = sub.add_parser('explain', help='the statements about one CVE and how they decide')
    p.add_argument('cve')
    inputs(p)
    p.add_argument('--package', help='only this package')
    p.add_argument('--limit', type=int, default=60)
    p.set_defaults(fn=cmd_explain)

    sub.add_parser('doctor', help='tools and data present').set_defaults(fn=cmd_doctor)
    args = ap.parse_args(argv)
    if not getattr(args, 'fn', None):
        ap.print_help()
        return 2
    return args.fn(args) or 0


if __name__ == '__main__':
    sys.exit(main())
