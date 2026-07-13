"""cli.py — the `vextriage` umbrella CLI.

One tool, scanner as subcommand; the engine judges every scanner the same way
(scanner = discovery, engine = verdict, OpenVEX = output):

    vextriage rhacs    ...             today's rhacs-vex CLI, unchanged
    vextriage grype    <image|sbom>    syft SBOM + grype scan → engine triage
    vextriage trivy    <image|report>  trivy scan → engine triage
    vextriage generate --images FILE   batch: scan → triage → OpenVEX hub
    vextriage hub      ...             (re)build hub index + manifest
    vextriage pipeline|operators|retriage|parquet   passthroughs

OpenVEX documents are generated ONLY from consumer-side scans (syft+grype):
the statement purls come from the scanner's own artifacts, so grype/trivy are
guaranteed to match them.  RHACS triage output is never converted to OpenVEX —
RHACS does not consume OpenVEX.  `--openvex-dir` on the scanner subcommands
writes per-image documents in the vexhub layout (see hub.py / openvex.py).
Run from the repository root — all data paths are relative, like every other
tool in this package.
"""
from __future__ import annotations

import argparse
import os
import sys

from rich.console import Console


def _export_openvex(result_df, image_ref: str, hub_dir: str, author: str,
                    console: Console) -> None:
    """Write one image's FALSE-POSITIVE verdicts into the hub and reindex."""
    from . import hub, openvex
    statements = openvex.statements_from_df(result_df, image_ref)
    if not statements:
        console.print('[yellow]No FALSE POSITIVE verdicts — nothing to export.[/yellow]')
        return
    path, changed = hub.write_image_doc(hub_dir, image_ref, statements, author=author)
    stats = hub.build_index(hub_dir, name=author,
                            description='Red Hat VEX triage verdicts (OpenVEX)')
    state = 'updated' if changed else 'unchanged'
    console.print(f"OpenVEX: [bold]{len(statements)}[/bold] statements → {path} "
                  f"({state}; hub: {stats['documents']} documents)")


def _scanner_cmd(scanner: str, args) -> int:
    """Shared grype/trivy flow: adapt → context → audit → render → export."""
    from . import triage
    from .context import context_for_image
    console = Console()

    if scanner == 'grype':
        from .adapters import grype as adapter
        target = args.target
        if not os.path.exists(target):
            console.print(f"🧾 syft SBOM for [bold cyan]{target}[/bold cyan]...")
            target = adapter.syft_sbom(args.target, platform=args.platform,
                                       force=args.force)
        console.print("🔍 grype scan...")
        doc = adapter.grype_scan(target)
        df = adapter.to_df(doc)
        hint = adapter.os_hint(doc)
    else:
        from .adapters import trivy as adapter
        console.print("🔍 trivy scan...")
        doc = adapter.trivy_scan(args.target, platform=args.platform)
        df = adapter.to_df(doc)
        hint = adapter.os_hint(doc)

    image_ref = args.image or (args.target if not os.path.exists(args.target) else '')
    if not image_ref:
        console.print('[red]--image <digest-pinned ref> is required when scanning '
                      'from a file (context + OpenVEX product identity).[/red]')
        return 2

    console.print(f"🧭 Image context via labels: [bold cyan]{image_ref}[/bold cyan]")
    ctx = context_for_image(image_ref, os_hint=hint)

    result_df = triage._audit_and_display(
        df, ctx, console, output_path=args.output, output_fmt=args.format,
        false_only=args.false_only)

    if args.openvex_dir:
        try:
            _export_openvex(result_df, image_ref, args.openvex_dir, args.author, console)
        except ValueError as e:
            console.print(f'[red]OpenVEX export skipped: {e}[/red]')
            return 1
    return 0


def _generate_cmd(args) -> int:
    """Scan a list of images with grype and populate the OpenVEX hub.

    This is the ONLY hub-population pipeline: statements are minted from the
    consumer-side scanner's own artifacts, so the purls in the document are
    guaranteed to match what that scanner (and trivy) will look up.  RHACS
    triage output is never converted to OpenVEX — RHACS does not consume it.
    """
    import re as _re
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from . import hub, openvex, triage
    from .adapters import grype as adapter
    from .context import context_for_image
    console = Console()

    refs: list = []
    if args.image:
        refs.append(args.image)
    if args.images:
        with open(args.images) as fh:
            for line in fh:
                m = _re.search(r'(\S+@sha256:[a-f0-9]{64})', line)
                if m:
                    refs.append(m.group(1))
    if args.ocp:
        # Same discovery artifact the RHACS pipeline uses (stage 3, oc release
        # info) — an image list, not RHACS data.
        for v in args.ocp.split(','):
            path = os.path.join('data', 'pullspecs', f'{v.strip()}.txt')
            if not os.path.exists(path):
                console.print(f'[red]missing pullspec file: {path}[/red]')
                return 2
            with open(path) as fh:
                for line in fh:
                    m = _re.search(r'(\S+@sha256:[a-f0-9]{64})', line)
                    if m:
                        refs.append(m.group(1))
    if args.operators:
        # Channel-head bundles from the opm-rendered catalogs (pipeline stage 1)
        # — identical scope to the RHACS operators run.
        import glob as _glob

        from . import operators as ops
        pattern = f'catalog-{args.catalog}.json' if args.catalog else 'catalog-*.json'
        catalogs = sorted(_glob.glob(os.path.join('data', 'catalogs', pattern)))
        if not catalogs:
            console.print(f'[red]no catalogs match data/catalogs/{pattern}[/red]')
            return 2
        for cat in catalogs:
            for _pkg, entries in ops.build_operator_index(cat).items():
                for entry in entries:
                    for _role, img in ops._get_unique_workload_images(
                            entry['head_bundle']):
                        if _re.search(r'@sha256:[a-f0-9]{64}$', img):
                            refs.append(img)
    refs = list(dict.fromkeys(refs))
    if not refs:
        console.print('[red]No digest-pinned refs — use --image, --images, '
                      '--ocp or --operators.[/red]')
        return 2
    console.print(f'Generating OpenVEX for [bold]{len(refs)}[/bold] image(s), '
                  f'{args.workers} workers')

    # digest → OCP release map from the pullspec files: release images carry no
    # usable version label, so — exactly like retriage_ocp — the release
    # manifest is the authority for the OCP product scope.
    import glob as _glob
    ocp_by_digest: dict = {}
    for txt in _glob.glob(os.path.join('data', 'pullspecs', '*.txt')):
        ver = os.path.splitext(os.path.basename(txt))[0]
        minor = '.'.join(ver.split('.')[:2])
        try:
            with open(txt) as fh:
                for line in fh:
                    m = _re.search(r'@(sha256:[a-f0-9]{64})', line)
                    if m:
                        ocp_by_digest.setdefault(m.group(1), (ver, minor))
        except OSError:
            continue

    def _one(ref: str):
        sbom = adapter.syft_sbom(ref, platform=args.platform, force=args.force)
        doc = adapter.grype_scan(sbom)
        df = adapter.to_df(doc)
        ctx = context_for_image(ref, os_hint=adapter.os_hint(doc))
        digest = ref.split('@')[-1]
        if digest in ocp_by_digest:
            ver, minor = ocp_by_digest[digest]
            ctx.workload_type = 'ocp'
            ctx.ocp_ver = minor
            ctx.display_name = f'OpenShift {ver}'
            ctx.extra_prefixes = []
        result = triage._audit_silent(df, ctx)
        return openvex.statements_from_df(result, ref)

    per_image, errors = {}, 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(_one, ref): ref for ref in refs}
        for done, future in enumerate(as_completed(futures), 1):
            ref = futures[future]
            try:
                statements = future.result()
                if statements:
                    per_image[ref] = statements
                console.print(f'  [{done}/{len(refs)}] {ref.split("@")[0]}: '
                              f'{len(statements)} statements')
            except Exception as e:
                errors += 1
                console.print(f'  [{done}/{len(refs)}] [red]{ref}: {e}[/red]')

    docs = hub.write_image_docs(args.hub, per_image, author=args.author)
    stats = hub.build_index(args.hub, name=args.author,
                            description='Red Hat VEX triage verdicts (OpenVEX)',
                            base_url=args.base_url, archive=args.archive)
    console.print(f"Hub: [bold]{stats['documents']}[/bold] documents "
                  f"({docs} updated), {stats['packages']} index entries, "
                  f"{errors} errors → {args.hub}")

    if args.verify:
        return _verify_hub(per_image, args.hub, console)
    return 1 if errors else 0


def _verify_hub(per_image: dict, hub_dir: str, console: Console) -> int:
    """Gate: re-scan each image with trivy against its hub doc — count leaks."""
    import subprocess

    from . import hub as _hub
    leaks_total = 0
    for ref, statements in per_image.items():
        doc = _hub.doc_path(hub_dir, ref)
        proc = subprocess.run(
            ['trivy', 'image', ref, '--platform', 'linux/amd64',
             '--vex', doc, '-f', 'json', '-q'],
            capture_output=True, text=True)
        if proc.returncode != 0:
            console.print(f'  [yellow]verify skipped {ref}: trivy failed[/yellow]')
            continue
        import json as _json
        report = _json.loads(proc.stdout)
        # Package-level check: a statement leaks only when the exact
        # (CVE, package) pair it covers is still reported.  CVE-level would
        # miscount siblings the engine deliberately left open (e.g. bind-libs
        # POSITIVE while bind-utils is not_affected — per-binary VEX verdicts).
        active = {(v['VulnerabilityID'], v.get('PkgName', ''))
                  for res in report.get('Results', [])
                  for v in (res.get('Vulnerabilities') or [])}
        stated = set()
        for s in statements:
            cve = s['vulnerability']['name']
            for p in s.get('products', []):
                for sc in p.get('subcomponents', []) or []:
                    name = sc['@id'].split('@')[0].rsplit('/', 1)[-1]
                    stated.add((cve, name))
        leaks = sorted({f'{c}({p})' for c, p in (stated & active)})
        leaks_total += len(leaks)
        state = (f'[red]{len(leaks)} leaks: ' + ', '.join(leaks[:5]) + '[/red]') \
            if leaks else '[green]clean[/green]'
        console.print(f'  verify {ref.split("@")[0]}: {state}')
    return 1 if leaks_total else 0


def _hub_cmd(args) -> int:
    from . import hub
    console = Console()
    stats = hub.build_index(args.hub, name=args.author,
                            description='Red Hat VEX triage verdicts (OpenVEX)',
                            base_url=args.base_url, archive=args.archive)
    console.print(f"Hub rebuilt: {stats['documents']} documents, "
                  f"{stats['packages']} index entries → {args.hub}")
    return 0


def _passthrough(command: str, module: str, rest: list) -> int:
    """Delegate to an existing console-script main() with its own argv."""
    import importlib
    mod = importlib.import_module(f'rhacs_vex.{module}')
    sys.argv = [f'vextriage {command}'] + rest
    return mod.main() or 0


def _add_scanner_args(p: argparse.ArgumentParser) -> None:
    p.add_argument('target', help='image ref (digest-pinned) or scan/SBOM file')
    p.add_argument('--image', default=None,
                   help='digest-pinned image ref when target is a file')
    p.add_argument('--platform', default='linux/amd64')
    p.add_argument('--openvex-dir', default=None, metavar='DIR',
                   help='export FALSE POSITIVE verdicts as OpenVEX into this hub dir')
    p.add_argument('--author', default='rhacs-vex')
    p.add_argument('--output', default=None)
    p.add_argument('--format', default='csv', choices=['table', 'csv', 'json'])
    p.add_argument('--false-only', action='store_true', default=False)
    p.add_argument('--force', action='store_true', default=False,
                   help='regenerate the cached syft SBOM (grype only)')


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='vextriage',
        description='Scan images with RHACS, grype or trivy; triage against '
                    'Red Hat CSAF-VEX; export OpenVEX.')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('rhacs', add_help=False,
                   help="RHACS-backed triage (today's rhacs-vex CLI)")
    for name in ('pipeline', 'operators', 'retriage', 'parquet'):
        sub.add_parser(name, add_help=False, help=f'alias for rhacs-vex-{name}')

    for scanner in ('grype', 'trivy'):
        _add_scanner_args(sub.add_parser(
            scanner, help=f'{scanner} scan → engine triage (+ optional OpenVEX)'))

    pg = sub.add_parser('generate',
                        help='scan images (syft+grype → engine triage) and '
                             'populate the OpenVEX hub')
    pg.add_argument('--images', default=None, metavar='FILE',
                    help='file with digest-pinned image refs (pullspec files work)')
    pg.add_argument('--image', default=None, help='single digest-pinned image ref')
    pg.add_argument('--ocp', default=None, metavar='VER',
                    help='OCP version(s), comma-separated — reads data/pullspecs/<v>.txt')
    pg.add_argument('--operators', action='store_true', default=False,
                    help='all channel-head operator images from data/catalogs/')
    pg.add_argument('--catalog', default=None, metavar='VER',
                    help='restrict --operators to catalog-<VER>.json (e.g. 4.20)')
    pg.add_argument('--hub', default='vexhub', metavar='DIR')
    pg.add_argument('--workers', type=int, default=4)
    pg.add_argument('--platform', default='linux/amd64')
    pg.add_argument('--author', default='rhacs-vex')
    pg.add_argument('--base-url', default='')
    pg.add_argument('--archive', action='store_true', default=False)
    pg.add_argument('--force', action='store_true', default=False,
                    help='regenerate cached syft SBOMs')
    pg.add_argument('--verify', action='store_true', default=False,
                    help='re-scan each image with trivy against its doc; fail on leaks')

    ph = sub.add_parser('hub', help='rebuild hub index.json + vex-repository.json')
    ph.add_argument('--hub', default='vexhub', metavar='DIR')
    ph.add_argument('--author', default='rhacs-vex')
    ph.add_argument('--base-url', default='')
    ph.add_argument('--archive', action='store_true', default=False)

    argv = sys.argv[1:]
    if argv and argv[0] in ('rhacs', 'pipeline', 'operators', 'retriage', 'parquet'):
        return _passthrough(argv[0], 'triage' if argv[0] == 'rhacs' else argv[0],
                            argv[1:])

    args = parser.parse_args(argv)
    if args.command in ('grype', 'trivy'):
        return _scanner_cmd(args.command, args)
    if args.command == 'generate':
        return _generate_cmd(args)
    if args.command == 'hub':
        return _hub_cmd(args)
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
