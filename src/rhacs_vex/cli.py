"""The `vextriage` CLI.

A scanner (or the VEX index, or OSV) only proposes (component, CVE) pairs; the
engine decides them against Red Hat's CSAF-VEX; OpenVEX publishes the verdicts
Red Hat stated or the engine inferred from it (marked as inferred).

    vextriage sync                      mirror Red Hat VEX + OSV, update the index
    vextriage openvex <image|sbom>      one image → OpenVEX (syft only)
    vextriage check <image|sbom>        scanner + that OpenVEX → what is left
    vextriage generate --ocp V | --operators | --images FILE
                                        many images → OpenVEX hub
    vextriage hub [--prune]             rebuild the hub index
    vextriage scanfree <image|sbom>     SBOM candidates → triage table
    vextriage grype|trivy <image>       scanner findings → triage table
    vextriage rhacs <image|csv> | --namespace NS | --ocp PULLSPECS [--offline]
    vextriage report CSV -o FILE        RHACS report → one HTML file
    vextriage doctor                    external tools, credentials, data

Run from the repository root: every data path is relative to ./data.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

from rich.console import Console

from . import vexindex

HUB_DESCRIPTION = 'Red Hat VEX triage verdicts (OpenVEX)'
STATED_ONLY_HELP = ('publish only verdicts Red Hat stated about this build; by default '
                    'inferred false positives are published too, marked "Inferred" in '
                    'their impact_statement')


# ── shared steps ─────────────────────────────────────────────────────────────

def _index(args, console, *, required: bool = True):
    """The on-disk VEX index, or None (with a message when it is required)."""
    path = getattr(args, 'index', None) or vexindex.INDEX_PATH
    index = vexindex.open_index(path)
    if not index and required:
        console.print(f'[red]no VEX index at {path} — run `vextriage sync` first.[/red]')
    return index


def _sbom(target: str, args, console):
    """(SyftSBOM, path) for an SBOM file or an image ref (syft, cached); None
    when unreadable — an empty SBOM must never read as "no findings"."""
    from .adapters import grype as adapter
    from .sbom import SyftSBOM
    path = target
    if not os.path.exists(path):
        console.print(f"🧾 syft SBOM for [cyan]{target}[/cyan]")
        path = adapter.syft_sbom(target, platform=args.platform,
                                 force=getattr(args, 'force', False))
    sbom = SyftSBOM.load(path)
    if sbom is None or not sbom.artifacts:
        console.print(f'[red]unreadable or empty SBOM: {path} — regenerate it.[/red]')
        return None, path
    return sbom, path


def _pinned_ref(args, sbom=None, console=None) -> str:
    """The digest-pinned image ref: --image, the target itself, or the SBOM's."""
    ref = args.image or ('' if os.path.exists(args.target) else args.target)
    ref = ref or (sbom.image_ref() if sbom else '')
    if '@sha256:' not in ref and console:
        console.print('[red]--image <repo@sha256:…> is required: the verdicts are about '
                      'one digest-pinned build.[/red]')
    return ref if '@sha256:' in ref else ''


def _release(image_ref: str, given=None):
    """OCP release of a payload image: as given, else from data/pullspecs."""
    from .discovery import release_by_digest
    return given or release_by_digest().get(image_ref.split('@')[-1])


def _write_hub(hub_dir: str, image_ref: str, statements: list, author: str, console) -> None:
    from . import hub
    path, changed = hub.write_image_doc(hub_dir, image_ref, statements, author=author)
    hub.build_index(hub_dir, name=author, description=HUB_DESCRIPTION)
    console.print(f"📦 {path} ({'updated' if changed else 'unchanged'})")


def _scan_findings(scanner: str, target: str, *, platform: str, vex: str = '') -> set:
    """{(CVE, package, version, severity)} a scanner reports, optionally with --vex."""
    is_file = os.path.exists(target)
    if scanner == 'trivy':
        cmd = ['trivy', 'sbom' if is_file else 'image', '--quiet', '-f', 'json']
        cmd += [] if is_file else ['--platform', platform]
    else:
        cmd = ['grype', f'sbom:{target}' if is_file else target, '--by-cve', '-o', 'json']
    cmd += ['--vex', vex] if vex else []
    if scanner == 'trivy':
        cmd.append(target)
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{scanner} failed: {out.stderr.strip()[-300:]}")
    doc = json.loads(out.stdout or '{}')
    if scanner == 'trivy':
        return {(v['VulnerabilityID'], v.get('PkgName', ''), v.get('InstalledVersion', ''),
                 v.get('Severity', ''))
                for r in doc.get('Results', []) for v in r.get('Vulnerabilities') or []}
    return {(m.get('vulnerability', {}).get('id', ''), m.get('artifact', {}).get('name', ''),
             m.get('artifact', {}).get('version', ''), m.get('vulnerability', {}).get('severity', ''))
            for m in doc.get('matches', [])}


# ── OpenVEX ──────────────────────────────────────────────────────────────────

def _openvex_cmd(args) -> int:
    """One image → OpenVEX: syft SBOM + Red Hat VEX (+ OSV, optionally grype)."""
    import collections

    from . import openvex, vexgen
    from .adapters import grype as adapter
    console = Console()
    index = _index(args, console)
    if not index:
        return 2
    sbom, sbom_path = _sbom(args.target, args, console)
    if sbom is None:
        return 1
    image_ref = _pinned_ref(args, sbom, console)
    if not image_ref:
        return 2
    release = _release(image_ref, args.ocp_release)
    findings = adapter.to_df(adapter.grype_scan(sbom_path)) if args.grype else None
    statements, result = vexgen.generate(image_ref, sbom, index, ocp_release=release,
                                         findings=findings, use_osv=not args.no_osv,
                                         stated_only=args.stated_only)
    by_src = collections.Counter(zip(result['SOURCE'], result['AUDIT_RESULT'],
                                     result['VEX_STATED'].astype(str))) if len(result) else {}
    console.print(f"\n[bold]{image_ref}[/bold]" + (f"  (OpenShift {release})" if release else ''))
    console.print(f"{len(result):,} candidate (component, CVE) pairs from "
                  f"{len(sbom.artifacts):,} SBOM artifacts")
    for (src, verdict, stated), n in sorted(by_src.items()):
        tag = 'stated' if stated == 'True' else 'inferred'
        console.print(f"  {src or '?':7} {verdict:18} {tag:8} {n:6,}")
    kinds = collections.Counter(s['status'] for s in statements)
    console.print(f"→ [bold]{len(statements)}[/bold] OpenVEX statements "
                  f"({', '.join(f'{v} {k}' for k, v in sorted(kinds.items())) or 'none'})")
    if args.output:
        with open(args.output, 'w') as fh:
            json.dump(openvex.build_document(image_ref, statements, author=args.author),
                      fh, indent=2)
        console.print(f"📄 {args.output}")
    if args.hub:
        _write_hub(args.hub, image_ref, statements, args.author, console)
    return 0


def _check_cmd(args) -> int:
    """Triage = scanner + OpenVEX.  What the scanner still reports with Red Hat's
    published verdicts applied is the list to act on."""
    import tempfile

    from rich.table import Table

    from . import hub, openvex, vexgen
    console = Console()
    image_ref = _pinned_ref(args, console=console)
    if not image_ref:
        return 2
    if not shutil.which(args.scanner):
        console.print(f'[red]{args.scanner} is not installed.[/red]')
        return 2

    vex_doc, tmp = (hub.doc_path(args.hub, image_ref) if args.hub else ''), None
    if vex_doc and os.path.exists(vex_doc):
        console.print(f"🧾 using {vex_doc}")
    else:
        # No published document for this image yet: generate it now.
        index = _index(args, console)
        if not index:
            return 2
        src = args.sbom or (args.target if os.path.exists(args.target) else image_ref)
        sbom, _path = _sbom(src, args, console)
        if sbom is None:
            return 1
        statements, _res = vexgen.generate(image_ref, sbom, index, ocp_release=_release(image_ref),
                                           stated_only=args.stated_only)
        fd, tmp = tempfile.mkstemp(suffix='.openvex.json')
        with os.fdopen(fd, 'w') as fh:
            json.dump(openvex.build_document(image_ref, statements, author='vextriage'), fh)
        vex_doc = tmp
        console.print(f"🧾 generated {len(statements)} OpenVEX statements for this image")
    try:
        before = _scan_findings(args.scanner, args.target, platform=args.platform)
        after = _scan_findings(args.scanner, args.target, platform=args.platform, vex=vex_doc)
    except RuntimeError as e:
        console.print(f'[red]{e}[/red]')
        return 1
    finally:
        if tmp:
            os.unlink(tmp)

    rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    remaining = sorted(after, key=lambda f: (rank.get(f[3].upper(), 9), f[0]))
    if args.output:
        with open(args.output, 'w') as fh:
            json.dump([dict(zip(('cve', 'package', 'version', 'severity'), f))
                       for f in sorted(after)], fh, indent=2)
    if not args.quiet:
        t = Table(title=f'{image_ref.split("@")[0]} — not cleared by Red Hat')
        for col in ('CVE', 'Package', 'Version', 'Severity'):
            t.add_column(col)
        for f in remaining:
            t.add_row(*f)
        console.print(t)
    console.print(f"{args.scanner}: [bold]{len(before):,}[/bold] findings → "
                  f"[bold red]{len(after):,}[/bold red] after Red Hat's VEX "
                  f"([green]{len(before) - len(after):,} cleared[/green])")
    return 0


_GEN_INDEX = None


def _gen_worker(ref: str, sbom_path: str, release, findings, use_osv: bool,
                stated_only: bool = False) -> list:
    """CPU stage of generate, run in a worker process: SBOM → statements."""
    global _GEN_INDEX
    os.environ['VEX_AUDIT_WORKERS'] = '1'        # no nested process pools
    from . import vexgen
    from .sbom import SyftSBOM
    if _GEN_INDEX is None:
        _GEN_INDEX = vexindex.open_index()
    sbom = SyftSBOM.load(sbom_path)
    if sbom is None:
        raise RuntimeError(f'unreadable SBOM {sbom_path}')
    statements, _result = vexgen.generate(ref, sbom, _GEN_INDEX, ocp_release=release,
                                          findings=findings, use_osv=use_osv,
                                          stated_only=stated_only)
    return statements


def _generate_refs(args, console) -> list:
    """The digest-pinned refs --image / --images / --ocp / --operators name."""
    from . import discovery
    refs = ([args.image] if args.image else []) + \
        (discovery.refs_in_file(args.images) if args.images else [])
    if args.ocp:
        versions = [v.strip() for v in args.ocp.split(',') if v.strip()]
        missing = [p for p in discovery.pullspec_files(versions) if not os.path.exists(p)]
        if missing:
            console.print(f'[red]missing pullspec file(s): {", ".join(missing)} — '
                          f'`oc adm release info <ver> --pullspecs > data/pullspecs/<ver>.txt`[/red]')
            return []
        refs += discovery.release_refs(versions)
    if args.operators:
        minors = [args.catalog] if args.catalog else discovery.catalog_versions()
        if not any(os.path.exists(discovery.catalog_path(m)) for m in minors):
            console.print('[red]no operator catalogs under data/catalogs/ — `opm render '
                          '<index> > data/catalogs/catalog-<minor>.json`[/red]')
            return []
        refs += discovery.operator_refs(minors)
    return list(dict.fromkeys(refs))


def _generate_cmd(args) -> int:
    """syft-SBOM a list of images and publish Red Hat's verdicts into a hub.

    Scanner threads run syft/grype (subprocesses, registry I/O); the pandas
    audit runs in worker PROCESSES or it would serialize on the GIL.  spawn,
    not fork: forked children abort on macOS and inherit thread locks.
    """
    import multiprocessing as mp
    import time
    from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

    from . import discovery, hub
    from .adapters import grype as adapter
    console = Console()
    refs = _generate_refs(args, console)
    if not refs:
        console.print('[red]No digest-pinned refs — use --image, --images, --ocp or '
                      '--operators.[/red]')
        return 2
    if args.resume:
        done = hub.digests_in_hub(args.hub, refs)
        refs = [r for r in refs if r.split('@')[-1] not in done.get(hub.doc_path(args.hub, r), ())]
        console.print(f'--resume: {len(refs)} image(s) left')
        if not refs:
            return 0
    if not _index(args, console):
        return 2

    # grype is optional: one DB update up front, then no per-call network checks
    if args.grype and not args.no_db_update:
        subprocess.run(['grype', 'db', 'update'], capture_output=True)
    for var in ('GRYPE_DB_AUTO_UPDATE', 'GRYPE_CHECK_FOR_APP_UPDATE', 'SYFT_CHECK_FOR_APP_UPDATE'):
        os.environ.setdefault(var, 'false')
    release_of = discovery.release_by_digest()

    def one(ref: str):
        try:
            sbom = adapter.syft_sbom(ref, platform=args.platform, force=args.force)
        except Exception as e:
            alt = adapter.fallback_platform(ref) if 'no child with platform' in str(e) else ''
            if 'no child with platform' in str(e) and not alt:
                raise
            if not alt:
                time.sleep(5)            # transient registry/CDN errors: one retry
            sbom = adapter.syft_sbom(ref, platform=alt or args.platform, force=True)
        findings = adapter.to_df(adapter.grype_scan(sbom)) if args.grype else None
        return cpu.submit(_gen_worker, ref, sbom, release_of.get(ref.split('@')[-1]),
                          findings, not args.no_osv, args.stated_only).result()

    workers = max(2, min(args.workers, (os.cpu_count() or 8) - 2))
    cpu = ProcessPoolExecutor(max_workers=workers, mp_context=mp.get_context('spawn'))
    for w in [cpu.submit(time.sleep, 0.2) for _ in range(workers)]:
        w.result()                       # pre-spawn before any scanner thread starts
    console.print(f'Generating OpenVEX for [bold]{len(refs)}[/bold] image(s): '
                  f'{args.workers} scanner threads, {workers} audit processes')

    # Hub writes are checkpointed every 25 images (an interrupted run keeps
    # nearly everything) and batched per document: every digest of one image
    # name shares a document.  Empty results are written too — a re-scan is the
    # complete truth for its digest and must be able to retract statements.
    per_image, pending, errors, updates = {}, {}, 0, 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(one, ref): ref for ref in refs}
        for n, future in enumerate(as_completed(futures), 1):
            ref = futures[future]
            try:
                per_image[ref] = pending[ref] = future.result()
                console.print(f'  [{n}/{len(refs)}] {ref.split("@")[0]}: '
                              f'{len(per_image[ref])} statements')
            except Exception as e:
                errors += 1
                console.print(f'  [{n}/{len(refs)}] [red]{ref}: {e}[/red]')
            if len(pending) >= 25:
                updates += hub.write_image_docs(args.hub, pending, author=args.author)
                pending.clear()
    cpu.shutdown()
    if pending:
        updates += hub.write_image_docs(args.hub, pending, author=args.author)
    stats = hub.build_index(args.hub, name=args.author, description=HUB_DESCRIPTION,
                            base_url=args.base_url, archive=args.archive)
    console.print(f"Hub: [bold]{stats['documents']}[/bold] documents ({updates} updated), "
                  f"{stats['packages']} index entries, {errors} errors → {args.hub}")
    if args.verify and _verify_hub(per_image, args, console):
        return 1
    return 1 if errors else 0


def _verify_hub(per_image: dict, args, console) -> int:
    """Re-scan each image with trivy against its hub document; count leaks —
    a stated (CVE, package) pair the scanner still reports."""
    from . import hub
    leaks_total = 0
    for ref, statements in per_image.items():
        try:
            active = {(c, p) for c, p, _v, _s in _scan_findings(
                'trivy', ref, platform=args.platform, vex=hub.doc_path(args.hub, ref))}
        except RuntimeError:
            console.print(f'  [yellow]verify skipped {ref}: trivy failed[/yellow]')
            continue
        stated = {(s['vulnerability']['name'], sc['@id'].split('@')[0].rsplit('/', 1)[-1])
                  for s in statements for p in s.get('products', [])
                  for sc in p.get('subcomponents', []) or []}
        leaks = sorted(f'{c}({p})' for c, p in stated & active)
        leaks_total += len(leaks)
        console.print(f'  verify {ref.split("@")[0]}: ' +
                      (f'[red]{len(leaks)} leaks: {", ".join(leaks[:5])}[/red]' if leaks
                       else '[green]clean[/green]'))
    return leaks_total


def _hub_cmd(args) -> int:
    from . import discovery, hub
    console = Console()
    if args.prune:
        live: dict = {}
        for ref in discovery.release_refs() + discovery.operator_refs():
            live.setdefault(hub.doc_path(args.hub, ref), set()).add(ref.split('@')[-1])
        if not live:
            console.print('[red]--prune: no data/pullspecs or data/catalogs — refusing to '
                          'prune against an empty live set.[/red]')
            return 2
        st = hub.prune(args.hub, live)
        console.print(f"Pruned {st['statements']} statements for rotated-out digests "
                      f"({st['docs_updated']} docs updated, {st['docs_removed']} removed)")
    stats = hub.build_index(args.hub, name=args.author, description=HUB_DESCRIPTION,
                            base_url=args.base_url, archive=args.archive)
    console.print(f"Hub rebuilt: {stats['documents']} documents, "
                  f"{stats['packages']} index entries → {args.hub}")
    return 0


# ── triage tables ────────────────────────────────────────────────────────────

def _scanfree_cmd(args) -> int:
    """SBOM + Red Hat VEX, no scanner: every candidate pair, triaged."""
    from . import display, scan, vexgen
    console = Console()
    index = _index(args, console)
    if not index:
        return 2
    sbom, _path = _sbom(args.target, args, console)
    if sbom is None:
        return 1
    image_ref = _pinned_ref(args, sbom, console)
    if not image_ref:
        return 2
    ctx, result = vexgen.triage_sbom(image_ref, sbom, index, ocp_release=_release(image_ref),
                                     use_osv=not args.no_osv, vex_product=True)
    if result.empty:
        console.print('[yellow]no candidates — nothing in the SBOM is named by the VEX '
                      'corpus or OSV.[/yellow]')
        return 0
    display.print_preamble(console, image_ref=image_ref, mode='SBOM + Red Hat VEX (no scanner)',
                           df=result, ctx=ctx, noun='candidates')
    scan.show(result, ctx, console, args, candidates=True)
    return 0


def _scanner_cmd(scanner: str, args) -> int:
    """grype or trivy findings → engine → table."""
    from . import candidates, display, scan
    from .core.workload import context_for_image
    console = Console()
    sbom = None
    if scanner == 'grype':
        from .adapters import grype as adapter
        sbom, path = _sbom(args.target, args, console)
        if sbom is None:
            return 1
        console.print("🔍 grype scan...")
        doc = adapter.grype_scan(path)
        labels, digests = sbom.labels, sbom.digests
    else:
        from .adapters import trivy as adapter
        console.print("🔍 trivy scan...")
        doc = adapter.trivy_scan(args.target, platform=args.platform)
        labels, digests = adapter.labels(doc), adapter.digests(doc)
    image_ref = _pinned_ref(args, sbom, console)
    if not image_ref:
        return 2
    df, hint = adapter.to_df(doc), adapter.os_hint(doc)
    ctx = context_for_image(image_ref, os_hint=hint, labels=labels or None, digests=digests)
    added = 0
    index = _index(args, console, required=False)
    if args.vex_index:
        df, added = candidates.add_to_findings(df, index, image_ref=image_ref, labels=labels)
    if sbom:
        sbom.enrich(df, ctx)
        ctx.osv_evidence = candidates.osv_evidence(sbom, index)
    display.print_preamble(console, image_ref=image_ref, mode=f'{scanner} scan',
                           os_info=hint or '', df=df, ctx=ctx,
                           noun='candidates' if added else 'CVE findings')
    result = scan.triage(df, ctx, console, args, candidates=bool(added))
    # SBOM and findings both come from syft's catalogue: this only catches a
    # version changing shape between them (epochs, purl normalisation).
    if sbom and result is not None and not result.empty:
        display.print_sbom_summary(console, display.verify_versions(
            result, sbom.package_versions()))
    return 0


def _rhacs_cmd(args) -> int:
    """RHACS findings → engine: one image, a CSV export, a namespace, or a release."""
    import pandas as pd

    from . import candidates, display, discovery, scan
    from .adapters.rhacs import Central
    from .core.workload import WorkloadContext, parse_image_ref
    console = Console()
    index = _index(args, console, required=False) if args.vex_index else None
    central = Central.from_env(offline=args.offline)
    target = args.target
    actionable = not (args.false_only or args.all_rows)

    def write(frames):
        if frames and args.output:
            display.write_output(pd.concat(frames, ignore_index=True), args.output,
                                 args.format, console)

    if target and os.path.exists(target):          # a CSV export: no Central needed
        ctx = parse_image_ref(args.image) if args.image else WorkloadContext()
        df, _added = candidates.add_to_findings(pd.read_csv(target), index,
                                                image_ref=args.image or '')
        display.print_preamble(console, mode=f'RHACS CSV {target}', df=df, ctx=ctx)
        scan.triage(df, ctx, console, args)
        return 0
    if not (args.offline or central.configured):
        console.print('[red]ROX_ENDPOINT and ROX_API_TOKEN must be set (or use --offline '
                      'to re-triage cached scans).[/red]')
        return 1

    if target and not (args.namespace or args.ocp):
        res = scan.rhacs_image(central, target, index=index, force=args.force,
                               false_only=args.false_only)
        if not res.get('found'):
            console.print(f"[red]❌ {res.get('error') or 'no scan for ' + target}[/red]")
            return 1
        display.print_preamble(console, image_ref=target, mode='RHACS',
                               os_info=res['os_info'], df=res['result_df'], ctx=res['ctx'])
        if res['result_df'] is None or res['result_df'].empty:
            console.print('[green]No findings.[/green]')
            return 0
        display.render_table(console, res['result_df'], res['ctx'], actionable_only=actionable)
        if res.get('sbom_check'):
            display.print_sbom_summary(console, res['sbom_check'])
        write([res['result_df']])
        return 0

    release = None
    if args.ocp:
        release, comps = discovery.read_pullspecs(args.ocp)
        items = [(comp, ref, None, comp) for comp, ref in comps]
    elif args.namespace:
        items = [(ref, ref, iid, None) for ref, iid in central.namespace_images(args.namespace)]
    else:
        console.print('[red]give an image ref, a CSV, --namespace or --ocp[/red]')
        return 2
    if not items:
        console.print('[red]no images to triage[/red]')
        return 1
    console.print(f"🚀 {len(items)} images, {args.workers} workers"
                  + (f" — OpenShift {release}" if release else ''))
    results = scan.rhacs_batch(central, items, workers=args.workers, console=console,
                               ocp_release=release, index=index, force=args.force,
                               false_only=args.false_only)
    frames = []
    for key, ref, _iid, comp in items:
        res = results[key]
        display.image_result(console, key if key == ref else f"{key}  [dim]{ref}[/dim]", res,
                             actionable_only=actionable)
        if res.get('result_df') is not None:
            df = res['result_df'].copy()
            if comp:
                df['OCP_COMPONENT'] = comp
            df['IMAGE'] = ref
            frames.append(df)
    write(frames)
    return 2 if any(r.get('found') is None for r in results.values()) else 0


def _report_cmd(args) -> int:
    """Triage a RHACS report CSV end to end and write one shareable HTML file."""
    import time

    from . import report
    console = Console()
    if not os.path.exists(args.csv):
        console.print(f'[red]no such file: {args.csv}[/red]')
        return 2
    try:
        result = report.triage_report(args.csv, workers=args.workers, platform=args.platform,
                                      console=console, rescan=args.rescan, ocp=args.ocp)
    except ValueError as e:
        console.print(f'[red]{e}[/red]')
        return 2
    rows = result['rows']
    if rows.empty:
        console.print('[yellow]nothing to report — no row survived triage.[/yellow]')
        return 1
    real = int((~rows['AUDIT_RESULT'].str.contains('FALSE', na=False)).sum())
    path = report.render_html(result, args.output, when=time.strftime('%Y-%m-%d %H:%M'))
    if not args.no_parquet:
        pq_path = args.parquet or os.path.splitext(args.output)[0] + '.parquet'
        try:
            report.write_parquet(result, pq_path)
            console.print(f"🗃  {pq_path}")
        except Exception as e:
            console.print(f'[yellow]parquet skipped: {type(e).__name__}: {e}[/yellow]')
    if args.rescan:
        # a rescan enumerates candidates: the cleared ones were never claims
        console.print(f"\n[bold]{len(rows):,}[/bold] candidates checked → "
                      f"[red]{real:,} findings[/red]; {len(rows) - real:,} not a match")
    else:
        console.print(f"\n[bold]{len(rows):,}[/bold] findings → [green]{len(rows) - real:,} "
                      f"false positives[/green], [red]{real:,} real[/red]")
    console.print(f"📄 {path}")
    return 0


# ── data ─────────────────────────────────────────────────────────────────────

def _sync_cmd(args) -> int:
    """Bring the local data up to date — only what changed is fetched or re-indexed.

    data/vex/              Red Hat VEX, delta from Red Hat's change feed
    data/vex-index.sqlite  re-indexes just the fetched CVEs; OSV records changed
                           since the last sync are fetched one by one
    """
    from . import mirror, osv
    console = Console()
    try:
        st = mirror.sync(console, workers=args.workers, limit=args.limit, bulk=args.bulk)
    except RuntimeError as e:
        console.print(f'[red]{e}[/red]')
        return 1
    console.print(f"✅ VEX: fetched [bold]{st['fetched']:,}[/bold] file(s) "
                  f"({st['missing']:,} missing, {st['changed']:,} changed)")
    if args.no_index:
        return 0
    path = args.index or vexindex.INDEX_PATH
    if args.rebuild or st.get('updated') is None or not vexindex.has_vex(path):
        console.print(f"🧱 building the index → [cyan]{path}[/cyan]")
        b = vexindex.build_vex(path=path, progress=lambda i, n: console.print(
            f"   {i:,}/{n:,} CVE files", highlight=False))
        console.print(f"   indexed [bold]{b['files']:,}[/bold] CVE files: "
                      f"{b['rpm']:,} rpm names, {b['oci']:,} image keys")
    elif st['updated']:
        r = vexindex.update_vex(st['updated'], path=path)
        console.print(f"🧱 index: re-indexed {r['updated']:,} changed CVE file(s)")
    else:
        console.print("🧱 index: VEX already current")
    if not vexindex.has_images(path):
        console.print("🧱 index: learning image → product from the mirror (one pass)")
        n = vexindex.build_images(path=path)
        console.print(f"   {n:,} image listings")
    if not args.no_osv:
        console.print("📥 OSV (CVE → Go/PyPI/npm/Maven packages)")
        try:
            osv.sync(path, console=console)
        except Exception as e:
            console.print(f'[yellow]OSV sync failed ({e}) — the index keeps what it had[/yellow]')
    return 0


def _doctor_cmd(_args) -> int:
    """External tools, credentials and data artifacts."""
    import glob

    from rich.table import Table
    console = Console()
    tools = [('syft', ['--version'], 'SBOMs for openvex / generate / grype / report'),
             ('grype', ['--version'], 'check, grype, generate --grype'),
             ('trivy', ['--version'], 'check --scanner trivy, trivy, generate --verify'),
             ('skopeo', ['--version'], 'label fallback, single-arch images'),
             ('oc', ['version', '--client'], 'data/pullspecs for generate --ocp'),
             ('opm', ['version'], 'data/catalogs for generate --operators')]
    t = Table(title='External tools')
    for col in ('tool', 'found', 'version', 'used by'):
        t.add_column(col)
    missing = []
    for binary, vargs, purpose in tools:
        version = ''
        if shutil.which(binary):
            try:
                out = subprocess.run([binary, *vargs], capture_output=True, text=True, timeout=10)
                version = ((out.stdout or out.stderr).strip().splitlines() or [''])[0][:60]
            except Exception:
                pass
            t.add_row(binary, '[green]✓[/green]', version, purpose)
        else:
            missing.append(binary)
            t.add_row(binary, '[red]✗ not found[/red]', '', purpose)
    console.print(t)

    e = Table(title='Environment')
    for col in ('variable', 'state', 'needed for'):
        e.add_column(col)
    for var in ('ROX_ENDPOINT', 'ROX_API_TOKEN'):
        e.add_row(var, '[green]set[/green]' if os.environ.get(var) else '[yellow]unset[/yellow]',
                  'vextriage rhacs')
    raf = os.environ.get('REGISTRY_AUTH_FILE', '')
    e.add_row('REGISTRY_AUTH_FILE', '[green]set, file exists[/green]' if raf and os.path.isfile(raf)
              else '[red]set, file MISSING[/red]' if raf else '[yellow]unset[/yellow]',
              'oc / opm / skopeo / syft auth')
    console.print(e)

    d = Table(title='Data (relative to the repo root)')
    for col in ('artifact', 'state'):
        d.add_column(col)
    rows = [('VEX index', 'present' if vexindex.has_vex() else ''),
            ('data/vex/  (Red Hat VEX mirror)', len(glob.glob('data/vex/CVE-*.json'))),
            ('data/pullspecs/*.txt  (OCP releases)', len(glob.glob('data/pullspecs/*.txt'))),
            ('data/catalogs/catalog-*.json  (operator indexes)',
             len(glob.glob('data/catalogs/catalog-*.json'))),
            ('data/syft/*.json  (SBOM cache)', len(glob.glob('data/syft/*.json'))),
            ('vexhub documents', len(glob.glob('vexhub/pkg/**/scan.openvex.json', recursive=True)))]
    for label, n in rows:
        d.add_row(label, f'[green]{n}[/green]' if n else '[yellow]missing[/yellow]')
    console.print(d)
    if missing:
        console.print(f"[yellow]missing: {', '.join(missing)} — only the commands above "
                      f"that need them are affected[/yellow]")
    return 1 if missing else 0


# ── arguments ────────────────────────────────────────────────────────────────

def _opts(p, *names) -> None:
    """Options several commands share, by name."""
    spec = {
        'image': lambda: p.add_argument('--image', default=None,
                                        help='digest-pinned ref when the target is a file'),
        'platform': lambda: p.add_argument('--platform', default='linux/amd64'),
        'force': lambda: p.add_argument('--force', action='store_true',
                                        help='regenerate the cached syft SBOM'),
        'index': lambda: p.add_argument('--index', default=None, metavar='FILE',
                                        help=f'VEX index (default: {vexindex.INDEX_PATH})'),
        'skip-sync': lambda: p.add_argument('--skip-sync', action='store_true',
                                            help='do not refresh the VEX mirror first'),
        'author': lambda: p.add_argument('--author', default='vextriage'),
        'hub': lambda: p.add_argument('--hub', default='vexhub', metavar='DIR'),
        'stated-only': lambda: p.add_argument('--stated-only', action='store_true',
                                              help=STATED_ONLY_HELP),
        'no-osv': lambda: p.add_argument('--no-osv', action='store_true',
                                         help='no OSV candidates for Go/Python/npm/Maven'),
        'table': lambda: (p.add_argument('--output', default=None,
                                         help='also write every row to this file'),
                          p.add_argument('--format', default='csv', choices=['csv', 'json']),
                          p.add_argument('--false-only', action='store_true'),
                          p.add_argument('--all-rows', action='store_true',
                                         help='show false positives in the table too')),
        'vex-index': lambda: p.add_argument('--vex-index', action='store_true',
                                            help="add the VEX index's rpm and image "
                                                 "candidates to the scanner's findings"),
        'archive': lambda: (p.add_argument('--base-url', default=''),
                            p.add_argument('--archive', action='store_true')),
    }
    for n in names:
        spec[n]()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='vextriage', description='Triage scanner findings against Red Hat CSAF-VEX; '
                                      'publish the verdicts as OpenVEX.')
    sub = parser.add_subparsers(dest='command')

    p = sub.add_parser('sync', help='mirror Red Hat VEX + OSV and update the index '
                                    '(deltas only; afterwards runs need no network)')
    p.add_argument('--workers', type=int, default=0, metavar='N')
    p.add_argument('--limit', type=int, default=0, metavar='N',
                   help='stop after N files (try a slice before the full corpus)')
    p.add_argument('--rebuild', action='store_true', help='rebuild the index from scratch')
    p.add_argument('--no-index', action='store_true', help='mirror only')
    p.add_argument('--no-osv', action='store_true', help='skip the OSV update')
    p.add_argument('--bulk', dest='bulk', action='store_true', default=None,
                   help='force the tarball path (default: above 2,000 outstanding files)')
    p.add_argument('--no-bulk', dest='bulk', action='store_false',
                   help='force file-by-file fetching')
    _opts(p, 'index')

    p = sub.add_parser('openvex', help='one image → OpenVEX from Red Hat VEX (syft SBOM, '
                                       'no scanner needed)')
    p.add_argument('target', help='digest-pinned image ref, or a syft-json SBOM path')
    p.add_argument('--ocp-release', default=None, metavar='VER',
                   help='OCP release of the image (default: looked up in data/pullspecs)')
    p.add_argument('--output', '-o', default=None, metavar='FILE',
                   help='write the OpenVEX document here')
    p.add_argument('--hub', default=None, metavar='DIR', help='also write it into a VEX hub')
    p.add_argument('--grype', action='store_true', help='add grype findings as candidates')
    _opts(p, 'image', 'platform', 'force', 'author', 'no-osv', 'stated-only', 'index',
          'skip-sync')

    p = sub.add_parser('check', help="triage = scanner + OpenVEX: run grype (or trivy) with "
                                     "Red Hat's verdicts applied and list what is left")
    p.add_argument('target', help='digest-pinned image ref, or an SBOM file the scanner '
                                  'reads (syft-json for grype, CycloneDX for trivy)')
    p.add_argument('--scanner', default='grype', choices=['grype', 'trivy'])
    p.add_argument('--sbom', default=None, help='syft-json SBOM to generate from')
    p.add_argument('--output', '-o', default=None, help='write the remaining findings as JSON')
    p.add_argument('--quiet', action='store_true', help='summary line only')
    _opts(p, 'image', 'hub', 'platform', 'stated-only', 'index', 'skip-sync')

    p = sub.add_parser('generate', help='many images → OpenVEX hub')
    p.add_argument('--image', default=None, help='one digest-pinned image ref')
    p.add_argument('--images', default=None, metavar='FILE',
                   help='file with digest-pinned image refs (pullspec files work)')
    p.add_argument('--ocp', default=None, metavar='VER',
                   help='OCP version(s), comma-separated — reads data/pullspecs/<v>.txt')
    p.add_argument('--operators', action='store_true',
                   help='every channel-head operator image in data/catalogs/')
    p.add_argument('--catalog', default=None, metavar='VER',
                   help='restrict --operators to catalog-<VER>.json')
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--resume', action='store_true',
                   help='skip images whose digest is already in its hub document')
    p.add_argument('--grype', action='store_true',
                   help='also add grype findings as candidates')
    p.add_argument('--no-db-update', action='store_true',
                   help='keep the current grype DB (cached grype results stay valid)')
    p.add_argument('--verify', action='store_true',
                   help='re-scan each image with trivy against its document; fail on leaks')
    _opts(p, 'hub', 'platform', 'force', 'author', 'archive', 'no-osv', 'stated-only',
          'index', 'skip-sync')

    p = sub.add_parser('hub', help='rebuild hub index.json + vex-repository.json')
    p.add_argument('--prune', action='store_true',
                   help='drop statements for digests no longer in data/pullspecs or the '
                        'catalog channel heads (images outside discovery untouched)')
    _opts(p, 'hub', 'author', 'archive')

    p = sub.add_parser('scanfree', help='triage an SBOM against Red Hat VEX, no scanner')
    p.add_argument('target', help='digest-pinned image ref, or a syft-json SBOM path')
    _opts(p, 'image', 'platform', 'force', 'no-osv', 'table', 'index', 'skip-sync')

    for scanner in ('grype', 'trivy'):
        p = sub.add_parser(scanner, help=f'{scanner} scan → engine triage')
        p.add_argument('target', help='image ref (digest-pinned), or a syft-json SBOM '
                                      '(grype) / trivy JSON report (trivy)')
        _opts(p, 'image', 'platform', 'force', 'table', 'vex-index', 'index', 'skip-sync')

    p = sub.add_parser('rhacs', help='RHACS findings → engine triage')
    p.add_argument('target', nargs='?', default=None, help='image ref, or a RHACS scan CSV')
    p.add_argument('--image', default=None, help='workload image for a CSV target')
    p.add_argument('--namespace', default=None, help='every image deployed in a namespace')
    p.add_argument('--ocp', default=None, metavar='PULLSPECS',
                   help='every image of an OCP release (`oc adm release info --pullspecs`)')
    p.add_argument('--offline', action='store_true', help='cached RHACS scans only')
    p.add_argument('--force', action='store_true', help='re-scan, ignoring the scan cache')
    p.add_argument('--workers', type=int, default=10)
    _opts(p, 'table', 'vex-index', 'index', 'skip-sync')

    p = sub.add_parser('report', help='triage a RHACS vulnerability report CSV into one '
                                      'self-contained HTML file')
    p.add_argument('csv', help='RHACS report CSV export')
    p.add_argument('--output', '-o', required=True, metavar='FILE', help='the HTML report')
    p.add_argument('--workers', type=int, default=4, metavar='N',
                   help='images SBOM-ed in parallel (the verdict pass is single-threaded)')
    p.add_argument('--ocp', default='', metavar='VER',
                   help="the cluster's OpenShift version(s), comma-separated")
    p.add_argument('--parquet', default=None, metavar='FILE',
                   help='also write the rows as parquet (default: alongside --output)')
    p.add_argument('--no-parquet', action='store_true', help='HTML only')
    p.add_argument('--rescan', action='store_true',
                   help='ignore the CSV findings and scan every image live (syft + grype '
                        '+ VEX index), keeping the placement from the CSV')
    _opts(p, 'platform', 'skip-sync')

    sub.add_parser('doctor', help='check external tools, credentials and data')
    return parser


COMMANDS = {'sync': _sync_cmd, 'openvex': _openvex_cmd, 'check': _check_cmd,
            'generate': _generate_cmd, 'hub': _hub_cmd, 'scanfree': _scanfree_cmd,
            'grype': lambda a: _scanner_cmd('grype', a), 'trivy': lambda a: _scanner_cmd('trivy', a),
            'rhacs': _rhacs_cmd, 'report': _report_cmd, 'doctor': _doctor_cmd}

# commands that read the VEX mirror: refreshed first when stale, unless --skip-sync
_READS_MIRROR = {'openvex', 'check', 'generate', 'scanfree', 'grype', 'trivy', 'rhacs', 'report'}


def main(argv=None) -> int:
    parser = _parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if not args.command:
        parser.print_help()
        return 0
    if getattr(args, 'skip_sync', False):
        os.environ['VEX_SKIP_SYNC'] = '1'
    if args.command in _READS_MIRROR:
        from . import mirror
        mirror.ensure_mirror(Console())
    return COMMANDS[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
