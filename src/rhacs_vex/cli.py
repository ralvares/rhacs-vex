"""cli.py — the `vextriage` umbrella CLI.

One tool, scanner as subcommand; the engine judges every scanner the same way
(scanner = discovery, engine = verdict, OpenVEX = output):

    vextriage rhacs    ...             RHACS-backed triage, unchanged
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
import json
import os
import sys

from rich.console import Console

from . import scanfree


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
    triage.ensure_mirror(console)

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
        labels = adapter.sbom_labels(target)
        digests = adapter.sbom_digests(target)
    else:
        from .adapters import trivy as adapter
        console.print("🔍 trivy scan...")
        doc = adapter.trivy_scan(args.target, platform=args.platform)
        df = adapter.to_df(doc)
        hint = adapter.os_hint(doc)
        labels = adapter.labels(doc)
        digests = adapter.digests(doc)

    image_ref = args.image or (args.target if not os.path.exists(args.target) else '')
    if not image_ref:
        console.print('[red]--image <digest-pinned ref> is required when scanning '
                      'from a file (context + OpenVEX product identity).[/red]')
        return 2

    console.print(f"🧭 Image context via labels: [bold cyan]{image_ref}[/bold cyan]")
    ctx = context_for_image(image_ref, os_hint=hint, labels=labels or None,
                            digests=digests)
    df, merged = _merge_index(df, args, console, image_ref, labels)
    if scanner == 'grype':
        _wire_rpm_owners(df, ctx, adapter.rpm_file_owners(target))

    result_df = triage._audit_and_display(
        df, ctx, console, output_path=args.output, output_fmt=args.format,
        false_only=args.false_only, source_label=scanner, candidates=merged)

    if args.openvex_dir:
        try:
            _export_openvex(result_df, image_ref, args.openvex_dir, args.author, console)
        except ValueError as e:
            console.print(f'[red]OpenVEX export skipped: {e}[/red]')
            return 1
    return 0


def _wire_rpm_owners(df, ctx, owners: dict) -> None:
    """Go-binary → vendoring-rpm link; shared with the RHACS path."""
    from .engine import wire_rpm_owners
    wire_rpm_owners(df, ctx, owners)


def _scanfree_cmd(args) -> int:
    """SBOM + VEX triage with no scanner: index → candidates → engine → export."""
    from . import triage
    from .adapters import grype as adapter
    from .context import context_for_image
    console = Console()
    triage.ensure_mirror(console)

    index_path = args.index or scanfree.INDEX_PATH
    if args.build_index or not os.path.exists(index_path):
        why = 'rebuilding' if args.build_index else 'no index yet — building'
        console.print(f"🧱 {why} VEX index → [cyan]{index_path}[/cyan]")
        _build_index(console, index_path)
        if not args.target:
            return 0
    if not args.target:
        console.print('[red]an image ref or syft-json SBOM path is required '
                      '(or --build-index alone).[/red]')
        return 2

    # Same ergonomics as `vextriage grype`: a path is used as-is, anything else
    # is an image ref and syft produces (or reuses) the cached SBOM for it.
    sbom_path, image_ref = args.target, args.image
    if not os.path.exists(sbom_path):
        console.print("🧾 syft SBOM...")
        try:
            sbom_path = adapter.syft_sbom(args.target, platform=args.platform,
                                          force=args.force)
        except Exception as e:
            console.print(f'[red]syft failed: {e}[/red]')
            return 1
        image_ref = image_ref or args.target

    index = scanfree.load_index(index_path)
    if not index:
        console.print(f'[red]could not read the index at {index_path}.[/red]')
        return 1

    try:
        df = scanfree.candidates_from_sbom(sbom_path, index)
    except scanfree.UnreadableSBOM as e:
        console.print(f'[red]unreadable SBOM: {e}[/red]')
        console.print('[red]regenerate it (`syft ... -o syft-json`) — an empty or truncated '
                      'SBOM must not be read as "no findings".[/red]')
        return 1
    if df.empty:
        console.print('[yellow]no candidates — the SBOM has no rpm or image '
                      'identity the VEX corpus names.[/yellow]')
        return 0
    console.print(f"🧮 {len(df):,} candidates from the VEX index (no scanner)")

    if not image_ref:
        # repoDigests carries the ref as pulled; manifestDigest is the per-arch
        # manifest and is NOT what a consumer resolves, so it must not become the
        # OpenVEX product identity.
        try:
            src = json.load(open(sbom_path)).get('source') or {}
            meta = src.get('metadata') or {}
            image_ref = next(iter(meta.get('repoDigests') or []), '')
            if not image_ref:
                name, ver = src.get('name') or '', str(src.get('version') or '')
                if name and ver.startswith('sha256:'):
                    image_ref = f'{name}@{ver}'
        except Exception:
            image_ref = ''
    if not image_ref:
        console.print('[red]--image <digest-pinned ref> is required (context + '
                      'OpenVEX product identity).[/red]')
        return 2

    ctx = context_for_image(image_ref, labels=adapter.sbom_labels(sbom_path) or None,
                            digests=adapter.sbom_digests(sbom_path))
    _wire_rpm_owners(df, ctx, adapter.rpm_file_owners(sbom_path))

    result_df = triage._audit_and_display(
        df, ctx, console, output_path=args.output, output_fmt=args.format,
        false_only=args.false_only, source_label='VEX index (no scanner)',
        candidates=True)

    if args.openvex_dir:
        try:
            _export_openvex(result_df, image_ref, args.openvex_dir, args.author, console)
        except ValueError as e:
            console.print(f'[red]OpenVEX export skipped: {e}[/red]')
            return 1
    return 0


def _audit_worker(df, ctx, ref: str) -> list:
    """CPU stage of generate, run in a forked worker process.

    The audit is pandas-heavy pure Python — in the thread pool it serializes
    on the GIL, so scanner threads beyond ~2 buy nothing.  Same pattern as
    retriage's fork ProcessPool.
    """
    from . import openvex, triage
    result = triage._audit_silent(df, ctx, vex_product=False)
    return openvex.statements_from_df(result, ref)


def _generate_cmd(args) -> int:
    """Scan a list of images with grype and populate the OpenVEX hub.

    This is the ONLY hub-population pipeline: statements are minted from the
    consumer-side scanner's own artifacts, so the purls in the document are
    guaranteed to match what that scanner (and trivy) will look up.  RHACS
    triage output is never converted to OpenVEX — RHACS does not consume it.
    """
    import re as _re
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from . import triage as _triage
    _triage.ensure_mirror(Console())

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

    if args.resume:
        # A digest already present in its hub doc's product ids was fully
        # scanned+written — skip it.  0-statement images leave no trace, so
        # they re-scan (cheap: SBOM cached).
        import json as _json
        by_doc: dict = {}
        for ref in refs:
            by_doc.setdefault(hub.doc_path(args.hub, ref), []).append(ref)
        skip = set()
        for path, group in by_doc.items():
            if not os.path.exists(path):
                continue
            try:
                with open(path) as fh:
                    doc = _json.load(fh)
            except Exception:
                continue
            done_digests = set()
            for s in doc.get('statements', []):
                for p in s.get('products', []) or []:
                    m = _re.search(r'(sha256:[a-f0-9]{64})', str(p.get('@id', '')))
                    if m:
                        done_digests.add(m.group(1))
            skip.update(r for r in group if r.split('@')[-1] in done_digests)
        if skip:
            refs = [r for r in refs if r not in skip]
            console.print(f'--resume: [bold]{len(skip)}[/bold] image(s) already '
                          f'in hub, {len(refs)} left')
        if not refs:
            console.print('Nothing to do.')
            return 0

    # One grype DB update up front, then freeze the per-call network checks —
    # they otherwise run once per image.  --no-db-update keeps the current DB
    # so cached grype results (keyed on the DB build stamp) stay valid — a
    # re-audit-only regeneration after engine changes never touches grype.
    import subprocess as _sp
    if not args.no_db_update:
        _sp.run(['grype', 'db', 'update'], capture_output=True)
    os.environ.setdefault('GRYPE_DB_AUTO_UPDATE', 'false')
    os.environ.setdefault('GRYPE_CHECK_FOR_APP_UPDATE', 'false')
    os.environ.setdefault('SYFT_CHECK_FOR_APP_UPDATE', 'false')

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
        try:
            sbom = adapter.syft_sbom(ref, platform=args.platform,
                                     force=args.force)
        except Exception as e:
            if 'no child with platform' in str(e):
                # Image doesn't ship the requested arch at all (e.g. OpenJ9 =
                # ppc64le/s390x only) — scan whatever the index does carry;
                # statements are per-digest and valid for that build.
                alt = adapter.fallback_platform(ref)
                if not alt:
                    raise
                sbom = adapter.syft_sbom(ref, platform=alt, force=True)
            else:
                # Transient registry/CDN hiccups (e.g. quay CDN TLS errors) —
                # one retry; force=True so a partially-written SBOM can't be
                # reused.
                import time as _time
                _time.sleep(5)
                sbom = adapter.syft_sbom(ref, platform=args.platform,
                                         force=True)
        doc = adapter.grype_scan(sbom)
        df = adapter.to_df(doc)
        # Labels + build digests from the SBOM itself — skopeo only as
        # fallback (scratch images); the platform manifest digest enables
        # exact-build VEX matching (per-arch product ids).
        ctx = context_for_image(ref, os_hint=adapter.os_hint(doc),
                                labels=adapter.sbom_labels(sbom) or None,
                                digests=adapter.sbom_digests(sbom))
        _wire_rpm_owners(df, ctx, adapter.rpm_file_owners(sbom))
        digest = ref.split('@')[-1]
        if digest in ocp_by_digest:
            ver, minor = ocp_by_digest[digest]
            ctx.workload_type = 'ocp'
            ctx.ocp_ver = minor
            ctx.display_name = f'OpenShift {ver}'
            ctx.extra_prefixes = []
        # CPU stage in the fork pool — the scanner thread just waits here.
        return cpu_pool.submit(_audit_worker, df, ctx, ref).result()

    # Scanner threads handle syft/grype subprocesses and registry I/O (GIL
    # released); the pandas audit runs in worker PROCESSES or it would
    # serialize every thread on the GIL.  spawn, not fork: forked children
    # abort on macOS (Objective-C runtime) and inherit thread locks; the
    # one-time import cost is amortized by pre-spawning all workers here,
    # before any scanner thread starts.
    import multiprocessing as _mp
    from concurrent.futures import ProcessPoolExecutor
    cpu_workers = max(2, min(args.workers, (os.cpu_count() or 8) - 2))
    cpu_pool = ProcessPoolExecutor(max_workers=cpu_workers,
                                   mp_context=_mp.get_context('spawn'))
    import time as _time
    # N concurrent sleeps can't share a worker → all N spawn now.
    for w in [cpu_pool.submit(_time.sleep, 0.2) for _ in range(cpu_workers)]:
        w.result()
    console.print(f'CPU audit pool: {cpu_workers} worker processes')

    # Checkpointed hub writes: flush every FLUSH_EVERY completions so an
    # interrupted run keeps (almost) everything on disk.  Batching per flush —
    # not per image — matters because refs sharing a doc (every digest of
    # ocp-v4.0-art-dev) would otherwise re-read+rewrite the same growing file
    # once per digest.
    FLUSH_EVERY = 25
    per_image, pending, errors, doc_updates = {}, {}, 0, 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(_one, ref): ref for ref in refs}
        for done, future in enumerate(as_completed(futures), 1):
            ref = futures[future]
            try:
                statements = future.result()
                # 0-statement results still flow to the writer: a re-scan is
                # the complete truth for its digest, and the doc merge must be
                # able to RETRACT statements that no longer hold.
                per_image[ref] = statements
                pending[ref] = statements
                console.print(f'  [{done}/{len(refs)}] {ref.split("@")[0]}: '
                              f'{len(statements)} statements')
            except Exception as e:
                errors += 1
                console.print(f'  [{done}/{len(refs)}] [red]{ref}: {e}[/red]')
            if len(pending) >= FLUSH_EVERY:
                doc_updates += hub.write_image_docs(args.hub, pending,
                                                    author=args.author)
                pending.clear()

    cpu_pool.shutdown()
    if pending:
        doc_updates += hub.write_image_docs(args.hub, pending, author=args.author)
    stats = hub.build_index(args.hub, name=args.author,
                            description='Red Hat VEX triage verdicts (OpenVEX)',
                            base_url=args.base_url, archive=args.archive)
    console.print(f"Hub: [bold]{stats['documents']}[/bold] documents "
                  f"({doc_updates} doc updates), {stats['packages']} index "
                  f"entries, {errors} errors → {args.hub}")

    rc = 0
    if args.crosscheck:
        rc = 1 if _crosscheck_statements(per_image, console) else 0
    if args.verify:
        return _verify_hub(per_image, args.hub, console) or rc
    return 1 if errors else rc


def _crosscheck_statements(per_image: dict, console: Console) -> int:
    """Does each OpenVEX statement say the SAME thing as Red Hat's VEX?

    For every statement, find what Red Hat says about the same subject —
    strongest match first: this exact image digest, then the packages the
    statement names (including image name for OCP/operator images).  Compare:

      ours: not_affected → Red Hat: known_not_affected, or not listed at all
                           (absence IS Red Hat's answer: no supported product
                           affected — the engine's not-listed rule)
      ours: fixed        → Red Hat: fixed

    MISMATCH = the subject appears ONLY in a contradicting bucket
    (known_affected / under_investigation).  Nothing is auto-dropped —
    mismatches are printed for a human.  Returns the mismatch count.
    """
    import json as _json
    import re as _re

    from .engine import VEX_DIR

    EXPECT = {'not_affected': 'known_not_affected', 'fixed': 'fixed'}
    tally = {'match': 0, 'match_by_absence': 0, 'ambiguous': 0, 'mismatch': 0,
             'no_vex_file': 0}
    for ref, statements in per_image.items():
        digest = ref.split('@')[-1]
        image_name = ref.split('@')[0].rsplit('/', 1)[-1]
        for s in statements:
            cve = s['vulnerability']['name']
            expected = EXPECT.get(s['status'])
            if not expected:
                continue
            vp = os.path.join(VEX_DIR, f'{cve}.json')
            if not os.path.exists(vp):
                tally['no_vex_file'] += 1
                continue
            try:
                ps = _json.load(open(vp))['vulnerabilities'][0].get('product_status', {})
            except Exception:
                continue

            # subjects Red Hat could name: the exact build, the packages, the image
            names = {image_name}
            for pr in s.get('products', []):
                for sc in (pr.get('subcomponents') or []):
                    m = _re.match(r'pkg:[^/]+/(?:redhat/)?(.+?)@', sc['@id'])
                    if m:
                        names.add(m.group(1).rsplit('/', 1)[-1])

            def _buckets_naming(subject_is_digest=False):
                found = set()
                for bucket, ids in ps.items():
                    for pid in ids:
                        if subject_is_digest:
                            if digest in pid:
                                found.add(bucket)
                        else:
                            tail = pid.split(':', 1)[-1]
                            if any(_re.search(rf'(^|[/:]){_re.escape(n)}(-\d|\.|@|$)', tail)
                                   for n in names):
                                found.add(bucket)
                                break
                return found

            exact = _buckets_naming(subject_is_digest=True)
            buckets = exact or _buckets_naming()
            level = 'exact build' if exact else 'package/image name'
            bad = buckets & {'known_affected', 'under_investigation'}
            good = buckets & {'known_not_affected', 'fixed'}
            if not buckets:
                tally['match_by_absence'] += 1      # RH lists nothing → not-listed rule
            elif bad and not good:
                tally['mismatch'] += 1
                console.print(f'  [red]MISMATCH {ref.split("@")[0]} {cve}: we say '
                              f'{s["status"]}, Red Hat ({level}) says only '
                              f'{sorted(buckets)}[/red]')
            elif bad and good:
                # Red Hat says different things for different streams/products;
                # a name-only comparison cannot adjudicate — count, don't hide.
                tally['ambiguous'] += 1
            else:
                tally['match'] += 1

    total = sum(tally.values())
    console.print(f"Crosscheck vs Red Hat VEX: {total} statements — "
                  f"{tally['match']} match, {tally['match_by_absence']} match by "
                  f"absence (not listed), {tally['ambiguous']} ambiguous "
                  f"(mixed streams), {tally['mismatch']} MISMATCH, "
                  f"{tally['no_vex_file']} no local VEX"
                  + (' [green](clean)[/green]' if not tally['mismatch'] else ''))
    return tally['mismatch']


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


def _doctor_cmd() -> int:
    """System check: external tools, auth env, discovery/cache artifacts."""
    import glob as _glob
    import shutil as _shutil
    import subprocess as _sp

    from rich.table import Table
    console = Console()

    def _version(binary: str, vargs: list) -> str:
        try:
            out = _sp.run([binary, *vargs], capture_output=True, text=True,
                          timeout=10)
            line = (out.stdout or out.stderr).strip().splitlines()
            return line[0][:60] if line else ''
        except Exception:
            return ''

    # (binary, version args, used by)
    tools = [
        ('syft',   ['--version'],           'OpenVEX generation — SBOM + image pull'),
        ('grype',  ['--version'],           'OpenVEX generation — CVE discovery'),
        ('trivy',  ['--version'],           'trivy scanner / generate --verify gate'),
        ('skopeo', ['--version'],           'label fallback (images without labels)'),
        ('oc',     ['version', '--client'], 'discovery — OCP release pullspecs'),
        ('opm',    ['version'],             'discovery — operator index catalogs'),
        ('podman', ['--version'],           'optional — registry login helper'),
    ]
    t = Table(title='External tools')
    for col in ('tool', 'found', 'version', 'used by'):
        t.add_column(col)
    missing = []
    for binary, vargs, purpose in tools:
        path = _shutil.which(binary)
        if path:
            t.add_row(binary, '[green]✓[/green]', _version(binary, vargs), purpose)
        else:
            missing.append(binary)
            t.add_row(binary, '[red]✗ not found[/red]', '', purpose)
    console.print(t)

    e = Table(title='Environment')
    for col in ('variable', 'state', 'needed for'):
        e.add_column(col)
    for var, needed in (('ROX_ENDPOINT', 'RHACS triage'),
                        ('ROX_API_TOKEN', 'RHACS triage')):
        e.add_row(var, '[green]set[/green]' if os.environ.get(var)
                  else '[yellow]unset[/yellow]', needed)
    raf = os.environ.get('REGISTRY_AUTH_FILE', '')
    e.add_row('REGISTRY_AUTH_FILE',
              '[green]set, file exists[/green]' if raf and os.path.isfile(raf)
              else '[red]set, file MISSING[/red]' if raf
              else '[yellow]unset[/yellow]', 'oc / opm / skopeo auth')
    dc = os.environ.get('DOCKER_CONFIG', '')
    dc_cfg = os.path.join(dc, 'config.json') if dc \
        else os.path.expanduser('~/.docker/config.json')
    e.add_row('DOCKER_CONFIG',
              f'[green]{"set" if dc else "default"}, config.json exists[/green]'
              if os.path.isfile(dc_cfg)
              else f'[yellow]{"set" if dc else "unset"}, no config.json '
                   f'({dc_cfg})[/yellow]', 'syft image pulls')
    console.print(e)

    d = Table(title='Data artifacts (relative to cwd — run from the repo root)')
    for col in ('artifact', 'state'):
        d.add_column(col)
    counts = [
        ('data/pullspecs/*.txt   (OCP releases)',
         len(_glob.glob('data/pullspecs/*.txt'))),
        ('data/catalogs/catalog-*.json  (operator indexes)',
         len(_glob.glob('data/catalogs/catalog-*.json'))),
        ('data/syft/*.json       (SBOM cache)',
         len(_glob.glob('data/syft/*.json'))),
        ('vexhub documents',
         len(_glob.glob('vexhub/pkg/**/scan.openvex.json', recursive=True))),
    ]
    for label, n in counts:
        d.add_row(label, f'[green]{n}[/green]' if n else '[yellow]0[/yellow]')
    if not os.path.isdir('data'):
        d.add_row('[red]data/ not found[/red]',
                  '[red]not the repo root?[/red]')
    console.print(d)

    if _shutil.which('grype'):
        st = _sp.run(['grype', 'db', 'status'], capture_output=True, text=True)
        console.print('grype DB: ' +
                      ('; '.join(st.stdout.strip().splitlines()[:3])
                       if st.returncode == 0 else '[red]status failed[/red]'))
    if missing:
        console.print(f"[yellow]missing: {', '.join(missing)} — only the "
                      f"workflows above that need them are affected[/yellow]")
    return 1 if missing else 0


def _live_digests_by_doc(hub_dir: str) -> dict:
    """doc path → set of 'sha256:…' digests still referenced by discovery.

    Union of every data/pullspecs/*.txt ref and every catalog channel-head
    workload image — the same sources `generate --ocp/--operators` scans from.
    """
    import glob as _glob
    import re as _re

    from . import hub, operators as ops
    refs = []
    for txt in _glob.glob(os.path.join('data', 'pullspecs', '*.txt')):
        try:
            with open(txt) as fh:
                for line in fh:
                    m = _re.search(r'(\S+@sha256:[a-f0-9]{64})', line)
                    if m:
                        refs.append(m.group(1))
        except OSError:
            continue
    for cat in _glob.glob(os.path.join('data', 'catalogs', 'catalog-*.json')):
        for _pkg, entries in ops.build_operator_index(cat).items():
            for entry in entries:
                for _role, img in ops._get_unique_workload_images(
                        entry['head_bundle']):
                    if _re.search(r'@sha256:[a-f0-9]{64}$', img):
                        refs.append(img)
    live: dict = {}
    for ref in set(refs):
        live.setdefault(hub.doc_path(hub_dir, ref), set()).add(
            ref.split('@')[-1])
    return live


def _hub_cmd(args) -> int:
    from . import hub
    console = Console()
    if getattr(args, 'prune', False):
        live = _live_digests_by_doc(args.hub)
        if not live:
            console.print('[red]--prune: no discovery artifacts found '
                          '(data/pullspecs, data/catalogs) — refusing to '
                          'prune against an empty live set.[/red]')
            return 2
        pstats = hub.prune(args.hub, live)
        console.print(f"Pruned: {pstats['statements']} statements for "
                      f"rotated-out digests ({pstats['docs_updated']} docs "
                      f"updated, {pstats['docs_removed']} removed); images "
                      f"outside discovery untouched")
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
    p.add_argument('--author', default='vextriage')
    p.add_argument('--output', default=None)
    p.add_argument('--format', default='csv', choices=['table', 'csv', 'json'])
    p.add_argument('--false-only', action='store_true', default=False)
    p.add_argument('--force', action='store_true', default=False,
                   help='regenerate the cached syft SBOM (grype only)')
    _add_index_args(p, default=False)


def _add_index_args(p: argparse.ArgumentParser, *, default: bool) -> None:
    """--vex-index / --no-vex-index and where the index lives."""
    p.add_argument('--vex-index', dest='vex_index', action='store_true',
                   default=default,
                   help='add the rpm and image candidates the VEX index names '
                        'to the scanner\'s own findings'
                        + ('' if default else ' (off by default)'))
    p.add_argument('--no-vex-index', dest='vex_index', action='store_false',
                   help='scanner findings only')
    p.add_argument('--index', default=None, metavar='FILE',
                   help=f'index location (default: {scanfree.INDEX_PATH})')
    p.add_argument('--skip-sync', dest='skip_sync', action='store_true', default=False,
                   help='do not refresh the VEX mirror, however old it is')


def _apply_sync_policy(args) -> None:
    """A run reads the mirror; --skip-sync stops it being refreshed first."""
    if getattr(args, 'skip_sync', False):
        os.environ['VEX_SKIP_SYNC'] = '1'


def _build_index(console, index_path: str) -> dict:
    """(Re)build the inverted VEX index, reporting progress."""
    idx = scanfree.build_index(
        out_path=index_path,
        progress=lambda i, n: console.print(f"   {i:,}/{n:,} CVE files", highlight=False))
    console.print(f"   indexed [bold]{idx['files']:,}[/bold] CVE files: "
                  f"{len(idx['rpm']):,} rpm names, {len(idx['oci']):,} image keys")
    return idx


def _merge_index(df, args, console, image_ref: str, labels) -> tuple:
    """Union scanner findings with the index candidates, when asked for.

    The index is never built implicitly here: building it walks the whole VEX
    mirror and a scan should not silently turn into a several-minute job.
    """
    if not getattr(args, 'vex_index', False):
        return df, False
    index_path = getattr(args, 'index', None) or scanfree.INDEX_PATH
    index = scanfree.load_index(index_path)
    if not index:
        console.print(f'[yellow]no VEX index at {index_path} — scanner findings '
                      f'only; run `vextriage build-index` for the rpm + image '
                      f'classes too.[/yellow]')
        return df, False
    df, added = scanfree.merge_index_candidates(df, index, image_ref=image_ref,
                                                labels=labels)
    if added:
        console.print(f"🧮 +{added:,} candidates from the VEX index "
                      f"(rpm + image classes the scanner did not report)")
    return df, bool(added)


def _build_index_cmd(args) -> int:
    """Build the inverted VEX index every scan path can draw candidates from."""
    from . import triage
    console = Console()
    index_path = args.index or scanfree.INDEX_PATH
    if getattr(args, 'sync', False):
        try:
            st = triage.sync_vex_mirror(console)
        except RuntimeError as e:
            console.print(f'[red]{e}[/red]')
            return 1
        console.print(f"   mirrored [bold]{st['fetched']:,}[/bold] file(s); "
                      f"{st['corpus']:,} CVEs in the corpus")
    console.print(f"🧱 building VEX index → [cyan]{index_path}[/cyan]")
    _build_index(console, index_path)
    return 0


def _report_cmd(args) -> int:
    """Triage a RHACS report CSV end to end and write one shareable HTML file."""
    import time
    from . import report, triage as triage_mod
    console = Console()
    triage_mod.ensure_mirror(console)
    if not os.path.exists(args.csv):
        console.print(f'[red]no such file: {args.csv}[/red]')
        return 2
    try:
        result = report.triage_report(args.csv, workers=args.workers,
                                      platform=args.platform, console=console,
                                      rescan=args.rescan, ocp=args.ocp)
    except ValueError as e:
        console.print(f'[red]{e}[/red]')
        return 2
    rows = result['rows']
    if rows.empty:
        console.print('[yellow]nothing to report — no row survived triage.[/yellow]')
        return 1
    real = int((~rows['AUDIT_RESULT'].str.contains('FALSE', na=False)).sum())
    path = report.render_html(result, args.output,
                              when=time.strftime('%Y-%m-%d %H:%M'))
    if not args.no_parquet:
        pq_path = args.parquet or os.path.splitext(args.output)[0] + '.parquet'
        try:
            report.write_parquet(result, pq_path)
            console.print(f"🗃  {pq_path}")
        except Exception as e:
            console.print(f'[yellow]parquet skipped: {type(e).__name__}: {e}[/yellow]')
    if args.rescan:
        # A rescan enumerates candidates, so the cleared rows were never claims
        # about these images — same wording as scanfree.
        console.print(f"\n[bold]{len(rows):,}[/bold] candidates checked → "
                      f"[red]{real:,} findings[/red]; "
                      f"{len(rows) - real:,} not a match")
    else:
        console.print(f"\n[bold]{len(rows):,}[/bold] findings → "
                      f"[green]{len(rows) - real:,} false positives[/green], "
                      f"[red]{real:,} real[/red]")
    console.print(f"📄 {path}")
    return 0


def _sync_cmd(args) -> int:
    """Mirror the Red Hat VEX corpus, then refresh the index over it."""
    from . import triage
    console = Console()
    try:
        st = triage.sync_vex_mirror(console, workers=args.workers, limit=args.limit,
                                    bulk=args.bulk)
    except RuntimeError as e:
        console.print(f'[red]{e}[/red]')
        return 1
    console.print(f"✅ mirrored [bold]{st['fetched']:,}[/bold] file(s) "
                  f"({st['missing']:,} missing, {st['changed']:,} changed)")
    if not args.no_index:
        index_path = args.index or scanfree.INDEX_PATH
        console.print(f"🧱 rebuilding VEX index → [cyan]{index_path}[/cyan]")
        _build_index(console, index_path)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='vextriage',
        description='Scan images with RHACS, grype or trivy; triage against '
                    'Red Hat CSAF-VEX; export OpenVEX.')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('rhacs', add_help=False,
                   help="RHACS-backed triage")
    for name in ('pipeline', 'operators', 'retriage', 'parquet'):
        sub.add_parser(name, add_help=False, help=f'passthrough to rhacs_vex.{name}')

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
    pg.add_argument('--author', default='vextriage')
    pg.add_argument('--base-url', default='')
    pg.add_argument('--archive', action='store_true', default=False)
    pg.add_argument('--force', action='store_true', default=False,
                    help='regenerate cached syft SBOMs')
    pg.add_argument('--resume', action='store_true', default=False,
                    help='skip images whose digest is already in its hub doc')
    pg.add_argument('--no-db-update', action='store_true', default=False,
                    help='keep the current grype DB so cached grype results stay '
                         'valid — re-audit from cache without rescanning')
    pg.add_argument('--crosscheck', action='store_true', default=False,
                    help='after generating, re-check every statement against '
                         'the raw Red Hat VEX with independent rules '
                         '(offline, seconds)')
    pg.add_argument('--verify', action='store_true', default=False,
                    help='re-scan each image with trivy against its doc; fail on leaks')

    pf = sub.add_parser('scanfree',
                        help='triage an SBOM against Red Hat VEX with no '
                             'vulnerability scanner (rpm + image classes)')
    pf.add_argument('target', nargs='?', default=None,
                    help='image ref (digest-pinned) or syft-json SBOM path; an '
                         'image ref is SBOM-ed with syft and cached '
                         '(omit with --build-index)')
    pf.add_argument('--image', default=None,
                    help='digest-pinned image ref when target is a file '
                         '(default: the SBOM source)')
    pf.add_argument('--platform', default='linux/amd64')
    pf.add_argument('--force', action='store_true', default=False,
                    help='regenerate the cached syft SBOM')
    pf.add_argument('--build-index', action='store_true', default=False,
                    help='(re)build the inverted VEX index, then exit unless a '
                         'target is given — same as `vextriage build-index`')
    pf.add_argument('--index', default=None, metavar='FILE',
                    help=f'index location (default: {scanfree.INDEX_PATH})')
    pf.add_argument('--openvex-dir', default=None, metavar='DIR',
                    help='export FALSE POSITIVE verdicts as OpenVEX into this hub dir')
    pf.add_argument('--author', default='vextriage')
    pf.add_argument('--output', default=None)
    pf.add_argument('--format', default='table', choices=['table', 'csv', 'json'])
    pf.add_argument('--false-only', action='store_true', default=False)
    pf.add_argument('--skip-sync', dest='skip_sync', action='store_true', default=False,
                    help='do not refresh the VEX mirror, however old it is')

    pb = sub.add_parser('build-index',
                        help='(re)build the inverted VEX index every scan path '
                             'draws rpm + image candidates from')
    pb.add_argument('--index', default=None, metavar='FILE',
                    help=f'index location (default: {scanfree.INDEX_PATH})')
    pb.add_argument('--sync', action='store_true', default=False,
                    help='mirror the Red Hat VEX corpus first (same as `vextriage sync`)')

    pr = sub.add_parser('report',
                        help='triage a RHACS vulnerability report CSV (clusters, '
                             'namespaces, deployments, images) into one '
                             'self-contained HTML file')
    pr.add_argument('csv', help='RHACS report CSV export')
    pr.add_argument('--output', '-o', required=True, metavar='FILE',
                    help='where to write the HTML report')
    pr.add_argument('--workers', type=int, default=4, metavar='N',
                    help='images SBOM-ed in parallel (default: 4).  Scanning '
                         'only — the verdict pass is single-threaded on '
                         'purpose, so raising this costs registry bandwidth, '
                         'not memory')
    pr.add_argument('--platform', default='linux/amd64')
    pr.add_argument('--ocp', default='', metavar='VER',
                    help="the cluster's OpenShift version(s), comma-separated — an "
                         "image's labels carry its own build version, not the "
                         "cluster's, so this is the only place it can come from")
    pr.add_argument('--parquet', default=None, metavar='FILE',
                    help='also write the rows as parquet for triage.html / DuckDB '
                         '(default: alongside --output)')
    pr.add_argument('--no-parquet', action='store_true', default=False,
                    help='HTML only')
    pr.add_argument('--rescan', action='store_true', default=False,
                    help='ignore the CSV findings and scan every image live '
                         '(syft + grype + VEX index), keeping the cluster, '
                         'namespace and deployment placement from the CSV — run '
                         'it alongside the default to compare the two')
    pr.add_argument('--skip-sync', dest='skip_sync', action='store_true', default=False,
                    help='do not refresh the VEX mirror, however old it is')

    psy = sub.add_parser('sync',
                         help='mirror the whole Red Hat VEX corpus from the '
                              'change feed, then rebuild the index — after this '
                              'a run needs no network (--offline)')
    psy.add_argument('--workers', type=int, default=0, metavar='N')
    psy.add_argument('--limit', type=int, default=0, metavar='N',
                     help='stop after N files (try a slice before the full corpus)')
    psy.add_argument('--index', default=None, metavar='FILE')
    psy.add_argument('--no-index', action='store_true', default=False,
                     help='mirror only, leave the index alone')
    psy.add_argument('--bulk', dest='bulk', action='store_true', default=None,
                     help='force the tarball path (default: automatic above '
                          '2,000 outstanding files)')
    psy.add_argument('--no-bulk', dest='bulk', action='store_false',
                     help='force file-by-file fetching')

    sub.add_parser('doctor', help='check external tools, auth env and data '
                                  'artifacts')

    ph = sub.add_parser('hub', help='rebuild hub index.json + vex-repository.json')
    ph.add_argument('--hub', default='vexhub', metavar='DIR')
    ph.add_argument('--prune', action='store_true', default=False,
                    help='drop statements for digests no longer in '
                         'data/pullspecs or catalog channel heads '
                         '(images outside discovery untouched)')
    ph.add_argument('--author', default='vextriage')
    ph.add_argument('--base-url', default='')
    ph.add_argument('--archive', action='store_true', default=False)

    argv = sys.argv[1:]
    if argv and argv[0] in ('rhacs', 'pipeline', 'operators', 'retriage', 'parquet'):
        return _passthrough(argv[0], 'triage' if argv[0] == 'rhacs' else argv[0],
                            argv[1:])

    args = parser.parse_args(argv)
    _apply_sync_policy(args)
    if args.command in ('grype', 'trivy'):
        return _scanner_cmd(args.command, args)
    if args.command == 'generate':
        return _generate_cmd(args)
    if args.command == 'scanfree':
        return _scanfree_cmd(args)
    if args.command == 'build-index':
        return _build_index_cmd(args)
    if args.command == 'sync':
        return _sync_cmd(args)
    if args.command == 'report':
        return _report_cmd(args)
    if args.command == 'doctor':
        return _doctor_cmd()
    if args.command == 'hub':
        return _hub_cmd(args)
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
