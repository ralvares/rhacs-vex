#!/usr/bin/env python3
"""
triage_operators.py — Triage all operators from OLM catalogs against Red Hat VEX data.

For each OCP catalog version found in data/catalogs/, the tool:
  1. Parses the catalog to find all operator packages.
  2. Identifies the head bundle of each operator's default channel.
  3. Retrieves all workload images from that bundle's relatedImages.
  4. Triages every image via the RHACS API using the VEX audit engine from triage.py.
  5. Writes per-operator reports to:
       data/reports/ocp-{version}/{operator}-{bundle_version}.csv

Environment variables required:
  ROX_ENDPOINT  — RHACS Central hostname:port (e.g. central.example.com:443)
  ROX_API_TOKEN — RHACS API bearer token
"""

import argparse
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# requests_cache logs spurious "Unable to deserialize response" errors when
# multiple threads hit the SQLite cache simultaneously.  The cache miss is
# already handled gracefully (a live HTTP request follows), so silence it.
logging.getLogger('requests_cache.backends.base').setLevel(logging.CRITICAL)

import pandas as pd
from rich.console import Console
from rich import box
from rich.table import Table

import triage as triage  # noqa: E402

# ── Constants ─────────────────────────────────────────────────────────────────

BASE_DIR    = "data"
CATALOG_DIR = os.path.join(BASE_DIR, "catalogs")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
MAX_WORKERS = 10

console = Console()


# ── Catalog parsing ───────────────────────────────────────────────────────────

def _parse_catalog(catalog_path: str) -> tuple:
    """
    Parse a multi-object JSON catalog file (OLM FBC format) and return
    (packages, channels, bundles) as separate lists.

    The file contains sequential top-level JSON objects (not JSON-lines);
    we use brace-depth tracking to split them correctly.
    """
    packages, channels, bundles = [], [], []
    buf   = ''
    depth = 0
    with open(catalog_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            depth += line.count('{') - line.count('}')
            buf   += line
            if depth == 0 and buf:
                try:
                    obj    = json.loads(buf)
                    schema = obj.get('schema', '')
                    if schema == 'olm.package':
                        packages.append(obj)
                    elif schema == 'olm.channel':
                        channels.append(obj)
                    elif schema == 'olm.bundle':
                        bundles.append(obj)
                except Exception:
                    pass
                buf = ''
    return packages, channels, bundles


def _find_channel_head(channel: dict) -> str | None:
    """
    Return the name of the head bundle in an OLM channel.

    The head is the entry not reachable via another entry's 'replaces' or
    'skips' fields (i.e. nothing upgrades *to* it from within the channel).
    Falls back to the last entry alphabetically if the graph is ambiguous.
    """
    entries = channel.get('entries', [])
    if not entries:
        return None

    entry_names = {e['name'] for e in entries}
    pointed_to: set = set()
    for e in entries:
        if e.get('replaces'):
            pointed_to.add(e['replaces'])
        for s in e.get('skips', []):
            pointed_to.add(s)

    heads = entry_names - pointed_to
    if not heads:
        return entries[-1]['name']

    # If multiple candidates, pick the lexicographically greatest (highest version string).
    return sorted(heads)[-1]


def build_operator_index(catalog_path: str) -> dict:
    """
    Return a dict keyed by operator package name.  Each value is a list of
    channel entries — one per channel in the catalog:
      {
        'pkg_name': [
          {'channel': str, 'is_default': bool, 'head_bundle': <bundle dict>},
          ...
        ],
        ...
      }
    Channels whose head bundle cannot be resolved are silently skipped.
    """
    packages, channels, bundles = _parse_catalog(catalog_path)
    bundle_by_name = {b['name']: b for b in bundles}

    # Build a set of default channels per package
    default_ch_map: dict = {pkg['name']: pkg.get('defaultChannel', '') for pkg in packages}

    result: dict = {}
    for ch in channels:
        pkg_name = ch.get('package', '')
        ch_name  = ch.get('name', '')
        if not pkg_name:
            continue

        head_name = _find_channel_head(ch)
        if not head_name:
            continue

        head_bundle = bundle_by_name.get(head_name)
        if not head_bundle:
            continue

        result.setdefault(pkg_name, []).append({
            'channel':    ch_name,
            'is_default': ch_name == default_ch_map.get(pkg_name, ''),
            'head_bundle': head_bundle,
        })

    # Sort each package's channels so the default channel comes first,
    # then alphabetically for deterministic ordering.
    for pkg_name in result:
        result[pkg_name].sort(key=lambda x: (not x['is_default'], x['channel']))

    return result


# ── Image helpers ─────────────────────────────────────────────────────────────

def _sha_from_ref(image_ref: str) -> str | None:
    """Extract the sha256 hex digest from an image reference, or None."""
    m = re.search(r'@sha256:([a-f0-9]+)', image_ref, re.IGNORECASE)
    return m.group(1) if m else None


def _get_unique_workload_images(bundle: dict) -> list:
    """
    Return a deduplicated list of (role_name, image_ref) pairs for all
    *workload* images in a bundle's relatedImages.

    Exclusions:
      - The bundle image itself (it is a metadata artifact, not a workload).
      - Duplicate digests (annotation entries that repeat the operator image).
    """
    bundle_sha = _sha_from_ref(bundle.get('image', ''))
    seen_shas: set = set()
    result: list = []

    for ri in bundle.get('relatedImages', []):
        img  = ri.get('image', '')
        name = ri.get('name', '')
        sha  = _sha_from_ref(img)

        # Skip the bundle image
        if bundle_sha and sha == bundle_sha:
            continue
        # Skip duplicate digests (annotation copies, etc.)
        if sha and sha in seen_shas:
            continue
        if sha:
            seen_shas.add(sha)

        result.append((name or '', img))

    return result


# ── Report path helper ────────────────────────────────────────────────────────

def _report_path(ocp_version: str, operator_name: str, channel: str, bundle_version: str) -> str:
    """
    Build and ensure the output CSV path:
      data/reports/ocp-{version}/{operator}-{channel}-{bundle_version}.csv
    """
    safe_ver = re.sub(r'[/\\:*?"<>|]', '_', bundle_version)
    safe_ch  = re.sub(r'[/\\:*?"<>|]', '_', channel)
    dirname  = os.path.join(REPORTS_DIR, f"ocp-{ocp_version}")
    os.makedirs(dirname, exist_ok=True)
    return os.path.join(dirname, f"{operator_name}-{safe_ch}-{safe_ver}.csv")


# ── Core triage logic ─────────────────────────────────────────────────────────

def triage_operator(
    bundle: dict,
    session,
    false_only: bool = False,
    workers:    int  = MAX_WORKERS,
) -> pd.DataFrame | None:
    """
    Triage all workload images in *bundle* via RHACS and return a combined
    DataFrame, or None if no actionable findings were produced.

    Uses on-demand scanning (POST /v1/images/scan) so images that are not
    currently deployed in the cluster are scanned and triaged correctly.

    Each row in the DataFrame carries the standard triage columns plus:
      IMAGE      — full image reference
      IMAGE_ROLE — the 'name' field from relatedImages (may be empty)
    """
    images = _get_unique_workload_images(bundle)
    if not images:
        return None

    frame_parts: list = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(triage._fetch_and_audit, session, img, None, false_only): (role, img)
            for role, img in images
        }
        for future in as_completed(futures):
            role, img = futures[future]
            try:
                res = future.result()
            except Exception:
                continue
            if not res.get('found') or res.get('result_df') is None:
                continue
            rdf = res['result_df'].copy()
            rdf.insert(0, 'IMAGE',      img)
            rdf.insert(1, 'IMAGE_ROLE', role)
            frame_parts.append(rdf)

    if not frame_parts:
        return None
    return pd.concat(frame_parts, ignore_index=True)


# ── Catalog version discovery ─────────────────────────────────────────────────

def available_catalog_versions() -> list:
    """
    Return sorted OCP version strings inferred from
    data/catalogs/catalog-{version}.json file names.
    """
    versions = []
    if not os.path.isdir(CATALOG_DIR):
        return versions
    for fname in os.listdir(CATALOG_DIR):
        m = re.match(r'^catalog-(\d+\.\d+)\.json$', fname)
        if m:
            versions.append(m.group(1))
    return sorted(versions)


# ── Terminal summary table ────────────────────────────────────────────────────

def _print_version_summary(version: str, rows: list, false_only: bool = False) -> None:
    """
    Print a Rich table summarising all operator channels processed for *version*.

    *rows* is a list of dicts with keys:
      operator, channel, bundle_version, images, vulnerable, false_positive, skipped, report
    """
    table = Table(
        title=f"OCP {version} — Operator Triage Summary",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Operator",       style="cyan",       no_wrap=True)
    table.add_column("Channel",        style="magenta",    no_wrap=True)
    table.add_column("Bundle",         style="dim",        no_wrap=True)
    table.add_column("Images",         justify="right")
    if not false_only:
        table.add_column("Positive",   justify="right",    style="bold red")
    table.add_column("False Positive", justify="right",    style="bold green")
    table.add_column("Report",         style="dim")

    for r in rows:
        row_cells = [
            r['operator'],
            r.get('channel', ''),
            r['bundle_version'],
            str(r['images']),
        ]
        if not false_only:
            row_cells.append(str(r['vulnerable']) if r['vulnerable'] else '-')
        row_cells.append(str(r['false_positive']) if r['false_positive'] else '-')
        row_cells.append(r['report'] if r['report'] else '[dim]no findings[/dim]')
        table.add_row(*row_cells)

    console.print(table)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            'Triage all operators from OLM catalogs against Red Hat VEX data.\n\n'
            'Scans each operator\'s latest bundle images via RHACS and writes\n'
            'per-operator CSV reports to data/reports/ocp-{version}/.\n\n'
            'Requires: ROX_ENDPOINT and ROX_API_TOKEN environment variables.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--version', default=None, metavar='VERSION',
        help=(
            'Comma-separated OCP version(s) to process, e.g. "4.21" or "4.20,4.21".\n'
            'Defaults to all versions found in data/catalogs/.'
        ),
    )
    parser.add_argument(
        '--operator', default=None, metavar='NAME',
        help='Comma-separated operator package name(s) to process.  Defaults to all.',
    )
    parser.add_argument(
        '--workers', type=int, default=MAX_WORKERS, metavar='N',
        help=f'Parallel image workers per operator (default: {MAX_WORKERS}).',
    )
    parser.add_argument(
        '--false-only', action='store_true', default=False,
        help='Include only FALSE POSITIVE findings in the output CSVs.',
    )
    parser.add_argument(
        '--skip-existing', action='store_true', default=False,
        help='Skip operators whose report CSV already exists (useful for resuming).',
    )
    args = parser.parse_args()

    ROX_ENDPOINT  = os.environ.get('ROX_ENDPOINT', '')
    ROX_API_TOKEN = os.environ.get('ROX_API_TOKEN', '')
    if not ROX_ENDPOINT or not ROX_API_TOKEN:
        console.print('[bold red]❌ ROX_ENDPOINT and ROX_API_TOKEN environment variables must be set.[/bold red]')
        raise SystemExit(1)

    import urllib3  # noqa: PLC0415
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Resolve OCP versions to process
    if args.version:
        versions = [v.strip() for v in args.version.split(',') if v.strip()]
    else:
        versions = available_catalog_versions()
    if not versions:
        console.print(f'[bold red]❌ No catalog files found in {CATALOG_DIR}[/bold red]')
        raise SystemExit(1)

    # Resolve operator name filter
    op_filter = {o.strip() for o in args.operator.split(',')} if args.operator else None

    session = triage._rhacs_session(ROX_ENDPOINT, ROX_API_TOKEN)

    for ocp_ver in versions:
        cat_path = os.path.join(CATALOG_DIR, f'catalog-{ocp_ver}.json')
        if not os.path.exists(cat_path):
            console.print(f'[yellow]⚠  Catalog not found for OCP {ocp_ver}: {cat_path}[/yellow]')
            continue

        console.rule(f'[bold cyan]OCP {ocp_ver}[/bold cyan]')
        console.print(f'📂 Parsing [cyan]{cat_path}[/cyan] ...')
        op_index = build_operator_index(cat_path)
        total_channels = sum(len(v) for v in op_index.values())
        console.print(f'   {len(op_index)} operators, {total_channels} channels in catalog.')

        # Apply operator filter
        operators = {
            k: v for k, v in op_index.items()
            if op_filter is None or k in op_filter
        }
        if not operators:
            console.print('[yellow]  No matching operators.[/yellow]')
            continue

        summary_rows: list = []

        for op_name, ch_entries in operators.items():
            for ch_entry in ch_entries:
                channel     = ch_entry['channel']
                is_default  = ch_entry['is_default']
                bundle      = ch_entry['head_bundle']
                bundle_name = bundle.get('name', '')

                # Extract version token: find the first ".vN" in the bundle name.
                _vm = re.search(r'\.v(\d)', bundle_name)
                if _vm:
                    bundle_version = bundle_name[_vm.start(0) + 1:]
                elif bundle_name.startswith(op_name + '.'):
                    bundle_version = bundle_name[len(op_name) + 1:]
                else:
                    bundle_version = bundle_name

                report_path = _report_path(ocp_ver, op_name, channel, bundle_version)

                default_tag = ' [dim](default)[/dim]' if is_default else ''
                if args.skip_existing and os.path.exists(report_path):
                    console.print(f'  [dim]━ {op_name} / {channel} {bundle_version} — skipped (exists)[/dim]')
                    continue

                images = _get_unique_workload_images(bundle)
                console.print(
                    f'\n  [bold]{op_name}[/bold] / [cyan]{channel}[/cyan]{default_tag} '
                    f'[dim]{bundle_version}[/dim] — [cyan]{len(images)}[/cyan] image(s)'
                )

                if not images:
                    console.print('    [dim]No workload images in this bundle.[/dim]')
                    summary_rows.append({
                        'operator': op_name, 'channel': channel,
                        'bundle_version': bundle_version,
                        'images': 0, 'vulnerable': 0, 'false_positive': 0,
                        'skipped': True, 'report': '',
                    })
                    continue

                t0      = time.time()
                df      = triage_operator(bundle, session,
                                          false_only=args.false_only,
                                          workers=args.workers)
                elapsed = time.time() - t0

                if df is None or df.empty:
                    console.print(
                        f'    [dim]No findings — images not in RHACS or no CVE data. '
                        f'({elapsed:.1f}s)[/dim]'
                    )
                    summary_rows.append({
                        'operator': op_name, 'channel': channel,
                        'bundle_version': bundle_version,
                        'images': len(images), 'vulnerable': 0, 'false_positive': 0,
                        'skipped': False, 'report': '',
                    })
                    continue

                df.to_csv(report_path, index=False)

                counts       = df['AUDIT_RESULT'].value_counts().to_dict()
                n_vuln       = counts.get('❌ POSITIVE', 0)
                n_fp         = counts.get('✅ FALSE POSITIVE', 0)
                n_imgs_found = df['IMAGE'].nunique()

                if args.false_only:
                    console.print(
                        f'    [bold green]✅ {n_fp}[/bold green] false-positive  '
                        f'({n_imgs_found}/{len(images)} images in RHACS)  '
                        f'→ [cyan]{report_path}[/cyan]  [dim]({elapsed:.1f}s)[/dim]'
                    )
                else:
                    console.print(
                        f'    [bold green]✅ {n_fp}[/bold green] false-positive  '
                        f'[bold red]❌ {n_vuln}[/bold red] positive  '
                        f'({n_imgs_found}/{len(images)} images in RHACS)  '
                        f'→ [cyan]{report_path}[/cyan]  [dim]({elapsed:.1f}s)[/dim]'
                    )
                summary_rows.append({
                    'operator': op_name, 'channel': channel,
                    'bundle_version': bundle_version,
                    'images': len(images), 'vulnerable': n_vuln,
                    'false_positive': n_fp, 'skipped': False, 'report': report_path,
                })

        console.print()
        if summary_rows:
            _print_version_summary(ocp_ver, summary_rows, false_only=args.false_only)

    console.print('\n[bold green]Done.[/bold green]')


if __name__ == '__main__':
    main()
