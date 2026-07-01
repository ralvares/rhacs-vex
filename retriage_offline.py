#!/usr/bin/env python3
"""Offline retriage — re-run audit on all OCP + operator reports from cached data. Zero network."""
import sys, os, re, json, time, glob, argparse
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd

REPORT_DIR = 'data/reports'


def retriage_ocp(txt):
    import triage  # import per-process for multiprocessing
    ver = os.path.splitext(os.path.basename(txt))[0]
    out = os.path.join(REPORT_DIR, f'ocp-{ver}.csv')
    images, ocp_ver = [], None
    with open(txt) as f:
        for line in f:
            nm = re.match(r'^Name:\s+(.+)', line)
            if nm and ocp_ver is None: ocp_ver = nm.group(1).strip(); continue
            m = re.match(r'^(\S+)\s+(\S+@sha256:[a-f0-9]+)', line.strip())
            if m: images.append((m.group(1), m.group(2)))
    if not images: return ver, 0, 0, 0
    minor_ver = '.'.join((ocp_ver or ver).split('.')[:2])
    scanned = skipped = 0
    all_results = []
    for comp_name, image_ref in images:
        cache_path = triage._scan_cache_path('', image_ref)
        if not os.path.exists(cache_path): skipped += 1; continue
        try:
            with open(cache_path) as fh: image_data = json.load(fh)
        except: skipped += 1; continue
        labels = (image_data.get('metadata') or {}).get('v1', {}).get('labels') or {}
        img_ctx = triage.parse_context_from_labels(labels, image_ref) if labels else triage.parse_image_ref(image_ref)
        os_info = (image_data.get('scan') or {}).get('operatingSystem', '')
        img_ctx.workload_type = 'ocp'
        img_ctx.ocp_ver = minor_ver
        os_rhel = re.search(r'(?:rhel|coreos):(\d+)', os_info or '')
        if os_rhel: img_ctx.rhel_ver = os_rhel.group(1)
        img_ctx.display_name = f'OpenShift {ocp_ver or ver}'
        img_ctx.extra_prefixes = []
        img_ctx.ocp_component = comp_name
        if hasattr(triage, '_sbom_cache_path'):
            sp = triage._sbom_cache_path(image_ref)
            if os.path.exists(sp):
                try:
                    with open(sp) as fh: img_ctx.sbom_src_map = triage._build_sbom_src_map(json.load(fh))
                except: pass
        img_df = triage.rhacs_to_df(image_data)
        if img_df.empty: scanned += 1; continue
        img_df['RHACS_SEVERITY'] = img_df['SEVERITY'].apply(lambda s: triage._RHACS_SEVERITY_MAP.get(str(s).strip().upper(), 'Unknown'))
        img_df[['AUDIT_RESULT','VEX_FIX_VER','JUSTIFICATION','SEVERITY']] = img_df.apply(lambda row: list(triage.audit_row_detailed(row, img_ctx)), axis=1, result_type='expand')
        img_df['VEX_PRODUCT'] = img_df.apply(lambda row: triage._vex_product_for_row(row, img_ctx), axis=1)
        img_df['SEVERITY_MISMATCH'] = (img_df['RHACS_SEVERITY'] != 'Unknown') & (img_df['SEVERITY'] != img_df['RHACS_SEVERITY'])
        img_df['OCP_COMPONENT'] = comp_name
        img_df['IMAGE'] = image_ref
        all_results.append(triage._sort_and_filter_df(img_df, False))
        scanned += 1
    if all_results:
        combined = pd.concat(all_results, ignore_index=True)
        combined.to_csv(out, index=False)
        return ver, scanned, skipped, len(combined)
    return ver, scanned, skipped, 0

def _retriage_one_operator_csv(csv_path):
    """Retriage a single operator CSV. Returns (basename, success_bool, error_str)."""
    import triage  # imported once per worker process, cached by Python
    basename = os.path.basename(csv_path)
    try:
        df = pd.read_csv(csv_path, dtype=str)
        if df.empty:
            return basename, False, None
        image_groups = df.groupby('IMAGE') if 'IMAGE' in df.columns else [(None, df)]
        parts = []
        for image_ref, group in image_groups:
            if not image_ref or pd.isna(image_ref):
                continue
            cache_path = triage._scan_cache_path('', str(image_ref))
            if os.path.exists(cache_path):
                try:
                    with open(cache_path) as fh:
                        image_data = json.load(fh)
                    labels = (image_data.get('metadata') or {}).get('v1', {}).get('labels') or {}
                    img_ctx = triage.parse_context_from_labels(labels, str(image_ref)) if labels else triage.parse_image_ref(str(image_ref))
                    os_info = (image_data.get('scan') or {}).get('operatingSystem', '')
                    if os_info:
                        os_rhel = re.search(r'(?:rhel|coreos):(\d+)', os_info)
                        if os_rhel:
                            img_ctx.rhel_ver = os_rhel.group(1)
                except Exception:
                    img_ctx = triage.parse_image_ref(str(image_ref))
            else:
                img_ctx = triage.parse_image_ref(str(image_ref))

            if hasattr(triage, '_sbom_cache_path'):
                sp = triage._sbom_cache_path(str(image_ref))
                if os.path.exists(sp):
                    try:
                        with open(sp) as fh:
                            img_ctx.sbom_src_map = triage._build_sbom_src_map(json.load(fh))
                    except Exception:
                        pass

            img_df = triage.rhacs_to_df(image_data) if os.path.exists(cache_path) else pd.DataFrame()
            if img_df.empty:
                continue
            img_df['RHACS_SEVERITY'] = img_df['SEVERITY'].apply(lambda s: triage._RHACS_SEVERITY_MAP.get(str(s).strip().upper(), 'Unknown'))
            img_df[['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY']] = img_df.apply(lambda row: list(triage.audit_row_detailed(row, img_ctx)), axis=1, result_type='expand')
            img_df['VEX_PRODUCT'] = img_df.apply(lambda row: triage._vex_product_for_row(row, img_ctx), axis=1)
            img_df['SEVERITY_MISMATCH'] = (img_df['RHACS_SEVERITY'] != 'Unknown') & (img_df['SEVERITY'] != img_df['RHACS_SEVERITY'])
            img_df['IMAGE'] = str(image_ref)
            img_df['IMAGE_ROLE'] = group.iloc[0].get('IMAGE_ROLE', '') if 'IMAGE_ROLE' in group.columns else ''
            parts.append(triage._sort_and_filter_df(img_df, False))

        if parts:
            combined = pd.concat(parts, ignore_index=True)
            combined.to_csv(csv_path, index=False)
            return basename, True, None
        return basename, False, None
    except Exception as e:
        return basename, False, str(e)


def retriage_operators(workers=10, minor_versions=None):
    """Re-run audit on operator CSVs using cached scan data (threaded).

    Uses ThreadPoolExecutor (not Process) so all workers share the _load_vex
    LRU cache — each VEX file is read from disk once instead of once-per-process.

    When minor_versions is set (e.g. {'4.22'}), only directories matching those
    minor versions are processed.  Operators shared across versions (identical
    CSV content) are triaged once and the result is copied to duplicates.
    """
    op_dirs = sorted(glob.glob(os.path.join(REPORT_DIR, 'ocp-*')))
    op_dirs = [d for d in op_dirs if os.path.isdir(d)]
    if minor_versions:
        op_dirs = [d for d in op_dirs
                   if os.path.basename(d).replace('ocp-', '') in minor_versions]
    all_csvs = [csv for d in op_dirs for csv in sorted(glob.glob(os.path.join(d, '*.csv')))]

    # Deduplicate: group CSVs by basename, pick one canonical path per group,
    # triage it, then copy the result to duplicates.
    from collections import defaultdict
    by_name = defaultdict(list)
    for csv in all_csvs:
        by_name[os.path.basename(csv)].append(csv)
    canonical = [paths[0] for paths in by_name.values()]
    dupes_map = {paths[0]: paths[1:] for paths in by_name.values() if len(paths) > 1}
    n_deduped = len(all_csvs) - len(canonical)

    print(f'  Found {len(all_csvs)} operator CSVs across {len(op_dirs)} OCP version(s), '
          f'{len(canonical)} unique, {n_deduped} duplicates, {workers} threads', flush=True)

    total = done = errors = copied = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_retriage_one_operator_csv, csv): csv for csv in canonical}
        for future in as_completed(futures):
            done += 1
            csv_path = futures[future]
            basename, ok, err = future.result()
            if ok:
                total += 1
                for dup in dupes_map.get(csv_path, []):
                    try:
                        import shutil
                        shutil.copy2(csv_path, dup)
                        copied += 1
                    except Exception:
                        pass
            if err:
                errors += 1
                print(f'  ERROR {basename}: {err}', flush=True)
            if done % 20 == 0 or done == len(canonical):
                print(f'  [{done}/{len(canonical)}] ({100*done//len(canonical)}%) updated={total} errors={errors} copied={copied}', flush=True)
    return total + copied

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Offline retriage — zero network calls')
    parser.add_argument('--workers', type=int, default=10, help='Parallel workers (default: 10)')
    parser.add_argument('--ocp-only', action='store_true', help='Skip operators')
    parser.add_argument('--operators-only', action='store_true', help='Skip OCP')
    parser.add_argument('--version', help='OCP version(s), comma-separated (e.g., 4.22.0,4.22.1)')
    args = parser.parse_args()

    t0 = time.time()

    if not args.operators_only:
        if args.version:
            manifests = [f'{v.strip()}.txt' for v in args.version.split(',') if v.strip()]
        else:
            manifests = sorted(glob.glob('4.*.txt'), key=lambda f: tuple(int(x) for x in re.findall(r'\d+', f)))

        print(f'=== Offline retriage: {len(manifests)} OCP versions, {args.workers} workers ===', flush=True)

        done = 0
        with ProcessPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(retriage_ocp, txt): txt for txt in manifests}
            for future in as_completed(futures):
                done += 1
                txt = futures[future]
                try:
                    ver, ok, skip, nf = future.result()
                    pct = int(100 * done / len(manifests))
                    print(f'  [{done}/{len(manifests)}] ({pct}%) {ver}: {ok} images, {skip} skipped, {nf} findings', flush=True)
                except Exception as e:
                    print(f'  [{done}/{len(manifests)}] ERROR {txt}: {e}', flush=True)

        print(f'  OCP done in {time.time() - t0:.0f}s', flush=True)

    if not args.ocp_only:
        print(f'\n=== Retriaging operators ===', flush=True)
        op_t0 = time.time()
        minor_vers = None
        if args.version:
            minor_vers = {'.'.join(v.strip().split('.')[:2]) for v in args.version.split(',') if v.strip()}
        op_count = retriage_operators(workers=args.workers, minor_versions=minor_vers)
        print(f'  {op_count} operator reports updated in {time.time() - op_t0:.0f}s', flush=True)

    # Rebuild parquets
    print(f'\n=== Rebuilding parquets ===', flush=True)
    import subprocess
    subprocess.run([sys.executable, 'build_parquet.py'], check=False)

    total = time.time() - t0
    print(f'\nDone: {total:.0f}s ({total/60:.1f} min)', flush=True)
