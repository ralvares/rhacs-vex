#!/usr/bin/env python3
"""Retriage existing parquet files with updated VEX audit logic.

Only re-audits rows with known-bad justification patterns (Tracked in: /
CVE tracked in other products). Skips clean rows entirely.
Uses multiprocessing for parallelism across files.
"""
import pandas as pd
import os
import sys
import glob
import time
import multiprocessing

TRIAGE_COLS = ['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY']
BAD_PATTERN = r'Tracked in:|CVE tracked in other products|Under investigation by Red Hat|Treat as vulnerable|treat as vulnerable|until resolved|until cleared|no vendor assessment exists|Per Red Hat errata policy|Red Hat Product Security states|Confirmed affected in|Red Hat will not fix this CVE|component known not affected \(vulnerable'


def retriage_file(filepath):
    import triage as t
    df = pd.read_parquet(filepath)
    if df.empty:
        return filepath, 0, 0, 0

    mask = df['JUSTIFICATION'].str.contains(BAD_PATTERN, na=False, regex=True)
    n_dirty = int(mask.sum())
    if n_dirty == 0:
        return filepath, len(df), 0, 0

    ctx_cache = {}
    def get_ctx(img):
        if img not in ctx_cache:
            ctx_cache[img] = t.parse_image_ref(img)
        return ctx_cache[img]

    old_results = df.loc[mask, 'AUDIT_RESULT'].copy()

    new_cols = df.loc[mask].apply(
        lambda row: t.audit_row_detailed(row, get_ctx(row['IMAGE'])),
        axis=1, result_type='expand')
    new_cols.columns = TRIAGE_COLS
    df.loc[mask, TRIAGE_COLS] = new_cols.values

    df.loc[mask, 'VEX_PRODUCT'] = df.loc[mask].apply(
        lambda row: t._vex_product_for_row(row, get_ctx(row['IMAGE'])), axis=1)
    df.loc[mask, 'SEVERITY_MISMATCH'] = (
        (df.loc[mask, 'RHACS_SEVERITY'] != 'Unknown') &
        (df.loc[mask, 'SEVERITY'] != df.loc[mask, 'RHACS_SEVERITY']))

    changed = int((df.loc[mask, 'AUDIT_RESULT'] != old_results).sum())
    df.to_parquet(filepath, index=False)
    return filepath, len(df), n_dirty, changed


def main():
    dirs = sys.argv[1:] or ['data/parquet/ocp', 'data/parquet/operators/4.21', 'data/parquet/operators/4.20']
    workers = max(1, multiprocessing.cpu_count() - 2)

    dirty_files = []
    for d in dirs:
        for f in sorted(glob.glob(os.path.join(d, "*.parquet"))):
            j = pd.read_parquet(f, columns=['JUSTIFICATION'])
            if j['JUSTIFICATION'].str.contains(BAD_PATTERN, na=False, regex=True).any():
                dirty_files.append(f)

    print(f"Files to fix: {len(dirty_files)}, Workers: {workers}", flush=True)
    if not dirty_files:
        print("Nothing to fix.")
        return

    t0 = time.time()
    total_rows = 0
    total_dirty_rows = 0
    total_changed = 0
    done = 0

    with multiprocessing.Pool(workers) as pool:
        for filepath, rows, n_dirty, changed in pool.imap_unordered(retriage_file, dirty_files):
            done += 1
            total_rows += rows
            total_dirty_rows += n_dirty
            total_changed += changed
            if done % 50 == 0 or done == len(dirty_files):
                elapsed = time.time() - t0
                rate = done / elapsed if elapsed > 0 else 1
                eta = (len(dirty_files) - done) / rate
                print(f"  [{done}/{len(dirty_files)}] {elapsed:.0f}s ~{eta:.0f}s | "
                      f"{total_dirty_rows} rows re-audited, {total_changed} changed",
                      flush=True)

    elapsed = time.time() - t0
    print(f"\nDone: {len(dirty_files)} files, {total_dirty_rows}/{total_rows} rows re-audited, "
          f"{total_changed} verdicts changed in {elapsed:.0f}s")


if __name__ == '__main__':
    multiprocessing.set_start_method('fork')
    main()
