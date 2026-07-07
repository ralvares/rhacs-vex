#!/usr/bin/env python3
"""
migrate_operator_reports.py — One-time migration from per-OCP-version operator
report directories to a single flat directory.

Before:
    data/reports/ocp-{minor}/{operator}-{channel}-{bundle}.csv   (duplicated per OCP minor)

After:
    data/reports/operators/{operator}-{channel}-{bundle}.csv     (one file per unique bundle)
    data/reports/operators_index.json = {report_basename: ["4.20","4.21", ...]}

The same operator bundle is served by multiple OCP minors, so the per-version
layout stored the identical CSV up to 3× on disk.  This script keeps the NEWEST
copy of each unique basename, records which OCP minors referenced it into
operators_index.json (the ONLY place the version association now lives), removes
the duplicate copies, and deletes the now-empty per-version directories.

Idempotent: safe to re-run.  Merges into an existing operators_index.json.
"""

import glob
import json
import os
import shutil

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")
FLAT_DIR    = os.path.join(REPORTS_DIR, "operators")
INDEX_PATH  = os.path.join(REPORTS_DIR, "operators_index.json")


def _load_index() -> dict:
    if os.path.exists(INDEX_PATH):
        try:
            with open(INDEX_PATH) as f:
                data = json.load(f)
            # Normalise every value to a set for union-merging.
            return {k: set(v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def _save_index(index: dict) -> None:
    serialisable = {k: sorted(v) for k, v in sorted(index.items())}
    with open(INDEX_PATH, "w") as f:
        json.dump(serialisable, f, indent=2)


def main() -> None:
    # Discover per-version operator directories: data/reports/ocp-*/ (dirs only).
    # The suffix after "ocp-" is treated as an opaque OCP-minor tag.
    op_dirs = sorted(
        d for d in glob.glob(os.path.join(REPORTS_DIR, "ocp-*"))
        if os.path.isdir(d)
    )
    if not op_dirs:
        print("No per-version operator directories (data/reports/ocp-*/) found — nothing to migrate.")
        return

    # base -> list of (mtime, minor, path)
    copies: dict[str, list] = {}
    for d in op_dirs:
        minor = os.path.basename(d).replace("ocp-", "", 1)
        for path in glob.glob(os.path.join(d, "*.csv")):
            base = os.path.splitext(os.path.basename(path))[0]
            copies.setdefault(base, []).append((os.path.getmtime(path), minor, path))

    total_csvs = sum(len(v) for v in copies.values())
    unique     = len(copies)
    print(f"Found {total_csvs} operator CSVs across {len(op_dirs)} version dir(s): "
          f"{unique} unique bundles, {total_csvs - unique} duplicate copies.")

    os.makedirs(FLAT_DIR, exist_ok=True)
    index = _load_index()

    moved = 0
    dup_removed = 0
    bytes_reclaimed = 0

    for base, entries in copies.items():
        # Candidate copies for this bundle, newest first.  Include an existing
        # flat file (from a prior partial run) as a candidate so re-runs keep
        # the genuinely newest content.
        candidates = list(entries)
        flat_target = os.path.join(FLAT_DIR, f"{base}.csv")
        if os.path.exists(flat_target):
            candidates.append((os.path.getmtime(flat_target), None, flat_target))

        candidates.sort(key=lambda t: t[0], reverse=True)
        newest_path = candidates[0][2]

        # Move / keep the newest copy at the flat location.
        if newest_path != flat_target:
            shutil.move(newest_path, flat_target)
            moved += 1

        # Remove every remaining per-version copy (duplicates).
        for _, minor, path in entries:
            if path == newest_path:
                continue
            if os.path.exists(path):
                bytes_reclaimed += os.path.getsize(path)
                os.remove(path)
                dup_removed += 1

        # Record all source minors for this bundle (union-merge).
        minors = {minor for _, minor, _ in entries}
        index.setdefault(base, set()).update(minors)

    _save_index(index)

    # Delete the now-empty per-version directories (directories only).
    dirs_removed = 0
    for d in op_dirs:
        remaining = os.listdir(d)
        if not remaining:
            os.rmdir(d)
            dirs_removed += 1
        else:
            print(f"  WARN: {d} not empty ({len(remaining)} item(s) left) — leaving in place.")

    gb = bytes_reclaimed / (1024 ** 3)
    print("\n=== Migration summary ===")
    print(f"  Unique bundles migrated to flat dir : {unique}")
    print(f"  Newest copies moved                 : {moved}")
    print(f"  Duplicate copies removed            : {dup_removed}")
    print(f"  Per-version directories removed     : {dirs_removed}")
    print(f"  Disk space reclaimed                : {gb:.2f} GB ({bytes_reclaimed:,} bytes)")
    print(f"  operators_index.json entries        : {len(index)} → {INDEX_PATH}")
    total_refs = sum(len(v) for v in index.values())
    print(f"  Total (bundle, minor) references    : {total_refs}")


if __name__ == "__main__":
    main()
