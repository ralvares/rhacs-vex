#!/usr/bin/env python3
"""
build_parquet.py — Combine all CSV triage reports into a single compressed Parquet file.

Usage:
    python3 build_parquet.py

Output:
    data/ocp.parquet  (ZSTD level 22, dictionary encoded)
"""

import os
import glob
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "data", "reports")
OUTPUT = os.path.join(os.path.dirname(__file__), "data", "ocp.parquet")


def load_csvs(reports_dir):
    pattern = os.path.join(reports_dir, "**", "*.csv")
    files = sorted(glob.glob(pattern, recursive=True))
    if not files:
        raise FileNotFoundError(f"No CSV files found under {reports_dir}")

    frames = []
    skipped = 0
    for filepath in files:
        try:
            df = pd.read_csv(filepath, dtype=str)
            df["source_file"] = os.path.relpath(filepath, os.path.dirname(OUTPUT))
            frames.append(df)
        except Exception as e:
            print(f"  SKIP {os.path.basename(filepath)}: {e}")
            skipped += 1

    print(f"Loaded {len(frames)} files ({skipped} skipped)")
    combined = pd.concat(frames, ignore_index=True)
    combined.columns = [c.strip() for c in combined.columns]
    for col in combined.select_dtypes(include="str").columns:
        combined[col] = combined[col].str.strip()
    return combined


def write_parquet(df, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    table = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_table(
        table,
        output_path,
        compression="zstd",
        compression_level=22,
        use_dictionary=True,
        write_statistics=True,
    )
    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"Written : {output_path}")
    print(f"Rows    : {len(df):,}")
    print(f"Columns : {list(df.columns)}")
    print(f"Size    : {size_mb:.2f} MB")


if __name__ == "__main__":
    df = load_csvs(REPORTS_DIR)
    write_parquet(df, OUTPUT)
