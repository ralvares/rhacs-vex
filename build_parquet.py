#!/usr/bin/env python3
"""
build_parquet.py — Build per-version parquet files + manifest + CVE index.

Usage:
    python3 build_parquet.py                      # all CSVs → per-version parquets
    python3 build_parquet.py --version 4.21.15    # single version only
    python3 build_parquet.py --manifest-only       # regenerate manifest.json from existing parquets
    python3 build_parquet.py --legacy              # also build combined data/ocp.parquet (backwards compat)

Output:
    data/parquet/ocp/<version>.parquet   — one per OCP release
    data/parquet/cve-index.parquet       — lightweight CVE × version index
    data/manifest.json                   — summary stats per scope
    data/ocp.parquet                     — (legacy, only with --legacy)
"""

import argparse
import glob
import json
import os
import re
import sys
import time

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")
PARQUET_DIR = os.path.join(BASE_DIR, "data", "parquet")
OCP_DIR     = os.path.join(PARQUET_DIR, "ocp")
OPS_DIR     = os.path.join(PARQUET_DIR, "operators")
MANIFEST    = os.path.join(BASE_DIR, "data", "manifest.json")
CVE_INDEX   = os.path.join(PARQUET_DIR, "cve-index.parquet")
LEGACY_OUT  = os.path.join(BASE_DIR, "data", "ocp.parquet")

COMPRESSION      = "zstd"
COMPRESSION_LEVEL = 22


def load_csv(filepath):
    try:
        df = pd.read_csv(filepath, dtype=str)
        df.columns = [c.strip() for c in df.columns]
        for col in df.select_dtypes(include=["object", "str"]).columns:
            df[col] = df[col].str.strip()
        if "SEVERITY_MISMATCH" in df.columns:
            df["SEVERITY_MISMATCH"] = df["SEVERITY_MISMATCH"].map(
                {"True": True, "False": False}
            ).astype("boolean")
        return df
    except Exception as e:
        print(f"  SKIP {os.path.basename(filepath)}: {e}")
        return None


def extract_version(filepath):
    """Extract OCP version from filename: ocp-4.21.15.csv → 4.21.15"""
    base = os.path.basename(filepath)
    m = re.match(r"ocp-([\d.]+)\.csv$", base)
    return m.group(1) if m else None


def build_one_version(csv_path, version):
    """Build a single per-version parquet. Returns (version, stats_dict) or None."""
    df = load_csv(csv_path)
    if df is None or df.empty:
        return None

    df["OCP_VERSION"] = version
    df["SCOPE"]       = f"ocp/{version}"
    df["source_file"] = f"reports/ocp-{version}.csv"

    out_path = os.path.join(OCP_DIR, f"{version}.parquet")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    table = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_table(table, out_path,
                    compression=COMPRESSION,
                    compression_level=COMPRESSION_LEVEL,
                    use_dictionary=True,
                    write_statistics=True)

    size_kb = os.path.getsize(out_path) / 1024

    pos_mask = df["AUDIT_RESULT"].str.contains("POSITIVE", na=False) & \
               ~df["AUDIT_RESULT"].str.contains("FALSE", na=False)
    fp_mask  = df["AUDIT_RESULT"].str.contains("FALSE", na=False)

    pos_df = df[pos_mask]
    pos_cves = int(pos_df["CVE"].nunique()) if len(pos_df) else 0
    fp_cves  = int(df[fp_mask]["CVE"].nunique()) if fp_mask.any() else 0

    # Severity: unique CVEs per severity (positives only)
    sev = {}
    if "SEVERITY" in pos_df.columns and len(pos_df):
        sev = pos_df.drop_duplicates("CVE")["SEVERITY"].value_counts().to_dict()

    components = int(df["OCP_COMPONENT"].nunique()) if "OCP_COMPONENT" in df.columns else 0

    stats = {
        "file": f"data/parquet/ocp/{version}.parquet",
        "rows": len(df),
        "findings_positive": int(pos_mask.sum()),
        "findings_fp": int(fp_mask.sum()),
        "positive": pos_cves,
        "false_positive": fp_cves,
        "components": components,
        "severity": {k: int(v) for k, v in sev.items()},
        "size_kb": round(size_kb, 1),
    }
    return version, stats


def build_operators(ocp_version_dir):
    """Build per-operator parquets from CSVs in data/reports/ocp-{ver}/."""
    scopes = {}
    ocp_ver = os.path.basename(ocp_version_dir).replace("ocp-", "")

    csvs = sorted(glob.glob(os.path.join(ocp_version_dir, "*.csv")))
    if not csvs:
        return scopes

    # Build operator name lookup from catalog if available
    minor = '.'.join(ocp_ver.split('.')[:2])
    catalog_path = os.path.join(BASE_DIR, "data", "catalogs", f"catalog-{minor}.json")
    known_operators = set()
    if os.path.exists(catalog_path):
        try:
            buf, depth = '', 0
            with open(catalog_path) as cf:
                for line in cf:
                    buf += line
                    depth += line.count('{') - line.count('}')
                    if depth == 0 and buf.strip():
                        try:
                            obj = json.loads(buf)
                            if obj.get('schema') == 'olm.package':
                                known_operators.add(obj['name'])
                        except Exception:
                            pass
                        buf = ''
        except Exception:
            pass

    for csv_path in csvs:
        base = os.path.splitext(os.path.basename(csv_path))[0]
        df = load_csv(csv_path)
        if df is None or df.empty:
            continue

        df["OCP_VERSION"] = ocp_ver
        scope_key = f"operators/{ocp_ver}/{base}"
        df["SCOPE"] = scope_key
        df["source_file"] = os.path.relpath(csv_path, BASE_DIR)
        # Ensure consistent columns with OCP parquets
        if "OCP_COMPONENT" not in df.columns:
            df["OCP_COMPONENT"] = df.get("IMAGE_ROLE", "")
        for col in ("SOURCE", "LOCATION", "IMAGE", "FIXED_IN"):
            if col not in df.columns:
                df[col] = ""

        out_dir = os.path.join(OPS_DIR, ocp_ver)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{base}.parquet")

        table = pa.Table.from_pandas(df, preserve_index=False)
        pq.write_table(table, out_path,
                        compression=COMPRESSION,
                        compression_level=COMPRESSION_LEVEL,
                        use_dictionary=True,
                        write_statistics=True)

        size_kb = os.path.getsize(out_path) / 1024
        pos_mask = df["AUDIT_RESULT"].str.contains("POSITIVE", na=False) & \
                   ~df["AUDIT_RESULT"].str.contains("FALSE", na=False)
        fp_mask  = df["AUDIT_RESULT"].str.contains("FALSE", na=False)
        pos_df   = df[pos_mask]
        pos_cves = int(pos_df["CVE"].nunique()) if len(pos_df) else 0
        fp_cves  = int(df[fp_mask]["CVE"].nunique()) if fp_mask.any() else 0
        sev = pos_df.drop_duplicates("CVE")["SEVERITY"].value_counts().to_dict() if len(pos_df) and "SEVERITY" in pos_df.columns else {}

        # Parse {operator}-{channel}-{version} from filename using catalog lookup
        op_name = base
        op_channel = ""
        op_bundle = ""
        for known in sorted(known_operators, key=len, reverse=True):
            if base.startswith(known + "-"):
                op_name = known
                rest = base[len(known) + 1:]
                # rest = "gitops-1.20-v1.20.4" → channel "gitops-1.20", bundle "v1.20.4"
                # Find last -v segment as bundle version
                v_match = re.search(r'-v(\d[\d._-]*)$', rest)
                if v_match:
                    op_bundle = "v" + v_match.group(1)
                    op_channel = rest[:v_match.start()]
                else:
                    op_channel = rest
                break

        scopes[scope_key] = {
            "file": os.path.relpath(out_path, BASE_DIR),
            "label": base,
            "operator": op_name,
            "channel": op_channel,
            "bundle": op_bundle,
            "ocp_version": ocp_ver,
            "type": "operator",
            "rows": len(df),
            "findings_positive": int(pos_mask.sum()),
            "findings_fp": int(fp_mask.sum()),
            "positive": pos_cves,
            "false_positive": fp_cves,
            "severity": {k: int(v) for k, v in sev.items()},
            "size_kb": round(size_kb, 1),
        }

    return scopes


def _version_sort_key(ver):
    """Sort key for OCP versions: 4.21.3 → (4, 21, 3)."""
    return tuple(int(x) for x in ver.split('.') if x.isdigit())


def enrich_fixed_in():
    """Add FIXED_IN column to each OCP parquet — shows first later version where CVE is resolved."""
    parquets = sorted(glob.glob(os.path.join(OCP_DIR, "*.parquet")))
    if len(parquets) < 2:
        return

    print("\n=== Enriching FIXED_IN across OCP versions ===")

    # Load all versions into a lookup: {(CVE, COMPONENT, OCP_COMPONENT): set of versions where POSITIVE}
    positive_by_ver = {}  # version → set of (CVE, COMPONENT)
    versions = []

    for pf in parquets:
        ver = os.path.splitext(os.path.basename(pf))[0]
        versions.append(ver)
        try:
            df = pd.read_parquet(pf, columns=["CVE", "COMPONENT", "OCP_COMPONENT", "AUDIT_RESULT"])
            pos = df[df["AUDIT_RESULT"].str.contains("POSITIVE", na=False) &
                      ~df["AUDIT_RESULT"].str.contains("FALSE", na=False)]
            positive_by_ver[ver] = set(zip(pos["CVE"], pos["COMPONENT"],
                                           pos["OCP_COMPONENT"].fillna("")))
        except Exception as e:
            print(f"  SKIP {ver}: {e}")

    versions.sort(key=_version_sort_key)

    # For each version, for each POSITIVE finding, find the first later version
    # where that (CVE, COMPONENT, OCP_COMPONENT) is no longer POSITIVE
    enriched = 0
    for pf in parquets:
        ver = os.path.splitext(os.path.basename(pf))[0]
        try:
            df = pd.read_parquet(pf)
        except Exception:
            continue

        ver_idx = versions.index(ver) if ver in versions else -1
        later_versions = versions[ver_idx + 1:] if ver_idx >= 0 else []

        fixed_in = []
        for _, row in df.iterrows():
            is_pos = "POSITIVE" in str(row.get("AUDIT_RESULT", "")) and \
                     "FALSE" not in str(row.get("AUDIT_RESULT", ""))
            if not is_pos or not later_versions:
                fixed_in.append("")
                continue

            key = (row["CVE"], row["COMPONENT"],
                   str(row.get("OCP_COMPONENT", "") or ""))
            found = ""
            for lv in later_versions:
                if key not in positive_by_ver.get(lv, set()):
                    found = lv
                    break
            fixed_in.append(found)

        df["FIXED_IN"] = fixed_in
        table = pa.Table.from_pandas(df, preserve_index=False)
        pq.write_table(table, pf,
                        compression=COMPRESSION,
                        compression_level=COMPRESSION_LEVEL,
                        use_dictionary=True,
                        write_statistics=True)
        n = sum(1 for f in fixed_in if f)
        if n:
            enriched += n
            print(f"  {ver}: {n} findings have FIXED_IN")

    print(f"  Total: {enriched} findings enriched")


def enrich_operator_fixed_in():
    """Add FIXED_IN column to operator parquets — cross-version across all OCP dirs."""
    op_dirs = sorted(glob.glob(os.path.join(OPS_DIR, "*")))
    op_dirs = [d for d in op_dirs if os.path.isdir(d)]
    if not op_dirs:
        return

    print("\n=== Enriching FIXED_IN across operator versions ===")

    # Load manifest for operator name grouping
    manifest_data = {}
    if os.path.exists(MANIFEST):
        try:
            with open(MANIFEST) as f:
                manifest_data = json.load(f).get("scopes", {})
        except Exception:
            pass

    # Collect ALL operator parquets across ALL OCP version dirs, group by operator name
    op_groups = {}  # operator_name → [(sort_key, label, parquet_path)]
    for op_dir in op_dirs:
        ocp_ver = os.path.basename(op_dir)
        for pf in sorted(glob.glob(os.path.join(op_dir, "*.parquet"))):
            base = os.path.splitext(os.path.basename(pf))[0]
            scope_key = f"operators/{ocp_ver}/{base}"
            entry = manifest_data.get(scope_key, {})
            op_name = entry.get("operator", base)
            channel = entry.get("channel", "")
            # Sort key: OCP version + channel for cross-version ordering
            sort_key = f"{ocp_ver}-{channel}"
            label = f"{op_name} {ocp_ver}/{channel}" if channel else f"{op_name} {ocp_ver}"
            op_groups.setdefault(op_name, []).append((sort_key, label, base, pf))

    total_enriched = 0
    for op_name, versions in op_groups.items():
        if len(versions) < 2:
            continue

        versions.sort(key=lambda x: x[0])

        # Build positive sets per version
        positive_by_ver = {}
        for sort_key, label, base, pf in versions:
            try:
                df = pd.read_parquet(pf, columns=["CVE", "COMPONENT", "AUDIT_RESULT"])
                pos = df[df["AUDIT_RESULT"].str.contains("POSITIVE", na=False) &
                          ~df["AUDIT_RESULT"].str.contains("FALSE", na=False)]
                positive_by_ver[base] = set(zip(pos["CVE"], pos["COMPONENT"]))
            except Exception:
                pass

        for idx, (sort_key, label, base, pf) in enumerate(versions):
            later = versions[idx + 1:]
            if not later:
                continue
            try:
                df = pd.read_parquet(pf)
            except Exception:
                continue

            fixed_in = []
            for _, row in df.iterrows():
                is_pos = "POSITIVE" in str(row.get("AUDIT_RESULT", "")) and \
                         "FALSE" not in str(row.get("AUDIT_RESULT", ""))
                if not is_pos:
                    fixed_in.append("")
                    continue
                key = (row["CVE"], row["COMPONENT"])
                found = ""
                for l_sk, l_label, l_base, l_pf in later:
                    if key not in positive_by_ver.get(l_base, set()):
                        found = l_label
                        break
                fixed_in.append(found)

            df["FIXED_IN"] = fixed_in
            table = pa.Table.from_pandas(df, preserve_index=False)
            pq.write_table(table, pf,
                            compression=COMPRESSION,
                            compression_level=COMPRESSION_LEVEL,
                            use_dictionary=True,
                            write_statistics=True)
            n = sum(1 for f in fixed_in if f)
            if n:
                total_enriched += n
                print(f"  {label}: {n} findings")

    if total_enriched:
        print(f"  Total: {total_enriched} operator findings enriched")


def build_cve_index():
    """Build lightweight CVE index from all per-version parquets."""
    parquets = sorted(glob.glob(os.path.join(OCP_DIR, "*.parquet")))
    if not parquets:
        print("  No parquets found for CVE index")
        return

    frames = []
    for pf in parquets:
        try:
            df = pd.read_parquet(pf, columns=["CVE", "OCP_VERSION", "SEVERITY",
                                               "AUDIT_RESULT", "OCP_COMPONENT", "COMPONENT"])
            frames.append(df)
        except Exception as e:
            print(f"  SKIP {os.path.basename(pf)} for index: {e}")

    if not frames:
        return

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.drop_duplicates()

    table = pa.Table.from_pandas(combined, preserve_index=False)
    pq.write_table(table, CVE_INDEX,
                    compression=COMPRESSION,
                    compression_level=COMPRESSION_LEVEL,
                    use_dictionary=True,
                    write_statistics=True)

    size_kb = os.path.getsize(CVE_INDEX) / 1024
    print(f"  CVE index: {len(combined):,} rows, {size_kb:.0f} KB")


def build_manifest(scopes):
    """Write manifest.json with summary stats per scope."""
    existing = {}
    if os.path.exists(MANIFEST):
        try:
            with open(MANIFEST) as f:
                existing = json.load(f).get("scopes", {})
        except Exception:
            pass

    existing.update(scopes)

    manifest = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scopes": dict(sorted(existing.items(), key=lambda x: x[0]))
    }

    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    with open(MANIFEST, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"  Manifest: {len(manifest['scopes'])} scopes → {MANIFEST}")


def build_legacy(scopes):
    """Build combined data/ocp.parquet for backwards compatibility."""
    parquets = sorted(glob.glob(os.path.join(OCP_DIR, "*.parquet")))
    if not parquets:
        return

    frames = []
    for pf in parquets:
        try:
            frames.append(pd.read_parquet(pf))
        except Exception as e:
            print(f"  SKIP {os.path.basename(pf)} for legacy: {e}")

    if not frames:
        return

    combined = pd.concat(frames, ignore_index=True)
    table = pa.Table.from_pandas(combined, preserve_index=False)
    pq.write_table(table, LEGACY_OUT,
                    compression=COMPRESSION,
                    compression_level=COMPRESSION_LEVEL,
                    use_dictionary=True,
                    write_statistics=True)

    size_mb = os.path.getsize(LEGACY_OUT) / 1024 / 1024
    print(f"  Legacy: {len(combined):,} rows, {size_mb:.1f} MB → {LEGACY_OUT}")


def main():
    parser = argparse.ArgumentParser(description="Build per-version parquet files")
    parser.add_argument("--version", help="Build only this OCP version (e.g., 4.21.15)")
    parser.add_argument("--manifest-only", action="store_true",
                        help="Only regenerate manifest.json from existing parquets")
    parser.add_argument("--legacy", action="store_true",
                        help="Also build combined data/ocp.parquet")
    args = parser.parse_args()

    t0 = time.time()

    if args.manifest_only:
        print("=== Manifest-only mode ===")
        scopes = {}
        for pf in sorted(glob.glob(os.path.join(OCP_DIR, "*.parquet"))):
            ver = os.path.splitext(os.path.basename(pf))[0]
            try:
                df = pd.read_parquet(pf)
                pos_mask = df["AUDIT_RESULT"].str.contains("POSITIVE", na=False) & \
                           ~df["AUDIT_RESULT"].str.contains("FALSE", na=False)
                fp_mask  = df["AUDIT_RESULT"].str.contains("FALSE", na=False)
                pos_df   = df[pos_mask]
                positive = int(pos_df["CVE"].nunique()) if len(pos_df) else 0
                false_positive = int(df[fp_mask]["CVE"].nunique()) if fp_mask.any() else 0
                sev = pos_df.drop_duplicates("CVE")["SEVERITY"].value_counts().to_dict() if len(pos_df) and "SEVERITY" in pos_df.columns else {}
                components = int(df["OCP_COMPONENT"].nunique()) if "OCP_COMPONENT" in df.columns else 0
                scopes[f"ocp/{ver}"] = {
                    "file": f"data/parquet/ocp/{ver}.parquet",
                    "rows": len(df),
                    "positive": int(positive),
                    "false_positive": int(false_positive),
                    "components": components,
                    "images": images,
                    "severity": {k: int(v) for k, v in sev.items()},
                    "size_kb": round(os.path.getsize(pf) / 1024, 1),
                }
                print(f"  ✅ ocp/{ver}: {len(df):,} rows")
            except Exception as e:
                print(f"  SKIP {ver}: {e}")
        build_manifest(scopes)
        print(f"\nDone in {time.time() - t0:.1f}s")
        return

    if args.version:
        print(f"=== Single version: {args.version} ===")
        csv_path = os.path.join(REPORTS_DIR, f"ocp-{args.version}.csv")
        if not os.path.exists(csv_path):
            print(f"ERROR: {csv_path} not found")
            sys.exit(1)
        result = build_one_version(csv_path, args.version)
        if result:
            ver, stats = result
            print(f"  ✅ ocp/{ver}: {stats['rows']:,} rows, "
                  f"{stats['positive']} positive, {stats['false_positive']} FP "
                  f"({stats['size_kb']:.0f} KB)")
            build_manifest({f"ocp/{ver}": stats})
            build_cve_index()
        else:
            print(f"  ERROR: failed to build {args.version}")
            sys.exit(1)
    else:
        print("=== Building all OCP versions ===")
        csvs = sorted(glob.glob(os.path.join(REPORTS_DIR, "ocp-*.csv")))
        if not csvs:
            print(f"ERROR: No ocp-*.csv files in {REPORTS_DIR}")
            sys.exit(1)

        scopes = {}
        for i, csv_path in enumerate(csvs, 1):
            ver = extract_version(csv_path)
            if not ver:
                print(f"  SKIP {csv_path}: can't extract version")
                continue
            result = build_one_version(csv_path, ver)
            if result:
                v, stats = result
                scopes[f"ocp/{v}"] = stats
                pct = int(100 * i / len(csvs))
                print(f"  [{i}/{len(csvs)}] ({pct}%) ocp/{v}: {stats['rows']:,} rows, "
                      f"{stats['positive']} pos, {stats['false_positive']} FP "
                      f"({stats['size_kb']:.0f} KB)")

        # Enrich OCP parquets with FIXED_IN — cross-version lookup
        enrich_fixed_in()

        # Build operator parquets from subdirectories
        op_dirs = sorted(glob.glob(os.path.join(REPORTS_DIR, "ocp-*")))
        op_dirs = [d for d in op_dirs if os.path.isdir(d)]
        if op_dirs:
            print(f"\n=== Building operator parquets ({len(op_dirs)} OCP versions) ===")
            op_count = 0
            for d in op_dirs:
                op_scopes = build_operators(d)
                scopes.update(op_scopes)
                op_count += len(op_scopes)
                if op_scopes:
                    ocp_v = os.path.basename(d).replace("ocp-", "")
                    print(f"  ocp-{ocp_v}: {len(op_scopes)} operators")
            print(f"  Total: {op_count} operator parquets")

        enrich_operator_fixed_in()

        build_manifest(scopes)
        build_cve_index()

        if args.legacy:
            print("\n=== Building legacy combined parquet ===")
            build_legacy(scopes)

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
