#!/usr/bin/env python3
"""
parquet.py — Build per-version parquet files + manifest + CVE index.

Usage (run from the repository root):
    python3 -m rhacs_vex.parquet                   # all CSVs → per-version parquets
    python3 -m rhacs_vex.parquet --version 4.21.15 # single version only
    python3 -m rhacs_vex.parquet --manifest-only   # regenerate manifest.json from existing parquets
    python3 -m rhacs_vex.parquet --legacy          # also build combined data/ocp.parquet (backwards compat)

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
import shutil
import sys
import time

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# Data lives under ./data relative to the current working directory: run all
# tools from the repository root (the `data/` paths are cwd-relative, and the
# relative paths stored in manifest.json must resolve for the static UI).
BASE_DIR    = os.getcwd()
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")
PARQUET_DIR = os.path.join(BASE_DIR, "data", "parquet")
OCP_DIR     = os.path.join(PARQUET_DIR, "ocp")
OPS_DIR     = os.path.join(PARQUET_DIR, "operators")
OPS_REPORTS_DIR = os.path.join(REPORTS_DIR, "operators")
OPS_INDEX       = os.path.join(REPORTS_DIR, "operators_index.json")
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


def load_operators_index():
    """Load data/reports/operators_index.json → {base: [minor, ...]}.

    This is now the ONLY place the operator-bundle → OCP-minor association
    lives (reports are stored flat, one CSV per unique bundle)."""
    if os.path.exists(OPS_INDEX):
        try:
            with open(OPS_INDEX) as f:
                return {k: list(v) for k, v in json.load(f).items()}
        except Exception as e:
            print(f"  WARN: could not read {OPS_INDEX}: {e}")
    return {}


def load_known_operators():
    """Union of olm.package names across all available catalogs, used to split
    a report basename into (operator, channel, bundle)."""
    known = set()
    for cat in glob.glob(os.path.join(BASE_DIR, "data", "catalogs", "catalog-*.json")):
        try:
            buf, depth = '', 0
            with open(cat) as cf:
                for line in cf:
                    buf += line
                    depth += line.count('{') - line.count('}')
                    if depth == 0 and buf.strip():
                        try:
                            obj = json.loads(buf)
                            if obj.get('schema') == 'olm.package':
                                known.add(obj['name'])
                        except Exception:
                            pass
                        buf = ''
        except Exception:
            pass
    return known


def parse_operator_base(base, known_operators):
    """Split a report basename into (operator, channel, bundle).

    e.g. 'openshift-gitops-operator-gitops-1.20-v1.20.4' →
         ('openshift-gitops-operator', 'gitops-1.20', 'v1.20.4')
    """
    op_name, op_channel, op_bundle = base, "", ""
    for known in sorted(known_operators, key=len, reverse=True):
        if base.startswith(known + "-"):
            op_name = known
            rest = base[len(known) + 1:]
            v_match = re.search(r'-v(\d[\d._-]*)$', rest)
            if v_match:
                op_bundle = "v" + v_match.group(1)
                op_channel = rest[:v_match.start()]
            else:
                op_channel = rest
            break
    return op_name, op_channel, op_bundle


def build_operators():
    """Build one flat parquet per unique operator bundle from
    data/reports/operators/*.csv and emit one ALIAS manifest scope per
    (OCP-minor, bundle) pair from operators_index.json.

    Every alias scope for a bundle carries the same manifest schema as before
    and its "file" points at the SAME shared flat parquet
    (data/parquet/operators/{base}.parquet), so the UI's
    operators/{minor}/{base} scope keys keep resolving unchanged while the
    bytes are stored exactly once.

    Because the parquet is shared across a bundle's minors, its baked
    OCP_VERSION/SCOPE columns use the bundle's primary (lowest) minor — enough
    for fixInfo()/navigation in the CVE-search view to resolve a valid scope.

    Returns (scopes, meta) where meta[base] = (operator, channel, bundle);
    meta feeds the FIXED_IN cross-bundle enrichment with fresh in-memory
    metadata instead of the (possibly stale) on-disk manifest.
    """
    scopes = {}
    meta = {}

    csvs = sorted(glob.glob(os.path.join(OPS_REPORTS_DIR, "*.csv")))
    if not csvs:
        return scopes, meta

    index = load_operators_index()
    known_operators = load_known_operators()
    os.makedirs(OPS_DIR, exist_ok=True)

    # Drop stale per-version parquet subdirs (data/parquet/operators/{minor}/)
    # left over from the old layout — storage is flat now.
    for sub in glob.glob(os.path.join(OPS_DIR, "*")):
        if os.path.isdir(sub):
            shutil.rmtree(sub)

    for csv_path in csvs:
        base = os.path.splitext(os.path.basename(csv_path))[0]
        df = load_csv(csv_path)
        if df is None or df.empty:
            continue

        minors = sorted(index.get(base, []))
        if not minors:
            print(f"  WARN: {base} absent from operators_index.json — "
                  f"parquet built but no scope emitted")
        primary_minor = minors[0] if minors else ""

        df["OCP_VERSION"] = primary_minor
        df["SCOPE"] = f"operators/{primary_minor}/{base}" if primary_minor else f"operators/{base}"
        df["source_file"] = os.path.relpath(csv_path, BASE_DIR)
        if "OCP_COMPONENT" not in df.columns:
            df["OCP_COMPONENT"] = df.get("IMAGE_ROLE", "")
        for col in ("SOURCE", "LOCATION", "IMAGE", "FIXED_IN"):
            if col not in df.columns:
                df[col] = ""

        out_path = os.path.join(OPS_DIR, f"{base}.parquet")
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

        op_name, op_channel, op_bundle = parse_operator_base(base, known_operators)
        meta[base] = (op_name, op_channel, op_bundle)

        rel_file = os.path.relpath(out_path, BASE_DIR)
        stats_common = {
            "file": rel_file,
            "label": base,
            "operator": op_name,
            "channel": op_channel,
            "bundle": op_bundle,
            "type": "operator",
            "rows": len(df),
            "findings_positive": int(pos_mask.sum()),
            "findings_fp": int(fp_mask.sum()),
            "positive": pos_cves,
            "false_positive": fp_cves,
            "severity": {k: int(v) for k, v in sev.items()},
            "size_kb": round(size_kb, 1),
        }

        # One alias scope per OCP minor referencing this bundle — all share the
        # same flat parquet (rel_file); only ocp_version differs.
        for minor in minors:
            entry = dict(stats_common)
            entry["ocp_version"] = minor
            entry["file"] = rel_file  # explicit: shared flat path
            scopes[f"operators/{minor}/{base}"] = entry

    return scopes, meta


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


def _bundle_sort_key(bundle):
    """Version-aware ordering key for a bundle string ('v1.20.4', 'v7.10.7-opr-1')."""
    nums = tuple(int(x) for x in re.findall(r'\d+', bundle or ''))
    return (nums, bundle or "")


def enrich_operator_fixed_in(meta):
    """Add FIXED_IN to the flat operator parquets — cross-BUNDLE within each
    operator.

    Reports are now flat (one parquet per unique bundle, OCP-version-agnostic),
    so a bundle is compared against the operator's *other* bundles ordered by
    (channel, bundle-version).  This is the faithful analog of the old
    per-OCP-dir logic: comparing a bundle against an identical copy of itself in
    another OCP dir always produced an empty FIXED_IN, so collapsing to
    per-bundle ordering preserves the meaningful behavior.

    *meta* maps base → (operator, channel, bundle) (fresh from build_operators;
    avoids depending on the possibly-stale manifest).  The FIXED_IN label keeps
    the '{operator} {x}/{channel}' shape the UI's fixInfo() parses (first token
    = operator, text after last '/' = channel).
    """
    parquets = sorted(glob.glob(os.path.join(OPS_DIR, "*.parquet")))
    if not parquets:
        return

    print("\n=== Enriching FIXED_IN across operator bundles ===")

    # Group parquets by operator name; order each operator's bundles by
    # (channel, bundle-version).
    op_groups = {}  # operator → [(sort_key, base, channel, bundle, pf)]
    for pf in parquets:
        base = os.path.splitext(os.path.basename(pf))[0]
        op_name, channel, bundle = meta.get(base, (base, "", ""))
        sort_key = (channel, _bundle_sort_key(bundle))
        op_groups.setdefault(op_name, []).append((sort_key, base, channel, bundle, pf))

    total_enriched = 0
    for op_name, bundles in op_groups.items():
        if len(bundles) < 2:
            continue

        bundles.sort(key=lambda x: x[0])

        # Positive (CVE, COMPONENT) sets per base
        positive_by_base = {}
        for _sk, base, _ch, _bn, pf in bundles:
            try:
                df = pd.read_parquet(pf, columns=["CVE", "COMPONENT", "AUDIT_RESULT"])
                pos = df[df["AUDIT_RESULT"].str.contains("POSITIVE", na=False) &
                          ~df["AUDIT_RESULT"].str.contains("FALSE", na=False)]
                positive_by_base[base] = set(zip(pos["CVE"], pos["COMPONENT"]))
            except Exception:
                pass

        for idx, (_sk, base, channel, bundle, pf) in enumerate(bundles):
            later = bundles[idx + 1:]
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
                for _l_sk, l_base, l_channel, l_bundle, _l_pf in later:
                    if key not in positive_by_base.get(l_base, set()):
                        found = (f"{op_name} {l_bundle}/{l_channel}"
                                 if l_channel else f"{op_name} {l_bundle}")
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
                label = f"{op_name} {bundle}/{channel}" if channel else f"{op_name} {bundle}"
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


def build_manifest(scopes, prune_operators=False):
    """Write manifest.json with summary stats per scope.

    Existing scopes are merged (so single-version / OCP-only builds don't drop
    unrelated scopes).  When prune_operators=True (a full operator rebuild),
    stale operators/* keys not in *scopes* are dropped first — this clears dead
    scope keys whose backing per-version parquet has been removed by the flat
    migration."""
    existing = {}
    if os.path.exists(MANIFEST):
        try:
            with open(MANIFEST) as f:
                existing = json.load(f).get("scopes", {})
        except Exception:
            pass

    if prune_operators:
        existing = {k: v for k, v in existing.items() if not k.startswith("operators/")}

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

        def _parquet_stats(pf, df):
            pos_mask = df["AUDIT_RESULT"].str.contains("POSITIVE", na=False) & \
                       ~df["AUDIT_RESULT"].str.contains("FALSE", na=False)
            fp_mask  = df["AUDIT_RESULT"].str.contains("FALSE", na=False)
            pos_df   = df[pos_mask]
            pos_cves = int(pos_df["CVE"].nunique()) if len(pos_df) else 0
            fp_cves  = int(df[fp_mask]["CVE"].nunique()) if fp_mask.any() else 0
            sev = pos_df.drop_duplicates("CVE")["SEVERITY"].value_counts().to_dict() if len(pos_df) and "SEVERITY" in pos_df.columns else {}
            components = int(df["OCP_COMPONENT"].nunique()) if "OCP_COMPONENT" in df.columns else 0
            return {
                "rows": len(df),
                "findings_positive": int(pos_mask.sum()),
                "findings_fp": int(fp_mask.sum()),
                "positive": pos_cves,
                "false_positive": fp_cves,
                "components": components,
                "severity": {k: int(v) for k, v in sev.items()},
                "size_kb": round(os.path.getsize(pf) / 1024, 1),
            }

        for pf in sorted(glob.glob(os.path.join(OCP_DIR, "*.parquet"))):
            ver = os.path.splitext(os.path.basename(pf))[0]
            try:
                df = pd.read_parquet(pf)
                stats = _parquet_stats(pf, df)
                stats["file"] = f"data/parquet/ocp/{ver}.parquet"
                scopes[f"ocp/{ver}"] = stats
                print(f"  ocp/{ver}: {len(df):,} rows")
            except Exception as e:
                print(f"  SKIP ocp/{ver}: {e}")

        existing = {}
        if os.path.exists(MANIFEST):
            try:
                with open(MANIFEST) as f:
                    existing = json.load(f).get("scopes", {})
            except Exception:
                pass

        # Flat operator parquets → alias scopes operators/{minor}/{base} from
        # operators_index.json (all aliases share the one flat parquet).
        index = load_operators_index()
        known_operators = load_known_operators()
        for pf in sorted(glob.glob(os.path.join(OPS_DIR, "*.parquet"))):
            base = os.path.splitext(os.path.basename(pf))[0]
            minors = sorted(index.get(base, []))
            try:
                df = pd.read_parquet(pf)
            except Exception as e:
                print(f"  SKIP operators/*/{base}: {e}")
                continue
            stats = _parquet_stats(pf, df)
            rel_file = os.path.relpath(pf, BASE_DIR)
            op_name, op_channel, op_bundle = parse_operator_base(base, known_operators)
            if not minors:
                print(f"  WARN operators/*/{base}: absent from operators_index.json")
            for minor in minors:
                scope_key = f"operators/{minor}/{base}"
                old = existing.get(scope_key, {})
                entry = dict(stats)
                entry["file"] = rel_file
                entry["label"] = old.get("label", base)
                entry["operator"] = old.get("operator", op_name)
                entry["channel"] = old.get("channel", op_channel)
                entry["bundle"] = old.get("bundle", op_bundle)
                entry["ocp_version"] = minor
                entry["type"] = "operator"
                scopes[scope_key] = entry
            print(f"  operators/*/{base}: {len(df):,} rows → {len(minors)} alias scope(s)")

        build_manifest(scopes, prune_operators=True)
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

        # Build one flat parquet per unique operator bundle (data/reports/
        # operators/*.csv) and emit alias scopes operators/{minor}/{base} from
        # operators_index.json, all pointing at the shared flat parquet.
        print(f"\n=== Building operator parquets (flat) ===")
        op_scopes, op_meta = build_operators()
        scopes.update(op_scopes)
        n_bundles = len({s["file"] for s in op_scopes.values()}) if op_scopes else 0
        print(f"  {n_bundles} unique bundles → {len(op_scopes)} alias scopes")

        enrich_operator_fixed_in(op_meta)

        # prune_operators=True drops dead operators/* keys carried over from the
        # old per-version layout (their per-version parquets are gone now).
        build_manifest(scopes, prune_operators=True)
        build_cve_index()

        if args.legacy:
            print("\n=== Building legacy combined parquet ===")
            build_legacy(scopes)

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
