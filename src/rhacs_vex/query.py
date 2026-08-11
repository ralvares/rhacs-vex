#!/usr/bin/env python3
"""Query OCP parquet data for CVE reports with upgrade recommendations."""

import argparse
import re
from collections import Counter, defaultdict
from packaging.version import Version

import pyarrow.compute as pc
import pyarrow.parquet as pq


PARQUET = "data/ocp.parquet"
POSITIVE = "❌ POSITIVE"
FALSE_POSITIVE = "✅ FALSE POSITIVE"
SEVERITY_ORDER = ["Critical", "Important", "Moderate", "Low", "Unknown"]


def load_table():
    return pq.read_table(PARQUET)


def parse_ocp_version(source_file):
    m = re.match(r"reports/ocp-(\d+\.\d+\.\d+)\.csv$", source_file)
    return m.group(1) if m else None


def get_available_versions(table):
    """Get all OCP platform versions (not operator catalogs)."""
    sfs = set(table.column("source_file").to_pylist())
    versions = {}
    for sf in sfs:
        v = parse_ocp_version(sf)
        if v:
            versions[v] = sf
    return versions


def get_operator_catalog_versions(table, ocp_minor):
    """Get operator catalog source files for a given OCP minor (e.g. '4.20')."""
    sfs = set(table.column("source_file").to_pylist())
    pattern = re.compile(rf"reports/ocp-{re.escape(ocp_minor)}/(.+)\.csv$")
    catalogs = {}
    for sf in sfs:
        m = pattern.match(sf)
        if m:
            catalogs[m.group(1)] = sf
    return catalogs


def filter_version(table, source_file):
    return table.filter(pc.equal(table.column("source_file"), source_file))


def cve_summary(subset):
    """Return {cve: {severity, components, audit_result, fix_ver, justification}}."""
    cves = {}
    for i in range(subset.num_rows):
        cve = subset.column("CVE")[i].as_py()
        sev = subset.column("SEVERITY")[i].as_py()
        comp = subset.column("COMPONENT")[i].as_py()
        audit = subset.column("AUDIT_RESULT")[i].as_py()
        fix = subset.column("VEX_FIX_VER")[i].as_py()
        image = subset.column("IMAGE")[i].as_py()
        if cve not in cves:
            cves[cve] = {
                "severity": sev,
                "audit_result": audit,
                "components": set(),
                "images": set(),
                "fix_ver": fix,
            }
        cves[cve]["components"].add(comp)
        cves[cve]["images"].add(image)
    return cves


def severity_table(cve_dict, label=""):
    """Print severity breakdown table."""
    by_sev = Counter(v["severity"] for v in cve_dict.values())
    total = len(cve_dict)
    if label:
        print(f"\n{'=' * 60}")
        print(f"  {label}")
        print(f"{'=' * 60}")
    print(f"\n  {'Severity':<12} {'Count':>6} {'%':>7}")
    print(f"  {'-' * 27}")
    for s in SEVERITY_ORDER:
        c = by_sev.get(s, 0)
        pct = (c / total * 100) if total else 0
        print(f"  {s:<12} {c:>6} {pct:>6.1f}%")
    print(f"  {'-' * 27}")
    print(f"  {'TOTAL':<12} {total:>6}")
    return by_sev


def audit_breakdown(subset):
    """Print audit result breakdown (row-level, not unique CVE)."""
    audits = Counter(subset.column("AUDIT_RESULT").to_pylist())
    total = subset.num_rows
    print(f"\n  Audit Result Breakdown (all findings):")
    print(f"  {'Status':<20} {'Count':>8} {'%':>7}")
    print(f"  {'-' * 37}")
    # legacy parquet rows may carry statuses beyond the current two
    for status in [POSITIVE, FALSE_POSITIVE] + sorted(set(audits) - {POSITIVE, FALSE_POSITIVE}):
        c = audits.get(status, 0)
        pct = (c / total * 100) if total else 0
        print(f"  {status:<20} {c:>8} {pct:>6.1f}%")
    print(f"  {'-' * 37}")
    print(f"  {'TOTAL':<20} {total:>8}")


def version_sort_key(v):
    parts = v.split(".")
    return tuple(int(p) for p in parts)


def upgrade_analysis(table, current_version, available_versions):
    """Compare current version against later z-streams to find best upgrade."""
    cur_parts = current_version.split(".")
    cur_minor = f"{cur_parts[0]}.{cur_parts[1]}"

    same_minor = sorted(
        [v for v in available_versions if v.startswith(cur_minor + ".")],
        key=version_sort_key,
    )

    later = [v for v in same_minor if version_sort_key(v) > version_sort_key(current_version)]
    if not later:
        print(f"\n  No later z-stream releases available in {cur_minor}.x")
        return

    cur_data = filter_version(table, available_versions[current_version])
    cur_positive = set(
        cur_data.filter(pc.equal(cur_data.column("AUDIT_RESULT"), POSITIVE))
        .column("CVE")
        .to_pylist()
    )
    cur_cves = cve_summary(
        cur_data.filter(pc.equal(cur_data.column("AUDIT_RESULT"), POSITIVE))
    )

    print(f"\n{'=' * 60}")
    print(f"  UPGRADE ANALYSIS from {current_version}")
    print(f"{'=' * 60}")
    print(f"\n  Current: {len(cur_positive)} unique POSITIVE CVEs")
    print(f"\n  {'Target':<12} {'Fixed':>6} {'New':>6} {'Net':>7} {'Remaining':>10}")
    print(f"  {'-' * 47}")

    best_target = None
    best_net = 0
    best_remaining = len(cur_positive)

    results = []
    for target_v in later:
        tgt_data = filter_version(table, available_versions[target_v])
        tgt_positive = set(
            tgt_data.filter(pc.equal(tgt_data.column("AUDIT_RESULT"), POSITIVE))
            .column("CVE")
            .to_pylist()
        )
        fixed = cur_positive - tgt_positive
        new_cves = tgt_positive - cur_positive
        remaining = len(tgt_positive)
        net = len(fixed) - len(new_cves)

        results.append((target_v, len(fixed), len(new_cves), net, remaining, fixed, new_cves))
        sign = f"-{net}" if net > 0 else f"+{abs(net)}" if net < 0 else "0"
        print(f"  {target_v:<12} {len(fixed):>6} {len(new_cves):>6} {sign:>7} {remaining:>10}")

        if remaining < best_remaining:
            best_remaining = remaining
            best_target = target_v
            best_net = net

    if best_target:
        print(f"\n  RECOMMENDATION: Upgrade to {best_target}")
        print(f"  Reduces POSITIVE CVEs from {len(cur_positive)} → {best_remaining} (net -{best_net})")

        # Show what gets fixed by severity
        for target_v, fixed_count, new_count, net, remaining, fixed_set, new_set in results:
            if target_v == best_target:
                fixed_by_sev = Counter()
                for cve in fixed_set:
                    if cve in cur_cves:
                        fixed_by_sev[cur_cves[cve]["severity"]] += 1
                print(f"\n  CVEs fixed by upgrading to {best_target}:")
                for s in SEVERITY_ORDER:
                    c = fixed_by_sev.get(s, 0)
                    if c:
                        print(f"    {s}: {c}")

                if new_set:
                    print(f"\n  ⚠ {len(new_set)} new CVEs introduced in {best_target}:")
                    # Get severity of new CVEs
                    tgt_data = filter_version(table, available_versions[best_target])
                    tgt_cves = cve_summary(
                        tgt_data.filter(pc.equal(tgt_data.column("AUDIT_RESULT"), POSITIVE))
                    )
                    new_by_sev = Counter()
                    for cve in new_set:
                        if cve in tgt_cves:
                            new_by_sev[tgt_cves[cve]["severity"]] += 1
                    for s in SEVERITY_ORDER:
                        c = new_by_sev.get(s, 0)
                        if c:
                            print(f"    {s}: {c}")

    # Check next minor version too
    next_minor_num = int(cur_parts[1]) + 1
    next_minor = f"{cur_parts[0]}.{next_minor_num}"
    next_minor_versions = sorted(
        [v for v in available_versions if v.startswith(next_minor + ".")],
        key=version_sort_key,
    )
    if next_minor_versions:
        latest_next = next_minor_versions[-1]
        tgt_data = filter_version(table, available_versions[latest_next])
        tgt_positive = set(
            tgt_data.filter(pc.equal(tgt_data.column("AUDIT_RESULT"), POSITIVE))
            .column("CVE")
            .to_pylist()
        )
        fixed = cur_positive - tgt_positive
        new_cves = tgt_positive - cur_positive
        remaining = len(tgt_positive)
        print(f"\n  Cross-minor upgrade to {latest_next}:")
        print(f"    Fixed: {len(fixed)}, New: {len(new_cves)}, Remaining: {remaining}")


def top_cves(cve_dict, n=10):
    """Show top CVEs by impact (most components affected)."""
    sorted_cves = sorted(
        cve_dict.items(),
        key=lambda x: (SEVERITY_ORDER.index(x[1]["severity"]) if x[1]["severity"] in SEVERITY_ORDER else 99, -len(x[1]["components"])),
    )
    print(f"\n  Top {min(n, len(sorted_cves))} CVEs by severity and spread:")
    print(f"  {'CVE':<20} {'Severity':<12} {'Components':>10} {'Images':>7}")
    print(f"  {'-' * 51}")
    for cve, info in sorted_cves[:n]:
        print(f"  {cve:<20} {info['severity']:<12} {len(info['components']):>10} {len(info['images']):>7}")


def component_report(subset):
    """Show most affected components."""
    pos = subset.filter(pc.equal(subset.column("AUDIT_RESULT"), POSITIVE))
    comp_cves = defaultdict(set)
    for i in range(pos.num_rows):
        comp = pos.column("OCP_COMPONENT")[i].as_py()
        cve = pos.column("CVE")[i].as_py()
        if comp:
            comp_cves[comp].add(cve)

    sorted_comps = sorted(comp_cves.items(), key=lambda x: -len(x[1]))
    print(f"\n  Top 15 affected OCP components:")
    print(f"  {'Component':<45} {'CVEs':>6}")
    print(f"  {'-' * 53}")
    for comp, cves in sorted_comps[:15]:
        print(f"  {comp:<45} {len(cves):>6}")


def list_versions(table):
    """List all available OCP versions."""
    versions = get_available_versions(table)
    by_minor = defaultdict(list)
    for v in versions:
        parts = v.split(".")
        minor = f"{parts[0]}.{parts[1]}"
        by_minor[minor].append(v)

    print("\nAvailable OCP platform versions:")
    for minor in sorted(by_minor.keys()):
        vlist = sorted(by_minor[minor], key=version_sort_key)
        print(f"  {minor}: {vlist[0]} → {vlist[-1]} ({len(vlist)} releases)")


def operator_report(table, ocp_minor, operator_name):
    """Report on a specific operator catalog."""
    catalogs = get_operator_catalog_versions(table, ocp_minor)

    if operator_name not in catalogs:
        # Fuzzy match
        matches = [k for k in catalogs if operator_name.lower() in k.lower()]
        if not matches:
            print(f"\nOperator '{operator_name}' not found in {ocp_minor}")
            print("Available operators (first 20):")
            for k in sorted(catalogs.keys())[:20]:
                print(f"  {k}")
            return
        if len(matches) > 1:
            print(f"\nMultiple matches for '{operator_name}':")
            for m in sorted(matches):
                print(f"  {m}")
            return
        operator_name = matches[0]

    sf = catalogs[operator_name]
    subset = filter_version(table, sf)
    pos_subset = subset.filter(pc.equal(subset.column("AUDIT_RESULT"), POSITIVE))
    cves = cve_summary(pos_subset)

    severity_table(cves, f"Operator: {operator_name} (OCP {ocp_minor})")
    audit_breakdown(subset)
    if cves:
        top_cves(cves)


def main():
    parser = argparse.ArgumentParser(description="OCP Vulnerability Report")
    parser.add_argument("version", nargs="?", help="OCP version (e.g. 4.20.0) or 'list'")
    parser.add_argument("--operator", "-o", help="Operator catalog name (requires OCP minor, e.g. -o rhacs-operator-rhacs-4)")
    parser.add_argument("--top", type=int, default=10, help="Number of top CVEs to show")
    parser.add_argument("--components", action="store_true", help="Show component breakdown")
    parser.add_argument("--no-upgrade", action="store_true", help="Skip upgrade analysis")
    parser.add_argument("--cve", help="Search for specific CVE across versions")

    args = parser.parse_args()
    table = load_table()

    if args.cve:
        cve_search(table, args.cve)
        return

    if not args.version or args.version == "list":
        list_versions(table)
        return

    available = get_available_versions(table)

    if args.operator:
        parts = args.version.split(".")
        ocp_minor = f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else args.version
        operator_report(table, ocp_minor, args.operator)
        return

    if args.version not in available:
        print(f"Version {args.version} not found.")
        list_versions(table)
        return

    # Main report
    subset = filter_version(table, available[args.version])
    pos_subset = subset.filter(pc.equal(subset.column("AUDIT_RESULT"), POSITIVE))
    cves = cve_summary(pos_subset)

    severity_table(cves, f"OCP {args.version} — Vulnerability Report")
    audit_breakdown(subset)
    top_cves(cves, args.top)

    if args.components:
        component_report(subset)

    if not args.no_upgrade:
        upgrade_analysis(table, args.version, available)


def parse_operator_source(source_file):
    """Parse operator catalog from source_file like reports/ocp-4.20/rhacs-operator-rhacs-4.10-v4.10.3.csv"""
    m = re.match(r"reports/ocp-(\d+\.\d+)/(.+)\.csv$", source_file)
    if m:
        return m.group(1), m.group(2)
    return None, None


def cve_search(table, cve_id):
    """Search for a specific CVE across all OCP versions and operator catalogs."""
    matches = table.filter(pc.equal(table.column("CVE"), cve_id))
    if matches.num_rows == 0:
        print(f"CVE {cve_id} not found in any version.")
        return

    print(f"\n{'=' * 60}")
    print(f"  CVE: {cve_id}")
    print(f"{'=' * 60}")

    sev = matches.column("SEVERITY")[0].as_py()
    print(f"  Severity: {sev}")

    # Group by source_file — OCP platform versions
    by_version = defaultdict(lambda: {"audit": set(), "components": set()})
    # Group by source_file — operator catalogs
    by_operator = defaultdict(lambda: {"audit": set(), "components": set(), "ocp_minor": None})

    for i in range(matches.num_rows):
        sf = matches.column("source_file")[i].as_py()
        audit = matches.column("AUDIT_RESULT")[i].as_py()
        comp = matches.column("COMPONENT")[i].as_py()

        v = parse_ocp_version(sf)
        if v:
            by_version[v]["audit"].add(audit)
            by_version[v]["components"].add(comp)
        else:
            ocp_minor, catalog = parse_operator_source(sf)
            if catalog:
                by_operator[catalog]["audit"].add(audit)
                by_operator[catalog]["components"].add(comp)
                by_operator[catalog]["ocp_minor"] = ocp_minor

    # --- OCP Platform ---
    if by_version:
        affected = []
        not_affected = []
        for v in sorted(by_version.keys(), key=version_sort_key):
            audits = by_version[v]["audit"]
            if POSITIVE in audits:
                affected.append(v)
            else:
                not_affected.append(v)

        print(f"\n  OCP Platform")
        print(f"  {'-' * 40}")
        print(f"  Affected versions ({len(affected)}):")
        for v in affected:
            print(f"    {v}")

        if not_affected:
            print(f"\n  Not affected / fixed in ({len(not_affected)}):")
            for v in not_affected:
                print(f"    {v}")

        if affected and not_affected:
            min_fix = min(not_affected, key=version_sort_key)
            print(f"\n  Earliest fix: {min_fix}")

    # --- Operators ---
    if by_operator:
        op_affected = {}
        op_not_affected = {}
        for catalog, info in sorted(by_operator.items()):
            if POSITIVE in info["audit"]:
                op_affected[catalog] = info
            else:
                op_not_affected[catalog] = info

        print(f"\n  Operator Catalogs")
        print(f"  {'-' * 40}")
        if op_affected:
            print(f"  Affected ({len(op_affected)}):")
            # Group by operator base name for readability
            by_base = defaultdict(list)
            for catalog, info in sorted(op_affected.items()):
                base = re.sub(r"-v?\d+[\.\d]*$", "", catalog)
                base = re.sub(r"-\d+[\.\d]*$", "", base)
                by_base[base].append((catalog, info))

            for base in sorted(by_base.keys()):
                entries = by_base[base]
                if len(entries) == 1:
                    cat, info = entries[0]
                    print(f"    {cat} (OCP {info['ocp_minor']})")
                else:
                    print(f"    {base}:")
                    for cat, info in entries:
                        ver_part = cat[len(base):].lstrip("-")
                        print(f"      {ver_part or cat} (OCP {info['ocp_minor']})")

        if op_not_affected:
            print(f"\n  Not affected ({len(op_not_affected)}):")
            for catalog in sorted(op_not_affected.keys())[:20]:
                info = op_not_affected[catalog]
                print(f"    {catalog} (OCP {info['ocp_minor']})")
            if len(op_not_affected) > 20:
                print(f"    ... and {len(op_not_affected) - 20} more")


if __name__ == "__main__":
    main()
