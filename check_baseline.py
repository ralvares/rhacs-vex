#!/usr/bin/env python3
"""Check audit results against baseline — reports any regressions."""
import sys, json, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
from triage import (audit_row_detailed, WorkloadContext, parse_context_from_labels,
                    rhacs_to_df, download_and_convert_with_lib)
from concurrent.futures import ThreadPoolExecutor, as_completed

with open('data/baseline.json') as f:
    baseline = json.load(f)

# Rebuild contexts and rows
with open('data/scans/registry.redhat.io_openshift4_ose-cli@sha256:4f2e216ad46aa75f84e27aa2e6303327b99a4331c7ed8ef65850102898f3a9b0.json') as f:
    scan = json.load(f)
image_ref = "registry.redhat.io/openshift4/ose-cli@sha256:4f2e216ad46aa75f84e27aa2e6303327b99a4331c7ed8ef65850102898f3a9b0"
labels = (scan.get('metadata') or {}).get('v1', {}).get('labels') or {}
ctx_cli = parse_context_from_labels(labels, image_ref)
df_cli = rhacs_to_df(scan)

# Sync VEX
cves = set(b['cve'] for b in baseline)
with ThreadPoolExecutor(max_workers=20) as ex:
    for f in as_completed({ex.submit(download_and_convert_with_lib, c): c for c in cves}): pass

results = {}

# Errata cases
row_podman = pd.Series({
    'COMPONENT': 'github.com/containers/podman/v5',
    'VERSION': 'v5.0.0-20260216113829-cfa44d05d6f6+dirty',
    'CVE': 'CVE-2025-6032', 'SEVERITY': 'IMPORTANT_VULNERABILITY_SEVERITY',
    'FIXED_VERSION': '5.5.2', 'SOURCE': 'GO', 'LOCATION': '',
})
for ver in ["4.14", "4.16", "4.18", "4.20", "4.22"]:
    ctx = WorkloadContext(workload_type="ocp", ocp_ver=ver, ocp_component="rhel-coreos-10",
                          rhel_ver="10", display_name=f"OpenShift {ver}")
    r = audit_row_detailed(row_podman, ctx)
    results[f"errata-{ver}"] = {"verdict": r.iloc[0], "fix": r.iloc[1], "severity": r.iloc[3]}

# Fast Datapath
row_ovs = pd.Series({
    'COMPONENT': 'openvswitch-selinux-extra-policy', 'VERSION': '1.0-39.el9fdp',
    'CVE': 'CVE-2026-34956', 'SEVERITY': 'MODERATE_VULNERABILITY_SEVERITY',
    'FIXED_VERSION': '', 'SOURCE': 'OS', 'LOCATION': 'var/lib/rpm',
})
ctx_ovs = WorkloadContext(workload_type="ocp", ocp_ver="4.21", ocp_component="ovnkube-node",
                           rhel_ver="9", display_name="OpenShift 4.21")
r = audit_row_detailed(row_ovs, ctx_ovs)
results["fastdatapath"] = {"verdict": r.iloc[0], "fix": r.iloc[1], "severity": r.iloc[3]}

# Gnutls
row_gnutls = pd.Series({
    'COMPONENT': 'gnutls', 'VERSION': '3.8.3-9.el9',
    'CVE': 'CVE-2026-33845', 'SEVERITY': 'IMPORTANT_VULNERABILITY_SEVERITY',
    'FIXED_VERSION': '', 'SOURCE': 'OS', 'LOCATION': 'var/lib/rpm',
})
ctx_gnutls = WorkloadContext(workload_type="ocp", ocp_ver="4.21", rhel_ver="9", display_name="OpenShift 4.21")
r = audit_row_detailed(row_gnutls, ctx_gnutls)
results["gnutls-stream"] = {"verdict": r.iloc[0], "fix": r.iloc[1], "severity": r.iloc[3]}

# ose-cli scan
for _, row in df_cli.iterrows():
    r = audit_row_detailed(row, ctx_cli)
    key = f"cli-{row['CVE']}-{row['COMPONENT'][:30]}"
    results[key] = {"verdict": r.iloc[0], "fix": r.iloc[1], "severity": r.iloc[3]}

# Compare
regressions = []
improvements = []
for b in baseline:
    rid = b['id']
    if rid not in results:
        regressions.append(f"  MISSING: {rid}")
        continue
    r = results[rid]
    changes = []
    if r['verdict'] != b['verdict']:
        changes.append(f"verdict: {b['verdict'][:20]} → {r['verdict'][:20]}")
    if r['severity'] != b['severity']:
        changes.append(f"severity: {b['severity']} → {r['severity']}")
    if changes:
        line = f"  {rid}: {', '.join(changes)}"
        # Classify: is this a regression or improvement?
        old_fp = 'FALSE' in b['verdict']
        new_fp = 'FALSE' in r['verdict']
        if old_fp and not new_fp:
            regressions.append(line + "  ← was FP, now POS!")
        else:
            improvements.append(line)

if regressions:
    print(f"REGRESSIONS ({len(regressions)}):")
    for r in regressions[:20]:
        print(r)
if improvements:
    print(f"\nCHANGES ({len(improvements)}):")
    for i in improvements[:20]:
        print(i)
if not regressions and not improvements:
    print(f"ALL {len(baseline)} cases match baseline. No regressions.")
else:
    print(f"\nTotal: {len(baseline)} cases, {len(regressions)} regressions, {len(improvements)} changes")
sys.exit(1 if regressions else 0)
