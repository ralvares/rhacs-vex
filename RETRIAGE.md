# Offline Retriage

Re-run the VEX triage decision tree on all cached data without contacting RHACS. Use this after changing triage logic to regenerate all reports and parquets.

## What it does

1. Reads cached RHACS scan JSONs from `data/scans/`
2. Reads cached VEX files from `data/vex/`
3. Reads cached SBOMs from `data/sbom/`
4. Re-runs `audit_row_detailed()` on every finding with the latest triage code
5. Writes fresh CSV reports to `data/reports/`
6. Rebuilds per-version parquets, FIXED_IN enrichment, and `manifest.json`

Zero network calls. All data is local.

## Usage

```bash
# Full retriage — all OCP versions + operators + parquet rebuild
python3 retriage_offline.py

# More parallelism (default: 10 workers)
python3 retriage_offline.py --workers 20

# Single OCP version
python3 retriage_offline.py --version 4.21.18

# OCP only, skip operators
python3 retriage_offline.py --ocp-only

# Operators only, skip OCP
python3 retriage_offline.py --operators-only
```

## Performance

| Workers | 43 OCP versions | Operators | Total |
|---------|----------------|-----------|-------|
| 1       | ~19 min        | ~3 min    | ~22 min |
| 10      | ~3 min         | ~3 min    | ~6 min |
| 20      | ~2 min         | ~3 min    | ~5 min |

Bottleneck is VEX JSON parsing per CVE finding (~50-100 unique CVEs per image, each VEX file 100KB-30MB).

## Prerequisites

Cached data must exist from a previous `triage.py --ocp` or `triage_operators.py` run:

| Directory | Contents | Created by |
|-----------|----------|------------|
| `data/scans/` | RHACS scan JSONs per image | `triage.py --ocp` or `triage.py --image` |
| `data/vex/` | Red Hat CSAF/VEX JSONs per CVE | `triage.py` (auto-synced during audit) |
| `data/sbom/` | SPDX 2.3 SBOMs per image | `triage.py` (fetched from RHACS) |
| `4.*.txt` | OCP release manifests | `oc adm release info --pullspecs` |

If scan data doesn't exist for an image, it is skipped (shown as "skipped" in output).

## When to use

- After changing triage logic in `triage.py` (new VEX matching rules, bug fixes)
- After updating VEX files (`data/vex/`) with fresh Red Hat advisories
- To regenerate reports with new output columns (SOURCE, LOCATION, FIXABLE, VEX_STATE, etc.)
- To rebuild parquets with FIXED_IN cross-version enrichment

## What it does NOT do

- Does NOT contact RHACS (no scan, no SBOM fetch)
- Does NOT download VEX files from Red Hat CDN
- Does NOT modify scan cache in `data/scans/`
- Does NOT re-render OLM catalogs or namespace maps

To get fresh scan data, use `triage.py --ocp` or `setup_and_scan.py` instead.

## Output

```
=== Offline retriage: 43 OCP versions, 10 workers ===
  [1/43] (2%) 4.21.18: 190 images, 0 skipped, 10218 findings
  [2/43] (5%) 4.21.15: 190 images, 0 skipped, 10737 findings
  ...
  OCP done in 135s

=== Retriaging operators ===
  17 operator reports updated in 42s

=== Rebuilding parquets ===
  ...FIXED_IN enriched...
  Manifest: 21 scopes

Done: 182s (3.0 min)
```
