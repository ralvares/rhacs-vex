# query_ocp.py — OCP Vulnerability Report Tool

Query `data/ocp.parquet` for CVE reports per OCP version or operator catalog, with severity breakdown, component analysis, and upgrade recommendations.

## Requirements

```bash
pip install pyarrow
```

## Usage

```bash
python3 query_ocp.py <command> [options]
```

### List Available Versions

```bash
python3 query_ocp.py list
```

Output:
```
Available OCP platform versions:
  4.20: 4.20.0 → 4.20.24 (24 releases)
  4.21: 4.21.0 → 4.21.18 (19 releases)
```

### Full Version Report

```bash
python3 query_ocp.py <version> [--top N] [--components] [--no-upgrade]
```

| Flag | Description |
|------|-------------|
| `--top N` | Number of top CVEs to display (default: 10) |
| `--components` | Include OCP component breakdown |
| `--no-upgrade` | Skip upgrade analysis |

Example:
```bash
python3 query_ocp.py 4.20.0 --top 15 --components
```

Report includes:
- **Severity breakdown** — unique CVEs grouped by Critical/Important/Moderate/Low/Unknown
- **Audit result breakdown** — POSITIVE (real), FALSE POSITIVE (VEX-assessed not affected), NOT ASSESSED
- **Top CVEs** — ranked by severity, then by spread across components/images
- **Component breakdown** — most affected OCP components (with `--components`)
- **Upgrade analysis** — every z-stream compared showing fixed/new/net/remaining CVEs
- **Upgrade recommendation** — target with lowest remaining CVEs
- **Cross-minor comparison** — e.g. 4.20.x → latest 4.21.x

### CVE Search

Search a specific CVE across all OCP versions **and** operator catalogs:

```bash
python3 query_ocp.py --cve CVE-2024-41110
python3 query_ocp.py --cve CVE-2026-4786
```

Shows severity, then two sections:
- **OCP Platform** — affected/not-affected platform versions with earliest fix
- **Operator Catalogs** — affected/not-affected operator catalog entries, grouped by base operator name

### Operator Catalog Report

Query operator catalogs scanned within an OCP minor version:

```bash
python3 query_ocp.py <ocp-minor> -o <operator-name>
```

Supports fuzzy matching — partial name shows all matches:

```bash
# Shows matching catalog names
python3 query_ocp.py 4.20 -o rhacs-operator-rhacs-4

# Exact catalog report
python3 query_ocp.py 4.20 -o rhacs-operator-rhacs-4.10-v4.10.3
```

## Understanding the Data

### Audit Results

| Status | Meaning |
|--------|---------|
| ❌ POSITIVE | Real vulnerability — a fix exists at the package level, but the OCP release ships an older package |
| ✅ FALSE POSITIVE | VEX assessment says not affected (e.g., vulnerable code path not reachable) |
| ⚠️ NOT ASSESSED | Not yet evaluated by Red Hat VEX |

### Counting

- CVE counts are **unique CVEs** (deduplicated across components/images)
- A single CVE can appear in many components and images within one OCP release
- Row-level counts (audit breakdown) show total findings before dedup

### Upgrade Analysis

The upgrade table compares POSITIVE CVE sets between your version and each later z-stream:

| Column | Meaning |
|--------|---------|
| Fixed | CVEs in your version that are gone in the target |
| New | CVEs in the target that didn't exist in your version |
| Net | Fixed minus New (negative = improvement) |
| Remaining | Total POSITIVE CVEs in the target version |

New CVEs in later versions come from new components, updated base images pulling in new packages, or newly published CVEs affecting existing packages.

### Severity Sources

Two severity fields exist:
- `SEVERITY` — from Red Hat VEX data (used in reports)
- `RHACS_SEVERITY` — from RHACS scanner

When they disagree, `SEVERITY_MISMATCH` is `true`. The tool uses VEX severity.

## Examples

Pre-generated example outputs are in the [examples/](examples/) folder:

| File | Command |
|------|---------|
| [report-4.20.0.txt](examples/report-4.20.0.txt) | `python3 query_ocp.py 4.20.0 --top 15 --components` |
| [report-4.21.0.txt](examples/report-4.21.0.txt) | `python3 query_ocp.py 4.21.0 --top 10` |
| [report-no-upgrade.txt](examples/report-no-upgrade.txt) | `python3 query_ocp.py 4.20.0 --no-upgrade --top 5` |
| [cve-search-CVE-2024-41110.txt](examples/cve-search-CVE-2024-41110.txt) | `python3 query_ocp.py --cve CVE-2024-41110` |
| [cve-search-CVE-2026-4786.txt](examples/cve-search-CVE-2026-4786.txt) | `python3 query_ocp.py --cve CVE-2026-4786` (shows operator catalogs) |
| [operator-rhacs-4.10.txt](examples/operator-rhacs-4.10.txt) | `python3 query_ocp.py 4.20 -o rhacs-operator-rhacs-4.10-v4.10.3` |
| [list-versions.txt](examples/list-versions.txt) | `python3 query_ocp.py list` |

## Web Dashboard

[`dashboard.html`](dashboard.html) is an interactive browser-based dashboard powered by DuckDB WASM + Chart.js. No backend — all 23MB of parquet data loads and queries entirely in the browser.

```bash
python3 -m http.server 8080
# Open http://localhost:8080/dashboard.html
```

### Features

| Tab | What it shows |
|-----|---------------|
| **Overview** | Severity donut, fix availability breakdown (RPM fix vs Non-RPM), audit results, severity-by-fix stacked bar |
| **Upgrade Path** | Line chart showing CVE trend across z-streams (stacked by severity) + upgrade target table with recommendation |
| **Components** | Top 20 affected OCP components with stacked severity bars |
| **Version Compare** | Side-by-side comparison of two versions: fixed, new, common CVEs |
| **CVE Search** | Search any CVE — shows affected versions as color-coded chips + operator catalogs |

### Fix Availability Categories

The dashboard breaks down POSITIVE CVEs into:

| Category | Meaning |
|----------|---------|
| **RPM Fix Available** | `VEX_FIX_VER` is set — an RPM package update exists but the OCP release ships an older version |
| **Non-RPM Fixed Upstream** | Go/stdlib component — fix released in upstream/other products (JUSTIFICATION: "Non-RPM…Fixed in") |
| **Non-RPM Affected** | Go/stdlib component — affected, fix not yet available in this stream (JUSTIFICATION: "Non-RPM…Affected in") |
