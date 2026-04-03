# triage_operators.py

Triages all operators from OLM catalogs against Red Hat VEX data.

For each OCP catalog version in `data/catalogs/`, the tool:
1. Parses the catalog (OLM FBC format) to find all operator packages.
2. Identifies the head bundle of each operator's default channel.
3. Retrieves all workload images from that bundle's `relatedImages`.
4. Scans and triages every image via the RHACS API.
5. Writes per-operator CSVs to `data/reports/ocp-{version}/`.

## Prerequisites

```bash
pip install -r requirements.txt
```

Two environment variables are required:

```bash
export ROX_ENDPOINT=central.example.com:443
export ROX_API_TOKEN=<your-token>
```

Catalog files must exist under `data/catalogs/catalog-{version}.json`.  
Currently available: `4.20`, `4.21`.  
See `CATALOG_SETUP.md` to fetch or update catalogs.

## Usage

```
python3 triage_operators.py [OPTIONS]
```

| Option | Description |
|---|---|
| `--version VERSION` | Comma-separated OCP version(s) to process, e.g. `4.21` or `4.20,4.21`. Defaults to all versions found in `data/catalogs/`. |
| `--operator NAME` | Comma-separated operator package name(s) to process. Defaults to all. |
| `--workers N` | Parallel image workers per operator (default: 10). |
| `--false-only` | Include only FALSE POSITIVE findings in the output CSVs. |
| `--skip-existing` | Skip operators whose report CSV already exists. Useful for resuming an interrupted run. |

## Examples

**Triage all operators across all catalog versions:**
```bash
python3 triage_operators.py
```

**Triage a single OCP version:**
```bash
python3 triage_operators.py --version 4.21
```

**Triage two specific operators:**
```bash
python3 triage_operators.py --version 4.21 --operator advanced-cluster-management,multicluster-engine
```

**Resume a partial run, skipping already-completed operators:**
```bash
python3 triage_operators.py --version 4.21 --skip-existing
```

**Only write false positives to the CSVs:**
```bash
python3 triage_operators.py --version 4.21 --false-only
```

## Output

Reports are written to:
```
data/reports/ocp-{version}/{operator}-{channel}-{bundle_version}.csv
```

Each CSV contains a row per CVE finding with columns:

| Column | Description |
|---|---|
| `IMAGE` | Full image reference |
| `IMAGE_ROLE` | Role name from `relatedImages` (may be empty) |
| `COMPONENT` | RPM/package name |
| `VERSION` | Installed version |
| `CVE` | CVE identifier |
| `SEVERITY` | Red Hat severity (Critical / Important / Moderate / Low) |
| `AUDIT_RESULT` | `✅ FALSE POSITIVE` or `❌ POSITIVE` |
| `VEX_FIX_VER` | Fixed version from VEX, or `N/A` |
| `JUSTIFICATION` | Human-readable explanation |

A summary table is printed to the terminal after each OCP version completes.
