# triage_operators.py

Triages all operators from OLM catalogs against Red Hat VEX data.

The tool uses a three-phase approach with image-level dedup:

**Phase 1 — Catalog analysis:** Parses all OCP catalog versions from `data/catalogs/`,
identifies head bundles across all operators/channels, collects all unique workload
images, and respects `--skip-existing` to skip already-completed reports.

**Phase 2 — Batch scan:** Scans all unique images once via the RHACS API with parallel
workers. Each image SHA is scanned exactly once, even if it appears in multiple
operators or across OCP versions. Progress shows elapsed time and ETA.

**Phase 3 — Report assembly:** Assembles per-operator CSV reports from cached scan
results — no additional RHACS calls. Writes to `data/reports/ocp-{version}/`.

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

---

## Local scanner variants (no RHACS)

The same operator triage is available with local scanners — identical CLI, output,
and reports, but **no `ROX_ENDPOINT` / `ROX_API_TOKEN`** required:

| Script | Scanner |
|--------|---------|
| `triage_operators.py` | RHACS Central API (default) |
| `triage_operators_grype.py` | local grype + syft |
| `triage_operators_clairv4.py` | local StackRox Scanner V4 (ClairCore) — RHACS-identical results |

```bash
# grype (auth via `podman login`)
python3 triage_operators_grype.py --version 4.21 --pull-secret ~/pullsecret.txt

# Scanner V4 (start the rhacs-scanner-local stack first; pull secret forwarded
# to the scanner container per registry)
python3 triage_operators_clairv4.py --version 4.21 --pull-secret ~/pullsecret.txt
```

The `clairv4` variant adds `--auth user:pass`, `--indexer-address`,
`--matcher-address`, and `--scannerctl` flags. See
[`rhacs-scanner-local/README.md`](rhacs-scanner-local/README.md) to bring up the
local Scanner V4 stack.

---

## Related Documentation

- [VEX_TRIAGE_EXPLAINER.md](VEX_TRIAGE_EXPLAINER.md) -- Comprehensive technical explainer covering all triage logic and architecture
- [TRIAGE_WORKFLOW.md](TRIAGE_WORKFLOW.md) -- Code-level workflow and data flow details
- [CATALOG_SETUP.md](CATALOG_SETUP.md) -- How to fetch operator catalogs and build the namespace map
- [EXPLORER_GUIDE.md](EXPLORER_GUIDE.md) -- Browser-based UI for querying triage results
