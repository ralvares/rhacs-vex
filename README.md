# rhacs-vex — RHACS Triage, Done Right

> [!IMPORTANT]
> **NOT A RED HAT PRODUCT — USE AT YOUR OWN RISK**
>
> This project is an independent, community-developed tool and is **not** affiliated with, endorsed by, or supported by Red Hat, Inc. There are no warranties, express or implied. You use this tool entirely at your own risk.
>
> It was designed exclusively to triage vulnerabilities in **Red Hat products** (OCP, RHACM, UBI-based images, Red Hat Operators, …) by cross-referencing Red Hat VEX/CSAF advisories. It is **not** intended for third-party, upstream, or non-Red Hat content — results for those will be inaccurate or meaningless.

**Your scanner found 300 CVEs. How many actually matter?**

Most VEX tools do one thing: look up a CVE ID in an advisory file and echo back "not affected". That is a string match with extra steps, not triage.

`rhacs-vex` takes RHACS scan results and cross-checks them against three authoritative sources — Red Hat VEX/CSAF advisories, SPDX SBOMs, and RPM version data — to separate real vulnerabilities from noise:

| Layer | What it does |
|-------|-------------|
| **Image context detection** | Parses the image reference and live labels/CPEs to determine product type (OCP, RHACM, UBI, operator, …), RHEL base version, and product release — no manual input |
| **Scoped VEX cross-reference** | Fetches the authoritative Red Hat CSAF/VEX advisory for each CVE and scopes it to the *specific product and version* the image belongs to — not just "any Red Hat product" |
| **SBOM version verification** | Pulls the SPDX 2.3 SBOM and cross-checks every flagged component version against what is actually installed |
| **RPM backport detection** | Compares the installed RPM against the VEX fix version with proper RPM version comparison, closing findings where the patch is already present |
| **Build-exact identity matching** | Matches the image's own OCI purl and SHA256 digest against VEX product IDs, so a vendor assessment of the *exact build* overrides generic product-level entries |

A finding is marked **FALSE POSITIVE** only when all of the following hold: the VEX says not-affected *for the right product and RHEL version*, the component version is confirmed in the SBOM, and (for RPMs) the installed version is at or beyond the fix. Everything else stays open.

No image pull. No container runtime. Works fully offline once the VEX and SBOM caches are populated.

---

## Install

Requires **Python 3.10+** (the code uses `X | Y` union type syntax). Install the package editable from the repository root:

```bash
pip3 install -e .
```

This installs the `rhacs_vex` package and the console scripts below. On an externally-managed Python (Homebrew/PEP 668) use a virtualenv:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -e .
```

> [!IMPORTANT]
> **Run every command from the repository root.** All tools read and write `./data` by relative path, and the paths stored in `data/manifest.json` must stay relative for the static UI to resolve them.

### Red Hat pull secret (required for scanning)

Every image lives in authenticated Red Hat registries. Download your pull secret from
[console.redhat.com/openshift/install/pull-secret](https://console.redhat.com/openshift/install/pull-secret)
and save it (e.g. `~/pullsecret.txt`). It is needed by the full pipeline (`opm`, `oc`, `podman`).

### External tools (full pipeline only)

| Tool | Used by | Purpose |
|------|---------|---------|
| **podman** | pipeline stage 0 | Registry login |
| **oc** | pipeline stage 3 | Resolve OCP release pullspecs |
| **opm** | pipeline stage 1 | Render OLM operator index catalogs |

Single-image triage needs none of these — only a reachable RHACS Central (or a warm cache).

---

## Quickstart — triage one image

Point at your RHACS Central, then triage a single image:

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>

rhacs-vex --image registry.redhat.io/openshift4/ose-cli@sha256:4f2e216ad46aa75f84e27aa2e6303327b99a4331c7ed8ef65850102898f3a9b0
```

(equivalently `python3 -m rhacs_vex.triage --image …`). Output is a compact, colour-coded table with the scanner severity and Red Hat's product-specific severity side by side, followed by a one-line summary and an SBOM cross-check:

```
┌────────────────┬───────────┬───────────┬───────────┬────────────────┬───────────────┬─────────────────┬──────────────────────────────────┐
│ CVE            │ Component │ RHACS Sev │ VEX Sev   │ Verdict        │ State         │ Fix             │ Justification                    │
├────────────────┼───────────┼───────────┼───────────┼────────────────┼───────────────┼─────────────────┼──────────────────────────────────┤
│ CVE-2026-27532 │ openssl   │ Important │ Important │ POSITIVE       │ Fix available │ 3.2.2-6.el9_5.1 │ Installed 3.2.2-6.el9_5 < fix.   │
│ CVE-2026-33186 │ grpc      │ Important │ Important │ FALSE POSITIVE │ Not affected  │ -               │ Vulnerable code not present.     │
│ CVE-2026-1229  │ circl     │ Moderate  │ Moderate  │ FALSE POSITIVE │ Not affected  │ -               │ No supported Red Hat product …   │
└────────────────┴───────────┴───────────┴───────────┴────────────────┴───────────────┴─────────────────┴──────────────────────────────────┘

Image: registry.redhat.io/openshift4/ose-cli (sha256:4f2e21…)
RHACS reports 182 findings → VEX triage: 122 false positives (67%), 60 real.
🔍 SBOM verified: 20/20 component versions confirmed in image
```

If the image is not already indexed in RHACS, the tool triggers an on-demand scan (`POST /v1/images/scan`) and waits for the result.

### `rhacs-vex` (triage) options

```
rhacs-vex [--image REF | --namespace NS | --ocp FILE | --scan CSV]
          [--format {table,csv,json}] [--output FILE]
          [--false-only] [--sbom] [--workers N]
```

| Flag | Description |
|------|-------------|
| `--image REF` | Triage a single image by digest or tag |
| `--namespace NS` | Triage all images deployed in a Kubernetes namespace |
| `--ocp FILE` | Triage every component in an OCP release manifest (`oc adm release info --pullspecs`) |
| `--scan FILE` | Triage from an RHACS CSV export instead of the live API |
| `--format` | `table` (default), `csv`, or `json` |
| `--output FILE` | Write `csv`/`json` output to a file |
| `--false-only` | Show only `FALSE POSITIVE` rows |
| `--sbom` | Print the full installed-package list for `--image` |
| `--workers N` | Parallel image workers for `--ocp` / `--namespace` (default: 10) |

For `csv`/`json`, all progress/summary text goes to stderr so stdout is clean, parseable data. Verdicts: `FALSE POSITIVE` (VEX not-affected, or fix backported into the installed RPM), `POSITIVE` (real — no not-affected/fix statement applies), and states mirroring Red Hat's CVE pages (`Not affected`, `Fix available`, `Will not fix`, `Under investigation`, …), exported as `VEX_STATE`.

---

## The full pipeline

`rhacs-vex-pipeline` is the one-command, end-to-end run: it renders operator catalogs,
builds the namespace map, resolves OCP release pullspecs, and triages every OCP-release
and operator image against VEX. It shells out to the other modules (`python -m
rhacs_vex.ns_map`, `… .triage`, `… .operators`, `… .retriage`) for process isolation.

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>
rhacs-vex-pipeline --pull-secret ~/pullsecret.txt
```

### Stages

| Stage | Does | Skip flag |
|:---:|------|-----------|
| 0 | `podman login` to the Red Hat registries | `--skip-login` |
| 1 | Render OLM operator index catalogs via `opm` → `data/catalogs/` | `--skip-catalogs` |
| 2 | Build the namespace → VEX-prefix map → `data/ns_vex_prefixes.json` | `--skip-ns-map` |
| 3 | Fetch OCP release pullspecs via `oc adm release info` → `data/pullspecs/` | `--skip-ocp` |
| 4 | Triage each OCP release → `data/reports/ocp-<ver>.csv` | `--skip-ocp` |
| 5 | Triage all operators → `data/reports/operators/*.csv` | `--skip-operators` |
| 6 | *(optional)* offline verdict refresh for operators (`--refresh-operator-verdicts`) | — |

### Freshness / skip flags

| Flag | Effect |
|------|--------|
| `--skip-existing` | Skip catalogs / pullspecs / reports already on disk (resume an interrupted run) |
| `--max-report-age DAYS` | Re-audit OCP report CSVs older than N days so verdicts track current VEX (0 = never). Re-runs reuse the permanent digest-pinned scan/SBOM cache — no extra load on Central. Default: 7 |
| `--max-catalog-age DAYS` | Re-render operator catalogs older than N days to pick up new bundles (0 = never). Default: 7 |
| `--refresh-operator-verdicts` | After stage 5, recompute operator verdicts offline from cached scans (Stage 6) |
| `--versions CSV` | Custom OCP version list (CSV with a `Version` column). Defaults to the list embedded in the module |
| `--workers N` | Parallel image workers per stage (default: 10) |

Run the non-scanning stages (catalogs + namespace map) without Central by passing `--skip-ocp --skip-operators`.

---

## Refresh, rebuild, and explore

The CSV reports under `data/reports/` are the source of truth. Two follow-up steps turn them into the browsable dataset:

```bash
# 1. (optional) Re-audit ALL cached reports against fresh VEX — zero network, CPU only.
#    Bounds each worker's VEX cache via VEX_CACHE_SIZE; uses a fork ProcessPool.
python3 -m rhacs_vex.retriage                 # or: rhacs-vex-retriage
python3 -m rhacs_vex.retriage --operators-only --version 4.21,4.22

# 2. Build per-version parquet + manifest + CVE index from the CSV reports.
python3 -m rhacs_vex.parquet                  # or: rhacs-vex-parquet

# 3. Serve the static explorer (reads data/parquet + data/manifest.json by relative path).
python3 -m http.server 8080
open http://localhost:8080          # index.html — search by CVE, package, image, operator
```

`retriage` recomputes verdicts from the cached scans/SBOMs with no RHACS or network calls,
so it is the cheap way to re-run everything after Red Hat updates its VEX data. `parquet`
then regenerates `data/parquet/**` and `data/manifest.json`, which the static pages
`index.html` and `triage.html` consume directly.

Ad-hoc queries over the built OCP parquet are available via `python3 -m rhacs_vex.query`.

---

## Environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `ROX_ENDPOINT` | triage, operators, pipeline | RHACS Central `host:port` (scanning stages only) |
| `ROX_API_TOKEN` | triage, operators, pipeline | RHACS API bearer token (scanning stages only) |
| `VEX_CACHE_SIZE` | engine | Max parsed-VEX documents kept in each process's LRU cache (default `512`). `rhacs-vex-retriage` sets it to `96` per worker to bound memory across a fork ProcessPool — override to trade memory for hit rate |

---

## Data layout

Everything lives under `./data` (relative to the repo root). Tracked in git: the parquet
dataset, manifest, namespace map, and baseline. Ignored (regenerated locally): the caches,
CSV reports, catalogs, and pullspecs.

```
data/
  vex/                       ← Red Hat CSAF/VEX advisories, one JSON per CVE   (cache)
  sbom/                      ← SPDX 2.3 SBOMs from RHACS, one per image digest (cache)
  scans/                     ← raw RHACS scan JSON, one per image digest       (cache)
  catalogs/                  ← rendered OLM operator index catalogs            (stage 1)
  pullspecs/                 ← OCP release manifests, one 4.x.y.txt per release (stage 3)
  reports/
    ocp-<ver>.csv            ← per-OCP-release triage report                   (stage 4)
    operators/*.csv          ← per-operator triage report, flat (one per bundle)(stage 5)
    operators_index.json     ← minor-version → operator-bundle association map
  parquet/
    ocp/<ver>.parquet        ← per-release columnar data for the UI
    operators/…              ← per-operator columnar data
    cve-index.parquet        ← lightweight CVE × scope index
  manifest.json              ← scope catalogue + summary stats consumed by the UI
  ns_vex_prefixes.json       ← namespace → VEX-prefix map (from stage 2)
  baseline.json              ← regression fixture for tests/check_baseline.py
```

The static site is served from the repo root: `index.html`, `triage.html`, and `assets/`
fetch `data/parquet/**` and `data/manifest.json` by relative path — keep them where they are.

---

## How matching works

The clean-room matching engine (`rhacs_vex.engine`) decides each verdict from the
authoritative Red Hat CSAF-VEX data, scoped to the exact product the image belongs to:

1. **Identify the workload** — product family, RHEL base, and release version from the image ref, live RHACS labels, and CPEs.
2. **Scope the VEX** — resolve the set of Red Hat VEX product IDs that apply to *this* image (registry namespace, purl, digest, CPE), so an unrelated product's assessment never leaks in.
3. **Read the remediation** — `known_not_affected` (with justification) closes a finding; `fixed` yields a fix version; `known_affected` / `under_investigation` keep it open.
4. **Verify against reality** — confirm the flagged component and version exist in the SBOM, and for RPMs compare the installed NEVRA against the fix using RPM version rules (backport-aware).

For the full data model — CSAF-VEX structure, product-ID grammar, RHEL/product stream
rules, and every decision branch — see **[docs/VEX-MODEL.md](docs/VEX-MODEL.md)**.

---

## Project layout

```
pyproject.toml              ← package metadata, dependencies, console scripts
README.md                   ← this file
docs/VEX-MODEL.md           ← Red Hat CSAF-VEX ground-truth reference
src/rhacs_vex/
  engine.py                 ← clean-room VEX matching engine
  triage.py                 ← RHACS ↔ VEX triage CLI / IO layer   (rhacs-vex)
  operators.py              ← operator triage                     (rhacs-vex-operators)
  retriage.py               ← offline re-audit from cache         (rhacs-vex-retriage)
  parquet.py                ← build parquet + manifest + CVE index (rhacs-vex-parquet)
  pipeline.py               ← end-to-end orchestrator             (rhacs-vex-pipeline)
  ns_map.py                 ← namespace → VEX-prefix map builder
  query.py                  ← ad-hoc queries over OCP parquet
tests/check_baseline.py     ← 189-case regression check (run from repo root)
index.html, triage.html, assets/, data/   ← static explorer + dataset
```

Console scripts: `rhacs-vex`, `rhacs-vex-pipeline`, `rhacs-vex-operators`,
`rhacs-vex-retriage`, `rhacs-vex-parquet`. Modules without a script are run with
`python3 -m rhacs_vex.<module>`.
