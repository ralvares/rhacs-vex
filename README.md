# RHACS Triage - Done Right

> [!IMPORTANT]
> **NOT A RED HAT PRODUCT — USE AT YOUR OWN RISK**
>
> This project is an independent, community-developed tool and is **not** affiliated with, endorsed by, or supported by Red Hat, Inc. in any way. There are no warranties, express or implied. You use this tool entirely at your own risk.
>
> This tool was designed exclusively to triage vulnerabilities in **Red Hat products** (OCP, RHACM, UBI-based images, Red Hat Operators, etc.) by cross-referencing Red Hat VEX/CSAF advisories. It is **not** intended for use with third-party, upstream, or non-Red Hat container images and packages. Results for non-Red Hat content will be inaccurate or meaningless.

**Your scanner found 300 CVEs. How many actually matter?**

Most VEX triage tools do one thing: look up a CVE ID in an advisory file and echo back "not affected". That's not triage - that's a string match with extra steps.

This tool takes scan results and cross-checks them against three authoritative sources - Red Hat VEX/CSAF advisories, SPDX SBOMs, and RPM version data - to separate real vulnerabilities from noise:

| Layer | What it does |
|-------|-------------|
| **Image context detection** | Parses the image reference and live labels/CPEs to determine product type (OCP, RHACM, UBI, operator, ...), RHEL base version, and product release version - with no manual input |
| **Scoped VEX cross-reference** | Fetches the authoritative Red Hat CSAF/VEX advisory for each CVE and scopes it to the *specific product and version* the image belongs to - not just "any Red Hat product" |
| **SBOM version verification** | Pulls the SPDX 2.3 SBOM and cross-checks every flagged component version against what is actually installed in the image |
| **RPM backport detection** | Compares the installed RPM against the VEX fix version using proper RPM version comparison, automatically closing findings where the patch is already present |

A finding is only marked **FALSE POSITIVE** when all of the following are true: the VEX says not-affected *for the right product and RHEL version*, the component version is confirmed in the SBOM, and (for RPMs) the installed version is at or beyond the fix. Everything else stays open.

No image pull. No container runtime. Works fully offline once the VEX and SBOM caches are populated.

---

## Prerequisites

### Red Hat Pull Secret (MANDATORY)

> [!CAUTION]
> **A Red Hat pull secret is required for ALL workflows.** Every image scanned by this tool lives in authenticated Red Hat registries (`registry.redhat.io`, `quay.io`). Without a valid pull secret, nothing works.

Download yours from [console.redhat.com/openshift/install/pull-secret](https://console.redhat.com/openshift/install/pull-secret) and save it (e.g. `~/pullsecret.txt`).

### Python

- **Python 3.10 or later** (the scripts use `X | Y` union type syntax introduced in 3.10)
- `pip` / `pip3` for installing dependencies

```bash
pip install -r requirements.txt
```

### External tools

| Tool | Required by | Purpose | Install |
|------|------------|---------|---------|
| **podman** | all backends | Registry login, image pulls | [podman.io](https://podman.io/getting-started/installation) |
| **oc** | `setup_and_scan.py` | Resolve OCP release pullspecs | [mirror.openshift.com](https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/) |
| **opm** | `setup_and_scan.py` | Render OLM operator index catalogs | [mirror.openshift.com](https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/) |
| **grype** + **syft** | grype backend | Local vulnerability scanning | [github.com/anchore/grype](https://github.com/anchore/grype) |
| **Go 1.21+** | clairv4 backend | Build `scannerctl` CLI | [go.dev](https://go.dev/dl/) |

All binaries are assumed to be on your `PATH`. Use `--podman`, `--oc`, and `--opm` flags to specify custom paths if needed.

---

## Quick Start

### Option A: Full pipeline (scan everything)

```bash
# Set up (choose your scanner backend)
pip install -r requirements.txt

# RHACS backend — needs a running RHACS Central
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>
python3 setup_and_scan.py --pull-secret ~/pullsecret.txt

# OR: grype backend — no infrastructure needed
python3 setup_and_scan.py --scanner grype --pull-secret ~/pullsecret.txt

# OR: clairv4 backend — RHACS-identical results, no Central
# (start the local scanner first: see rhacs-scanner-local/deploy.sh)
python3 setup_and_scan.py --scanner clairv4 --pull-secret ~/pullsecret.txt
```

### Option B: Triage a single image

```bash
# With RHACS
python3 triage.py --image registry.redhat.io/ubi9/ubi:latest --false-only

# With grype (no RHACS needed)
python3 triage_grype.py --image registry.redhat.io/ubi9/ubi:latest --pull-secret ~/pullsecret.txt

# With local Scanner V4 (no RHACS needed)
python3 triage_clairv4.py --image registry.redhat.io/ubi9/ubi:latest --pull-secret ~/pullsecret.txt
```

### Option C: Browse results in the explorer

```bash
python3 build_parquet.py          # combine CSV reports into parquet
python3 -m http.server 8080       # serve the UI
open http://localhost:8080         # search by CVE, package, operator
```

---

## When to Use What

### Choosing a scanner backend

| Backend | Needs RHACS? | Needs infra? | Best for |
|---------|:----------:|:----------:|----------|
| **rhacs** | Yes (`ROX_ENDPOINT` + `ROX_API_TOKEN`) | RHACS Central | You already run RHACS in a cluster |
| **grype** | No | grype + syft on PATH | Quick local scan, no infrastructure |
| **clairv4** | No | Local podman containers | RHACS-identical results without RHACS — same scanner engine |

All three produce the **same report schema and verdicts**. Pick based on what you have available.

### Choosing a script

| What you want to do | Script | Pull secret? |
|---------------------|--------|:---:|
| **Triage a single image** | `triage.py` / `triage_grype.py` / `triage_clairv4.py` | Yes |
| **Triage all images in a namespace** | `triage.py --namespace <NS>` | Yes |
| **Triage an entire OCP release** | `triage.py --ocp 4.21.2.txt` (or grype/clairv4 variant) | Yes |
| **Triage all operators in OCP catalogs** | `triage_operators.py` (or grype/clairv4 variant) | Yes |
| **Run the full pipeline** (catalogs + OCP releases + operators) | `setup_and_scan.py` | Yes |
| **Find CVEs your scanner MISSED** | `false_negative_check.py` | No (uses cached data) |
| **Build the namespace-to-VEX prefix map** | `build_ns_map.py` | No |
| **Combine reports into parquet for the explorer** | `build_parquet.py` | No |
| **Browse results in a browser** | `python3 -m http.server` + open `index.html` | No |
| **Deploy local Scanner V4 stack** | `rhacs-scanner-local/deploy.sh` | No (uses public quay.io images) |

---

## Scanner Backends

The VEX triage engine is scanner-agnostic — it consumes a CVE list and cross-checks
it against Red Hat VEX/SBOM/RPM data. Three scanner backends feed it, all producing
the **same** report schema and verdicts:

| Backend | Scanner | Needs Central? | Entry scripts | When to use |
|---------|---------|----------------|---------------|-------------|
| **rhacs** (default) | RHACS Central API | Yes | `triage.py`, `triage_operators.py` | You already run RHACS |
| **grype** | local grype + syft | No | `triage_grype.py`, `triage_operators_grype.py` | Quick local scan, no infra |
| **clairv4** | local StackRox Scanner V4 (ClairCore — the same engine RHACS uses) | No | `triage_clairv4.py`, `triage_operators_clairv4.py` | Local scan with RHACS-identical results |

All three share the VEX engine, the `--ocp` / operator workflows, and the output
format. Pick one with `setup_and_scan.py --scanner {rhacs,grype,clairv4}`.

### RHACS backend (default)

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>
```

> `ROX_ENDPOINT` / `ROX_API_TOKEN` are only needed for the **RHACS** backend.
> The local backends (**grype**, **clairv4**) need no Central.

### Local Scanner V4 (clairv4)

`clairv4` runs the **actual RHACS scanner** (Scanner V4 / ClairCore) locally in
containers — so its package detection and CVE matching are identical to RHACS, with
no OpenShift or Central required. Bring the stack up once:

```bash
cd rhacs-scanner-local
./deploy.sh                 # automated setup: certs, vuln data, containers, health check
```

Then scan:

```bash
# single image (private registry — pull secret forwarded to the scanner)
python3 triage_clairv4.py \
  --image registry.redhat.io/advanced-cluster-security/rhacs-main-rhel8:4.10.2 \
  --pull-secret ~/pullsecret.txt

# SBOM (SPDX 2.3) for an image
python3 triage_clairv4.py --image registry.access.redhat.com/ubi9/ubi:latest --sbom

# every component in an OCP release
python3 triage_clairv4.py --ocp 4.21.18.txt --pull-secret ~/pullsecret.txt \
  --format csv --output data/reports/ocp-4.21.18.csv

# every operator in an OCP catalog
python3 triage_operators_clairv4.py --version 4.21 --pull-secret ~/pullsecret.txt
```

Auth notes (clairv4): the **scanner container** pulls the image, so credentials are
parsed from `--pull-secret` (Docker-config or k8s-Secret JSON), matched per registry,
and forwarded as basic auth. Public registries (e.g. `registry.access.redhat.com`)
need no auth. Use `--auth user:pass` to force a single credential for all images.

See [`rhacs-scanner-local/README.md`](rhacs-scanner-local/README.md) for full details
on the local scanner stack.

### Full pipeline (`setup_and_scan.py`)

`setup_and_scan.py` orchestrates the whole flow — render catalogs, build the
namespace map, fetch OCP pullspecs, triage releases, triage operators — for the
chosen backend:

```bash
# RHACS (default) — needs ROX_ENDPOINT / ROX_API_TOKEN
python3 setup_and_scan.py --pull-secret ~/pullsecret.txt

# local grype — no Central
python3 setup_and_scan.py --scanner grype --pull-secret ~/pullsecret.txt

# local Scanner V4 — no Central (start the rhacs-scanner-local stack first)
python3 setup_and_scan.py --scanner clairv4 --pull-secret ~/pullsecret.txt
```

---

## Usage

```
python3 triage.py [--image IMAGE_REF]
                  [--namespace NAMESPACE]
                  [--ocp PULLSPECS_FILE]
                  [--scan CSV_FILE]
                  [--format {table,csv,json}]
                  [--output FILE]
                  [--false-only]
                  [--sbom]
                  [--workers N]
```

| Flag | Description |
|------|-------------|
| `--image IMAGE_REF` | Triage a single image by digest or tag |
| `--namespace NS` | Triage all images deployed in a Kubernetes namespace |
| `--ocp FILE` | Triage every component in an OCP release manifest (`oc adm release info --pullspecs`) |
| `--scan FILE` | Triage from an RHACS CSV export instead of the live API |
| `--format` | Output format: `table` (default), `csv`, or `json` |
| `--output FILE` | Write output to a file (for `csv` / `json`) |
| `--false-only` | Show only `FALSE POSITIVE` rows |
| `--sbom` | Print the full package list for `--image` - no container access needed |
| `--workers N` | Parallel image workers for `--ocp` / `--namespace` (default: 10) |
| `--pull-secret FILE` | Path to Red Hat pull secret (required for grype/clairv4 backends) |

> **On-demand scan**: if the requested image is not already indexed in RHACS, the tool automatically triggers a scan via `POST /v1/images/scan` and waits for the result (up to 5 minutes).

## Output formats

| Format | Behaviour |
|--------|-----------|
| `table` | Pretty Rich table printed to the terminal (default) |
| `json` | Clean JSON array on stdout - no headers or emoji |
| `csv` | CSV on stdout or to `--output FILE` - no emoji |

For `json` and `csv`, all Rich/terminal output (progress messages, summaries) is redirected to stderr so that stdout contains only the parseable data.

## Triage results

| Result | Meaning |
|--------|---------|
| `FALSE POSITIVE` | VEX states this component is not affected |
| `FALSE POSITIVE (fix backported)` | Installed RPM version already contains the fix |
| `VULNERABLE` | No not-affected or fix statement found in VEX |
| `NEEDS REVIEW` | VEX advisory exists but verdict is still under investigation |

In `table` format, results are colour-coded (green / red). In `json` / `csv` output the values are plain text with no emoji or special characters.

---

## Examples

### Single image

```bash
python3 triage.py \
  --image "registry.redhat.io/advanced-cluster-security/rhacs-scanner-db-rhel8@sha256:6cc97529..." \
  --false-only
```

### JSON output to a file

```bash
python3 triage.py \
  --image "registry.redhat.io/advanced-cluster-security/rhacs-scanner-db-rhel8@sha256:6cc97529..." \
  --false-only --format json --output /tmp/report.json
```

### JSON output to stdout (pipe-friendly)

```bash
python3 triage.py \
  --image "registry.redhat.io/ubi8/ubi:latest" \
  --format json 2>/dev/null | jq '.[] | select(.AUDIT_RESULT == "FALSE POSITIVE")'
```

### All images in a namespace

```bash
python3 triage.py --namespace openshift-monitoring --false-only
```

### Full OCP release - parallel scan

Generate the pullspecs file first:

```bash
oc adm release info 4.21.2 --pullspecs > 4.21.2.txt
```

Then triage all component images in parallel:

```bash
python3 triage.py --ocp 4.21.2.txt --false-only --workers 30 --format csv --output ocp-4.21.2-triage.csv
```

The tool reads the `Name:` field from the manifest header to scope every component against the correct product release (e.g. `4.21.2`), even if an individual image was built from an earlier minor release.

### CSV mode (no live API required)

```bash
python3 triage.py --scan scan.csv --image "registry.../myimage@sha256:..." --false-only
```

---

## Sample output

```
$ python3 triage.py \
    --image "registry.redhat.io/rhacm2/multicluster-operators-subscription-rhel9@sha256:58f24f4a..." \
    --false-only

Image: registry.redhat.io/rhacm2/multicluster-operators-subscription-rhel9@sha256:58f24f4a...
Mode: RHACS API  endpoint=central-stackrox.apps.ocp.example.com:443
🔍 Searching for image in RHACS...
✅ Found image ID: sha256:58f24f4a9869b9fc5f67dfe5aed1bdaae61880654b20c750e17ca12867b1d9a4
📥 Fetching full scan data...
🏷  Labels found - refining context from CPE...
OS: rhel:9
Found: 112 CVE findings across 38 components
Context: type=operator  rhel=9  display=rhacm2/multicluster-operators-subscription-rhel9 2.16 (RHEL 9)
VEX scope: registry.redhat.io/rhacm2/, rhacm2/, advanced_cluster_management, ...

🔄 Syncing 80 CVEs into /vex folder...
✅ Sync Complete in 1.59s.
🚀 Running Structured Audit - context: rhacm2/multicluster-operators-subscription-rhel9 2.16 (RHEL 9)

          VEX Triage Report - rhacm2/multicluster-operators-subscription-rhel9 2.16 (RHEL 9)
╭─────────────────────────────┬───────────────────┬─────────┬────────────────┬───────────┬───────────────────┬─────────────┬──────────────────────╮
│ Component                   │ Product           │ Version │ CVE            │ Severity  │ Result            │ Fix Version │ Justification        │
├─────────────────────────────┼───────────────────┼─────────┼────────────────┼───────────┼───────────────────┼─────────────┼──────────────────────┤
│ google.golang.org/grpc      │ rhacm2/multiclu…  │ v1.79.1 │ CVE-2026-33186 │ Important │ ✅ FALSE POSITIVE │ N/A         │ Non-RPM - not        │
│                             │ 2.16 (RHEL 9)     │         │                │           │                   │             │ affected in          │
│                             │                   │         │                │           │                   │             │ rhacm2/multiclus…    │
│                             │                   │         │                │           │                   │             │ 2.16 (RHEL 9):       │
│                             │                   │         │                │           │                   │             │ vulnerable code      │
│                             │                   │         │                │           │                   │             │ not present.         │
├─────────────────────────────┼───────────────────┼─────────┼────────────────┼───────────┼───────────────────┼─────────────┼──────────────────────┤
│ stdlib                      │ rhacm2/multiclu…  │ 1.25.7  │ CVE-2026-25679 │ Important │ ✅ FALSE POSITIVE │ N/A         │ Non-RPM - not        │
│                             │ 2.16 (RHEL 9)     │         │                │           │                   │             │ affected in          │
│                             │                   │         │                │           │                   │             │ rhacm2/multiclus…    │
│                             │                   │         │                │           │                   │             │ 2.16 (RHEL 9):       │
│                             │                   │         │                │           │                   │             │ vulnerable code      │
│                             │                   │         │                │           │                   │             │ not present.         │
├─────────────────────────────┼───────────────────┼─────────┼────────────────┼───────────┼───────────────────┼─────────────┼──────────────────────┤
│ github.com/cloudflare/circl │                   │ v1.6.1  │ CVE-2026-1229  │ Moderate  │ ✅ FALSE POSITIVE │ N/A         │ Red Hat Product      │
│                             │                   │         │                │           │                   │             │ Security states no   │
│                             │                   │         │                │           │                   │             │ currently supported  │
│                             │                   │         │                │           │                   │             │ Red Hat product is   │
│                             │                   │         │                │           │                   │             │ affected by this CVE │
╰─────────────────────────────┴───────────────────┴─────────┴────────────────┴───────────┴───────────────────┴─────────────┴──────────────────────╯

  ✅ FALSE POSITIVE: 7

🔍 Verifying component versions against SBOM...
  🔍 SBOM verified: 4/4 component versions confirmed in image
```

---

## Documentation

| Document | What it covers |
|----------|---------------|
| **[VEX_TRIAGE_EXPLAINER.md](VEX_TRIAGE_EXPLAINER.md)** | Comprehensive technical explainer — the canonical reference for the entire triage engine, decision tree, all six RPM checks, non-RPM logic, and design invariants |
| **[VEX_TRIAGE_VERIFICATION_LOGIC.md](VEX_TRIAGE_VERIFICATION_LOGIC.md)** | Concise verification framework — binary-to-source mapping, stream-aware auditing, SBOM integrity checks |
| **[TRIAGE_WORKFLOW.md](TRIAGE_WORKFLOW.md)** | Code-level workflow — WorkloadContext, VEX scope filtering, module stream guards, data flow diagrams |
| **[OPERATORS_TRIAGE.md](OPERATORS_TRIAGE.md)** | Operator triage — three-phase approach, catalog parsing, batch scanning, per-operator reports |
| **[EXPLORER_GUIDE.md](EXPLORER_GUIDE.md)** | Browser-based explorer — DuckDB-WASM search interface, filters, severity mismatch analysis |
| **[CATALOG_SETUP.md](CATALOG_SETUP.md)** | Catalog setup — installing `opm`, rendering operator index catalogs, generating namespace maps |
| **[rhacs-scanner-local/README.md](rhacs-scanner-local/README.md)** | Local Scanner V4 stack — standalone podman deployment, architecture, scannerctl, troubleshooting |

---

## Cache layout

```
data/
  vex/    ← VEX/CSAF advisories fetched from access.redhat.com (one file per CVE)
  sbom/   ← SPDX 2.3 SBOMs fetched from RHACS (one file per image digest)
  scans/  ← Raw RHACS scan JSON (one file per image digest)
```

Both caches are populated on first use. Delete a file to force a refresh.

---

## False Negative Detection

`triage.py` eliminates false positives — CVEs your scanner reported that Red Hat's VEX says are not exploitable.  
`false_negative_check.py` does the opposite — it finds **false negatives**: CVEs that RHACS *should* have reported but silently missed.

### How it works

| Step | What it does |
|------|-------------|
| **VEX index** | Reads all locally cached VEX files and extracts every `known_affected` entry (vendor confirms vulnerable, no fix yet) and every `fixed` entry with a fix version |
| **SBOM cross-check** | For each image that has both a scan JSON and an SBOM, extracts installed RPM source packages |
| **Gap detection** | If VEX says a package is vulnerable AND the package is installed AND RHACS didn't report the CVE → **potential false negative** |
| **Stream isolation** | Version comparisons are scoped to the exact RHEL minor stream (e.g. `el9_4` vs `el9_5`) and product stream (`rhaos4.18.el9` vs `rhaos4.20.el9`) to prevent cross-stream false positives |

### Usage

```bash
# Summary report for OCP 4.20.0 (deduplicated by CVE+package)
python3 false_negative_check.py --ocp 4.20.0 --summary

# Important+ findings as CSV
python3 false_negative_check.py --ocp 4.20.0 --min-severity important \
    --format csv --output fn-4.20.0.csv

# All images, JSON output
python3 false_negative_check.py --format json --output fn-all.json
```

| Flag | Description |
|------|-------------|
| `--ocp VERSION` | Limit to images in a specific OCP release (reads `{VERSION}.txt` release manifest) |
| `--summary` | Deduplicate by `(CVE, package, status)` and show affected image count |
| `--min-severity SEV` | Filter to `critical`, `important`, `high`, `moderate`, `medium`, or `low` |
| `--format` | `table` (default), `csv`, or `json` |
| `--output FILE` | Write output to file |
| `--workers N` | Parallel loader threads (default: 10) |

### What the STATUS column means

| Status | Meaning |
|--------|---------|
| `known_affected` | Red Hat VEX explicitly marks this package as currently vulnerable (no fix released) — RHACS didn't report the CVE |
| `needs_fix` | A fix exists in the same RHEL/product stream as the installed version, but the installed version is older — RHACS didn't report the CVE |

### Real example (OCP 4.20.0)

```
CVE                    SEV        PACKAGE         STATUS         IMG#  FIX_VERSION
CVE-2025-31133         Important  runc            needs_fix         1  1.2.9-1.rhaos4.18.el9
CVE-2025-13502         Important  webkit2gtk3     needs_fix         1  2.50.3-1.el9_4
CVE-2024-12905         Important  librados2       known_affected    4
CVE-2025-11021         Important  libsoup         needs_fix         1  2.72.0-8.el9_4.6
CVE-2025-26625         Important  git-lfs         needs_fix         1  3.4.1-4.el9_4.3
```

`runc CVE-2025-31133` is a confirmed false negative: `runc 1.1.14-4.rhaos4.18.el9` is installed, the fix is at `1.2.9-1.rhaos4.18.el9` (same stream), and RHACS reports zero CVEs for that component.

> **Note:** Findings require manual validation. `known_affected` entries may be for packages that are not exploitable in container context (e.g. kernel-rt headers in development images). The tool flags *potential* false negatives for analyst review.
