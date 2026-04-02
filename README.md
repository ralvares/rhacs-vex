# vex-triage

Triage CVE findings from [Red Hat Advanced Cluster Security (RHACS)](https://www.redhat.com/en/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes) against Red Hat's official [VEX](https://www.redhat.com/en/blog/red-hat-vex-files) data to automatically classify findings as **VULNERABLE** or **FALSE POSITIVE**, and confirm every reported component version against the image's SBOM — without ever accessing the running container.

---

## How it works

### 1. Collect CVE findings from RHACS

The tool fetches the full image scan from the RHACS API (or reads a CSV export). Each row is a CVE + component + version tuple — the raw vulnerability report as RHACS sees it.

### 2. Download and cache VEX statements

For each unique CVE in the scan, the tool fetches Red Hat's official [CSAF/VEX](https://access.redhat.com/security/data/csaf/v2/advisories/) JSON file and caches it under `data/vex/<CVE-ID>.json`. Only missing files are fetched on subsequent runs.

VEX (Vulnerability Exploitability eXchange) files contain Red Hat's authoritative statement about which product versions are affected by a CVE and why — including explicit `not_affected` flags such as:

- `vulnerable_code_not_present` — the vulnerable code path does not exist in this build
- `component_not_present` — the affected sub-component is not shipped
- `vulnerable_code_not_in_execute_path` — the code is present but never reachable
- `inline_mitigations_already_exist` — a backported patch already neutralises the vulnerability

### 3. Determine workload context

This is the critical step. A CVE may be "not affected" for **RHEL 9 AppStream** but still affect **OpenShift 4.21**. Scoping to the wrong product would produce wrong results in either direction.

The tool determines context automatically from the container image's Docker labels (specifically the `com.redhat.component` and `vendor` CPE fields). It builds a `WorkloadContext` that captures:

| Field | Example | Description |
|-------|---------|-------------|
| `workload_type` | `ocp`, `operator`, `ubi` | Whether this is an OCP core image, an operator, or a plain RHEL/UBI image |
| `rhel_ver` | `8`, `9` | RHEL major version the image is built on |
| `ocp_ver` | `4.21` | OCP version for OCP/operator images |
| `display_name` | `RHACM 2.16 (RHEL 9)` | Human-readable label used in reports |
| `extra_prefixes` | `red_hat_advanced_cluster_management_2` | Additional VEX product-ID prefixes scoped to this workload |

When evaluating a VEX file, the tool only accepts `not_affected` statements whose `product_id` matches the computed scope — e.g. an OCP 4.21 image will not be cleared by a RHEL 8 AppStream not-affected entry.

### 4. Evaluate each finding against VEX

For every CVE row the tool:

1. Loads the cached VEX JSON for that CVE.
2. Finds all `not_affected` or `fixed` statements in the VEX file.
3. Checks whether the component version installed in the image falls within the applicable product scope.
4. Compares installed RPM version against the `fixed_version` using proper RPM version comparison (`version_utils.rpm`).

The result is one of:

| Result | Meaning |
|--------|---------|
| `✅ FALSE POSITIVE` | VEX explicitly says this component is not affected in your product context |
| `✅ FALSE POSITIVE (fix backported)` | The installed RPM version already includes the fix |
| `🔴 VULNERABLE` | No not-affected or fix statement found |
| `⚠️ Under investigation` | VEX exists but no verdict has been issued yet |
| `❓ VEX file missing` | CVE has no published VEX advisory |

### 5. SBOM cross-check — confirming the data is real

After triage, the tool fetches an **SPDX 2.3 SBOM** directly from the RHACS API (`POST /api/v1/images/sbom`) and cross-references every unique component+version that appeared in the triage results against the packages actually present in the image.

This answers the question: *"Is the version RHACS reported actually what's installed?"*

SBOMs are fetched once and cached locally under:
```
data/sbom/<registry>_<image-name>@sha256:<digest>.sbom
```

The SBOM check produces a one-line summary after the triage table:
```
🔍 SBOM verified: 17/17 component versions confirmed in image
```

If any component version in the triage report does not match the SBOM, it is listed as a warning — indicating a potential scanner metadata issue that deserves manual review.

**Why not just `exec` into the container?**  
Running `rpm -qa` on the container requires either the RPM binary to be present (it often isn't in minimal images) or re-deploying the image as a debug pod. The SBOM endpoint returns the complete package manifest directly from RHACS, with no cluster access needed beyond a read-only API token.

---

## Prerequisites

```bash
pip install requests pandas rich version-utils packageurl-python
```

Set environment variables for RHACS API access:

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>
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
| `--ocp FILE` | Triage every component in an OCP release manifest |
| `--scan FILE` | Triage from an RHACS CSV export instead of the API |
| `--format` | Output format: `table` (default, terminal), `csv`, or `json` |
| `--output FILE` | Output file path (e.g. `report.json`). No-op with `--format table` |
| `--false-only` | Show only `FALSE POSITIVE` rows (noise-free output) |
| `--sbom` | Print the full SBOM package list for `--image` (like `rpm -qa`, no container access needed) |
| `--workers N` | Parallel workers for `--ocp` / `--namespace` (default: 10) |

---

## Examples

### Single image — table output with SBOM verification

```bash
python3 triage.py \
  --image "registry.redhat.io/advanced-cluster-security/rhacs-scanner-db-rhel8@sha256:6cc97529..." \
  --false-only
```

Output ends with:
```
  ✅ FALSE POSITIVE: 27

🔍 Verifying component versions against SBOM...
  🔍 SBOM verified: 17/17 component versions confirmed in image
```

### Single image — JSON output to a file

```bash
python3 triage.py \
  --image "registry.redhat.io/advanced-cluster-security/rhacs-scanner-db-rhel8@sha256:6cc97529..." \
  --false-only \
  --format json \
  --output /tmp/scanner-db-triage.json
```

### Inspect what packages are installed in an image (no container access)

```bash
python3 triage.py \
  --image "registry.redhat.io/advanced-cluster-security/rhacs-scanner-db-rhel8@sha256:6cc97529..." \
  --sbom
```

Fetches and displays the SPDX 2.3 SBOM from RHACS — a `rpm -qa` equivalent without exec-ing into the container. Result is cached to `data/sbom/`.

### All images in a namespace

```bash
python3 triage.py --namespace openshift-monitoring --false-only
```

### Full OCP release — parallel scan

Generate the pullspecs file first:

```bash
oc adm release info 4.21.2 --pullspecs > 4.21.2.txt
```

Then triage all ~800 component images:

```bash
python3 triage.py --ocp 4.21.2.txt --false-only --workers 30 --format csv --output ocp-4.21.2-triage.csv
```

The tool reads the `Name:` field from the manifest header and enforces the release version (e.g. `4.21.2`) for every component image — even those promoted from an earlier minor release — so VEX scoping is always correct.

### CSV mode (no API access required)

```bash
python3 triage.py --scan scan.csv --image "registry.../myimage@sha256:..." --false-only
```

`--image` in CSV mode provides workload context (RHEL version, product family) without triggering an API scan.

---

## Data directory layout

```
data/
  vex/
    CVE-2024-1234.json      ← cached VEX/CSAF advisories (one per CVE)
    CVE-2025-5678.json
    ...
  sbom/
    registry.redhat.io_advanced-cluster-security_rhacs-scanner-db-rhel8@sha256:6cc97529....sbom
    ...                     ← cached SPDX 2.3 SBOMs (one per scanned image)
```

Both caches are populated on first use and reused on subsequent runs. Delete the relevant file to force a refresh.

---

## Output columns

| Column | Description |
|--------|-------------|
| Component | Package or module name as reported by RHACS |
| Product | Abbreviated VEX product scope used for the verdict (e.g. `OCP 4.21`, `RHEL 9 AppStream`, `RHACM 2.16`) |
| Version | Installed version |
| CVE | CVE identifier |
| Severity | RHACS severity rating |
| Result | Triage verdict |
| Fix Version | Version in which the fix is available (`N/A` if not applicable) |
| Justification | Human-readable reason for the verdict |

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `ROX_ENDPOINT` | RHACS Central hostname and port, e.g. `central-stackrox.apps.mycluster.com:443` |
| `ROX_API_TOKEN` | RHACS API token with image read access |


---

## Prerequisites

```bash
pip install requests pandas rich version-utils packageurl-python
```

Set environment variables for RHACS API access:

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>
```

---

## Usage

```
python3 triage.py [--image IMAGE_REF]
                  [--namespace NAMESPACE]
                  [--ocp PULLSPECS_FILE]
                  [--scan CSV_FILE]
                  [--false-only]
                  [--workers N]
```

| Flag | Description |
|------|-------------|
| `--image IMAGE_REF` | Triage a single image by digest or tag |
| `--namespace NS` | Triage all images deployed in a Kubernetes namespace |
| `--ocp FILE` | Triage every component in an OCP release manifest |
| `--scan FILE` | Triage from an RHACS CSV export instead of the API |
| `--false-only` | Show only `FALSE POSITIVE` rows (noise-free output) |
| `--workers N` | Parallel workers for `--ocp` / `--namespace` (default: 10) |

---

## Examples

### Single image

```bash
python3 triage.py \
  --image "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:046f5864..." \
  --false-only
```

### All images in a namespace

```bash
python3 triage.py --namespace openshift-monitoring --false-only
```

### Full OCP release — parallel scan

Generate the pullspecs file first:

```bash
oc adm release info 4.21.2 --pullspecs > 4.21.2.txt
```

Then triage all ~800 component images:

```bash
python3 triage.py --ocp 4.21.2.txt --false-only --workers 30
```

The tool reads the `Name:` field from the manifest header to ensure every component is evaluated against the correct release (e.g. `4.21.2`), even if an individual image was built/promoted from an earlier minor release.

### RHACM operator image

```bash
python3 triage.py \
  --image "registry.redhat.io/rhacm2/multicluster-operators-subscription-rhel9@sha256:58f24f4a9869b9fc5f67dfe5aed1bdaae61880654b20c750e17ca12867b1d9a4" \
  --false-only
```

```
Image: registry.redhat.io/rhacm2/multicluster-operators-subscription-rhel9@sha256:58f24f4a...
Mode: RHACS API  endpoint=central-stackrox.apps.mycluster.com:443
🔍 Searching for image in RHACS...
✅ Found image ID: sha256:58f24f4a9869b9fc5f67dfe5aed1bdaae61880654b20c750e17ca12867b1d9a4
📥 Fetching full scan data...
🏷  Labels found — refining context from CPE...
OS: rhel:9
Found: 112 CVE findings across 38 components
Context: type=operator  rhel=9  display=RHACM 2.16 (RHEL 9)
VEX scope: registry.redhat.io/rhacm2/, rhacm2/, red_hat_advanced_cluster_management_for_kubernetes_2, multicluster_global_hub

🔄 Syncing 80 CVEs into /vex folder...
✅ Sync Complete in 1.25s.
🚀 Running Structured Audit — context: RHACM 2.16 (RHEL 9)

                       VEX Triage Report — RHACM 2.16 (RHEL 9)
╭──────────────────────────────┬─────────────────────┬────────┬────────────────┬───────────┬───────────────────┬─────────┬───────────────────────────────────────────╮
│ Component                    │ Product             │ Ver.   │ CVE            │ Severity  │ Result            │ Fix Ver │ Justification                             │
├──────────────────────────────┼─────────────────────┼────────┼────────────────┼───────────┼───────────────────┼─────────┼───────────────────────────────────────────┤
│ google.golang.org/grpc       │ RHACM 2.16 (RHEL 9) │ v1.… │ CVE-2025-…    │ Important │ ✅ FALSE POSITIVE │ N/A     │ Non-RPM — not affected in RHACM 2.16     │
│ google.golang.org/grpc       │ RHACM 2.16 (RHEL 9) │ v1.… │ CVE-2025-…    │ Important │ ✅ FALSE POSITIVE │ N/A     │ Non-RPM — not affected in RHACM 2.16     │
│ google.golang.org/grpc       │ RHACM 2.16 (RHEL 9) │ v1.… │ CVE-2025-…    │ Important │ ✅ FALSE POSITIVE │ N/A     │ Non-RPM — not affected in RHACM 2.16     │
│ google.golang.org/grpc       │ RHACM 2.16 (RHEL 9) │ v1.… │ CVE-2025-…    │ Important │ ✅ FALSE POSITIVE │ N/A     │ Non-RPM — not affected in RHACM 2.16     │
│ stdlib                       │ RHACM 2.16 (RHEL 9) │ 1.2… │ CVE-2025-…    │ Important │ ✅ FALSE POSITIVE │ N/A     │ Non-RPM — not affected in RHACM 2.16     │
│ github.com/cloudflare/circl  │                     │ v1.…  │ CVE-2025-…    │ Moderate  │ ✅ FALSE POSITIVE │ N/A     │ Red Hat Product Security states no        │
│                              │                     │        │                │           │                   │         │ currently supported Red Hat product is    │
│                              │                     │        │                │           │                   │         │ affected by this CVE.                     │
│ github.com/cloudflare/circl  │                     │ v1.…  │ CVE-2025-…    │ Moderate  │ ✅ FALSE POSITIVE │ N/A     │ Red Hat Product Security states no        │
│                              │                     │        │                │           │                   │         │ currently supported Red Hat product is    │
│                              │                     │        │                │           │                   │         │ affected by this CVE.                     │
╰──────────────────────────────┴─────────────────────┴────────┴────────────────┴───────────┴───────────────────┴─────────┴───────────────────────────────────────────╯

  ✅ FALSE POSITIVE: 7
```


