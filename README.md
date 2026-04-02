# vex-triage

Triage CVE findings from [Red Hat Advanced Cluster Security (RHACS)](https://www.redhat.com/en/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes) against Red Hat's official [VEX](https://www.redhat.com/en/blog/red-hat-vex-files) data to automatically classify findings as **VULNERABLE** or **FALSE POSITIVE**.

Red Hat publishes VEX (Vulnerability Exploitability eXchange) statements for every CVE, declaring exactly which product versions are affected or not affected, and why. This tool fetches those statements, cross-references them with what RHACS reports, and surfaces only the findings that actually matter.

---

## How it works

1. **Collects** CVE findings — from RHACS API (single image, namespace, or full OCP release) or a CSV export.
2. **Downloads** the relevant VEX JSON files from Red Hat's CSAF feed and caches them locally.
3. **Evaluates** each finding against the VEX file scoped to your exact workload context (RHEL version, OCP version, product family).
4. **Classifies** each finding:
   - `✅ FALSE POSITIVE` — Red Hat's VEX explicitly states this component is not affected in your product context.
   - `🔴 VULNERABLE` — the package is affected and no fix or not-affected statement applies.
   - `✅ FALSE POSITIVE (fix backported)` — an RPM fix is already present in the installed version.

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

### CSV mode (no API access required)

```bash
python3 triage.py --scan scan.csv --false-only
```

---

## Output

Each image produces a Rich table with one row per CVE finding. The tool auto-detects workload context (UBI, OCP, operator) from Docker labels and scopes VEX lookups accordingly.

Example — RHACM operator image with `--false-only`:

```
Image: registry.redhat.io/rhacm2/multicluster-operators-subscription-rhel9@sha256:58f24f4a...
OS: rhel:9
Found: 112 CVE findings across 38 components
Context: type=operator  rhel=9  display=RHACM 2.16 (RHEL 9)
VEX scope: registry.redhat.io/rhacm2/, rhacm2/, red_hat_advanced_cluster_management_for_kubernetes_2

🔄 Syncing 80 CVEs into /vex folder...
✅ Sync Complete in 1.25s.
🚀 Running Structured Audit — context: RHACM 2.16 (RHEL 9)

                       VEX Triage Report — RHACM 2.16 (RHEL 9)
╭──────────────────────────────┬─────────────────────┬───────────┬───────────────────┬─────┬─────────────────────────────────╮
│ Component                    │ Product             │ Severity  │ Result            │ Fix │ Justification                   │
├──────────────────────────────┼─────────────────────┼───────────┼───────────────────┼─────┼─────────────────────────────────┤
│ google.golang.org/grpc       │ RHACM 2.16 (RHEL 9) │ Important │ ✅ FALSE POSITIVE │ N/A │ Non-RPM — not affected in       │
│                              │                     │           │                   │     │ RHACM 2.16 (vulnerable code     │
│                              │                     │           │                   │     │ not present or not executable). │
├──────────────────────────────┼─────────────────────┼───────────┼───────────────────┼─────┼─────────────────────────────────┤
│ stdlib                       │ RHACM 2.16 (RHEL 9) │ Important │ ✅ FALSE POSITIVE │ N/A │ Non-RPM — not affected in       │
│                              │                     │           │                   │     │ RHACM 2.16 (vulnerable code     │
│                              │                     │           │                   │     │ not present or not executable). │
├──────────────────────────────┼─────────────────────┼───────────┼───────────────────┼─────┼─────────────────────────────────┤
│ github.com/cloudflare/circl  │                     │ Moderate  │ ✅ FALSE POSITIVE │ N/A │ Red Hat Product Security states │
│                              │                     │           │                   │     │ no currently supported Red Hat  │
│                              │                     │           │                   │     │ product is affected by this CVE.│
╰──────────────────────────────┴─────────────────────┴───────────┴───────────────────┴─────┴─────────────────────────────────╯

  ✅ FALSE POSITIVE: 7
```

The **Product** column shows a shortened label derived from VEX data — e.g. `RHACM 2.16 (RHEL 9)`, `OCP 4.21`, `RHEL 9 AppStream`, `Ceph 8.1`. An empty Product cell means the CVE was dismissed at the vendor level (Red Hat Product Security states no supported product is affected).

---

## VEX cache

Downloaded VEX JSON files are cached locally under:

```
vex_knowledge/vex/<CVE-ID>.json
```

Only missing CVEs are fetched — subsequent runs against the same CVE set are instant.

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `ROX_ENDPOINT` | RHACS Central hostname and port, e.g. `central-stackrox.apps.mycluster.com:443` |
| `ROX_API_TOKEN` | RHACS API token with image read access |
