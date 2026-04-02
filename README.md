# vex-triage

Triage CVE findings from [RHACS](https://www.redhat.com/en/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes) against Red Hat's official [VEX](https://www.redhat.com/en/blog/red-hat-vex-files) data to automatically classify findings as **VULNERABLE** or **FALSE POSITIVE**, without ever accessing the running container.

## Setup

```bash
pip install -r requirements.txt
```

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>
```

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
| `--format` | Output format: `table` (default), `csv`, or `json` |
| `--output FILE` | Write output to a file |
| `--false-only` | Show only `FALSE POSITIVE` rows |
| `--sbom` | Print the full package list for `--image` (no container access needed) |
| `--workers N` | Parallel workers for `--ocp` / `--namespace` (default: 10) |

## Examples

### Single image

```bash
python3 triage.py --image "registry.redhat.io/advanced-cluster-security/rhacs-scanner-db-rhel8@sha256:6cc97529..." --false-only
```

### JSON output

```bash
python3 triage.py --image "registry.redhat.io/advanced-cluster-security/rhacs-scanner-db-rhel8@sha256:6cc97529..." \
  --false-only --format json --output /tmp/report.json
```

### All images in a namespace

```bash
python3 triage.py --namespace openshift-monitoring --false-only
```

### Full OCP release

```bash
oc adm release info 4.21.2 --pullspecs > 4.21.2.txt
python3 triage.py --ocp 4.21.2.txt --false-only --workers 30 --format csv --output ocp-4.21.2-triage.csv
```

### CSV mode (no API required)

```bash
python3 triage.py --scan scan.csv --image "registry.../myimage@sha256:..." --false-only
```

## Triage results

| Result | Meaning |
|--------|---------|
| `✅ FALSE POSITIVE` | VEX says this component is not affected |
| `✅ FALSE POSITIVE (fix backported)` | Installed RPM already includes the fix |
| `🔴 VULNERABLE` | No not-affected or fix statement found |
| `⚠️ Under investigation` | VEX exists but no verdict yet |
| `❓ VEX file missing` | No VEX advisory published for this CVE |

## Cache layout

```
data/
  vex/    ← cached VEX/CSAF advisories (one per CVE)
  sbom/   ← cached SPDX 2.3 SBOMs (one per scanned image)
```

Both caches are populated on first use. Delete a file to force a refresh.
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


