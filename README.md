# RHACS Triage - Done Right

**Your scanner found 300 CVEs. How many actually matter?**

Most VEX triage tools do one thing: look up a CVE ID in an advisory file and echo back "not affected". That's not triage - that's a string match with extra steps.

## Why we are different

RHACS is a powerful scanner - it knows the image, the packages, the CVEs, the product labels. But it still produces false positives. A package version in the scan results may not match what's actually installed. A CVE may be flagged for a component that Red Hat's own advisory explicitly marks as not affected for that exact product and RHEL version. Without cross-referencing that signal, every analyst ends up chasing ghosts.

This tool takes the RHACS scan results and cross-checks them against three authoritative sources - Red Hat VEX/CSAF advisories, SPDX SBOMs, and RPM version data - to separate real vulnerabilities from noise:

| Layer | What it does |
|-------|-------------|
| **Image context detection** | Parses the image reference and live RHACS labels/CPEs to automatically determine product type (OCP, RHACM, UBI, operator, …), RHEL base version, and product release version - with no manual input |
| **Scoped VEX cross-reference** | Fetches the authoritative Red Hat CSAF/VEX advisory for each CVE and scopes it to the *specific product and version* the image belongs to - not just "any Red Hat product" |
| **SBOM version verification** | Pulls the SPDX 2.3 SBOM from RHACS and cross-checks every flagged component version against what is actually installed in the image - catching ghost versions left over from stale scan data |
| **RPM backport detection** | Compares the installed RPM against the VEX fix version using proper RPM version comparison, automatically closing findings where the patch is already present |

A finding is only marked **FALSE POSITIVE** when all of the following are true: the VEX says not-affected *for the right product and RHEL version*, the component version is confirmed in the SBOM, and (for RPMs) the installed version is at or beyond the fix. Everything else stays open.

No image pull. No container runtime. Works fully offline once the VEX and SBOM caches are populated.

---

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
| `--ocp FILE` | Triage every component in an OCP release manifest (`oc adm release info --pullspecs`) |
| `--scan FILE` | Triage from an RHACS CSV export instead of the live API |
| `--format` | Output format: `table` (default), `csv`, or `json` |
| `--output FILE` | Write output to a file (for `csv` / `json`) |
| `--false-only` | Show only `FALSE POSITIVE` rows |
| `--sbom` | Print the full package list for `--image` - no container access needed |
| `--workers N` | Parallel image workers for `--ocp` / `--namespace` (default: 10) |

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

## Cache layout

```
data/
  vex/    ← VEX/CSAF advisories fetched from access.redhat.com (one file per CVE)
  sbom/   ← SPDX 2.3 SBOMs fetched from RHACS (one file per image digest)
```

Both caches are populated on first use. Delete a file to force a refresh.

