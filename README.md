# vex-triage

Triage CVE findings from [RHACS](https://www.redhat.com/en/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes) against Red Hat's official [VEX/CSAF](https://www.redhat.com/en/blog/red-hat-vex-files) advisories to automatically classify findings as **VULNERABLE** or **FALSE POSITIVE**, without ever accessing the running container.

VEX advisories and SPDX SBOMs are fetched on demand and cached locally under `data/`. No image pull or container runtime is required.

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
| `--sbom` | Print the full package list for `--image` — no container access needed |
| `--workers N` | Parallel image workers for `--ocp` / `--namespace` (default: 10) |

> **On-demand scan**: if the requested image is not already indexed in RHACS, the tool automatically triggers a scan via `POST /v1/images/scan` and waits for the result (up to 5 minutes).

## Output formats

| Format | Behaviour |
|--------|-----------|
| `table` | Pretty Rich table printed to the terminal (default) |
| `json` | Clean JSON array on stdout — no headers or emoji |
| `csv` | CSV on stdout or to `--output FILE` — no emoji |

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

### Full OCP release — parallel scan

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

## Cache layout

```
data/
  vex/    ← VEX/CSAF advisories fetched from access.redhat.com (one file per CVE)
  sbom/   ← SPDX 2.3 SBOMs fetched from RHACS (one file per image digest)
```

Both caches are populated on first use. Delete a file to force a refresh.

