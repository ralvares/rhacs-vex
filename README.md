# vextriage — Red Hat VEX triage for grype, trivy and syft

> Triage scanner findings against Red Hat's authoritative **CSAF-VEX**, and publish the
> verdicts as **OpenVEX** so grype and trivy drop the same false positives.

> [!IMPORTANT]
> **NOT A RED HAT PRODUCT — USE AT YOUR OWN RISK.** An independent, community tool, not
> affiliated with or supported by Red Hat. It is meant for Red Hat content (UBI / RHEL
> images, OpenShift, operators); for other software Red Hat's VEX says nothing and the
> scanner's finding stands.

Your scanner found 1,200 CVEs in an image. vextriage reads what Red Hat says about each
one — for this RHEL stream, this product version, this image build — and leaves you with
the ones that are real.

## Install

```bash
pip install -e .            # Python 3.10+; add .[archive] for the fast first sync
vextriage sync              # mirror Red Hat CSAF-VEX (~1.6 GB gzipped) and build the index (~800 MB)
vextriage doctor            # which of syft / grype / trivy are installed, data status
```

`sync` downloads Red Hat's dated archive once (~370 MB, 72,000+ documents; about 7
minutes), then only what changed (`changes.csv` / `deletions.csv`, seconds). Each document
is kept gzipped (`data/vex/CVE-….json.gz`): the corpus is ~22 GB as plain JSON. Run it
daily. Data lives in `./data` (`VEXTRIAGE_DATA` to move it).

## Use

```bash
# the free scan: syft SBOM against Red Hat VEX, no scanner
vextriage scan registry.redhat.io/ubi9/ubi:latest

# run a scanner and triage its findings
vextriage scan registry.redhat.io/openshift4/ose-cli-rhel9@sha256:… --scanner grype
vextriage scan registry.redhat.io/openshift4/ose-cli-rhel9@sha256:… --scanner trivy

# from files you already have (an SBOM makes it more precise)
vextriage scan --sbom sbom.syft.json --grype grype.json
vextriage scan --sbom sbom.syft.json --trivy trivy.json
vextriage scan --trivy trivy.json

# Red Hat's verdicts as OpenVEX, then let the scanners apply them
vextriage openvex IMAGE -o image.openvex.json
grype IMAGE --vex image.openvex.json
trivy image --vex image.openvex.json IMAGE

# why: every statement about one CVE and how it decided
vextriage explain CVE-2026-0915 --sbom sbom.syft.json
```

`scan` options: `--all` (show cleared rows too), `--json/--csv FILE` (every row),
`--openvex FILE`, `--stated-only` (OpenVEX with Red Hat's own statements only), `--fail`
(exit 1 when something is left to act on).

## What a verdict means

| status | meaning |
|---|---|
| `affected` | act on it: Red Hat lists it affected, or a fix exists that the image does not have, or Red Hat's VEX does not cover it |
| `under_investigation` | Red Hat has not decided yet |
| `fixed` | the installed build carries the fix |
| `not_affected` | Red Hat says so, or its data shows it (not listed for this stream, the code is not in this subpackage …) |

Every row says whether Red Hat **stated** it for this product and package, or it was
**inferred** from Red Hat's data (marked `*`). The rules, with the data behind each:
[docs/RULES.md](docs/RULES.md). What Red Hat's documents contain:
[docs/VEX-MODEL.md](docs/VEX-MODEL.md). `tools/vex_graph.py` turns the whole mirror into
one SQLite graph for checking any rule against all of the data.

## Layout

```
src/vextriage/
  csaf.py      CSAF-VEX document → statements; product classification (rhel / ocp / layered)
  index.py     SQLite index of the mirror        sync.py     Red Hat feed mirror
  sbom.py      syft JSON → image + packages      scanners.py grype / trivy JSON → findings
  engine.py    the verdict engine                 triage.py   candidates (free scan), orchestration
  openvex.py   OpenVEX writer                     report.py   table / JSON / CSV
  rpm.py version.py purl.py model.py cli.py
tests/         one test per rule, on synthetic Red Hat documents (pytest)
vexhub/        published OpenVEX repository (trivy --vex repo) — still the previous engine's output
```
