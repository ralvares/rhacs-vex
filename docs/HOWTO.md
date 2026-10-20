# HOWTO — vextriage in 10 minutes

One engine, two ways to use it:

1. **Publish** Red Hat's verdicts as OpenVEX (syft SBOM + Red Hat VEX, no scanner),
   then let grype or trivy apply them.
2. **Triage** what a scanner (grype, trivy, RHACS) or the SBOM itself proposes, as a
   table, CSV or one HTML report.

Run every command from the repository root: data lives under `./data` and the hub under
`./vexhub` by relative path.

## 0. Setup

```bash
pip install -e .
vextriage doctor           # tools, credentials, data
vextriage sync             # first run: Red Hat VEX (tarball) + OSV exports + index
```

After the first sync, `vextriage sync` fetches only what changed (run it daily, or let
any command refresh a mirror older than a day). Afterwards everything works offline.

### Registry credentials

The pull secret from [console.redhat.com](https://console.redhat.com/openshift/install/pull-secret)
is a docker-config file. One variable covers syft, skopeo, oc and opm:

```bash
export REGISTRY_AUTH_FILE=~/pullsecret.txt
```

(or `docker login`: without `REGISTRY_AUTH_FILE`, `~/.docker/config.json` is used).
grype and trivy read the cached SBOM, not the registry.

## 1. Publish OpenVEX

### One image

```bash
vextriage openvex registry.redhat.io/openshift4/ose-cli-rhel9@sha256:<digest> -o ose-cli.openvex.json
vextriage openvex data/syft/<image>.json --image <ref@sha256:…> --hub vexhub   # from an SBOM
```

The summary shows the candidate pairs per source (rpm, image, Go/Python/npm/Maven), how
many were cleared, and how many of those Red Hat stated for this build vs inferred.
`--stated-only` publishes stated verdicts only; `--grype` adds grype's findings as
candidates; `--ocp-release 4.20.3` scopes a payload image whose release is not in
`data/pullspecs`.

### Is it right? Check with the scanner

```bash
vextriage check <ref@sha256:…>                    # grype before/after the OpenVEX
vextriage check <ref@sha256:…> --scanner trivy
vextriage check sbom.syft.json --image <ref@sha256:…> -o remaining.json
```

`check` uses the hub document when the image has one (`--hub ""` to always generate) and
prints what is still reported: the list to act on.

### Many images — a hub

```bash
oc adm release info 4.20.3 --pullspecs > data/pullspecs/4.20.3.txt
opm render registry.redhat.io/redhat/redhat-operator-index:v4.20 > data/catalogs/catalog-4.20.json

vextriage generate --ocp 4.20.3               --hub vexhub
vextriage generate --operators --catalog 4.20 --hub vexhub
vextriage generate --images my-images.txt     --hub vexhub --workers 8
vextriage generate --image <ref@sha256:…>     --hub vexhub --verify
```

- `--resume` skips digests already in their document (interrupted runs).
- `--verify` re-scans every image with trivy against its document; any statement that
  does not suppress fails the run.
- `vextriage hub --prune` drops statements for digests that left the release lists and
  channel heads; `vextriage hub --base-url https://… --archive` publishes the archive.zip
  trivy's repository mode downloads.

### Consume it

```bash
grype <ref@sha256:…> --vex vexhub/pkg/oci/<registry>/<ns>/<name>/scan.openvex.json

# trivy: ~/.trivy/vex/repository.yaml
#   repositories:
#     - name: my-vexhub
#       url: https://github.com/<you>/<vexhub-repo>
#       enabled: true
trivy image <ref@sha256:…> --vex repo
```

## 2. Triage tables

```bash
vextriage scanfree <ref@sha256:…>                       # no scanner: VEX index + OSV candidates
vextriage grype    <ref@sha256:…> --output grype.csv    # grype's findings
vextriage grype    <ref@sha256:…> --vex-index           # + rpm/image pairs grype's DB lacks
vextriage trivy    <ref@sha256:…>
```

The table shows what needs action; `--all-rows` shows the false positives too,
`--false-only` only them. `--output` always writes every row (CSV, or `--format json`).

### RHACS

```bash
export ROX_ENDPOINT=central.example.com:443 ROX_API_TOKEN=<token>
vextriage rhacs <ref@sha256:…>
vextriage rhacs --namespace payments --output payments.csv
vextriage rhacs --ocp data/pullspecs/4.20.3.txt --workers 10
vextriage rhacs scan-export.csv --image <ref@sha256:…>    # a RHACS CSV export, no Central
vextriage rhacs --ocp data/pullspecs/4.20.3.txt --offline # re-triage the cached scans
```

### A RHACS report as one HTML file

```bash
vextriage report Report-RHACS.csv -o report.html --ocp 4.20
vextriage report Report-RHACS.csv -o live.html --rescan   # scan every image again today
```

## 3. Evidence for review

On a machine with registry access:

```bash
pip install zstandard
tests/collect_local_evidence.sh <ref@sha256:…> [<ref@sha256:…> …]
```

It syncs, SBOMs each image, generates the OpenVEX (inferred and stated-only), runs grype
with and without it, and the scanfree table — then packs everything into
`evidence.parquet` (the exact files, zstd; `python3 tests/evidence_parquet.py unpack
evidence.parquet out/` restores them).

## 4. Tests

```bash
python3 tests/test_engine_regressions.py
python3 tests/test_module_streams.py
python3 tests/test_scanfree.py
```

Offline, synthetic VEX documents, seconds. `tests/check_baseline.py` and
`tests/test_verdict_cases.py` need cached RHACS scans under `data/scans/`.
