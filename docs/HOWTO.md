# HOWTO — vextriage in 10 minutes

Two independent workflows, one engine:

1. **RHACS triage** — scan with RHACS Central, triage against Red Hat VEX, get CSV
   reports, parquet files and the static explorer UI.
2. **OpenVEX generation** — scan with syft+grype (no RHACS needed), export the
   FALSE-POSITIVE verdicts as OpenVEX documents that trivy and grype consume.

> Run **every** command from the repository root — all tools read/write `./data`
> and `./vexhub` by relative path.

## 0. Setup

```bash
pip3 install -e .          # installs the `vextriage` CLI
vextriage doctor           # check tools, auth env, discovery/cache artifacts
```

External tools by workflow:

| Workflow | Needs |
|----------|-------|
| RHACS triage | reachable RHACS Central only (`ROX_ENDPOINT` + `ROX_API_TOKEN`) |
| Discovery (catalogs + pullspecs) | `oc`, `opm` + Red Hat [pull secret](https://console.redhat.com/openshift/install/pull-secret) (`podman` optional — login convenience only) |
| OpenVEX generation | `syft`, `grype` (+ `trivy` for `--verify`; `skopeo` only as label fallback for scratch images) |

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>
```

### Registry auth — no podman needed

The pull secret from console.redhat.com **is** a docker-config file (`{"auths": …}`).
Two env vars cover every tool; set them once per shell:

```bash
# skopeo + opm read this directly
export REGISTRY_AUTH_FILE=~/pullsecret.txt

# syft (and some opm builds) want a directory containing a file named config.json
mkdir -p ~/.vextriage-auth && cp ~/pullsecret.txt ~/.vextriage-auth/config.json
export DOCKER_CONFIG=~/.vextriage-auth
```

Who needs what: **syft** pulls images (`DOCKER_CONFIG`), **opm**/**oc** fetch
catalogs/pullspecs (either var — the pipeline sets both, `oc` also takes
`--registry-config FILE`). **grype** never touches the registry here — it scans
the cached SBOM file. Image labels (workload context) come from the SBOM / trivy
report themselves; **skopeo** (`REGISTRY_AUTH_FILE`) is only the fallback when
they carry none. `podman login` (pipeline stage 0) just validates credentials;
skip it with `--skip-login` when the env vars are set.

---

## Part 1 — RHACS triage

### One image

```bash
vextriage rhacs --image registry.redhat.io/openshift4/ose-cli@sha256:4f2e216ad46aa75f84e27aa2e6303327b99a4331c7ed8ef65850102898f3a9b0
```

Colour table: scanner severity vs Red Hat severity, verdict (`POSITIVE` /
`FALSE POSITIVE`), fix version, justification. Not indexed yet? The tool triggers
an on-demand RHACS scan and waits.

Variants:

```bash
vextriage rhacs --namespace my-app                  # every image in a k8s namespace
vextriage rhacs --ocp data/pullspecs/4.20.0.txt     # every component of an OCP release
vextriage rhacs --image <ref> --format csv --output report.csv
vextriage rhacs --image <ref> --false-only          # only the suppressible noise
```

### Everything at once — the pipeline

```bash
vextriage pipeline --pull-secret ~/pullsecret.txt
```

Stages (each skippable with `--skip-*`):

| Stage | Does |
|:---:|------|
| 0 | `podman login` to Red Hat registries |
| 1 | `opm` renders operator catalogs → `data/catalogs/catalog-<minor>.json` |
| 2 | namespace → VEX-prefix map |
| 3 | `oc adm release info --pullspecs` → `data/pullspecs/<ver>.txt` |
| 4 | RHACS triage of every OCP release → `data/reports/ocp-<ver>.csv` |
| 5 | RHACS triage of all channel-head operators → `data/reports/operators/*.csv` |
| 6 | *(opt-in)* offline operator verdict refresh |
| 7 | OpenVEX hub generation (see Part 2) — `--skip-openvex` to disable |

OCP version list is embedded (override: `--versions my.csv`, CSV with a `Version`
column). Interrupted? Re-run with `--skip-existing`.

Operators standalone (without the pipeline):

```bash
vextriage operators --version 4.21,4.22        # minors from data/catalogs/
vextriage operators --operator amq-streams     # single package
```

### Refresh verdicts offline

Red Hat updates VEX daily; your cached scans don't age. Recompute verdicts with
zero network / zero Central load:

```bash
vextriage retriage                                  # everything
vextriage retriage --operators-only --version 4.21,4.22
```

### Parquet files + explorer

Turn the CSV reports into the browsable dataset:

```bash
vextriage parquet
```

Output:

```
data/parquet/ocp/<version>.parquet    one per OCP release
data/parquet/operators/…              per-operator parquet
data/parquet/cve-index.parquet        lightweight CVE × version index
data/manifest.json                    summary stats per scope
```

Flags: `--version 4.21.15` (single release), `--manifest-only` (rebuild
`manifest.json` from existing parquets), `--legacy` (also write combined
`data/ocp.parquet`).

Explore:

```bash
python3 -m http.server 8080     # then open http://localhost:8080
```

`index.html` queries the parquet files client-side — search by CVE, package,
image or operator.

---

## Part 2 — OpenVEX generation (no RHACS)

Hub documents are minted **only** from consumer-side scans (syft+grype): the purls
come from the scanner's own artifacts, so grype/trivy are guaranteed to match them.
RHACS triage output is never converted to OpenVEX.

### One image

```bash
# scan + triage + write the OpenVEX doc into the hub
vextriage grype registry.access.redhat.com/ubi8/ubi@sha256:<digest> --openvex-dir vexhub/

# trivy as the scanner works too
vextriage trivy <ref@sha256:…> --openvex-dir vexhub/
```

Refs must be **digest-pinned** — the digest is the OpenVEX product identity.

### Batch — images, OCP versions, operators

```bash
vextriage generate --image <ref@sha256:…>                 # single image
vextriage generate --images my-images.txt                 # file of digest-pinned refs
vextriage generate --ocp 4.20.0                           # one OCP release
vextriage generate --ocp 4.20.0,4.21.0,4.22.0             # several
vextriage generate --operators                            # all catalogs' channel heads
vextriage generate --operators --catalog 4.20             # one catalog only
```

- `--ocp` reads `data/pullspecs/<ver>.txt`, `--operators` reads
  `data/catalogs/catalog-*.json` — produced by pipeline stages 3 / 1, or by hand
  (next section).
- Re-runs are idempotent: docs merge per image, new digests append, versions bump
  only on real change. A re-scan of a digest also **retracts** statements that no
  longer hold (verdicts move as Red Hat updates its VEX).
- Three caches make re-runs cheap: SBOMs (`data/syft/`, immutable per digest),
  grype results (`data/scans/grype/`, valid per vulnerability-DB build — same-day
  re-runs skip grype entirely), and Red Hat VEX files (`data/vex/`, revalidated
  by ETag after 4 h).
- `--workers N` parallelizes; scanning threads feed a separate CPU worker pool,
  so the triage step actually uses your cores. `--force` regenerates cached SBOMs.
- `--resume` skips digests already present in their hub doc — restarts only pay
  for the tail. Use it for interrupted runs, NOT for a correctness sweep (a sweep
  must re-audit everything).
- `--crosscheck` re-checks every emitted statement against the raw Red Hat VEX
  files with independent rules (seconds, offline) and prints any statement whose
  answer differs from Red Hat's. Mismatches naming another RHEL major or an old
  OpenShift are scope noise; anything else deserves a look.
- Images without an amd64 build (e.g. OpenJ9 = Power/Z only) automatically fall
  back to a platform the image's index does carry.
- Scope: statements come from the **linux/amd64** build (images without an
  amd64 child fall back to whatever the index carries). Product identity is
  the multi-arch list digest and subcomponent purls are arch-less, so
  suppression works for consumers on any platform pulling the pinned ref —
  packages exclusive to non-amd64 children are simply not covered.

All OCP versions on disk, checkpointed per release:

```bash
for v in $(ls data/pullspecs | sed 's/\.txt$//' | sort -V); do
  vextriage generate --ocp "$v" --workers 8
done
vextriage generate --operators --workers 8
```

Or let the pipeline do all of it — **stage 7** runs exactly that loop. Without
RHACS credentials:

```bash
vextriage pipeline --pull-secret ~/pullsecret.txt --skip-ocp --skip-operators
```

(discovery stages still fetch catalogs + pullspecs; RHACS triage is skipped;
stage 7 generates the hub.)

### Discovery artifacts by hand (no pipeline)

Both inputs are plain files — fetch them yourself with `oc` and `opm`
(auth via the env vars from Setup):

**OCP release pullspecs** → `data/pullspecs/<full-version>.txt`, one file per
release. The filename **is** the version — it also drives the OpenVEX product
scope for release images:

```bash
VER=4.20.0
oc adm release info "quay.io/openshift-release-dev/ocp-release:${VER}-x86_64" \
   --pullspecs --registry-config ~/pullsecret.txt \
   > "data/pullspecs/${VER}.txt"
```

**Operator index catalogs** → `data/catalogs/catalog-<minor>.json`, one per OCP
minor. Big (100–170 MB) and slow to render — do it once, refresh weekly:

```bash
MINOR=4.20
opm render "registry.redhat.io/redhat/redhat-operator-index:v${MINOR}" -o json \
   > "data/catalogs/catalog-${MINOR}.json"
```

(Some `opm` builds ignore `REGISTRY_AUTH_FILE` — that's what the `DOCKER_CONFIG`
fallback in Setup is for.) Then `vextriage generate --ocp 4.20.0` /
`--operators --catalog 4.20` work without ever running the pipeline.

### Trust gate

```bash
vextriage generate --image <ref@sha256:…> --verify
```

Re-scans each image with trivy against its own document — fails on any statement
that does not actually suppress. Use before publishing.

### The hub

```
vexhub/
  vex-repository.json                        repository manifest (+ .well-known/ copy)
  index.json                                 purl → document location
  pkg/oci/<registry>/<ns>/<name>/scan.openvex.json
```

Rebuild the index without scanning: `vextriage hub`.

Housekeeping — drop statements for digests that rotated out of the current
pullspecs/catalogs (images generated outside discovery are never touched):

```bash
vextriage hub --prune
```

### Consuming

```bash
# trivy — native VEX repository support (~/.trivy/vex/repository.yaml):
#   repositories:
#     - name: my-vexhub
#       url: https://github.com/<you>/<vexhub-repo>
#       enabled: true
trivy image <ref@sha256:…> --vex repo

# grype — file-based, path derivable from the image ref:
grype <ref@sha256:…> --vex vexhub/pkg/oci/<registry>/<ns>/<name>/scan.openvex.json
```

Known limitation: trivy **repo-mode** can't suppress base-image-layer RPM findings
(file mode can); golang findings — the dominant false-positive class — are
unaffected. Details: [OPENVEX-SPIKE-RESULTS.md](OPENVEX-SPIKE-RESULTS.md).

---

## Cheat sheet

```bash
vextriage doctor                                     # system check
vextriage rhacs --image <ref>                        # RHACS triage, one image
vextriage pipeline --pull-secret ~/ps.txt            # everything: reports + hub
vextriage retriage                                   # refresh verdicts offline
vextriage parquet                                    # CSVs → parquet + manifest
vextriage generate --ocp <ver> | --operators | --images FILE   # OpenVEX hub
vextriage generate --image <ref> --verify            # publish gate
vextriage generate ... --crosscheck                  # second opinion vs Red Hat VEX
vextriage generate ... --resume                      # resume interrupted run
vextriage hub                                        # reindex only
vextriage hub --prune                                # drop rotated-out digests
```
