# vextriage — Red Hat VEX Triage, Done Right

> Scan images with **RHACS**, **grype** or **trivy** → triage against authoritative
> **Red Hat CSAF-VEX** → optionally export the verdicts as **OpenVEX** in a
> [VEX repository](https://github.com/aquasecurity/vex-repo-spec) ("vexhub") that
> trivy and grype consume to silence the same false positives.
> *(formerly `rhacs-vex` — the old console scripts still work, see Install)*

> [!IMPORTANT]
> **NOT A RED HAT PRODUCT — USE AT YOUR OWN RISK**
>
> This project is an independent, community-developed tool and is **not** affiliated with, endorsed by, or supported by Red Hat, Inc. There are no warranties, express or implied. You use this tool entirely at your own risk.
>
> It was designed exclusively to triage vulnerabilities in **Red Hat products** (OCP, RHACM, UBI-based images, Red Hat Operators, …) by cross-referencing Red Hat VEX/CSAF advisories. It is **not** intended for third-party, upstream, or non-Red Hat content — results for those will be inaccurate or meaningless.

**Your scanner found 300 CVEs. How many actually matter?**

Most VEX tools do one thing: look up a CVE ID in an advisory file and echo back "not affected". That is a string match with extra steps, not triage.

`vextriage` takes scan results — from RHACS, grype, or trivy — and cross-checks them against three authoritative sources — Red Hat VEX/CSAF advisories, SPDX SBOMs, and RPM version data — to separate real vulnerabilities from noise. The scanner is only discovery; the **engine** is the judge:

| Layer | What it does |
|-------|-------------|
| **Image context detection** | Parses the image reference and live labels/CPEs to determine product type (OCP, RHACM, UBI, operator, …), RHEL base version, and product release — no manual input |
| **Scoped VEX cross-reference** | Fetches the authoritative Red Hat CSAF/VEX advisory for each CVE and scopes it to the *specific product and version* the image belongs to — not just "any Red Hat product" |
| **SBOM version verification** | Pulls the SPDX 2.3 SBOM and cross-checks every flagged component version against what is actually installed |
| **RPM backport detection** | Compares the installed RPM against the VEX fix version with proper RPM version comparison, closing findings where the patch is already present |
| **Build-exact identity matching** | Matches the image's own OCI purl and SHA256 digest against VEX product IDs, so a vendor assessment of the *exact build* overrides generic product-level entries |

A finding is marked **FALSE POSITIVE** only when all of the following hold: the VEX says not-affected *for the right product and RHEL version*, the component version is confirmed in the SBOM, and (for RPMs) the installed version is at or beyond the fix. Everything else stays open.

The RHACS path needs no image pull and no container runtime, and works fully offline once the VEX and SBOM caches are populated. The grype/trivy paths pull the image once (syft) and cache the SBOM.

> [!TIP]
> In a hurry? See [docs/HOWTO.md](docs/HOWTO.md) — RHACS triage, parquet build, and
> OpenVEX generation for images / OCP releases / operators, all in one page.
> Numbers person? [docs/ACCURACY-REPORT.md](docs/ACCURACY-REPORT.md) — the measured
> false-positive/false-negative audit and the grype vs trivy vs RHACS bake-off.

---

## Install

Requires **Python 3.10+** (the code uses `X | Y` union type syntax). Install the package editable from the repository root:

```bash
pip3 install -e .
```

This installs the `vextriage` distribution: the umbrella `vextriage` CLI plus the
historical `rhacs-vex*` console scripts as compatibility aliases (same code, same
behaviour — existing automation keeps working). On an externally-managed Python
(Homebrew/PEP 668) use a virtualenv:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -e .
```

```
vextriage rhacs    <image|csv>     RHACS-backed triage (same as `rhacs-vex`)
vextriage grype    <image|sbom>    syft SBOM + grype scan → engine triage
vextriage trivy    <image|report>  trivy scan → engine triage
vextriage generate --ocp V | --operators | --images FILE
                                   batch scan → triage → OpenVEX hub
vextriage hub      ...             rebuild hub index + repository manifest
vextriage doctor                   check tools, auth env and data artifacts
vextriage pipeline|operators|retriage|parquet     passthrough aliases
```

> [!IMPORTANT]
> **Run every command from the repository root.** All tools read and write `./data` by relative path, and the paths stored in `data/manifest.json` must stay relative for the static UI to resolve them.

### Red Hat pull secret (required for scanning)

Every image lives in authenticated Red Hat registries. Download your pull secret from
[console.redhat.com/openshift/install/pull-secret](https://console.redhat.com/openshift/install/pull-secret)
and save it (e.g. `~/pullsecret.txt`). It is needed by the full pipeline (`opm`, `oc`, `podman`).

### External tools

| Tool | Used by | Purpose |
|------|---------|---------|
| **podman** | pipeline stage 0 | Registry login |
| **oc** | pipeline stage 3 | Resolve OCP release pullspecs |
| **opm** | pipeline stage 1 | Render OLM operator index catalogs |
| **syft** | `vextriage grype`, `generate` | SBOM generation (syft-json, cached) |
| **grype** | `vextriage grype`, `generate` | CVE discovery for the OpenVEX path |
| **trivy** | `vextriage trivy`, `generate --verify` | alternative scanner / suppression gate |
| **skopeo** | grype/trivy/generate paths | label fallback only — labels normally come from the SBOM / trivy report |

RHACS single-image triage needs none of these — only a reachable RHACS Central (or a warm cache).

---

## Quickstart — triage one image

Point at your RHACS Central, then triage a single image:

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>

vextriage rhacs registry.redhat.io/openshift4/ose-cli@sha256:4f2e216ad46aa75f84e27aa2e6303327b99a4331c7ed8ef65850102898f3a9b0
```

(equivalently `python3 -m rhacs_vex.triage …`). Output is a compact, colour-coded table with the scanner severity and Red Hat's product-specific severity side by side, followed by a one-line summary and an SBOM cross-check:

```
┌────────────────┬───────────┬───────────┬───────────┬────────────────┬───────────────┬────────────┬─────────────────┬──────────────────────────────┐
│ CVE            │ Component │ RHACS Sev │ VEX Sev   │ Verdict        │ State         │ Evidence   │ Fix             │ Justification                │
├────────────────┼───────────┼───────────┼───────────┼────────────────┼───────────────┼────────────┼─────────────────┼──────────────────────────────┤
│ CVE-2026-27532 │ openssl   │ Important │ Important │ POSITIVE       │ Fix available │ Red Hat    │ 3.2.2-6.el9_5.1 │ Installed 3.2.2-6.el9_5 < fix│
│ CVE-2026-33186 │ grpc      │ Important │ Important │ FALSE POSITIVE │ Not affected  │ Red Hat    │ -               │ Vulnerable code not present. │
│ CVE-2026-1229  │ circl     │ Moderate  │ Moderate  │ FALSE POSITIVE │ Not affected  │ no RH data │ -               │ No supported Red Hat product…│
└────────────────┴───────────┴───────────┴───────────┴────────────────┴───────────────┴────────────┴─────────────────┴──────────────────────────────┘

Image: registry.redhat.io/openshift4/ose-cli (sha256:4f2e21…)
RHACS reports 182 findings → VEX triage: 122 false positives (67%), 60 real.
  false positives by evidence: 41 stated for this build · 12 stated for another build/product ·
  8 inferred from absence where Red Hat does enumerate this package type · 61 with no Red Hat
  data for the component type at all.
  Only the 41 verdict(s) stated for this build are published as OpenVEX; the rest are triage
  judgements, not vendor claims.
🔍 SBOM verified: 20/20 component versions confirmed in image
```

The **Evidence** column is the provenance of the verdict, and it matters as much as the
verdict itself:

| label | meaning | published as OpenVEX |
|---|---|---|
| `Red Hat` | Red Hat stated this for **this** product/build | yes |
| `RH (other)` | a real statement exists, for another build/product/version | no |
| `inferred` | absent from an enumeration that **does** cover this package type — meaningful absence | no |
| `no RH data` | the component type is never tracked as a purl at all (Go, Python) — absence proves nothing | no |

Red Hat's errata policy — *"unless explicitly stated as not affected, all previous versions of
packages in any minor update stream of a product listed here should be assumed vulnerable"* —
only speaks about products it lists, so silence means different things per class. An absent
**rpm** is evidence (Red Hat enumerates rpms exhaustively); an absent **Go module** is not
(2 golang purls exist in the entire corpus). Only Red Hat-stated verdicts are ever published.

If the image is not already indexed in RHACS, the tool triggers an on-demand scan (`POST /v1/images/scan`) and waits for the result.

### `vextriage rhacs` (triage) options

```
vextriage rhacs [TARGET] [--image REF | --namespace NS | --ocp FILE | --scan CSV]
          [--format {table,csv,json}] [--output FILE]
          [--false-only] [--sbom] [--workers N]
```

| Flag | Description |
|------|-------------|
| `TARGET` | Image ref or RHACS scan CSV — same positional as `grype`/`trivy`. An existing path is treated as `--scan`, anything else as `--image` |
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

## Triage with grype or trivy (no RHACS required)

The same engine judges scans from grype or trivy. No Central, no RHACS — just the
scanner, `skopeo` (image labels → product context) and the Red Hat VEX cache:

```bash
# syft SBOM (cached under data/syft/) → grype --by-cve → engine triage
vextriage grype registry.redhat.io/openshift4/ose-cli@sha256:ef8396…

# trivy scan → engine triage
vextriage trivy registry.redhat.io/openshift4/ose-cli@sha256:ef8396…
```

Same table, same verdicts, same rules as the RHACS path. Add
`--openvex-dir vexhub/` to also write the image's FALSE-POSITIVE verdicts as an
OpenVEX document (see next section). Image refs must be digest-pinned — the
OpenVEX product identity is the digest.

---

## Triage with no scanner at all

A scanner contributes exactly one thing the VEX corpus cannot: the
(component, CVE) candidate list. `vextriage scanfree` supplies that from an
inverted index over the mirrored VEX files, so an SBOM alone is enough:

```bash
vextriage sync                                        # mirror the corpus + build the index
vextriage scanfree data/syft/<image>.json             # triage, no scanner
vextriage scanfree data/syft/<image>.json --openvex-dir vexhub/
```

The image ref is taken from the SBOM's `repoDigests`; pass `--image <ref@sha256:…>`
to override. Verdicts come from the same engine, so the ladder, scoping,
severity chain and publication gate are identical to every other path.

**Coverage is the mirror image of a scanner's**, and that is the point:

| class | scan-free | why |
|---|---|---|
| rpm | complete | Red Hat enumerates every binary subpackage per arch, and the syft and VEX purls agree on `(name, version-release, arch, epoch)` — an exact join |
| image (oci) | complete | 14.8% of all Red Hat statements |
| golang / pypi | **empty** | Red Hat publishes 2 golang purls and 19 pypi refs in the entire corpus — vendored Go is assessed at the operator/component image, never the module purl |

So it finds rpm CVEs a scanner database has not caught up with, and is blind to
language ecosystems. Run it *alongside* a scanner, not instead of one — which is
what the scanner paths now do by themselves. `vextriage grype` and
`vextriage trivy` union their findings with the index candidates once
`build-index` has run (`--no-vex-index` for scanner-only); `vextriage rhacs`
takes `--vex-index` opt-in, because an RHACS exception can only be written for a
CVE RHACS itself reports. On `jetstack-cert-manager-rhel9` the grype path went
from 166 rows to 1,650, of which 95 are POSITIVE findings grype never reported —
no scanner row changed verdict. On
`ose-cli-rhel9` it produced 543 statements where the grype-driven path produced
23, agreed with that path on all 691 overlapping (CVE, component) pairs, and
suppressed zero real findings when its document was fed back through
`grype --vex`.

---

## Triage a RHACS report into one shareable HTML

`triage.html` answers this in the browser by joining an uploaded CSV against the per-version
parquets. When those do not exist, or do not cover the versions in front of you, the same
question has a server-side answer:

```bash
vextriage report Report-RHACS-ROSA.csv -o rosa.html            # triage what RHACS reported
vextriage report Report-RHACS-ROSA.csv -o rosa-live.html --rescan
```

The CSV supplies the topology — cluster, namespace, deployment, image — which no scan can know.
Three things it does not supply come from elsewhere: installed NEVRAs and the OpenShift version
from a syft SBOM of each image, and the CVEs behind each `RHSA-…` row from Red Hat's CSAF advisory
document (2,001 of 5,200 rows on the reference report). The result is one self-contained file with
no external assets, safe to send to someone who has neither this repo nor a cluster.

`--rescan` ignores the CSV's findings and scans every image live (syft + grype + the VEX index),
keeping the placement from the CSV. Generate both and you can see what a newer scanner and today's
VEX data change against a report written by whatever RHACS version produced it.

---

## OpenVEX export — a vexhub for trivy and grype

`vextriage generate` scans a set of images (syft + grype), triages them through the
engine, and writes the FALSE-POSITIVE verdicts as OpenVEX documents in the
[vex-repo-spec](https://github.com/aquasecurity/vex-repo-spec) layout
(same shape as [rancher/vexhub](https://github.com/rancher/vexhub)):

```bash
vextriage generate --ocp 4.20.0                --hub vexhub/        # one OCP release
vextriage generate --operators --catalog 4.20  --hub vexhub/        # operator estate
vextriage generate --images my-images.txt      --hub vexhub/        # explicit list
vextriage generate --image  <ref@sha256:…>     --hub vexhub/ --verify
```

| Flag | Effect |
|------|--------|
| `--workers N` | Parallel scanners; the pandas triage runs in a separate CPU process pool |
| `--resume` | Skip digests already in their hub doc (resume interrupted runs) |
| `--crosscheck` | Re-check every statement against raw Red Hat VEX with independent rules; prints disagreements |
| `--verify` | trivy re-scan gate: fail if a statement doesn't actually suppress |
| `--force` | Regenerate cached SBOMs |

- `--ocp` / `--operators` reuse the pipeline's discovery artifacts
  (`data/pullspecs/*.txt`, `data/catalogs/*.json`) — the image lists, not RHACS data.
- `--verify` re-scans each image with trivy against its own document and **fails on
  any statement that does not actually suppress** — the trust gate for publishing.
- Re-runs are idempotent: documents merge per image name, new release digests append,
  the doc version bumps only on real change, and a re-scan **retracts** statements
  that no longer hold. Interrupted runs resume for free (`--resume`).
- Three layers of caching (immutable SBOMs, grype results keyed by DB build,
  ETag-revalidated Red Hat VEX) make repeat sweeps minutes, not hours.
- Suppression-safety rules baked into the emitter: a verdict never extends to a
  source-rpm whose sibling packages diverge, go-binary components are matched to
  their vendoring rpm via SBOM file ownership, and a not_affected claim never
  overrides a pending fix for the installed build.

```
vexhub/
  vex-repository.json                    ← repository manifest (+ .well-known/ copy)
  index.json                             ← purl → document location
  pkg/oci/<registry>/<ns>/<name>/scan.openvex.json
```

> [!NOTE]
> **OpenVEX documents are generated ONLY from consumer-side scans (syft + grype).**
> RHACS triage output is never converted to OpenVEX: RHACS does not consume OpenVEX,
> and statement purls minted from the consumer scanner's own artifacts are guaranteed
> to match what that scanner looks up. The RHACS path stays what it is — triage →
> CSV/UI.

### Consuming the hub

```bash
# trivy — native VEX repository support (~/.trivy/vex/repository.yaml):
#   repositories:
#     - name: my-vexhub
#       url: https://github.com/<you>/<vexhub-repo>
#       enabled: true
trivy image <ref@sha256:…> --vex repo

# grype — file-based; the document path is derivable from the image ref:
grype <ref@sha256:…> --vex vexhub/pkg/oci/<registry>/<ns>/<name>/scan.openvex.json
```

Statement rules (empirical, both scanners verified — see
[docs/OPENVEX-SPIKE-RESULTS.md](docs/OPENVEX-SPIKE-RESULTS.md) and
[docs/OPENVEX-PLAN.md §8d](docs/OPENVEX-PLAN.md)): product `@id` is the bare
digest-pinned OCI purl (`pkg:oci/<name>@sha256:…`, no qualifiers), subcomponents are
qualifier-free package purls (golang gets both `v`-prefixed and bare version
variants). RPM statements are extended to the **source-rpm** name — Red Hat assesses
per source package, and the two scanners flag different binary subpackages of the
same source — and are additionally listed as products (trivy's BOM walk misses
base-layer packages otherwise). OCP release images get their product scope from
`data/pullspecs/` (their labels don't carry the release). Justification is Red Hat's
raw CSAF flag. Note that sibling subpackages can carry *different* per-binary
verdicts (`bind-utils` not_affected while `bind-libs` has a pending fix) — the
suppressed set is exactly what the engine cleared, never the whole CVE. Known
limitation: trivy **repo-mode** cannot suppress base-image-layer RPM findings (file
mode can); golang — the dominant false-positive class — is unaffected.

---

## The full pipeline

`vextriage pipeline` is the one-command, end-to-end run: it renders operator catalogs,
builds the namespace map, resolves OCP release pullspecs, and triages every OCP-release
and operator image against VEX. It shells out to the other modules (`python -m
rhacs_vex.ns_map`, `… .triage`, `… .operators`, `… .retriage`) for process isolation.

Its discovery stages are scanner-agnostic: stages 1 and 3 produce the image lists
(`data/catalogs/`, `data/pullspecs/`) that `vextriage generate --operators` /
`--ocp` consume for the OpenVEX path — only the scan+triage engine differs between
the two pipelines.

```bash
export ROX_ENDPOINT=central-stackrox.apps.mycluster.example.com:443
export ROX_API_TOKEN=<your-api-token>
vextriage pipeline --pull-secret ~/pullsecret.txt
```

### Stages

| Stage | Does | Skip flag |
|:---:|------|-----------|
| 0 | `podman login` to the Red Hat registries | `--skip-login` |
| 1 | Render OLM operator index catalogs via `opm` → `data/catalogs/` | `--skip-catalogs` |
| 2 | Build the namespace → VEX-prefix map → `data/ns_vex_prefixes.json` | `--skip-ns-map` |
| 3 | Fetch OCP release pullspecs via `oc adm release info` → `data/pullspecs/` | `--skip-ocp` *and* `--skip-openvex` |
| 4 | Triage each OCP release → `data/reports/ocp-<ver>.csv` | `--skip-ocp` |
| 5 | Triage all operators → `data/reports/operators/*.csv` | `--skip-operators` |
| 6 | *(optional)* offline verdict refresh for operators (`--refresh-operator-verdicts`) | — |
| 7 | Generate the OpenVEX hub (`vextriage generate`, syft+grype — no RHACS) for every OCP release + all channel-head operators → `vexhub/` | `--skip-openvex` |

### Freshness / skip flags

| Flag | Effect |
|------|--------|
| `--skip-existing` | Skip catalogs / pullspecs / reports already on disk (resume an interrupted run) |
| `--max-report-age DAYS` | Re-audit OCP report CSVs older than N days so verdicts track current VEX (0 = never). Re-runs reuse the permanent digest-pinned scan/SBOM cache — no extra load on Central. Default: 7 |
| `--max-catalog-age DAYS` | Re-render operator catalogs older than N days to pick up new bundles (0 = never). Default: 7 |
| `--refresh-operator-verdicts` | After stage 5, recompute operator verdicts offline from cached scans (Stage 6) |
| `--versions CSV` | Custom OCP version list (CSV with a `Version` column). Defaults to the list embedded in the module |
| `--workers N` | Parallel image workers per stage (default: 10) |

Run the non-scanning stages (catalogs + namespace map) without Central by passing `--skip-ocp --skip-operators --skip-openvex`.

OpenVEX-only run (no RHACS Central needed — stage 3 discovery still runs, then syft+grype → `vexhub/`):

```bash
vextriage pipeline --pull-secret ~/pullsecret.txt --skip-ocp --skip-operators
```

---

## Refresh, rebuild, and explore

The CSV reports under `data/reports/` are the source of truth. Two follow-up steps turn them into the browsable dataset:

```bash
# 1. (optional) Re-audit ALL cached reports against fresh VEX — zero network, CPU only.
#    Bounds each worker's VEX cache via VEX_CACHE_SIZE; uses a fork ProcessPool.
python3 -m rhacs_vex.retriage                 # or: vextriage retriage
python3 -m rhacs_vex.retriage --operators-only --version 4.21,4.22

# 2. Build per-version parquet + manifest + CVE index from the CSV reports.
python3 -m rhacs_vex.parquet                  # or: vextriage parquet

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

## The VEX mirror

Every path reads `data/vex/`, and only `vextriage sync` writes it. A run refreshes the mirror
when it is more than a day old and then stays off the network, so a verdict never depends on
whether some earlier run happened to pull that CVE.

```bash
vextriage sync                  # mirror + rebuild the index
vextriage sync --no-index       # mirror only
vextriage <anything> --skip-sync   # use the mirror as it is, however old
```

Red Hat publishes a dated tarball of the whole corpus (`archive_latest.txt` names it) plus a
`changes.csv` change feed. Past 2,000 outstanding files sync pulls the 273 MB tarball and unpacks
it straight into the mirror, then fetches only what changed after the archive was cut; under that
it fetches file by file. The full corpus is 63,244 documents, about 16 GB unpacked. The freshness
stamp is written only when nothing is outstanding, so an interrupted or `--limit`ed sync does not
mark a short mirror current.

## Advisory IDs that are not CVEs

Scanners report Go, Python and npm findings under `GHSA-…` or `GO-…`, which Red Hat publishes no
VEX for, so those rows used to come out POSITIVE with an Unknown severity. OSV carries the alias
graph and the lookup is automatic; the original ID is kept in `ALIAS_ID`. Nothing is cached to
disk. Coverage is partial by nature — 7 of 27 sampled advisories carried a CVE, and 6 of those 7
had a Red Hat VEX document. Set `OSV_DISABLE=1` to keep every ID exactly as scanned.

---

## Environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `ROX_ENDPOINT` | triage, operators, pipeline | RHACS Central `host:port` (scanning stages only) |
| `ROX_API_TOKEN` | triage, operators, pipeline | RHACS API bearer token (scanning stages only) |
| `VEX_CACHE_SIZE` | engine | Max parsed-VEX documents kept in each process's LRU cache (default `512`). `vextriage retriage` sets it to `96` per worker to bound memory across a fork ProcessPool — override to trade memory for hit rate |
| `VEX_MAX_AGE` | every triage path | Seconds before a run refreshes the mirror (default `86400`) |
| `VEX_SKIP_SYNC` | every triage path | Set to skip the refresh entirely, same as `--skip-sync` |
| `VEX_BULK_THRESHOLD` | sync | Outstanding files above which the tarball beats per-file fetching (default `2000`) |
| `OSV_DISABLE` | triage | Set to leave GHSA/GO advisory IDs unresolved |
| `REGISTRY_AUTH_FILE` | syft, skopeo | Credentials for image pulls; falls back to `~/.docker/config.json`, which is where an OpenShift pull secret lands |

---

## Data layout

Everything lives under `./data` (relative to the repo root). Tracked in git: the parquet
dataset, manifest, namespace map, and baseline. Ignored (regenerated locally): the caches,
CSV reports, catalogs, and pullspecs.

```
data/
  vex/                       ← Red Hat CSAF/VEX advisories, one JSON per CVE   (cache, SHARED by all scanner paths)
  sbom/                      ← SPDX 2.3 SBOMs from RHACS, one per image digest (cache, RHACS path)
  syft/                      ← syft-json SBOMs, one per image ref              (cache, grype/generate path)
  scans/                     ← raw RHACS scan JSON, one per image digest       (cache, RHACS path)
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
  vex-index.json.gz          ← inverted VEX index for `scanfree` (derived; rebuild anytime)
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
docs/OPENVEX-PLAN.md        ← OpenVEX/vexhub architecture + decisions
docs/OPENVEX-SPIKE-RESULTS.md ← empirical purl/suppression rules (grype+trivy proofs)
src/rhacs_vex/
  engine.py                 ← clean-room VEX matching engine
  triage.py                 ← RHACS ↔ VEX triage CLI / IO layer   (vextriage rhacs)
  cli.py                    ← umbrella CLI                        (vextriage)
  openvex.py                ← triage verdicts → OpenVEX statements
  hub.py                    ← vexhub builder (layout, index, manifest, merge)
  context.py                ← workload context via skopeo labels (non-RHACS paths)
  scanfree.py               ← SBOM + VEX only, no scanner            (vextriage scanfree)
  adapters/grype.py         ← syft SBOM + grype scan → triage rows
  adapters/trivy.py         ← trivy scan → triage rows
  operators.py              ← operator triage                     (vextriage operators)
  retriage.py               ← offline re-audit from cache         (vextriage retriage)
  parquet.py                ← build parquet + manifest + CVE index (vextriage parquet)
  pipeline.py               ← end-to-end orchestrator             (vextriage pipeline)
  ns_map.py                 ← namespace → VEX-prefix map builder
  query.py                  ← ad-hoc queries over OCP parquet
tests/check_baseline.py     ← 189-case regression check (run from repo root)
tests/test_verdict_cases.py ← verdict case matrix (rpm, golang, image identity, states)
tests/test_module_streams.py ← module-stream guard cases
tests/test_scanfree.py      ← scan-free purl identity, candidates, emission safety
tests/test_engine_regressions.py ← bugs found by independent VEX cross-checking (synthetic VEX)
index.html, triage.html, assets/, data/   ← static explorer + dataset
```

Console scripts: `vextriage` (umbrella), plus the historical aliases `rhacs-vex`,
`rhacs-vex-pipeline`, `rhacs-vex-operators`, `rhacs-vex-retriage`, `rhacs-vex-parquet`.
Modules without a script are run with `python3 -m rhacs_vex.<module>`.
