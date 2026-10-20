# vextriage — Red Hat VEX triage

> Triage scanner findings against authoritative **Red Hat CSAF-VEX** and publish the
> verdicts as **OpenVEX**, so grype and trivy drop the same false positives.

> [!IMPORTANT]
> **NOT A RED HAT PRODUCT — USE AT YOUR OWN RISK**
>
> An independent, community-developed tool, not affiliated with, endorsed by, or
> supported by Red Hat, Inc., with no warranties. It is designed for **Red Hat
> products** (OCP, operators, UBI-based images, …); results for third-party or
> upstream content are meaningless.

**Your scanner found 300 CVEs. How many actually matter?** Run the scanner with Red
Hat's verdicts applied and look only at what is left:

```bash
vextriage sync                                   # once, then daily: Red Hat VEX + OSV → local index
vextriage openvex <image@sha256:…> --hub vexhub  # publish Red Hat's verdicts for the image
vextriage check   <image@sha256:…>               # grype with those verdicts → what is left
```

All the Red Hat-specific reasoning (product scoping, RHEL streams and backports,
module streams, vendored Go assessed at the image) happens once, when the OpenVEX
document is generated. After that, triage is just the scanner plus `--vex`. Generation
needs a syft SBOM and the local index only, and runs in ~130 MB of RAM.

## Install

Python 3.10+, from the repository root:

```bash
pip install -e .          # or in a venv: python3 -m venv .venv && . .venv/bin/activate && pip install -e .
vextriage doctor          # which external tools and data are present
```

Run every command from the repository root: data lives under `./data` by relative path.
External tools are only needed by the commands that use them: **syft** (SBOMs),
**grype** / **trivy** (scanning), **skopeo** (label fallback, single-arch images), **oc**
and **opm** (OCP release and operator image lists for `generate`). Image pulls use
`REGISTRY_AUTH_FILE`, falling back to `~/.docker/config.json`, where a Red Hat pull secret
installed with `docker login` lands.

## Commands

```
vextriage sync                         Red Hat VEX + OSV + index, deltas only (then offline)
vextriage openvex  <image|sbom>        one image → OpenVEX (syft SBOM, no scanner)
vextriage check    <image|sbom>        scanner + that OpenVEX → what is left to fix
vextriage generate --ocp V | --operators | --images FILE | --image REF
                                       many images → OpenVEX hub
vextriage hub [--prune]                rebuild the hub index / drop rotated-out digests
vextriage scanfree <image|sbom>        every SBOM candidate → triage table (no scanner)
vextriage grype    <image|sbom>        grype findings → triage table
vextriage trivy    <image|report>      trivy findings → triage table
vextriage rhacs    <image|csv> | --namespace NS | --ocp PULLSPECS [--offline]
vextriage report   CSV -o FILE         RHACS report → one self-contained HTML file
vextriage doctor                       tools, credentials, data
```

Every command that reads the mirror refreshes it first when it is more than a day old
(`--skip-sync` to use it as it is). Image refs must be digest-pinned: a verdict is about
one build.

## How a verdict is made

A scanner, the VEX index or OSV only **propose** (component, CVE) pairs; the engine
(`core/judge.py`) decides each one from Red Hat's CSAF-VEX. Every Red Hat statement is
a status about a component **purl** in a **product** (`core/csaf.py`); the rules are
filters over those, re-derived from the data (VEX-MODEL §11):

1. **The image** — its RHEL major and minor, its product (OpenShift release, layered
   product version from the CPE label or its registry namespace), its build stamp and
   digests, from the ref, labels and os-release.
2. **This build** — a statement naming the image's own digest decides.
3. **An rpm** — the exact build fixed or not affected; else a fix in the image's
   lineage (its own minor, else the newest mainline fix it inherits); else
   `known_affected` / `under_investigation` for its line; else `known_not_affected`;
   else a fix only in later or side streams (errata policy: POSITIVE). Module streams
   come from the SBOM. A plain `.elN` build is RHEL's to decide, an `rhaos` build its
   product's; a not-affected from either clears. An rpm Red Hat did not build (the
   SBOM's rpm vendor) is not Red Hat's to clear: POSITIVE.
4. **The image itself** — its version's builds ordered by build stamp against ours,
   then the product line, then other versions (a fix only in a newer version leaves
   ours POSITIVE).
5. **A module inside** (Go, npm, Python, Maven) — Red Hat's purl for it, else the rpm
   that ships it, else the image's verdict, else: our product listed affected with
   nothing cleared under it → assumed vulnerable; a non-Red Hat image's own module →
   POSITIVE (Red Hat's VEX does not cover it); otherwise not listed.
6. **Inferred positives meet the binaries** — a POSITIVE that rests on an inference
   (another product's or version's statement, the errata assumption) is checked against
   the modules the SBOM finds compiled into the binaries and OSV's vulnerable ranges:
   all past the fix, or the vulnerable package not compiled in → FALSE POSITIVE; in the
   range → POSITIVE, with that as the proof.  Red Hat's statements about this build are
   never overridden.

The full data model — product-ID grammar, RHEL and OpenShift streams, operator
versions, every decision branch — is in **[docs/VEX-MODEL.md](docs/VEX-MODEL.md)**.

Verdicts are `FALSE POSITIVE` or `POSITIVE`; `VEX_STATE` mirrors Red Hat's CVE pages
(`Not affected`, `Fixed`, `Fix available`, `Affected`, `Will not fix`, `Fix deferred`,
`Under investigation`). How much of a verdict is Red Hat's own claim:

| "Red Hat says" | meaning | in the OpenVEX |
|---|---|---|
| `Affected` | Red Hat stated it for **this** product/build | Red Hat's justification |
| `Affected (OpenShift 4)` | a real statement about another build, version or product — the one in parentheses (e.g. the product that ships the rpm, or a newer version) | `Inferred from Red Hat CSAF-VEX: …` |
| `Not affected (not listed)` | absent from Red Hat's enumeration | `Inferred from Red Hat CSAF-VEX: …` |

An absent **rpm** is evidence: RHEL lists every affected rpm.  Absence never clears what
Red Hat did not ship — a third-party rpm or a non-Red Hat image's own modules stay
POSITIVE ("not a Red Hat build").  `--stated-only` publishes Red Hat-stated verdicts only.

## OpenVEX and the vexhub

```
syft SBOM ─┬─ rpm artifacts ─────── VEX index (rpm purl → CVEs)     ┐
           ├─ the image itself ──── VEX index (oci repo → CVEs)     ├→ engine → OpenVEX
           ├─ go/pypi/npm/maven ─── OSV (package + version → CVEs)  │   (every false
           └─ (--grype) grype findings                              ┘    positive)
```

```bash
vextriage openvex <ref@sha256:…> -o image.openvex.json
vextriage openvex sbom.syft.json --image <ref@sha256:…> --hub vexhub

vextriage generate --ocp 4.20.0               --hub vexhub   # data/pullspecs/4.20.0.txt
vextriage generate --operators --catalog 4.20 --hub vexhub   # data/catalogs/catalog-4.20.json
vextriage generate --images my-images.txt     --hub vexhub
```

`generate` reads image lists you produce once:
`oc adm release info <ver> --pullspecs > data/pullspecs/<ver>.txt` and
`opm render <operator-index> > data/catalogs/catalog-<minor>.json`. It runs syft in
parallel threads and the engine in worker processes, checkpoints the hub every 25
images, `--resume`s interrupted runs, and `--verify` re-scans each image with trivy
against its document and fails on any statement that does not suppress.

Statement rules (both scanners verified, [docs/OPENVEX-SPIKE-RESULTS.md](docs/OPENVEX-SPIKE-RESULTS.md)):

- product `@id` is the bare digest-pinned OCI purl (`pkg:oci/<name>@sha256:…`);
  subcomponents are the purls syft recorded, without qualifiers (golang with and
  without `v`);
- an image-level Red Hat statement becomes a product-only statement, unless anything
  else in the image is still open for that CVE;
- rpm statements extend to the source rpm, never when sibling subpackages diverge,
  and are also listed as products (trivy's BOM walk misses base-layer packages);
- a Go module is never cleared while an rpm in the same image is open for the CVE.

```
vexhub/
  vex-repository.json                    repository manifest (+ .well-known/ copy)
  index.json                             purl → document location
  pkg/oci/<registry>/<ns>/<name>/scan.openvex.json
```

Documents merge per image name: new digests append, re-runs are idempotent, the version
bumps only on change, and a re-scan retracts statements that no longer hold.
`vextriage hub --prune` drops statements for digests no longer in `data/pullspecs` or
the catalogs' channel heads.

```bash
trivy image <ref@sha256:…> --vex repo        # with the hub in ~/.trivy/vex/repository.yaml
grype <ref@sha256:…> --vex vexhub/pkg/oci/<registry>/<ns>/<name>/scan.openvex.json
```

OpenVEX documents are generated only from syft SBOMs: the subcomponent purls must be
what the consuming scanner looks up. RHACS triage stays triage (tables, CSV, HTML).

## Triage tables

The same engine judges any finding source and prints the same table — what needs
action, with false positives counted in the footer (`--false-only`, `--all-rows`);
`--output FILE` writes every row as CSV (`--format json` for JSON).

```bash
vextriage scanfree <ref@sha256:…>                 # SBOM candidates only: VEX index + OSV
vextriage grype    <ref@sha256:…> [--vex-index]   # grype's findings (+ the index's rpm/image pairs)
vextriage trivy    <ref@sha256:…> [--vex-index]
vextriage rhacs    <ref@sha256:…>                 # RHACS Central (ROX_ENDPOINT, ROX_API_TOKEN)
vextriage rhacs    --namespace payments | --ocp data/pullspecs/4.20.0.txt [--offline]
```

`scanfree` needs no scanner: the VEX index proposes every rpm and image pair Red Hat
could decide (complete — Red Hat enumerates every binary rpm per arch, and the syft and
VEX purls join exactly) and OSV the language packages (Red Hat never publishes Go or
Python module purls). The scanner paths are what a scanner found; `--vex-index` adds the
rpm CVEs its database has not caught up with. RHACS responses are cached under
`data/scans/`, so `--offline` re-triages without Central.

### A RHACS report as one HTML file

```bash
vextriage report Report-RHACS.csv -o report.html             # triage what RHACS reported
vextriage report Report-RHACS.csv -o live.html --rescan      # scan every image again today
```

The CSV supplies the topology (cluster, namespace, deployment, image); installed versions
and the build's labels come from a syft SBOM of each image, and the CVEs behind each
`RHSA-…` row from Red Hat's CSAF advisory. The page has no external assets; a parquet of
the same rows is written alongside for `triage.html` / DuckDB.

## Local data

`vextriage sync` is the only command that downloads data, and fetches only what changed:

- **Red Hat VEX** → `data/vex/` (one JSON per CVE, ~70k documents). Past 2,000
  outstanding files it pulls Red Hat's dated tarball and then the change feed after it;
  otherwise file by file from `changes.csv`.
- **The index** → `data/vex-index.sqlite`: rpm name → CVEs, image repo → CVEs, OSV
  package records. Built by streaming, queried one key at a time; only changed CVEs are
  re-indexed (`--rebuild` starts over).
- **OSV** → the same index: the Go, PyPI, npm and Maven records that carry a CVE alias.
  The first sync imports each ecosystem's export; later syncs read `modified_id.csv` and
  fetch only changed records (`MAL-` malware reports skipped). It also maps scanner
  advisory IDs (`GHSA-…`, `GO-…`) to the CVE Red Hat publishes under; the original stays in
  `ALIAS_ID` (`OSV_DISABLE=1` keeps IDs as scanned).

| Variable | Purpose |
|----------|---------|
| `ROX_ENDPOINT`, `ROX_API_TOKEN` | RHACS Central for `vextriage rhacs` |
| `REGISTRY_AUTH_FILE` | registry credentials for syft / skopeo / oc / opm |
| `VEX_SKIP_SYNC` | never refresh the mirror (same as `--skip-sync`) |
| `VEX_MAX_AGE` | seconds before a run refreshes the mirror (default 86400) |
| `VEX_OFFLINE` | no network lookups at triage time (OSV advisory API) |
| `VEX_AUDIT_WORKERS` | engine worker processes (default: automatic) |
| `VEX_CACHE_SIZE` | parsed VEX documents kept by per-row callers (default 16) |
| `VEX_BULK_THRESHOLD` | outstanding files above which sync uses the tarball (default 2000) |
| `OSV_DISABLE` | leave GHSA/GO advisory IDs unresolved |

```
data/
  vex/  vex-index.sqlite        Red Hat VEX mirror and the index      (vextriage sync)
  syft/                         syft-json SBOM cache, one per image ref
  scans/  sbom/                 RHACS scan and SPDX caches
  pullspecs/  catalogs/         image lists for generate (oc / opm)
  baseline.json                 regression fixture for tests/check_baseline.py
```

## Project layout

```
src/rhacs_vex/
  core/            the engine: csaf (one CSAF document as statements), judge (the
                   verdict), workload (the image), versions (rpm arithmetic, streams), store
  engine.py        one finding → one verdict (tests, per-row callers)
  audit.py         the batch driver: findings × images → verdict columns, CVE-major
  candidates.py    (component, CVE) pairs from an SBOM, the index, OSV, scanner findings
  vexgen.py        syft SBOM → candidates → engine → OpenVEX statements
  openvex.py       statement assembly and cross-scanner purl rules
  hub.py           the vexhub: layout, merge, index, prune
  sbom.py          syft-json reader (labels, digests, file owners, source rpms)
  vexindex.py      the SQLite index;  osv.py  OSV sync, ranges, advisory IDs
  mirror.py        the Red Hat VEX mirror;  discovery.py  pullspec and catalog image lists
  adapters/        finding sources: grype, trivy, rhacs
  scan.py          triage table flow and the RHACS image/batch runs
  display.py       terminal and file output;  report.py + report.html  the HTML report
  cli.py           `vextriage`
tests/             offline suites (synthetic VEX): test_engine_regressions.py,
                   test_module_streams.py, test_scanfree.py; check_baseline.py and
                   test_verdict_cases.py need cached RHACS scans;
                   collect_local_evidence.sh + evidence_parquet.py for real-image evidence
tools/             vex_census.py, vex_identity_census.py (statement shapes over the mirror)
docs/              VEX-MODEL.md (the data model), OPENVEX-SPIKE-RESULTS.md (purl rules), HOWTO.md
```

`index.html`, `triage.html`, `assets/` and `data/parquet/` are the published explorer
site and its dataset snapshot; the batch that regenerated them was retired (see git
history), `triage.html` still reads the parquet `vextriage report` writes.
