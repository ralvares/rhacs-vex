# Plan — grype/syft inputs + OpenVEX output + vexhub publishing

> Status: **PLAN ONLY**, no code written. Design doc for extending `rhacs-vex`
> beyond RHACS-as-scanner into a scanner-agnostic Red Hat VEX triage engine that
> emits OpenVEX and publishes a Trivy/Grype-consumable VEX repository ("vexhub").

## 1. Goal

Keep the existing engine (product-scoped Red Hat CSAF-VEX cross-reference + RPM
backport detection) **unchanged**. Add two new edges:

- **Input**: accept `grype` scan JSON + `syft` SBOM as alternatives to
  RHACS scan JSON + Red Hat SPDX SBOM. Unlocks the tool from StackRox.
- **Output**: emit **OpenVEX** documents and assemble a **VEX repository**
  (rancher/vexhub layout) that `trivy` and `grype` consume downstream.

One-line pitch: **"any scanner → Red Hat VEX triage → OpenVEX out."**
The loop closes — grype/trivy have no Red Hat backport or product-scoping
knowledge; rhacs-vex supplies exactly that and hands it back as VEX they suppress on.

## 2. Architecture — three layers, engine in the middle

```
INPUT adapters            CORE engine (UNCHANGED)        OUTPUT emitters
────────────────          ──────────────────────         ───────────────
RHACS scan JSON ─┐                                       ┌─ OpenVEX docs (new)
grype JSON (new)─┼──►  rows → VEX cross-ref  ────────────┼─ vexhub repo   (new)
                 │     + RPM backport compare            │
Red Hat SPDX  ──┤     → decision dict per finding        └─ static HTML   (today)
syft SPDX (new) ─┘        (status + raw flag + fix)
```

The engine already reduces every finding to a structured decision
(status ∈ {known_affected, known_not_affected, fixed, under_investigation} +
raw CSAF flag + fix version). Both new edges bolt onto that boundary; the matching
logic in `engine.py` is not touched.

## 3. Phases

### Phase 0 — one-image proof (SPIKE) — ✅ DONE for golang, see [OPENVEX-SPIKE-RESULTS.md](OPENVEX-SPIKE-RESULTS.md)

**Result: proven end-to-end on `ose-cli` 4.15 — 7/7 golang CVEs suppressed in BOTH
grype and trivy (924→916, 8 instances removed).** Key outcomes fold back into the
build: product `@id` = `pkg:oci/<basename>@sha256:<pullDigest>` **no qualifiers**
(matches both tools; `repository_url=` breaks grype); subcomponent purls **diverge**
(grype `stdlib@1.20.12` vs trivy `stdlib@v1.20.12`) → emit both forms; feed grype
from **syft-JSON** and trivy from the **image/CycloneDX** (both drop the OCI root from
syft-SPDX); justification = raw CSAF flag verbatim. rpm class still to prove.

Prove purl alignment empirically before writing any generator. Purl matching is
the single make-or-break risk and is only knowable by running the real scanner.

1. Pick one already-triaged image with known FALSE POSITIVEs.
2. **Hand-author** one OpenVEX doc: `product` = image OCI purl `@sha256:<digest>`
   + `hashes`, `subcomponents` = the FP package purls, `status` = not_affected/fixed.
3. `trivy image <digest> --vex <file.openvex.json>`.
4. Confirm the FP CVEs actually drop from Trivy output.
5. Repeat pointing grype at the same file (`--vex`).

**Gate**: if CVEs drop → purls align → generalize. If not → fix rpm purl
qualifiers (`arch`, `distro`, `epoch`, `upstream`) until they match what
Trivy/grype generate for the same package. Do NOT skip to Phase 2 before this passes.

### Phase 1 — input adapters (independent of Phase 0)

- **syft SBOM adapter**: syft emits SPDX 2.3, which the existing SBOM layer already
  reads. Likely near drop-in — point the SBOM loader at a syft file, verify field
  parity (package name, version, purl).
- **grype scan adapter**: map grype JSON `matches[]` → the internal row shape the
  RHACS scan produces (CVE id, component name, version, purl, severity). One small
  adapter module; no engine change.
- CLI: add a `--scanner {rhacs,grype}` / `--sbom {redhat,syft}` selector (or infer
  from file shape). Everything downstream stays identical.

### Phase 2 — OpenVEX emitter

Per **image** produce one OpenVEX document. Suppression-only scope:
emit `not_affected` + `fixed` statements; skip `affected` / `under_investigation`
(positive assertions add noise, must be kept correct, and Trivy reports affected anyway).

Emit from the **structured decision dict**, not the humanized `JUSTIFICATION`
display string built at `triage.py:635`. OpenVEX needs the raw enum.

### Phase 3 — vexhub repository builder

Assemble the OpenVEX docs into an aquasecurity/vex-repo-spec repository
(exact layout in §5). Regenerate on VEX-cache refresh (staleness story via
per-doc `timestamp` + `version`).

### Phase 4 — consumption docs

Document both consumers (§6): Trivy VEX-repo config vs grype file-based.

## 4. Semantic mapping — Red Hat CSAF → OpenVEX

| Engine decision | OpenVEX `status` | `justification` | Notes |
|---|---|---|---|
| CSAF flag (`_NOT_AFFECTED_FLAGS`) | `not_affected` | **raw flag string** | 1:1, see below |
| RPM backport: installed ≥ fix | `fixed` | *(none)* | `fixed` takes no justification |
| CSAF `fixed` PID matched | `fixed` | *(none)* | |
| everything else (affected / UI) | *(not emitted)* | — | suppression-only scope |

**Verified 1:1 mapping** — `engine.py:_NOT_AFFECTED_FLAGS` are byte-identical to
the OpenVEX justification enum, zero translation:

```
component_not_present
vulnerable_code_not_present
vulnerable_code_not_in_execute_path
vulnerable_code_cannot_be_controlled_by_adversary
inline_mitigations_already_exist
```

**Load-bearing distinction**: do NOT flatten every FALSE POSITIVE into
`not_affected`. Backport findings are `fixed`. Both suppress downstream, but they
are different assertions and OpenVEX validates justification only on `not_affected`.

### OpenVEX document shape (per image)

- `@context`, `@id`, `author`, `timestamp`, `version` — doc metadata.
- Each `statement`:
  - `vulnerability.name` = CVE id.
  - `products[]`: `@id` = image OCI purl **with** `@sha256:<digest>`,
    plus `hashes.sha256` = digest. **This is where Red Hat's (product, RHEL-version)
    scoping is preserved.**
  - `subcomponents[]`: `@id` = vulnerable package purl(s).
  - `status` + `justification` per table above.

**Product = image digest, never bare package purl.** A bare `pkg:rpm/...`
not_affected statement leaks the verdict into contexts where it is false (same rpm,
different base image = different answer). The digest-scoped product is exactly
rancher's model: VEX keyed to *their own images*.

## 4b. Component-class matrix — the real difficulty axis

Two independent bridges must both close for a finding to be suppressible downstream:
**Bridge A** = our subcomponent purl must equal what grype/trivy mint for the same
component (scanner ↔ consumer). **Bridge B** = the engine must map the component to a
Red Hat product-scoped VEX verdict (scanner ↔ CSAF-VEX).

| class | scanner identity | VEX identity (Bridge B) | version-compare fallback | difficulty |
|---|---|---|---|---|
| **rpm / OS** | `pkg:rpm/redhat/<name>@nevra` | same — `pkg:rpm/redhat/<name>@nevra` | **yes** (installed ≥ fix ⇒ FP) | easy — one key, both bridges collapse |
| **golang** | `pkg:golang/<module>@<ver>` (from go build info) | **none golang** — only the `pkg:oci/<image>@sha256` / rpm that embeds it | **no** — module version is constant across RH rebuilds | hard — Bridge B is image-level only; no safety net |
| **operator** | operator/operand container image | `pkg:oci/<image>@sha256` under a product CPE, resolved via OLM catalog/bundle | n/a | hardest — image→product identity lives in the catalog, not the artifact |

**Empirical proof**: `data/vex/CVE-2024-24788.json` (Go stdlib CVE) — 1325 purls, **zero
`pkg:golang/`**. Red Hat scopes Go CVEs to the container/rpm built with the vulnerable
Go, never the upstream module. Meanwhile the RHACS scan reports the finding as
`source=GO, name=golang.org/x/net, version=v0.8.0` — a clean module path that has no
counterpart in the VEX product tree.

**Why it still works for output**: Bridge A closes for golang because grype/trivy read
the *same* go build info we do, so `pkg:golang/<module>@<ver>` matches consumer-side even
though it is foreign to VEX. The engine resolves Bridge B at the image/product level and
we **bake that resolved scope into a flat per-image-digest OpenVEX** — the consumer
suppresses with zero operator/CPE knowledge. That collapse is the product's value.

**Residual risks specific to golang/operators**:
- Go triage confidence hinges entirely on image→product resolution — no version fallback,
  so a missing explicit statement means the finding stays open (cannot prove FP).
- Operator suppression is per-digest: the consumer must scan the exact image digest we
  triaged; operator bundles fan out into many operand images.
- Go purl normalization (`+incompatible`, pseudo-versions `v0.0.0-<date>-<sha>`, case)
  must match grype/trivy's — a Bridge-A alignment check, same class as rpm qualifiers.

## 5. VEX repository layout (aquasecurity/vex-repo-spec — fetched, verbatim)

**Root files:**
- `vex-repository.json` — manifest.
- `index.json` — package index.

**`vex-repository.json`:**
```json
{
  "name": "...", "description": "...",
  "versions": [{
    "spec_version": "0.1",
    "locations": [{ "url": "https://.../archive.zip" }],
    "update_interval": "24h"
  }]
}
```

**`index.json`:**
```json
{
  "updated_at": "2023-07-04T12:00:00Z",
  "packages": [
    { "id": "pkg:oci/mongodb-community-server", "location": "pkg/oci/.../vex.json" }
  ]
}
```

> **CRITICAL** — `packages[].id` is the PURL **without version, qualifiers, or
> subpath**. So the index key is the **bare** `pkg:oci/<image-name>` (no digest/tag).
> The digest + hashes live **inside** the OpenVEX doc's `product`. Trivy strips the
> scanned purl to bare id → finds the doc via index → matches the precise
> version/hash statement inside. One doc per image name can hold many digests.

**Directory tree:**
```
index.json
vex-repository.json
pkg/
└── <type>/<namespace>/<name>/vex.json
```

## 6. Downstream consumption (fetched)

**Trivy — native VEX repository:**
- Config: `$HOME/.trivy/vex/repository.yaml` (or `$XDG_DATA_HOME`).
  ```yaml
  repositories:
    - name: rhacs-vexhub
      url: https://github.com/<org>/rhacs-vexhub
      enabled: true
  ```
- Run: `trivy image <ref> --vex repo`. Trivy generates purls during scan, looks
  them up in the index; **first matching doc wins** (repo order matters).

**Grype — file-based only:**
- OpenVEX for filtering + augmenting, via `--vex <file>` / `GRYPE_VEX_DOCUMENTS`.
  No repo auto-discovery. The same repo doubles as a plain OpenVEX store grype reads.
- Verify exact flag/env names against the installed grype version at build time.

## 7. Key decisions

1. Engine untouched — new code only at input adapter + output emitter boundaries.
2. Suppression-only VEX (`not_affected` + `fixed`); skip positive assertions.
3. `fixed` ≠ `not_affected` — keep backport vs CSAF-flag findings distinct.
4. Product = image OCI purl `@sha256`; index key = bare OCI purl.
5. Emit from raw decision dict, not the humanized display justification.
6. Trivy = repo consumer (native); grype = file consumer (manual).

## 8. Risks / open questions

- **The engine has NO rpm purls (empirical).** RHACS scanner-v4 / Claircore SBOMs
  in `data/sbom/` carry zero purls (`externalRefs` empty); the engine matches
  components by **name + version + epoch + RHEL base**, not purl. CPEs live only on
  the CSAF *input* side for scoping — they never reach the OpenVEX output.
  Consequence: converting CSAF→OpenVEX is two very different jobs —
  - **field translation (trivial)**: status + justification map 1:1, already
    resolved by the engine into a per-(image, component) verdict;
  - **purl minting (the actual work)**: we must synthesize the rpm subcomponent
    purl from name/version/arch/RHEL base, e.g.
    `pkg:rpm/redhat/<name>@<version>-<release>?arch=<arch>&distro=redhat-<X>&epoch=<n>`,
    and it must be **byte-equal** to what Trivy/grype mint for the same rpm.
- **Purl alignment (highest risk)** — the minted rpm purl's qualifiers (`arch`,
  `distro`, `epoch`, `upstream`) must match Trivy/grype's, or subcomponent matching
  silently misses. Only knowable empirically → Phase 0 exists to de-risk exactly this.
  A naive CSAF→OpenVEX converter that keeps CPE scoping is useless — grype/trivy
  do not match CPEs.
- Does Trivy's `pkg:oci` purl for a scanned image match our product `@id` on digest
  alone, or does it require the registry/name to line up too? Confirm in Phase 0.
- Grype exact VEX flags/env for the installed version — confirm at build time.
- Staleness — when to regenerate docs as the Red Hat VEX cache refreshes; per-doc
  `timestamp`/`version` bump policy.
- Hosting — GitHub repo (git URL) vs `.well-known/vex-repository.json` on a domain.

## 8b. Packaging & CLI (decided 2026-07-13)

**One package, renamed dist `vextriage`, scanner = subcommand.** No core/plugin split.

```
vextriage rhacs   ...        # today's rhacs-vex behavior, byte-identical (default)
vextriage grype   <image>    # syft SBOM + grype scan → engine triage → verdicts
vextriage trivy   <image>    # trivy scan JSON → engine triage → verdicts
vextriage hub     build ...  # assemble vexhub/ (index.json + vex-repository.json + docs)
--openvex-dir hub/           # OpenVEX export available on ALL paths (rhacs included)
```

- Scanner = discovery adapter; engine = judge; OpenVEX = output. Verdicts always from engine.
- Compat: keep `rhacs-vex*` console scripts as aliases → `vextriage rhacs …`. Zero breakage.
- Internal module stays `rhacs_vex` for now (invisible to users; rename later or never).
- New modules, engine untouched: `adapters/grype.py`, `adapters/trivy.py`, `context.py`
  (image ctx via skopeo labels — the one hard part; today ctx rides on RHACS metadata),
  `openvex.py` (emitter, spike rules), `hub.py` (layout + index + manifest).
- Build order: (1) openvex.py+hub.py on existing RHACS output → immediate hub from full
  OpenShift scans; (2) rename+CLI+aliases; (3) grype adapter; (4) trivy adapter.

## 8c. BUILT + VALIDATED (2026-07-13)

All four phases implemented and validated end-to-end:

| piece | file | validation |
|---|---|---|
| OpenVEX emitter | `src/rhacs_vex/openvex.py` | circle test: grype 108/108, trivy 101/101 suppressed, zero leaks |
| Hub builder | `src/rhacs_vex/hub.py` | idempotent re-runs (version stable), cross-version merge, trivy repo-mode consumes it |
| CLI | `src/rhacs_vex/cli.py` (`vextriage`) | rhacs/pipeline/… passthroughs OK; grype+trivy live paths ran on ose-cli |
| grype adapter | `src/rhacs_vex/adapters/grype.py` | 915 findings → 113 FP; engine agrees 7/7 with hand-verified spike CVEs |
| trivy adapter | `src/rhacs_vex/adapters/trivy.py` | 921 findings → 106 FP |
| context | `src/rhacs_vex/context.py` | skopeo labels → parse_context_from_labels (OCP 4.15 resolved correctly) |
| packaging | `pyproject.toml` → dist `vextriage` | `rhacs-vex*` compat scripts intact; `tests/check_baseline.py`: ALL 189 match |
| generate pipeline | `vextriage generate --images FILE` | batch syft→grype→triage→hub (2 art-dev digests → one merged doc); `--verify` trivy gate: clean |

**Pipeline principle (decided 2026-07-13): OpenVEX is generated ONLY from
consumer-side scans (syft+grype → engine triage).** RHACS triage output is never
converted to OpenVEX — RHACS does not consume OpenVEX, and statements minted from
RHACS component names carry no guarantee of purl-matching what grype/trivy emit.
Minting from grype's own artifacts makes Bridge A exact by construction. The former
`vextriage export` (report CSVs → hub) was removed for this reason; the RHACS path
stays what it is today: triage → CSV/UI for RHACS users.

**Pipeline layering — discovery is shared, only the scan engine differs.** The
RHACS pipeline's stages 0–3 produce scanner-agnostic image lists
(`data/pullspecs/*.txt` via oc, `data/catalogs/catalog-*.json` via opm);
`vextriage generate` consumes them directly:

    vextriage generate --ocp 4.20.0                --hub vexhub/   # 192 images
    vextriage generate --operators --catalog 4.20  --hub vexhub/   # 4115 images
    vextriage generate --images FILE | --image REF                 # explicit

Cost honesty: syft pull ≈ 1–2 min/image first run (cached in `data/syft/`
afterwards; grype re-scan on a cached SBOM is seconds). Full operator catalog ≈
days at 4 workers — run per-catalog / incrementally; hub merge is idempotent, so
interrupted runs resume for free.

**Data-folder split (decided)**: `data/vex` stays SHARED (same Red Hat truth for
every engine; 3.4 GB cache). SBOM caches are already engine-separated:
`data/sbom` = Red Hat SPDX (RHACS path), `data/syft` = syft-json (generate path).
`data/scans` = RHACS-only. grype verdicts are deliberately not cached — the SBOM
is the expensive artifact, and grype's DB moves daily.

**New empirical rule found during validation (trivy BOM quirk):** trivy's VEX walk
does not reach the image root for **base-layer** packages (ubi8 rpms in ose-cli),
so the OCI product alone never matches them. Fix in the emitter: rpm statements
also list each rpm purl as an additional product (`openvex.py`) — safe because a
Red Hat NEVRA is a build identity; golang/python stay OCI-scoped only (module
verdicts must not leak). With this, file-mode is leak-free on both scanners.

**Known limitation:** trivy **repo-mode** still misses base-layer rpm findings
(index routes by image purl; base-layer leaves never look it up) — e.g.
CVE-2025-4598/systemd: suppressed in file mode, leaks in repo mode. golang (the
dominant FP class) is unaffected. Future option: shared `pkg/rpm/...` docs with
NEVRA-product statements + rpm index entries.

**Not yet validated:** `vextriage rhacs` live run against a Central (no
ROX_ENDPOINT in this environment) — CLI passthrough + engine baseline are
verified; the RHACS API path is unchanged code.

## 8d. Action test (2026-07-13) — 12-image estate run, grype+trivy+RHACS三-way

Set: 8× OCP 4.21.0 release images + 4× 3scale operator images (all digest-pinned,
all with RHACS-path verdicts for comparison). `vextriage generate --verify`, then
grype file-mode circle + trivy repo-mode + RHACS diff.

**Results**: 715 statements / 790 (CVE,pkg) pairs. trivy verify **12/12 clean**;
grype circle **0 leaks** (package-level); trivy repo-mode on OCP image: none leaked.
RHACS comparison: ~96 % of RHACS FPs re-confirmed on OCP images; extra hub-only
statements = grype-only findings (newer DB / go-module view), engine-confirmed.
3scale-operator "0 vs 60" discrepancy resolved: RHACS saw only rpm positives
(genuinely affected), grype saw go modules the engine cleared — disjoint finding
sets, consistent judging.

**Two fixes found by the test** (why estate-scale verification matters):
1. **SRPM statement extension** — Red Hat assesses rpms per *source* package;
   trivy flagged `net-snmp` (parent) where grype flagged `net-snmp-libs`
   (subpackage). Adapters now carry `SRPM` (grype: purl `upstream=`; trivy:
   `SrcName`; whitelisted through `_sort_and_filter_df`), and the emitter extends
   rpm statements to the source-rpm purl.
2. **OCP product scope for release images** — `ocp-v4.0-art-dev` labels don't
   carry the release; name-parsing had scoped verdicts to "OpenShift 4.0".
   `generate` now builds a digest→release map from `data/pullspecs/*.txt`
   (mirroring `retriage_ocp`) and pins ctx to the right minor (4.21).
3. **Verify metric is package-level**, not CVE-level — sibling binaries of one
   source rpm can carry different per-binary verdicts (bind-utils not_affected
   while bind-libs has a pending fix), so a CVE-level check miscounts
   deliberately-open packages as leaks.

## 9. Sequencing

```
Phase 0 (spike) ──┐
                  ├──► Phase 2 (emitter) ──► Phase 3 (builder) ──► Phase 4 (docs)
Phase 1 (inputs) ─┘   (Phase 1 can land in parallel; independent of 0)
```

Phase 0 gates only the builder. Input adapters (Phase 1) can proceed immediately.
