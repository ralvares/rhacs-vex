# Phase 0 spike — RESULTS (golang, proven end-to-end)

> Ran the full loop on a real Red Hat image: **syft SBOM → grype scan → Red Hat
> CSAF-VEX → hand-built OpenVEX → suppression in both grype AND trivy.** The hard
> golang case works. Scratchpad artifacts under `…/scratchpad/vex-spike/`.

## Target
- Image: `registry.redhat.io/openshift4/ose-cli` (OpenShift CLI, `oc`)
- Pinned: repo digest `sha256:ef83967297f619f45075e7fd1428a1eb981622a6c174c46fb53b158ed24bed85`
- Labels: `version=v4.15.0`, `release=…el8`, component `openshift-enterprise-cli-container`
- Platform: linux/amd64

## Pipeline that ran
1. `syft registry:<img> -o spdx-json -o syft-json` → 430 pkgs (**224 rpm, 182 golang, 23 pypi**). syft DOES emit purls (unlike RHACS scanner-v4 SBOMs).
2. `grype sbom:<spdx> --by-cve -o json` → 926 matches (763 rpm, 163 go-module), 3 non-CVE unmapped. `--by-cve` normalizes GHSA→CVE.
3. Fetched Red Hat CSAF-VEX per CVE from `security.access.redhat.com/data/csaf/v2/vex/<year>/<cve>.json`.
4. Hand-built one OpenVEX doc, tested with `grype --vex` and `trivy image --vex`.

## RESULT: 7/7 golang CVEs suppressed in BOTH scanners
Confirmed `known_not_affected` for `openshift-clients` @ OCP 4.15/el8, flag
`vulnerable_code_not_present`:
`CVE-2023-45288` (x/net + stdlib), `CVE-2023-45290`, `CVE-2024-24790`,
`CVE-2024-34155`, `CVE-2024-34156`, `CVE-2024-34158`, `CVE-2025-22871` (all stdlib).

Strict trivy before/after: **924 → 916 total vulns, exactly 8 golang instances
removed, 0 of the 7 CVEs remain on any golang package.** grype: all 7 moved to
`ignoredMatches`.

## Load-bearing findings

### 1. One product `@id` matches BOTH scanners
```
pkg:oci/ose-cli@sha256:ef83967297f619f45075e7fd1428a1eb981622a6c174c46fb53b158ed24bed85
```
- **basename** (`ose-cli`), the **repo/pull digest** (`ef8396…`), **NO qualifiers**.
- Use the pull digest, **not** the manifest digest (`sha256:697629…`, amd64-specific) that syft puts in the SPDX OCI purl.
- **`?repository_url=…` qualifier BREAKS grype** (trivy tolerates it). → emit the bare purl, no qualifiers.
- grype also matches the raw digest ref string and the bare sha256; trivy matches the bare purl. The bare purl above is the common form.

### 2. Subcomponent purl DIVERGES between scanners (the Bridge-A risk, live)
| component | grype purl | trivy purl |
|---|---|---|
| stdlib | `pkg:golang/stdlib@1.20.12` | `pkg:golang/stdlib@`**`v`**`1.20.12` |
| golang.org/x/net | `pkg:golang/golang.org/x/net@v0.20.0` | same |

grype strips the `v` from the Go toolchain version; trivy keeps it. Fix that works:
**list both forms as `subcomponents`** in the statement — a statement applies if any
listed subcomponent matches, so grype hits its form and trivy hits its.

### 3. SBOM-interop gotchas (choose the input per consumer)
- **grype**: scan the **syft-JSON** SBOM, not the SPDX. The SPDX export **drops
  `repoDigests`**, leaving grype no image identifier → product never matches.
- **trivy**: scan the **live image** (or a trivy/CycloneDX SBOM), not the syft-SPDX.
  Trivy logs `Skipping a component with an unsupported type … type="oci"` and drops
  the OCI root → no product to match the statement against.

### 4. Justification = raw CSAF flag, verbatim
Red Hat CSAF flag `vulnerable_code_not_present` → OpenVEX `justification`
`vulnerable_code_not_present`. Zero translation, as predicted. Emit the raw flag,
not any humanized display string.

### 5. "No version fallback" for golang — CONFIRMED as a real limit
Of ~18 flagged golang CVEs checked, **only 7 had an `openshift-clients` 4.15
statement**; the rest returned *no entry* (e.g. CVE-2024-24791, CVE-2023-45289,
CVE-2025-4673, CVE-2024-24784…). Without an explicit product-scoped VEX statement
there is no version-compare safety net for Go (the binary reports the upstream
module version whether patched or not), so those findings **cannot be marked
not_affected** — they must stay open. Golang triage confidence == coverage of
explicit Red Hat statements. The real engine (catch-all CPE, related products,
RHSA fixes) will resolve more than this hand-check did, but the class limit stands.

## OpenVEX statement shape that worked
```json
{
  "vulnerability": { "name": "CVE-2023-45290" },
  "products": [{
    "@id": "pkg:oci/ose-cli@sha256:ef83967297f619f45075e7fd1428a1eb981622a6c174c46fb53b158ed24bed85",
    "subcomponents": [
      { "@id": "pkg:golang/stdlib@1.20.12" },
      { "@id": "pkg:golang/stdlib@v1.20.12" }
    ]
  }],
  "status": "not_affected",
  "justification": "vulnerable_code_not_present"
}
```

## Hub proven end-to-end on BOTH scanners (index/repo mode included)

Built a local vexhub (aquasecurity/vex-repo-spec layout) and drove both tools against it:
```
hub/
  vex-repository.json                                          # manifest
  index.json                                                  # pkg:oci purl → location
  pkg/oci/registry.redhat.io/openshift4/ose-cli/scan.openvex.json
```
- **grype** (file mode): the `location` path mirrors the image ref, so it is *derivable* —
  `grype … --vex hub/pkg/oci/<registry>/<ns>/<name>/scan.openvex.json`. grype ignores the
  index entirely. → **7/7 suppressed.**
- **trivy** (`--vex repo`): served the hub over HTTP, `trivy vex repo download`, then
  `trivy image … --vex repo`. Index routed the scanned image purl → doc → statements.
  → **7/7 suppressed, 924→916** (same as file mode).

**Cross-tool product `@id` rule (decisive):**
| product `@id` | grype | trivy |
|---|---|---|
| `pkg:oci/<name>?repository_url=…` (rancher's exact) | ❌ | ✅ |
| `pkg:oci/<name>` (name only) | ✅ | ✅ |
| `pkg:oci/<name>@sha256:<digest>` (**chosen**) | ✅ | ✅ |

The **`repository_url` qualifier breaks grype** → rancher's exact product format is
trivy-only. For both tools the product `@id` must be a **bare** `pkg:oci/<name>@sha256:<digest>`
(no qualifiers). Digest (not rancher's name-only) is required for Red Hat because one image
name spans many OCP versions with potentially different verdicts.

**Split of concerns that makes both work:**
- index `id` → may carry `repository_url` (trivy routing / registry disambiguation; grype ignores it)
- statement product `@id` → bare `pkg:oci/<name>@sha256:<digest>` (both tools match this)
- `location` → mirror the registry path (`pkg/oci/<registry>/<ns>/<name>/scan.openvex.json`) so grype can derive it

**Gotcha — trivy repo config path:** `$XDG_DATA_HOME/.trivy/vex/repository.yaml` (note the
nested `.trivy`), or `$HOME/.trivy/vex/repository.yaml`. Serve `vex-repository.json` (also at
`/.well-known/`) + the archive zip named in its `locations[].url`.

## "Test it all" — full matrix proven (classes × statuses × tools × hub)

| dimension | proven |
|---|---|
| classes | **golang** ✅, **rpm** ✅ |
| statuses | **not_affected** ✅, **fixed** ✅ (both suppress in both tools) |
| tools | **grype** (file) ✅, **trivy** (repo/index) ✅ |
| combined hub | 8 statements (7 golang + 1 rpm), **grype 8/8**, **trivy repo 8/8 (924→915)** |

**rpm subcomponent form — BARE wins both:**
| form | grype | trivy |
|---|---|---|
| `pkg:rpm/redhat/python3-urllib3@1.24.2-8.el8_10` (bare) | ✅ | ✅ |
| grype-form (`distro=rhel-8.10&upstream=…`) | ✅ | ❌ |
| trivy-form (`distro=redhat-8.10`) | ❌ | ✅ |

Rule: **strip all qualifiers from subcomponent purls** → `pkg:rpm/redhat/<name>@<nevra>`,
`pkg:golang/<module>@<version>`. Exception: where the *version string* itself differs
across tools (golang `stdlib@1.20.12` vs `@v1.20.12`) emit both version variants.

### Big empirical finding — where the FP value actually is
Across **485 CVEs, 408 had a RHEL-8 verdict for the installed rpm: 407 `known_affected`,
1 `known_not_affected`, 0 backport-`fixed`.** grype already consumes Red Hat's rpm data,
so it barely over-reports rpm — those 407 are genuinely affected per Red Hat and *should*
stay. The false-positive value of the VEX hub is **concentrated in golang (and operators)**,
where scanners use upstream module identity and miss Red Hat's product-scoped
`vulnerable_code_not_present` assessments. rpm not_affected cases exist but are rare;
backport-`fixed` FPs essentially don't occur for grype-on-RH (it pre-handles them).
→ Prioritize golang/operator coverage in the emitter; rpm is mostly already correct.

### trivy repo cache gotcha
`trivy vex repo download` honors the manifest `update_interval` and won't re-fetch within
it; the downloaded repo lives at `~/Library/Caches/trivy/vex/repositories/<name>/` (NOT
under `$XDG_DATA_HOME`). To force a refresh in testing, use a new repo `name`.

## Consequences for the build
- Emitter must key the product on the **pull digest**, bare purl, no qualifiers.
- Emitter must emit **per-scanner subcomponent variants** (at least the stdlib `v`
  vs no-`v` split; audit other ecosystems — pypi, npm — for similar normalization).
- Pipeline input: feed **grype from syft-JSON**, **trivy from image/CycloneDX**.
- rpm class still untested here — expected easy (name+version+backport), but the
  `pkg:rpm` qualifier set (`arch`,`distro=redhat-8.10`,`epoch`,`upstream`) should get
  the same one-image proof before the emitter generalizes.
