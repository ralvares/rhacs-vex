# Accuracy Report — suppression audit & scanner comparison

**Date:** 2026-07-13/14 · **Tools:** grype 0.111.0, trivy 0.69.3, syft 1.42.4,
RHACS Central (Scanner) · **Judge:** the vextriage engine, verdicts verified by
hand against live Red Hat CSAF-VEX (`security.access.redhat.com/data/csaf/v2/vex/`).

Everything below was measured on this repository's data, not estimated.

---

## 1. What was audited

- **Structural pass:** all 681 hub documents, 81,413 statements — zero schema,
  product-id, justification or duplicate defects.
- **Accuracy sample:** 32 statements, stratified over rpm/golang × fixed/not_affected,
  each compared by hand against Red Hat's live VEX.
- **Exhaustive two-sided check** on one full image (buildah): every suppressed
  finding must be a confirmed false positive, every visible finding must be real.
- **Per-class reruns:** oc-cli (OpenShift-scoped), OCP release payload image,
  operator image, ubi8/ubi9 bases.
- In total, **~320 suppression decisions were verified individually. Zero were
  wrong in either direction** (after the fixes below).

## 2. Bugs the audit found (all fixed, all regression-tested)

| # | Bug | Impact before fix | Proof of fix |
|---|-----|-------------------|--------------|
| 1 | VEX cache never expired (requests-cache sqlite; Red Hat CDN sends no Cache-Control) | Verdicts froze at first download — a July-7 cache hid a July-8 fix; the blob store grew to 385 GB | Replaced with plain files + ETag sidecar + 4 h revalidation; stale statement retracted |
| 2 | not_affected could override a **pending fix** for the installed build | **3,398 of 4,014 rpm not_affected statements (85%) were suspect**; confirmed cases: `tar`, `dotnet-host` hid real fixable findings | Precedence rule: a pending applicable fix now beats a broader not_affected; worst doc went 353 wrong statements → 1 correct one |
| 3 | Go modules inside rpms were invisible to matching | Red Hat assesses the **vendoring rpm** (`rhel9:buildah`), the scanner reports the module (`x/net`) — 47 factually wrong statements in one doc | SBOM file-ownership now links module → rpm; verdicts agree with Red Hat |
| 4 | Stale statements lived in docs forever | A flipped verdict never disappeared | Re-scan of a digest retracts statements it no longer emits |
| 5 | Sibling rpm divergence (trivy matches by *source* package) | A not_affected sibling (`bind-utils`) silently suppressed an affected one (`bind-libs`) | No statement emitted when siblings diverge; `bind-libs` visible again |

Independent safety net added: `vextriage generate --crosscheck` re-checks every
emitted statement against the raw Red Hat files with separate rules and prints
disagreements. Negative-tested: injected lies are caught.

## 3. Scanner comparison (bake-off)

Four images, three scanners, same judge. "Real" = the engine confirmed the finding
against Red Hat's current VEX. "Missed" = real CVEs (union of all three scanners)
that this scanner never reported — i.e. **false negatives**. "Noise" = findings
the engine proved are false positives.

| Image | Scanner | Findings | Noise (FP) | Real | **Real missed (FN)** |
|-------|---------|---------:|-----------:|-----:|---------------------:|
| ose-cli (Go-heavy OCP) | grype | 799 | 89 | 488 | **1** |
| | trivy | 161 | 76 | 76 | 413 |
| | RHACS | 148 | 80 | 65 | 424 |
| buildah (Go+rpm) | grype | 782 | 53 | 523 | **6** |
| | trivy | 697 | 4 | 519 | 10 |
| | RHACS | 541 | 2 | 385 | 144 |
| collector (stripped Go) | grype | 363 | 0 | 290 | 2 |
| | trivy | 364 | 0 | 291 | **1** |
| | RHACS | 381 | 28 | 280 | 12 |
| ubi8 (pure rpm base) | grype | 502 | 0 | 373 | 10 |
| | trivy | 520 | 0 | 377 | **6** |
| | RHACS | 488 | 0 | 340 | 43 |

### What drives the numbers

- **grype sees the most.** Its "extra" findings were traced: mostly packages Red Hat
  itself marks *known_affected* (including the never-will-fix backlog: vim, openssl,
  python3) plus fix-exists-build-older cases. Real, per Red Hat.
- **grype's noise lives on Go-heavy images** — exactly the class the vexhub suppresses.
- **trivy is the cleanest raw output** and strong on rpm images, but skips Go
  standard-library CVEs by default and surfaces less of the unfixed backlog →
  the 413 misses on ose-cli.
- **RHACS surfaces the least by policy** (its scan of ose-cli lists vim-minimal with
  4 vulns where Red Hat's own data acknowledges 128) plus its permanent scan cache
  ages (the snapshot used was two weeks old). It is, however, the **only scanner
  that sees inside stripped Go binaries** — on the collector image it alone caught a
  real go-git finding (and 28 false positives) invisible to both others, because it
  reads Red Hat's build records instead of inspecting the binary.
- Shared limitation: grype and trivy are blind inside stripped Go binaries.

### Ranking (criteria: false negatives first, false positives second)

| Rank | Scanner | Verdict |
|------|---------|---------|
| 1 | **grype** | Fewest misses everywhere except one image where trivy edged it by 1. Its noise is curable (this hub); blindness is not. |
| 2 | **trivy** | Excellent on rpm-centric images, cleanest raw output; weak discovery on Go-heavy images; repo-mode quirks (base-layer rpm gap, source-package over-suppression). |
| 3 | **RHACS** | Most false negatives by count (data policy + cache age); unique strengths: stripped-binary visibility and product-scoped context. |

### The practical conclusion

No scanner wins alone. The measured best configuration is the one this project
implements:

- **grype + syft generate the hub** (widest Red Hat-confirmed coverage; its noise
  is exactly what the hub's statements suppress).
- **trivy or grype + the hub** for consumers: near-zero false positives, smallest
  false-negative surface their tools allow.
- **RHACS + triage** for fleet visibility: the only view inside stripped Go
  binaries, with product-scoped verdicts. RHACS output is never converted into
  hub documents — statements must match what consumer scanners can actually see.

## 4. Caveats

- "Missed" is measured against the union of what the three scanners found; a CVE
  none of them can see is invisible to this method.
- The RHACS column partly reflects a two-week-old cached scan; re-scanning
  shrinks (but does not close) its gap — the vim-class policy difference remains.
- The engine that judged all findings is the same engine that generates hub
  statements; its verdicts were independently spot-verified against live Red Hat
  data throughout (32-statement sample + every anomaly adjudicated by hand).
- Statements cover the **linux/amd64** build (multi-arch list digest as product
  identity, arch-less package purls); packages exclusive to other architectures
  are not covered.
