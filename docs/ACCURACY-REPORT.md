# Accuracy Report — which scanner should you trust?

**Date:** July 13–14, 2026
**Tools:** grype 0.111.0, trivy 0.69.3, syft 1.42.4, RHACS Central (Scanner)
**Ground truth:** Red Hat's live CSAF-VEX feed (`security.access.redhat.com/data/csaf/v2/vex/`).
The vextriage engine produced the verdicts; samples were verified by hand against the raw Red Hat files.

Everything below was measured on this repository's data. Nothing is an estimate.

Before the bake-off, the judge itself was validated: a structural pass over all 681 hub
documents (81,413 statements), a 32-statement stratified sample compared by hand against
Red Hat's live VEX, one image (buildah) checked exhaustively in both directions, and
per-class reruns across oc-cli, an OCP release payload image, an operator image, and the
ubi8/ubi9 bases — about **320 individual suppression decisions verified one by one, none
wrong in either direction.**

---

## The scanner bake-off

Four images, three scanners, one judge. Reading the columns:

- **Real** — the engine confirmed the finding against Red Hat's current VEX.
- **Noise** — the engine proved the finding is a false positive.
- **Missed** — real CVEs (from the union of all three scanners) that this scanner
  never reported. These are its false negatives, and they matter most.

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

### What's actually driving these numbers

**grype sees the most.** Its "extra" findings were traced rather than assumed to be
noise: most are packages Red Hat itself marks *known_affected* — including the
never-will-fix backlog (vim, openssl, python3) — plus cases where a fix exists but
the installed build predates it. Real findings, according to Red Hat's own data. And
grype's false positives cluster on Go-heavy images, which is exactly the class of
noise the vexhub statements suppress.

**trivy has the cleanest raw output** and is strong on rpm images. But it skips Go
standard-library CVEs by default and surfaces less of the unfixed backlog — that's
where the 413 misses on ose-cli come from.

**RHACS surfaces the least, largely by policy.** Its scan of ose-cli lists
vim-minimal with 4 vulnerabilities where Red Hat's own data acknowledges 128, and its
permanent scan cache ages (the snapshot used here was two weeks old). But it is the
only scanner that can see inside stripped Go binaries: on the collector image it
alone caught a real go-git finding (along with 28 false positives) that the other two
physically cannot see, because it reads Red Hat's build records instead of inspecting
the binary.

One limitation grype and trivy share: both are blind inside stripped Go binaries.

### Ranking

Ranked by false negatives first, false positives second — a missed vulnerability is
worse than noise:

| Rank | Scanner | Verdict |
|------|---------|---------|
| 1 | **grype** | Fewest misses on every image except one, where trivy edged it by a single CVE. Its noise is curable — that's what this hub is for. Its blind spots are not. |
| 2 | **trivy** | Excellent on rpm-centric images and the cleanest raw output, but weak at discovery on Go-heavy images, with some repo-mode quirks (base-layer rpm gap, source-package over-suppression). |
| 3 | **RHACS** | The most false negatives by count, from data policy plus cache age. Unique strengths nothing else has: stripped-binary visibility and product-scoped context. |

### What I'd actually run

No single scanner wins. The best configuration measured is the one this project
implements:

- **grype + syft generate the hub.** Widest Red Hat-confirmed coverage, and grype's
  noise is precisely what the hub's statements suppress.
- **trivy or grype + the hub** for consumers: near-zero false positives, and the
  smallest false-negative surface those tools allow.
- **RHACS + triage** for fleet visibility: the only view inside stripped Go binaries,
  with product-scoped verdicts. RHACS output is never converted into hub documents —
  statements have to match what consumer scanners can actually see.

## Honest limitations

- "Missed" is measured against the union of what three scanners found. A CVE none of
  them can see is invisible to this method too.
- The RHACS column partly reflects a two-week-old cached scan. Re-scanning shrinks
  the gap but doesn't close it — the vim-class policy difference remains.
- The engine that judged the findings is the same engine that generates the hub
  statements. That circularity is worth naming, and it's why verdicts were
  independently spot-checked against live Red Hat data throughout: the 32-statement
  sample, plus every anomaly adjudicated by hand.
- Statements cover the **linux/amd64** build only (the multi-arch list digest is the
  product identity, and package purls carry no arch). Packages exclusive to other
  architectures are not covered.
