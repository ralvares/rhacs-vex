# How vextriage decides

Input: a finding (CVE × package) in an image. Evidence: Red Hat's CSAF-VEX document for
that CVE, read as flat statements (status × product × component, `csaf.py`). Output: a
verdict — `affected`, `under_investigation`, `not_affected` or `fixed` — with the reason,
the deciding statement, and whether Red Hat **stated** it (about our product and our
package / image / build) or it was **inferred** from Red Hat's data by one of the rules
below. Data facts behind each rule: [VEX-MODEL.md](VEX-MODEL.md).

## The image's products (`engine.resolve`)

* **RHEL** of the image's major; the minor stream from os-release.
* **The image's own product**: the products whose statements name the image's path
  (registry path, then the `name` label), or its digests. A payload image
  (`quay.io/openshift-release-dev/…`) is found by its label under OpenShift
  (`openshift/ose-cli-rhel9` → Red Hat's `openshift4/ose-cli-rhel9`). A non-RHEL `cpe`
  label (`cpe:/a:redhat:openshift:4.20::el9`) names the product and its version; a RHEL
  `cpe` label is usually inherited from the base image and is ignored.
* Relative to the image, a product is: `own` (our version), `line` (version-neutral,
  GitOps 1 / OpenShift 4), `newer`, `older`, or `foreign` (anything else: never evidence).

## Every finding

1. No VEX document for the CVE → **affected** (the finding stands).
2. `red_hat_products` not affected → **not affected**, stated.
3. A statement naming **this build's digest** decides, for everything in the image.
4. This image (no digest) not affected in our product, nothing open about it → **not
   affected** for what is inside it.

## An rpm (`engine._rpm`)

Statements name the binary, or its source package (version-less or `.src`). Per product,
statements naming the binary outrank those naming the source. Statements about another
architecture or another module stream are ignored; the SBOM's module stream outranks
stream-less version-less statements. An rpm whose vendor is not Red Hat is never decided
by Red Hat's statements (**affected**, not covered).

**Provenance.** A plain `.elN` / module build is RHEL's: the RHEL ladder decides (the
image's own product saying the package is not affected in its context clears first). A
build with a product's tag (`rhaos4.20`, `el9ap`, `el8sat` …) is that product's: the
product ladder decides (RHEL's version-less not affected still clears). An rpm RHEL never
names is decided by the products naming it with the same lineage — another lineage's
builds (Hardened Images `hum`) are never compared with ours.

**RHEL ladder**, first match wins:

| # | rule | verdict |
|---|---|---|
| 1 | the installed build is itself a fixed / not affected build | fixed / not affected, stated |
| 2 | Red Hat names this binary not affected for our line or stream | not affected, stated |
| 3 | a fix in our minor stream (dist tag, else the product's minor) | installed ≥ fix → fixed, else affected (stated) |
| 4 | else the newest **mainline** fix of an earlier minor (our minor inherited it) | ≥ → fixed, else affected (inferred) |
| 5 | known affected / under investigation for our line or stream | affected (plan: Fix deferred, Will not fix …) |
| 6 | not affected (version-less) for our line or stream; a not-affected build of our upstream version in our stream | not affected, stated |
| 7 | a subpackage not affected in the very build that fixes its source (libacl beside acl) | not affected, inferred |
| 8 | fixes only in other streams: newer upstream version than every fix; at or past a mainline fix; newer than every fix, all in earlier streams, nothing open | fixed, inferred |
| 9 | otherwise, fixes only elsewhere | affected, inferred (errata policy: older builds are assumed vulnerable) |
| 10 | statements name other streams only / nothing | not affected, inferred (Red Hat enumerates rpms) |

**Product ladder**: the exact build; a fix in our version (the `rhaos4.N` tag, the image's
product version, or the rpm's own version); past any fix of the product; open for our
version or the line; not affected; fixes only elsewhere → affected; else not listed.

## A module inside the image (Go, Java, npm, Python …)

1. Red Hat's purl for it (maven / npm / pypi / golang) in our products: exact version,
   fixed version order, open, not affected.
2. The rpm that ships it (SBOM file ownership) → that rpm's verdict, if Red Hat names the rpm.
3. The image's statements: our version's builds ordered by build time (the purl `tag` vs
   the image's `release` label) — the nearest at or before ours speaks for ours; a fix
   only in a later build → affected. Builds **after** ours never clear it. Then open /
   not affected for our version, then for the line. Then other versions: fixed or
   affected only in a newer version → affected; fixed in an older version → build time
   decides; not affected in older versions → not affected (inferred); not affected in a
   newer version, with nothing open or fixed about the image anywhere → not affected
   (inferred; holdout below).
4. Not a Red Hat image (registry not Red Hat's) and no Red Hat rpm ships it → **affected**
   (Red Hat VEX does not cover it).
5. Errata assumption: our product (own, line or a newer version) lists images known
   affected / under investigation and cleared nothing under that same product node, and
   our version's own node clears none of its images (Red Hat went through this version's
   images and did not name ours) → **affected**, inferred.
6. Otherwise → not affected, inferred (not listed).

## OpenVEX

One statement per (CVE, package). Products: `pkg:oci/<name>@sha256:<digest>` for every
digest of the image (plus the digest as a `sha-256` hash), with the package purl without
qualifiers as the subcomponent (Go also lowercased, as trivy writes it); then the package
purl again as a product of its own, with itself as its only subcomponent. go-vex `PurlMatches`: a purl without qualifiers matches
any qualifiers. grype matches the image product first, then the package as the product.
trivy checks the package as the product, then walks up the dependency graph to the image —
and keeps the finding when the walk meets a cycle (rpm Requires: glibc ↔ bash, which most
rpms in an image sit above), so without the package product trivy dropped nothing on ubi9
(verified: grype 527 → 525, trivy 534 → 532, the two findings vextriage clears). That
product needs the subcomponent: trivy reads a product without subcomponents as covering
everything below it in that walk, and `mod_http2` not affected (ubi9/python-312) then
cleared 27 findings of `httpd` — which mod_http2 requires — that vextriage keeps. A
statement about the image itself has no subcomponent: the scanners apply it to every
package, so a cleared one is written only when Red Hat stated it and no package of the
image is still affected for that CVE (an inferred "not listed" for registry.access.redhat.com/
ubi9/go-toolset cleared ten golang findings Red Hat lists affected). A
statement made from a scanner's findings (`scan --scanner … --openvex`) carries the
scanner's own id as an alias: grype reports Go modules as `GHSA-…` and matches only that
id (on the OpenShift release image its 19 cleared Go findings were applied only with it).
`vextriage openvex IMAGE` is the free scan: it holds what Red Hat's data names for the
image's rpms, purls and paths — a Go module Red Hat never names by purl has no statement
there, so to clear a scanner's findings use `scan --scanner … --openvex`.
`not_affected` carries Red Hat's justification only when stated; inferred ones carry an
`impact_statement`. `--stated-only` keeps Red Hat's own statements only.

## Calibration (holdout on the whole corpus)

`tools/holdout.py` hides Red Hat's own statement for an (image or rpm, CVE), lets the
engine infer, and compares with the hidden truth — 1,138,118 cases from all 72,458
documents (at most 40 per document per kind; 2 minutes). Run of 2026-10-20 (feed of the
same day). Accuracy counts a hidden `fixed` as affected (an unnamed build may predate
the fix); *decisive* scores only hidden affected vs. not affected with the component
present (`component_not_present` alone is set apart: a scanner would not report there).

| rule | case | n | accuracy | decisive |
|---|---|---:|---:|---:|
| errata_assumed | image unnamed | 28,832 | 96.7% | 96.8% |
| errata_assumed | image named only in other versions | 784 | 99.5% | 99.5% |
| not_listed (image) | image unnamed | 92,412 | 70.8% | 89.2% |
| image_build | one build hidden | 5,908 | 100% | 100% |
| image_older_not_affected | our version hidden | 13,526 | 96.3% | 100% |
| image_newer_not_affected | our version hidden | 7,103 | 97.3% | 100% |
| rpm_subpackage | stream not affected / at the fix / before the fix | 898 / 1,265 / 1,265 | 100% / 100% / 0% | |
| rpm_clean_build | stream not affected / at the fix / before the fix | 84 / 49 / 49 | 100% / 100% / 0% | |
| rpm_errata | before the stream's fix / stream not affected / at the fix | 89,069 / 646 / 86,925 | 100% / 0% / 0% | |

Reading the rpm rows: the hidden truth for a stream is a fix (installed just before it →
affected, or the fix itself → not affected) or a not-affected build. `rpm_errata` says
affected whenever a stream lists nothing, so it is right for every build before the
stream's fix and wrong for the fix itself — which no rule can know once the stream is
silent; the stream was not affected only 646 times against 89,069 fixes (99.3%).
`rpm_subpackage` / `rpm_clean_build` are right when the stream says the subpackage is
not affected or carries the fix, wrong when Red Hat lists the subpackage itself fixed in
that stream (it lists every binary of a fixed build) and the build predates it.

Rule changes this calibration made, each with its test:
* **errata_assumed** needed "our version's own node clears none of its images": without
  it the assumption was right 76.7% (decisive 75.7%) on 38,590 cases; the 9,758 it no
  longer fires on were clear 8,044, fixed 1,684, affected 29.
* **image_newer_not_affected** is new: "not affected only in newer versions clears
  nothing" left 1,288 such images to the errata assumption, right 3.4% of the time.

Measured and not changed:
* CVE-2026-42507 (OpenShift 4 node: 78 rpms and 3 images known affected, 1 image not
  affected) — an unnamed OpenShift image is "not listed", and all 4 holdouts of that
  node are wrong. Tolerating a few cleared images, or deciding by the share of open
  statements under the node (≥ 90 / 95 / 98%), moves corpus accuracy by ≤ 0.2 points;
  at 95% the 441 cases it adds are 63% affected across only 38 documents. Not evidence
  enough.
* An rpm RHEL never names, decided by another product's statement (Ironic's
  python3-decorator rebuild, Hardened Images' version-less python-urllib3): where RHEL
  does speak, those statements agree with RHEL's far better than "not listed" does
  (`foreign` case: product_errata 99.5%, product_not_affected 90.1% vs. not listed 19%).
  The holdout cannot see RHEL's real silence, but it gives no ground to drop them.
* The holdout can only test where Red Hat speaks; rules that read silence ("not listed")
  are scored on a selection a real scan does not meet.
