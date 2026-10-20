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
   decides; not affected in older versions → not affected (inferred); not affected only
   in newer versions clears nothing.
4. Not a Red Hat image (registry not Red Hat's) and no Red Hat rpm ships it → **affected**
   (Red Hat VEX does not cover it).
5. Errata assumption: our product (own, line or a newer version) lists images known
   affected / under investigation and cleared nothing under that same product node →
   **affected**, inferred.
6. Otherwise → not affected, inferred (not listed).

## OpenVEX

One statement per (CVE, package). Products: `pkg:oci/<name>@sha256:<digest>` for every
digest of the image (plus the digest as a `sha-256` hash); subcomponents: the package purl
without qualifiers (Go also lowercased, as trivy writes it). That is the shape grype and
trivy match (go-vex `PurlMatches`: a purl without qualifiers matches any qualifiers).
`not_affected` carries Red Hat's justification only when stated; inferred ones carry an
`impact_statement`. `--stated-only` keeps Red Hat's own statements only.
