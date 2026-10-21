# Next run: the images that need credentials

A prompt for an agent run on a machine with internet, Docker and an OpenShift pull
secret. Paste everything below the line; replace `PULL_SECRET_FILE` with the path of the
pull secret file.

**Status (2026-10-21).** Run once, with a temporary pull secret, on the feed of that day
(72,830 documents). With `scan --scanner … --openvex`, every finding vextriage clears was
gone under `--vex` and no finding it keeps was, in grype and trivy, on all of:

| image | resolved as | grype findings / cleared | trivy findings / cleared |
|---|---|---:|---:|
| ocp-v4.0-art-dev cli (4.22.18, b31735da…) | OpenShift 4.22, RHEL 9.8 | 547 / 27 | 93 / 23 |
| ocp-v4.0-art-dev cluster-version-operator (4.22.18, e5f227a4…) | OpenShift 4.22 | 487 / 21 | 76 / 18 |
| ocp-v4.0-art-dev cli (4.20.42, d44d07d3…) | OpenShift 4.20, RHEL 9.6 | 894 / 191 | 130 / 60 |
| registry.redhat.io/openshift4/ose-cli-rhel9:latest | OpenShift 4.22 | 509 / 27 | 55 / 23 |
| registry.redhat.io/rhel9/postgresql-16:latest | RHEL 9.8 | 864 / 5 | 873 / 5 |
| registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator:1.19 | GitOps 1.19, RHEL 8.10 | 409 / 44 | 408 / 43 |
| registry.redhat.io/web-terminal/web-terminal-tooling-rhel9:1.15 | Web Terminal 1.15 | 1,395 / 197 | 1,125 / 76 |

(the gitops and web-terminal repositories have no `latest` tag.) 140,983 deciding
statements across these and the public images were found in the raw documents with the
status their rule claims, 0 mismatches. Found and fixed on the way: one purl with two
verdicts in an image (web-terminal: stdlib go1.26.7 in two binaries) — grype applied the
clear to both copies. Still open, as listed in step 4: unowned content (pip in
ubi9/python-312), rpms decided by another product's statement (gitops: openssl-libs
affected by CVE-2014-3566 only through JBoss Web Server 1's `openssl.src`), and
CVE-2026-42507 (the payload images get "not listed"; neither scanner reports it there).

---

Repository ralvares/rhacs-vex, branch main (work and push on main only; no pull requests).
It is vextriage 3: it triages grype / trivy / syft findings against Red Hat CSAF-VEX and
publishes OpenVEX. Read README.md, docs/RULES.md (the engine's rules and the holdout
calibration) and docs/VEX-MODEL.md (facts about the data) first. Be sceptical: verify every
claim against Red Hat's raw documents (data/vex/CVE-….json.gz) and say how each result was
verified. Never print, copy or commit the pull secret. Do not regenerate or delete vexhub/
(it is published) — ask first.

What an earlier session already did (2026-10-20): first sync against the live feed (the
mirror is kept gzipped, 72,458 documents, an 827 MB index); the holdout calibration
(tools/holdout.py, results in docs/RULES.md); OpenVEX fixed so grype and trivy both apply
it. It ran end to end only on public images (ubi8/9/10, ubi9/python-312, ubi8/nodejs-20,
ubi9/go-toolset, quay.io/openshift-release-dev/ocp-release 4.22.18,
docker.io/mongodb/mongodb-community-server). Every OpenShift and layered image needed
credentials it did not have. That is your job.

1. Setup
   - `pip install -e '.[archive,test]'`; `python -m pytest -q tests` (39 must pass).
   - Install syft, grype and trivy (`vextriage doctor` shows what is found);
     `grype db update`; `trivy image --download-db-only`. Install `oc` if missing.
   - Credentials, without echoing them: `mkdir -p ~/.vextriage-auth && cp PULL_SECRET_FILE
     ~/.vextriage-auth/config.json && chmod 600 ~/.vextriage-auth/config.json && export
     DOCKER_CONFIG=~/.vextriage-auth`. syft, grype, trivy and `oc image info` read
     `$DOCKER_CONFIG/config.json`, which is a pull secret's format. Confirm with
     `oc image info --filter-by-os=linux/amd64 registry.redhat.io/rhel9/postgresql-16:latest`.

2. `vextriage sync` (first run about 7 minutes: a ~370 MB archive, then the index). Run it
   a second time and confirm it only fetches what changed. Report the document count and
   index size.

3. The images. Pick payload images with
   `oc adm release info --pullspecs quay.io/openshift-release-dev/ocp-release:<version>-x86_64`
   (4.22.18 was used before: cli = ocp-v4.0-art-dev@sha256:b31735da2b1e3b06734f3f504ac8ece7c71cfdd96ca74c5f750b600f3dc1a421,
   cluster-version-operator = ocp-v4.0-art-dev@sha256:e5f227a425d1f0d33c0e99fdcaf3b8465dffc56294cba19f4fc214709c5145cc).
   Run at least:
   - two payload images from quay.io/openshift-release-dev/ocp-v4.0-art-dev (cli and
     cluster-version-operator; add one from an older 4.x, e.g. 4.20, to exercise version order)
   - registry.redhat.io/rhel9/postgresql-16
   - registry.redhat.io/openshift4/ose-cli-rhel9
   - registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator
   - registry.redhat.io/web-terminal/web-terminal-tooling-rhel9

   For each: `tools/e2e.sh NAME IMAGE` (output under data/scans/NAME, ignored by git). It
   writes the syft SBOM and the grype / trivy reports, triages in all three modes (free scan,
   grype, trivy), writes OpenVEX twice (`vextriage openvex` = the free scan; `scan --openvex`
   = the scanner's own findings), re-runs both scanners with `--vex`, and prints the diff.
   Then `python3 tools/check_evidence.py data/scans/*/free.json data/scans/*/*-triage.json`:
   every deciding statement must exist in the raw document with the status its rule claims.
   Also run the `vextriage scan IMAGE`, `--scanner grype` and `--scanner trivy` commands on
   one image, to exercise the CLI path that pulls the image itself.

   What must hold, and what to report per image:
   - `KEPT BUT GONE` must never appear: a finding vextriage keeps must survive --vex.
   - In scan-openvex mode every clear must be gone; explain each `clears left` (the diff
     keys on CVE + package name, so a second version of the same package can show there).
   - How the image was resolved: the first line of `vextriage scan` (product, version,
     red hat image) and `vextriage explain CVE --sbom …` (`paths`). A payload image must be
     found by its `name` label under OpenShift (openshift/ose-cli-rhel9 → openshift4/…).
   - For every verdict class (rule × status) on these images — especially this_build,
     image_build, image_clear, image_*_open, image_older_not_affected,
     image_newer_not_affected, image_newer_version, errata_assumed, not_listed, purl_*,
     product_* (GitOps ships el8 rpms of its own) — open two or three rows with
     `vextriage explain CVE --sbom data/scans/NAME/sbom.syft.json --package PKG` and check
     them against the raw statements (`zcat data/vex/CVE-….json.gz`).

4. Open questions found earlier. Change a rule only on holdout evidence: add the case or
   variant to tools/holdout.py, run it on the whole corpus (~2 minutes), add a test per
   change, update docs/RULES.md (rule and calibration table). Report what you find either
   way.
   - Unowned content in a Red Hat image: pip 24.2 in ubi9/python-312's /opt/app-root
     belongs to no rpm. Red Hat lists RHEL 9's pip known_affected for CVE-2026-13346, but
     the engine says "not listed", and its OpenVEX makes grype and trivy drop a real
     finding. Look for the same pattern on the new images.
   - An rpm RHEL never names, decided by another product's statement (OpenShift Ironic's
     python3-decorator rebuild, Hardened Images' version-less python-urllib3). The holdout
     backed keeping it, but cannot see RHEL's real silence.
   - CVE-2026-42507: under the OpenShift 4 node, 78 rpms and 3 images are known affected and
     1 image is not affected, so an unnamed OpenShift image is "not listed". No variant
     tried beat the current rule by more than 0.2 points across the corpus. Check what the
     real payload images get for it.
   - On ubi10 trivy found no vulnerabilities at all (trivy's data, not vextriage). Re-check.

5. Commit and push to main with clear messages (what broke, the data that proved it, how
   the fix was verified), ending each with your session's attribution lines. Never commit
   the pull secret, data/, or scan output. End with a short report: per image the finding
   counts per mode, what vextriage cleared, the --vex results, what you checked by hand, and
   every rule or code change with its evidence.
