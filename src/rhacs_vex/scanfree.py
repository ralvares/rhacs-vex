"""Scan-free triage — SBOM + Red Hat CSAF-VEX only, no vulnerability scanner.

A scanner contributes exactly one thing the VEX corpus cannot: the (component,
CVE) candidate list.  An inverted index over the mirrored VEX files supplies it
instead — for every rpm purl in the SBOM, every CVE whose `product_status` names
that package becomes a candidate, and the image contributes the CVEs naming its
OCI repo.  Verdicts then come from the unchanged engine, so the decision ladder,
scoping, severity chain and publication gate are identical to the scanner-driven
paths.

Coverage is the mirror image of a scanner's:

* **rpm** — complete.  Red Hat enumerates every binary subpackage per arch
  (VEX-MODEL §9.1) and the syft purl and the VEX purl agree on
  (name, version-release, arch, epoch), so the join is exact.  This finds CVEs a
  scanner's database has not caught up with.
* **image (oci)** — complete, 14.8% of all Red Hat statements.
* **golang / pypi** — structurally empty.  Red Hat publishes 2 golang purls and
  19 pypi refs in the whole corpus because vendored Go is assessed at the
  operator/component image, never the module purl.  Nothing to enumerate, so a
  scanner is still required for that class.

Identity comes from the purl throughout — Red Hat's own csaf-lib models
`product_id` as an opaque string and parses only `product_identification_helper`.
"""
from __future__ import annotations

import json
import re

import pandas as pd

from .vexindex import INDEX_PATH, build_vex, oci_repo_keys, open_index, rpm_purl_name  # noqa: F401

# Rows minted for the image itself use SOURCE='IMAGE' rather than 'OS': an
# image-identity pseudo-component carries a path ('openshift/ose-cli-rhel9'), and
# the OS branch of openvex.subcomponent_ids would mint it as an rpm purl —
# pkg:rpm/redhat/openshift/ose-cli-rhel9@<build> — an identity no scanner emits.
IMAGE_SOURCE = 'IMAGE'


def build_index(vex_dir: str = None, out_path: str = INDEX_PATH, progress=None) -> dict:
    """(Re)build the on-disk index over the mirror; returns counts."""
    from .core.store import VEX_DIR
    return build_vex(vex_dir or VEX_DIR, out_path, progress)


def load_index(path: str = INDEX_PATH):
    """The on-disk index, or {} when it has not been built yet."""
    return open_index(path) or {}


# ── candidates ────────────────────────────────────────────────────────────────

def image_identity(repo: str, labels) -> tuple:
    """(index keys, pseudo-component, version) for the image's own identity.

    Both the repo path as pulled and the `name` label are looked up: the two
    purl eras index the image under either form (§4a), and an art-dev build
    carries no labels at all.
    """
    labels = labels or {}
    label_name = labels.get('name') or ''
    keys = {repo, repo.split('/')[-1]} if repo else set()
    if label_name:
        keys |= {label_name, label_name.split('/')[-1]}
    comp = label_name or (repo.split('/')[-1] if repo else '')
    return {k for k in keys if k}, comp, labels.get('release') or labels.get('version') or ''


def repo_from_ref(image_ref: str) -> str:
    """Repo path of an image reference, digest and tag dropped."""
    ref = (image_ref or '').split('@')[0]
    head, _, tail = ref.rpartition('/')
    return f"{head}/{tail.partition(':')[0]}" if head else tail.partition(':')[0]


def merge_index_candidates(df, index: dict, *, image_ref: str = '', labels=None):
    """Union a scanner's findings with every pair the VEX index can decide.

    The two candidate sources are complements, not rivals (see the module
    docstring): a scanner enumerates the classes Red Hat does not publish purls
    for, the index enumerates the classes it does.  Running one without the
    other leaves a hole on whichever side is missing — a scanner DB that has not
    caught up on rpms, or the golang/pypi components the corpus never names.

    Scanner rows win on collision: their severity, CVSS, fix version and file
    location are richer than anything the index can mint.  Only (component, CVE)
    pairs the scanner never reported are appended.  Returns (df, added).
    """
    if df is None or index is None:
        return df, 0
    # A hand-rolled scan CSV need not carry the triage schema; merging into one
    # that doesn't would KeyError deep inside the audit instead of here.
    if not {'COMPONENT', 'VERSION', 'CVE', 'SOURCE'} <= set(df.columns):
        return df, 0
    rpm_idx, oci_idx = index.get('rpm') or {}, index.get('oci') or {}
    if not (rpm_idx or oci_idx):
        return df, 0

    cols = list(df.columns)
    seen = set(zip(df['COMPONENT'], df['CVE'])) if not df.empty else set()
    has_srpm = 'SRPM' in cols
    rows = []

    def _add(comp, ver, cve, source, location, srpm=''):
        if (comp, cve) in seen:
            return
        seen.add((comp, cve))
        row = dict.fromkeys(cols, '')
        if 'CVSS' in row:
            row['CVSS'] = 0
        row.update(COMPONENT=comp, VERSION=ver, CVE=cve, SOURCE=source,
                   LOCATION=location)
        if has_srpm:
            row['SRPM'] = srpm
        rows.append(row)

    if not df.empty:
        os_rows = df[df['SOURCE'].astype(str).str.upper() == 'OS']
        # An image-identity pseudo-component (§7b) is not an rpm name; looking it
        # up in the rpm index would join on a path that no NEVRA carries.
        for comp, ver, srpm in {(str(r['COMPONENT']), str(r['VERSION']),
                                 str(r['SRPM']) if has_srpm and r.get('SRPM') else '')
                                for _i, r in os_rows.iterrows()}:
            if '/' in comp:
                continue
            cves = set(rpm_idx.get(comp, ()))
            if srpm:
                cves |= set(rpm_idx.get(srpm, ()))
            for cve in sorted(cves):
                _add(comp, ver, cve, 'OS', 'var/lib/rpm', srpm)

    img_keys, img_comp, img_ver = image_identity(repo_from_ref(image_ref), labels)
    if img_comp:
        img_cves: set = set()
        for key in img_keys:
            img_cves |= set(oci_idx.get(key, ()))
        for cve in sorted(img_cves):
            _add(img_comp, img_ver, cve, IMAGE_SOURCE, 'root/buildinfo/labels.json')

    if not rows:
        return df, 0
    return pd.concat([df, pd.DataFrame(rows, columns=cols)], ignore_index=True), len(rows)


class UnreadableSBOM(Exception):
    """The SBOM file could not be parsed — distinct from parsing to nothing.

    The syft cache can hold zero-byte files from an interrupted run (15 of 4,929
    in one local cache).  Silently returning "no candidates" for those reads as
    "this image is clean", which is the one thing a triage tool must never
    imply.
    """


def candidates_from_sbom(sbom_path: str, index: dict) -> pd.DataFrame:
    """Triage rows for every (component, CVE) pair the VEX corpus can decide.

    rpm rows carry SOURCE='OS' so they route to the RPM ladder; the image itself
    is emitted once per CVE naming its repo (SOURCE=IMAGE_SOURCE).

    Raises UnreadableSBOM when the file cannot be parsed.
    """
    try:
        sbom = json.load(open(sbom_path))
    except Exception as exc:
        raise UnreadableSBOM(f'{sbom_path}: {type(exc).__name__}: {exc}') from exc
    rpm_idx = index.get('rpm') or {}
    oci_idx = index.get('oci') or {}
    rows, seen = [], set()

    for art in sbom.get('artifacts') or []:
        if art.get('type') != 'rpm':
            continue
        purl = art.get('purl') or ''
        name, ver = art.get('name', ''), art.get('version', '')
        if not (purl and name):
            continue
        srpm = ''
        m = re.search(r'upstream=([^&]+?)-[^-]+-[^-]+\.src\.rpm', purl)
        if m:
            srpm = m.group(1)
        # Rung 5s can decide on the SOURCE package, so a binary-only lookup
        # would miss candidates the engine is able to resolve.
        cves = set(rpm_idx.get(rpm_purl_name(purl), ()))
        if srpm:
            cves |= set(rpm_idx.get(srpm, ()))
        for cve in sorted(cves):
            if (name, ver, cve) in seen:
                continue
            seen.add((name, ver, cve))
            rows.append({'COMPONENT': name, 'VERSION': ver, 'CVE': cve,
                         'SEVERITY': '', 'CVSS': 0, 'LINK': '',
                         'FIXED_VERSION': '', 'SOURCE': 'OS',
                         'LOCATION': 'var/lib/rpm', 'ADVISORY': '',
                         'ADVISORY_LINK': '', 'SRPM': srpm})

    src = sbom.get('source') or {}
    labels = (src.get('metadata') or {}).get('labels') or {}
    img_keys, img_comp, img_ver = image_identity(src.get('name') or '', labels)
    img_cves: set = set()
    for key in img_keys:
        img_cves |= set(oci_idx.get(key, ()))
    for cve in sorted(img_cves):
        if (img_comp, img_ver, cve) in seen:
            continue
        seen.add((img_comp, img_ver, cve))
        rows.append({'COMPONENT': img_comp, 'VERSION': img_ver, 'CVE': cve,
                     'SEVERITY': '', 'CVSS': 0, 'LINK': '',
                     'FIXED_VERSION': '', 'SOURCE': IMAGE_SOURCE,
                     'LOCATION': 'root/buildinfo/labels.json', 'ADVISORY': '',
                     'ADVISORY_LINK': '', 'SRPM': ''})

    return pd.DataFrame(rows)
