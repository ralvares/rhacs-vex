#!/usr/bin/env python3
"""Scan-free feature tests: purl identity, candidate shape, emission safety.

Runs offline against a synthetic SBOM and index — no VEX mirror, no scanner, so
it stays fast and deterministic.  The end-to-end behaviour (real index, real
SBOM, grype --vex suppression) is exercised by the CLI, not here.

Run from the repo root.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from rhacs_vex import scanfree, openvex          # noqa: E402

_failures = []


def check(name, cond, detail=''):
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ''))
    if not cond:
        _failures.append(name)


print('=== A. purl identity ===')

# Only the vendor namespace is dropped; a deeper product path must survive
# because the '/' is what routes a component to the non-RPM ladder (§3a rule 5).
check('A1 plain rpm purl → bare name',
      scanfree.rpm_purl_name('pkg:rpm/redhat/tar?arch=src') == 'tar')
check('A2 versioned rpm purl → name without version',
      scanfree.rpm_purl_name('pkg:rpm/redhat/openssl@3.0.7-24.el9?arch=x86_64') == 'openssl')
check('A3 product path kept (only `redhat/` stripped)',
      scanfree.rpm_purl_name('pkg:rpm/redhat/openshift4/ose-cli?arch=src')
      == 'openshift4/ose-cli')
check('A4 percent-encoded module release decodes',
      scanfree.rpm_purl_name(
          'pkg:rpm/redhat/httpd@2.4.37-51.module%2Bel8.7.0%2B18026?arch=src') == 'httpd')

# Two purl eras: repository_url is either the full repo path or the namespace
# only, with the image name in the purl itself (§4a).
k_old = scanfree.oci_repo_keys(
    'pkg:oci/ose-cli@sha256:ab?arch=amd64&repository_url=registry.redhat.io/openshift4/ose-cli')
k_new = scanfree.oci_repo_keys(
    'pkg:oci/openshift/ose-cli@sha256:ab?arch=amd64&repository_url=registry.redhat.io/openshift4')
check('A5 full-path era → effective repo + bare name',
      'registry.redhat.io/openshift4/ose-cli' in k_old and 'ose-cli' in k_old, str(k_old))
check('A6 namespace-only era composes the same effective repo',
      'registry.redhat.io/openshift4/ose-cli' in k_new and 'ose-cli' in k_new, str(k_new))

print('\n=== B. candidate generation ===')

SBOM = {
    'artifacts': [
        {'type': 'rpm', 'name': 'openssl', 'version': '3.0.7-24.el9',
         'purl': 'pkg:rpm/redhat/openssl@3.0.7-24.el9?arch=x86_64&'
                 'upstream=openssl-3.0.7-24.el9.src.rpm'},
        {'type': 'rpm', 'name': 'curl-minimal', 'version': '7.76.1-29.el9',
         'purl': 'pkg:rpm/redhat/curl-minimal@7.76.1-29.el9?arch=x86_64&'
                 'upstream=curl-7.76.1-29.el9.src.rpm'},
        {'type': 'go-module', 'name': 'golang.org/x/net', 'version': 'v0.38.0',
         'purl': 'pkg:golang/golang.org/x/net@v0.38.0'},
    ],
    'source': {'name': 'registry.redhat.io/openshift4/ose-cli-rhel9',
               'version': 'sha256:' + 'a' * 64,
               'metadata': {'labels': {'name': 'openshift/ose-cli-rhel9',
                                       'release': '202509252353'},
                            'repoDigests': [
                                'registry.redhat.io/openshift4/ose-cli-rhel9@sha256:' + 'a' * 64]}},
}
INDEX = {
    'rpm': {'openssl': ['CVE-1000-1', 'CVE-1000-2'],
            'curl': ['CVE-1000-3'],            # SRPM of curl-minimal
            'golang.org/x/net': ['CVE-1000-9']},   # must NOT be reached
    'oci': {'registry.redhat.io/openshift4/ose-cli-rhel9': ['CVE-2000-1']},
}

with tempfile.TemporaryDirectory() as td:
    sp = os.path.join(td, 'sbom.json')
    json.dump(SBOM, open(sp, 'w'))
    df = scanfree.candidates_from_sbom(sp, INDEX)

    cves = set(df['CVE'])
    check('B1 rpm binary name resolves candidates', {'CVE-1000-1', 'CVE-1000-2'} <= cves)
    check('B2 SRPM union reaches candidates the binary name misses',
          'CVE-1000-3' in cves, 'curl-minimal → curl')
    check('B3 go modules are NOT enumerated (Red Hat does not track them)',
          'CVE-1000-9' not in cves)
    check('B4 image identity contributes its own CVEs', 'CVE-2000-1' in cves)

    rpm_rows = df[df['SOURCE'] == 'OS']
    img_rows = df[df['SOURCE'] == scanfree.IMAGE_SOURCE]
    check('B5 rpm rows route to the RPM ladder (SOURCE=OS, rpm location)',
          len(rpm_rows) == 3 and set(rpm_rows['LOCATION']) == {'var/lib/rpm'})
    check('B6 image row is not SOURCE=OS', len(img_rows) == 1)

    # An image-identity component carries a path; emitting it as SOURCE=OS would
    # mint pkg:rpm/redhat/openshift/ose-cli-rhel9@<build> — an identity no
    # scanner produces.
    subs = openvex.subcomponent_ids(img_rows.iloc[0]['COMPONENT'],
                                    img_rows.iloc[0]['VERSION'],
                                    img_rows.iloc[0]['SOURCE'])
    check('B7 image row mints no fabricated rpm purl', subs == [], str(subs))
    bad = [s for s in openvex.subcomponent_ids('openssl', '3.0.7-24.el9', 'OS')
           if '/' in s[len('pkg:rpm/redhat/'):].split('@')[0]]
    check('B8 ordinary rpm rows still mint a clean purl', not bad)

print('\n=== B2. unreadable SBOM must not read as "clean" ===')

with tempfile.TemporaryDirectory() as td:
    empty = os.path.join(td, 'empty.json')
    open(empty, 'w').close()                     # zero-byte, as a killed syft leaves behind
    raised = False
    try:
        scanfree.candidates_from_sbom(empty, INDEX)
    except scanfree.UnreadableSBOM:
        raised = True
    check('B9 zero-byte SBOM raises instead of returning no candidates', raised)

    truncated = os.path.join(td, 'trunc.json')
    open(truncated, 'w').write('{"artifacts": [')
    raised = False
    try:
        scanfree.candidates_from_sbom(truncated, INDEX)
    except scanfree.UnreadableSBOM:
        raised = True
    check('B10 truncated SBOM raises too', raised)

print('\n=== C. index round-trip ===')

with tempfile.TemporaryDirectory() as td:
    out = os.path.join(td, 'idx.json.gz')
    vexdir = os.path.join(td, 'vex')
    os.makedirs(vexdir)
    doc = {
        'product_tree': {
            'branches': [{'branches': [
                {'product': {'product_id': 'openssl-0:3.0.7-24.el9.x86_64',
                             'product_identification_helper': {
                                 'purl': 'pkg:rpm/redhat/openssl@3.0.7-24.el9?arch=x86_64'}}},
            ]}],
            'relationships': [{
                'product_reference': 'openssl-0:3.0.7-24.el9.x86_64',
                'relates_to_product_reference': 'red_hat_enterprise_linux_9',
                'full_product_name': {
                    'product_id': 'red_hat_enterprise_linux_9:openssl-0:3.0.7-24.el9.x86_64'}}],
        },
        'vulnerabilities': [{'product_status': {
            'known_affected': ['red_hat_enterprise_linux_9:openssl-0:3.0.7-24.el9.x86_64']}}],
    }
    json.dump(doc, open(os.path.join(vexdir, 'CVE-3000-1.json'), 'w'))
    built = scanfree.build_index(vex_dir=vexdir, out_path=out)
    check('C1 composite status PID resolves to the component purl',
          built['rpm'].get('openssl') == ['CVE-3000-1'], str(built['rpm']))
    check('C2 index round-trips through gzip',
          scanfree.load_index(out).get('rpm') == built['rpm'])
    check('C3 missing index loads as empty, not an exception',
          scanfree.load_index(os.path.join(td, 'nope.json.gz')) == {})

print()
print('=== D. merging the index into a scanner run ===')

import pandas as pd                                   # noqa: E402

_IDX = {'rpm': {'openssl': ['CVE-3000-1', 'CVE-3000-2'],
                'openshift4/ose-cli': ['CVE-3000-9']},
        'oci': {'openshift4/ose-cli-rhel9': ['CVE-3000-3']}}
_COLS = ['COMPONENT', 'VERSION', 'CVE', 'SEVERITY', 'CVSS', 'LINK',
         'FIXED_VERSION', 'SOURCE', 'LOCATION']
_scan = pd.DataFrame(
    [{'COMPONENT': 'openssl', 'VERSION': '3.0.7-24.el9', 'CVE': 'CVE-3000-1',
      'SEVERITY': 'High', 'CVSS': 7.5, 'LINK': 'x', 'FIXED_VERSION': '3.0.7-25.el9',
      'SOURCE': 'OS', 'LOCATION': 'var/lib/rpm'},
     {'COMPONENT': 'golang.org/x/net', 'VERSION': 'v0.17.0', 'CVE': 'CVE-3000-7',
      'SEVERITY': 'Moderate', 'CVSS': 5.0, 'LINK': 'y', 'FIXED_VERSION': '',
      'SOURCE': 'GO', 'LOCATION': 'usr/bin/oc'}], columns=_COLS)

_merged, _added = scanfree.merge_index_candidates(
    _scan, _IDX, image_ref='registry.redhat.io/openshift4/ose-cli-rhel9@sha256:abc',
    labels={'name': 'openshift4/ose-cli-rhel9', 'release': '1'})
check('D1 the pair the scanner already reported is not duplicated',
      len(_merged[(_merged.COMPONENT == 'openssl') & (_merged.CVE == 'CVE-3000-1')]) == 1)
check('D2 the scanner row keeps its own metadata',
      _merged.iloc[0]['FIXED_VERSION'] == '3.0.7-25.el9' and _merged.iloc[0]['CVSS'] == 7.5)
check('D3 the rpm CVE the scanner missed is added at the installed version',
      len(_merged[_merged.CVE == 'CVE-3000-2']) == 1
      and _merged[_merged.CVE == 'CVE-3000-2'].iloc[0]['VERSION'] == '3.0.7-24.el9')
check('D4 the image identity contributes its own CVEs',
      len(_merged[(_merged.CVE == 'CVE-3000-3')
                  & (_merged.SOURCE == scanfree.IMAGE_SOURCE)]) == 1)
check('D5 added rows carry the frame\'s columns, nothing invented',
      list(_merged.columns) == _COLS, str(list(_merged.columns)))
check('D6 added count matches the rows appended', _added == len(_merged) - len(_scan),
      f'{_added} vs {len(_merged) - len(_scan)}')

# An image-identity pseudo-component (§7b) is a path, not an rpm name — looking
# it up in the rpm index joins on something no NEVRA carries.
_pseudo = pd.DataFrame(
    [{'COMPONENT': 'openshift4/ose-cli', 'VERSION': '4.20.0', 'CVE': 'CVE-3000-8',
      'SEVERITY': '', 'CVSS': 0, 'LINK': '', 'FIXED_VERSION': '', 'SOURCE': 'OS',
      'LOCATION': 'root/buildinfo/labels.json'}], columns=_COLS)
_m2, _a2 = scanfree.merge_index_candidates(_pseudo, _IDX)
check('D7 an image-path pseudo-component is not looked up as an rpm', _a2 == 0,
      f'added {_a2}')

_bare = pd.DataFrame([{'cve': 'CVE-3000-1', 'pkg': 'openssl'}])
_m3, _a3 = scanfree.merge_index_candidates(_bare, _IDX)
check('D8 a CSV without the triage schema is left untouched',
      _a3 == 0 and list(_m3.columns) == ['cve', 'pkg'])

print()
if _failures:
    print(f'{len(_failures)} FAILED: {_failures}')
    sys.exit(1)
print('ALL scan-free tests pass.')
