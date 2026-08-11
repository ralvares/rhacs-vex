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
if _failures:
    print(f'{len(_failures)} FAILED: {_failures}')
    sys.exit(1)
print('ALL scan-free tests pass.')
