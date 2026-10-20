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

from rhacs_vex import candidates, openvex        # noqa: E402
from rhacs_vex.sbom import SyftSBOM               # noqa: E402
from rhacs_vex import vexindex                   # noqa: E402
from rhacs_vex.vexindex import oci_repo_keys, rpm_purl_name  # noqa: E402

_failures = []


def check(name, cond, detail=''):
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ''))
    if not cond:
        _failures.append(name)


print('=== A. purl identity ===')

# Only the vendor namespace is dropped; a deeper product path must survive
# because the '/' is what routes a component to the non-RPM ladder (§3a rule 5).
check('A1 plain rpm purl → bare name',
      rpm_purl_name('pkg:rpm/redhat/tar?arch=src') == 'tar')
check('A2 versioned rpm purl → name without version',
      rpm_purl_name('pkg:rpm/redhat/openssl@3.0.7-24.el9?arch=x86_64') == 'openssl')
check('A3 product path kept (only `redhat/` stripped)',
      rpm_purl_name('pkg:rpm/redhat/openshift4/ose-cli?arch=src')
      == 'openshift4/ose-cli')
check('A4 percent-encoded module release decodes',
      rpm_purl_name(
          'pkg:rpm/redhat/httpd@2.4.37-51.module%2Bel8.7.0%2B18026?arch=src') == 'httpd')

# Two purl eras: repository_url is either the full repo path or the namespace
# only, with the image name in the purl itself (§4a).
k_old = oci_repo_keys(
    'pkg:oci/ose-cli@sha256:ab?arch=amd64&repository_url=registry.redhat.io/openshift4/ose-cli')
k_new = oci_repo_keys(
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
    df = candidates.from_sbom(SyftSBOM(SBOM), INDEX, use_osv=False,
                              image_ref=SBOM['source']['metadata']['repoDigests'][0])

    cves = set(df['CVE'])
    check('B1 rpm binary name resolves candidates', {'CVE-1000-1', 'CVE-1000-2'} <= cves)
    check('B2 SRPM union reaches candidates the binary name misses',
          'CVE-1000-3' in cves, 'curl-minimal → curl')
    check('B3 go modules are NOT enumerated (Red Hat does not track them)',
          'CVE-1000-9' not in cves)
    check('B4 image identity contributes its own CVEs', 'CVE-2000-1' in cves)

    rpm_rows = df[df['SOURCE'] == 'OS']
    img_rows = df[df['SOURCE'] == candidates.IMAGE_SOURCE]
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
    check('B9 zero-byte SBOM is unreadable, not empty', SyftSBOM.load(empty) is None)
    truncated = os.path.join(td, 'trunc.json')
    open(truncated, 'w').write('{"artifacts": [')
    check('B10 truncated SBOM is unreadable too', SyftSBOM.load(truncated) is None)

print('\n=== C. index round-trip ===')

with tempfile.TemporaryDirectory() as td:
    out = os.path.join(td, 'idx.sqlite')
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
    built = vexindex.build_vex(vexdir, out)
    idx = vexindex.open_index(out)
    check('C1 composite status PID resolves to the component purl',
          idx.get('rpm').get('openssl') == ['CVE-3000-1'], str(built))
    check('C2 the on-disk index reports what it holds',
          built == {'files': 1, 'rpm': 1, 'oci': 0}, str(built))
    check('C3 missing index loads as empty, not an exception',
          not vexindex.open_index(os.path.join(td, 'nope.sqlite')))
    check('C4 an unknown key reads as no CVEs', idx.get('rpm').get('nope', ()) == ())

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

_merged, _added = candidates.add_to_findings(
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
                  & (_merged.SOURCE == candidates.IMAGE_SOURCE)]) == 1)
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
_m2, _a2 = candidates.add_to_findings(_pseudo, _IDX)
check('D7 an image-path pseudo-component is not looked up as an rpm', _a2 == 0,
      f'added {_a2}')

_bare = pd.DataFrame([{'cve': 'CVE-3000-1', 'pkg': 'openssl'}])
_m3, _a3 = candidates.add_to_findings(_bare, _IDX)
check('D8 a CSV without the triage schema is left untouched',
      _a3 == 0 and list(_m3.columns) == ['cve', 'pkg'])

print()
print('=== E. names shared across ecosystems ===')

from rhacs_vex.core.csaf import Document              # noqa: E402
from rhacs_vex.core.judge import judge                # noqa: E402
from rhacs_vex.core.workload import WorkloadContext   # noqa: E402
from rhacs_vex.sbom import wire_rpm_owners            # noqa: E402

# npm `tar` vendored in the `npm` rpm, next to the rpm `tar` itself (ubi8
# nodejs images): the owner map must not send the rpm `tar` to the `npm`
# rpm's statements.
_df = pd.DataFrame([
    {'COMPONENT': 'tar', 'VERSION': '2:1.30-9.el8', 'SOURCE': 'OS', 'LOCATION': 'var/lib/rpm'},
    {'COMPONENT': 'tar', 'VERSION': '6.2.0', 'SOURCE': 'NODEJS',
     'LOCATION': '/usr/lib/node_modules/npm/node_modules/tar/package.json'},
    {'COMPONENT': 'semver', 'VERSION': '7.5.4', 'SOURCE': 'NODEJS',
     'LOCATION': '/usr/lib/node_modules/npm/node_modules/semver/package.json'}])
_ctx = WorkloadContext()
wire_rpm_owners(_df, _ctx, {
    '/usr/lib/node_modules/npm/node_modules/tar/package.json': ('npm', '10.2.4-1.el8'),
    '/usr/lib/node_modules/npm/node_modules/semver/package.json': ('npm', '10.2.4-1.el8')})
# CVE shape: the npm rpm known_affected, the tar rpm fixed in el8_10.
_R8 = {'product_id': 'red_hat_enterprise_linux_8', 'name': 'Red Hat Enterprise Linux 8',
       'product_identification_helper': {'cpe': 'cpe:/o:redhat:enterprise_linux:8'}}
_M8 = {'product_id': 'BaseOS-8.10.0.Z.MAIN.EUS', 'name': 'Red Hat Enterprise Linux BaseOS (v. 8)',
       'product_identification_helper': {'cpe': 'cpe:/o:redhat:enterprise_linux:8::baseos'}}
_doc = Document({
    'product_tree': {
        'branches': [{'product': _R8}, {'product': _M8},
                     {'product': {'product_id': 'npm', 'product_identification_helper': {
                         'purl': 'pkg:rpm/redhat/npm'}}},
                     {'product': {'product_id': 'tar-2:1.30-10.el8_10.x86_64',
                                  'product_identification_helper': {
                                      'purl': 'pkg:rpm/redhat/tar@1.30-10.el8_10?arch=x86_64&epoch=2'}}}],
        'relationships': [
            {'product_reference': 'npm', 'relates_to_product_reference': 'red_hat_enterprise_linux_8',
             'full_product_name': {'product_id': 'red_hat_enterprise_linux_8:npm'}},
            {'product_reference': 'tar-2:1.30-10.el8_10.x86_64',
             'relates_to_product_reference': 'BaseOS-8.10.0.Z.MAIN.EUS',
             'full_product_name': {'product_id': 'BaseOS-8.10.0.Z.MAIN.EUS:tar-2:1.30-10.el8_10.x86_64'}}]},
    'vulnerabilities': [{'product_status': {
        'known_affected': ['red_hat_enterprise_linux_8:npm'],
        'fixed': ['BaseOS-8.10.0.Z.MAIN.EUS:tar-2:1.30-10.el8_10.x86_64']}}]})
_ctx.rhel_ver, _ctx.rhel_minor = '8', '10'
_ctx.sbom_packages = {'tar': {'2:1.30-9.el8', '6.2.0'}, 'npm': {'10.2.4-1.el8'}}
_npm_tar = judge(_df.iloc[1].to_dict(), _ctx, _doc)
check('E1 the vendored npm `tar` answers to its owning rpm',
      '❌' in _npm_tar.result and 'ships in npm' in _npm_tar.note, _npm_tar.note)
_rpm_tar = judge(_df.iloc[0].to_dict(), _ctx, _doc)
check('E2 the rpm `tar` does not — it is its own package',
      '❌' in _rpm_tar.result and _rpm_tar.fix == '2:1.30-10.el8_10' and 'npm' not in _rpm_tar.note,
      f'{_rpm_tar.fix} {_rpm_tar.note}')
check('E3 other vendored packages map to their owning rpm',
      _ctx.sbom_owner_map.get('semver') == 'npm', str(_ctx.sbom_owner_map))
check('E4 the installed version present in the SBOM is "verified", whatever '
      'else shares the name', '(SBOM verified)' in _rpm_tar.note, _rpm_tar.note)

print()
if _failures:
    print(f'{len(_failures)} FAILED: {_failures}')
    sys.exit(1)
print('ALL scan-free tests pass.')
