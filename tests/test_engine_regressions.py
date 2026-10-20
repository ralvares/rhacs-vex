#!/usr/bin/env python3
"""Regression tests for engine bugs found by independent VEX cross-checking.

Each case is built from a SYNTHETIC VEX document rather than the live mirror, so
these cannot be skipped by data drift the way the case-matrix tests are — the
shapes here are exactly the ones that produced a wrong verdict.

Run from the repo root.
"""
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

import pandas as pd                                                  # noqa: E402
from rhacs_vex import engine                                         # noqa: E402
from rhacs_vex.engine import WorkloadContext, audit_row_detailed     # noqa: E402
from rhacs_vex.core import versions as V                             # noqa: E402
from rhacs_vex.core.csaf import classify                              # noqa: E402

_failures = []


def check(name, cond, detail=''):
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ''))
    if not cond:
        _failures.append(name)


def vex(nodes, statuses):
    """Minimal CSAF doc: nodes = [(component_pid, purl)], statuses = {bucket: [pid]}."""
    return {
        'product_tree': {
            'branches': [{'product': {
                'product_id': 'red_hat_enterprise_linux_9',
                'name': 'Red Hat Enterprise Linux 9',
                'product_identification_helper': {
                    'cpe': 'cpe:/o:redhat:enterprise_linux:9'}},
                'branches': [
                {'product': {'product_id': pid,
                             'product_identification_helper': {'purl': purl}}}
                for pid, purl in nodes]}],
            'relationships': [
                {'product_reference': pid,
                 'relates_to_product_reference': 'red_hat_enterprise_linux_9',
                 'full_product_name': {'product_id': f'red_hat_enterprise_linux_9:{pid}'}}
                for pid, _ in nodes],
        },
        'vulnerabilities': [{'product_status': statuses}],
    }


print('=== A. a binary rpm reaches statements only through its own source rpm ===')

# python3 ships a version-less .src statement, and python3-chardet shares its
# dash prefix — but chardet is built from python-chardet.  A name-prefix guess
# let chardet inherit python3's statements; only the SBOM's SRPM links them.
DOC = vex(
    [('python3-0:3.9.21-1.el9_5.x86_64', 'pkg:rpm/redhat/python3@3.9.21-1.el9_5?arch=x86_64'),
     ('python3.src', 'pkg:rpm/redhat/python3?arch=src')],
    {'fixed': ['red_hat_enterprise_linux_9:python3-0:3.9.21-1.el9_5.x86_64'],
     'known_affected': ['red_hat_enterprise_linux_9:python3.src']},
)


def _a(comp, ver, srpm):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: dict(DOC)
    try:
        r = audit_row_detailed(pd.Series({
            'COMPONENT': comp, 'VERSION': ver, 'CVE': 'CVE-9999-0001', 'SOURCE': 'OS',
            'SRPM': srpm, 'SEVERITY': '', 'FIXED_VERSION': ''}),
            WorkloadContext(workload_type='ubi', rhel_ver='9', rhel_minor='5', display_name='UBI9'))
        return r.iloc[0], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


_v, _n = _a('python3-libs', '3.9.21-1.el9_5', 'python3')
check('A1 a subpackage takes its source rpm\'s fix', '✅' in _v and 'fixed' in _n, f'{_v} {_n}')
_v, _n = _a('python3-chardet', '4.0.0-5.el9', 'python-chardet')
check('A2 a dash-prefix sibling does not inherit python3\'s statements',
      'not listed' in _n, f'{_v} {_n}')

print('\n=== B. products are classified from their CPE and product id ===')


def _cls(pid, cpe, name=''):
    return classify(pid, name, cpe)


_p = _cls('BaseOS-8.10.0.Z.MAIN.EUS', 'cpe:/o:redhat:rhel_eus:8.10::baseos')
check('B1 Z.MAIN.EUS is the mainline of 8.10', (_p.family, _p.minor, _p.mainline) == ('rhel', 10, True), _p)
_p = _cls('AppStream-9.0.0.Z.E4S', 'cpe:/a:redhat:rhel_e4s:9.0::appstream')
check('B2 E4S is a side branch', (_p.family, _p.minor, _p.mainline) == ('rhel', 0, False), _p)
_p = _cls('7Server-ELS', 'cpe:/o:redhat:rhel_els:7')
check('B3 7Server-ELS is RHEL 7 and a side branch', (_p.family, _p.major, _p.mainline) == ('rhel', '7', False), _p)
_p = _cls('red_hat_enterprise_linux_9', 'cpe:/o:redhat:enterprise_linux:9')
check('B4 the version-neutral RHEL product is the line', (_p.family, _p.major, _p.minor) == ('rhel', '9', None), _p)
_p = _cls('9Base-RHOSE-4.16', 'cpe:/a:redhat:openshift:4.16::el9')
check('B5 RHOSE-4.16 is OpenShift 4.16 on RHEL 9', (_p.family, _p.version, _p.major) == ('ocp', '4.16', '9'), _p)
_p = _cls('red_hat_openshift_container_platform_4', 'cpe:/a:redhat:openshift:4')
check('B6 OpenShift 4 is the version-neutral line', (_p.family, _p.version) == ('ocp', ''), _p)
_p = _cls('BaseOS-10.2.Z', 'cpe:/o:redhat:enterprise_linux:10.2')
check('B7 RHEL 10 minors read from BaseOS-10.2.Z', (_p.major, _p.minor, _p.mainline) == ('10', 2, True), _p)
_p = _cls('red_hat_products', 'cpe:/a:redhat')
check('B8 the vendor catch-all', _p.family == 'vendor', _p)

print('\n=== C. SRPM reaches the matcher (both paths decide alike) ===')

# libsmartcols is a util-linux subpackage.  Without the binary->source link it
# reads as "not listed as affected" (a FALSE POSITIVE) while a scanner path that
# carries SRPM correctly reports known_affected.
DOC2 = vex(
    [('util-linux.src', 'pkg:rpm/redhat/util-linux?arch=src')],
    {'known_affected': ['red_hat_enterprise_linux_9:util-linux.src']},
)
_orig = engine._load_vex
engine._load_vex = lambda cve: dict(DOC2)
try:
    ctx = WorkloadContext(workload_type='ubi', rhel_ver='9', display_name='UBI9')
    base = {'COMPONENT': 'libsmartcols', 'VERSION': '2.37.4-21.el9', 'CVE': 'CVE-9999-0001',
            'SEVERITY': 'MODERATE_VULNERABILITY_SEVERITY', 'FIXED_VERSION': '',
            'SOURCE': 'OS', 'LOCATION': 'var/lib/rpm'}
    with_srpm = audit_row_detailed(pd.Series({**base, 'SRPM': 'util-linux'}), ctx)
    check('C1 SRPM lets a subpackage reach its source statement',
          'POSITIVE' in str(with_srpm.iloc[0]) and 'FALSE' not in str(with_srpm.iloc[0]),
          f'verdict={with_srpm.iloc[0]!r}')
finally:
    engine._load_vex = _orig

print('\n=== D. layered-product fixes must not decide a base-RHEL workload ===')

# `el8pc` is Satellite Capsule, `el9cp` Ceph, `el9ap` Ansible AP (§2) — layered
# products with their own version streams.  libsolv is 0.7.20 in RHEL 8 base and
# 0.7.22 in Satellite; picking the Satellite fix makes the base package look
# permanently behind.
DOC3 = {
    'product_tree': {
        'branches': [{'branches': [
            {'product': {'product_id': 'libsolv-0:0.7.19-1.el8.x86_64',
                         'product_identification_helper': {
                             'purl': 'pkg:rpm/redhat/libsolv@0.7.19-1.el8?arch=x86_64'}}},
            {'product': {'product_id': 'libsolv-0:0.7.22-1.el8pc.x86_64',
                         'product_identification_helper': {
                             'purl': 'pkg:rpm/redhat/libsolv@0.7.22-1.el8pc?arch=x86_64'}}},
            {'product': {'product_id': 'BaseOS-8.5.0.GA',
                         'name': 'Red Hat Enterprise Linux BaseOS (v. 8)',
                         'product_identification_helper': {
                             'cpe': 'cpe:/o:redhat:enterprise_linux:8::baseos'}}},
            {'product': {'product_id': '8Base-satellite-6.16',
                         'name': 'Red Hat Satellite 6.16 for RHEL 8',
                         'product_identification_helper': {
                             'cpe': 'cpe:/a:redhat:satellite:6::el8'}}},
        ]}],
        'relationships': [
            {'product_reference': 'libsolv-0:0.7.19-1.el8.x86_64',
             'relates_to_product_reference': 'BaseOS-8.5.0.GA',
             'full_product_name': {
                 'product_id': 'BaseOS-8.5.0.GA:libsolv-0:0.7.19-1.el8.x86_64'}},
            {'product_reference': 'libsolv-0:0.7.22-1.el8pc.x86_64',
             'relates_to_product_reference': '8Base-satellite-6.16',
             'full_product_name': {
                 'product_id': '8Base-satellite-6.16:libsolv-0:0.7.22-1.el8pc.x86_64'}},
        ],
    },
    'vulnerabilities': [{'product_status': {'fixed': [
        'BaseOS-8.5.0.GA:libsolv-0:0.7.19-1.el8.x86_64',
        '8Base-satellite-6.16:libsolv-0:0.7.22-1.el8pc.x86_64']}}],
}
_orig = engine._load_vex
engine._load_vex = lambda cve: dict(DOC3)
try:
    ctx8 = WorkloadContext(workload_type='ubi', rhel_ver='8', display_name='UBI8')
    r = audit_row_detailed(pd.Series({
        'COMPONENT': 'libsolv', 'VERSION': '0.7.20-6.el8', 'CVE': 'CVE-9999-0002',
        'SEVERITY': 'MODERATE_VULNERABILITY_SEVERITY', 'FIXED_VERSION': '',
        'SOURCE': 'OS', 'LOCATION': 'var/lib/rpm', 'SRPM': 'libsolv'}), ctx8)
    verdict, fix = str(r.iloc[0]), str(r.iloc[1])
    check('D1 base-RHEL install cleared by the base fix, not the Satellite one',
          'FALSE POSITIVE' in verdict, f'verdict={verdict!r} fix={fix!r}')
    check('D2 the reported fix is the base-RHEL NEVRA',
          'el8pc' not in fix, f'fix={fix!r}')
finally:
    engine._load_vex = _orig

print('\n=== E. rpmvercmp — version decides before release ===')

_rpmvercmp, _evr_compare, compare_versions = V.rpmvercmp, V.vr_compare, V.evr_compare

# Vectors lifted from rpm's own tests/rpmvercmp.at.  The previous dependency
# (version_utils.rpm.compare_versions) decided some pairs on the RELEASE even
# when the VERSIONS already differed, e.g.
#   compare_versions('1.1.1-9.el8', '1.1.1k-4.el8') -> +1
# marking a genuinely vulnerable openssl as "installed >= fix".
RPMVERCMP = [
    ('1.0', '1.0', 0), ('1.0', '2.0', -1), ('2.0', '1.0', 1),
    ('2.0', '2.0.1', -1), ('2.0.1a', '2.0.1', 1), ('2.0.1', '2.0.1a', -1),
    ('5.5p1', '5.5p2', -1), ('5.5p1', '5.5p10', -1), ('10xyz', '10.1xyz', -1),
    ('xyz10', 'xyz10.1', -1), ('xyz.4', '8', -1), ('20101121', '20101122', -1),
    ('1.0~rc1', '1.0', -1), ('1.0', '1.0~rc1', 1), ('1.0~rc1', '1.0~rc2', -1),
    ('1.0~rc1~git123', '1.0~rc1', -1), ('1.0^', '1.0', 1), ('1.0', '1.0^', -1),
    ('1.0^git1', '1.0^git2', -1), ('1b.0', '1.0', -1), ('b', 'a', 1),
    ('1', '1.0', -1), ('a', '1', -1), ('1.006', '1.6', 0), ('01', '1', 0),
]
_vbad = [(a, b, w, _rpmvercmp(a, b)) for a, b, w in RPMVERCMP if _rpmvercmp(a, b) != w]
check('E1 rpmvercmp matches rpm\'s own test vectors',
      not _vbad, f'{len(RPMVERCMP) - len(_vbad)}/{len(RPMVERCMP)}; failures={_vbad[:3]}')

check('E2 a letter-suffixed version beats a bare one regardless of release',
      _evr_compare('1.1.1-9.el8', '1.1.1k-4.el8') < 0,
      'openssl 1.1.1 must be older than the 1.1.1k fix')
check('E3 and the reverse direction agrees',
      _evr_compare('1.1.1k-4.el8', '1.1.1-9.el8_0') > 0)
check('E4 release still breaks a version tie',
      _evr_compare('1.1.1k-4.el8', '1.1.1k-3.el8') > 0)
check('E5 a longer version wins over a bigger release',
      _evr_compare('0.1-21.el9', '0.1.1-53.el9') < 0)
check('E6 epoch outranks everything', compare_versions('1:1.0-1', '2:1.0-1') < 0
      and compare_versions('2:1.0-1', '1:9.9-9') > 0)

print('\n=== F. dist-tag suffix separates build lineages ===')

_rpm_stream_family, _stream_comparable = V.lineage, V.same_lineage

# §2: el8pc is Satellite Capsule, el9cp Ceph, el9ap Ansible AP, el7a RHEL Alt,
# hum Red Hat Hardened Images.  Each ships its own build of a shared package, so
# an el8 install must never be compared against an el8pc fix — libsolv is 0.7.20
# in RHEL 8 base and 0.7.22 in Satellite, which made the current base package
# look permanently behind.  §8a deliberately admits "any product mentioning the
# workload's RHEL major" (for Fast Datapath), so scope alone cannot prevent it.
for ver, want in (('0.7.20-6.el8', ('el', None)),
                  ('0.7.22-1.el8pc', ('el', 'pc')),
                  ('2.9.0-5.el9cp', ('el', 'cp')),
                  ('2.7.0-1.el9ap', ('el', 'ap')),
                  ('4.14.0-115.el7a', ('el', 'a')),
                  ('1.26.19-3.el9_8', ('el', None)),
                  ('2.4.37-64.module+el8.10.0+123', ('el', None)),
                  ('5.42.2-524.hum1', ('hum', None)),
                  ('5.4.0-14.rhaos4.21.el9', ('rhaos', '4.21'))):
    check(f'F1 lineage of {ver}', _rpm_stream_family(ver) == want,
          f'got {_rpm_stream_family(ver)}')

check('F2 base el8 is not comparable to a Satellite el8pc build',
      not _stream_comparable('0.7.20-6.el8', '0.7.22-1.el8pc'))
check('F3 base el7 is not comparable to RHEL Alt el7a',
      not _stream_comparable('3.10.0-1160.el7', '4.14.0-115.el7a'))
check('F4 base el9 is not comparable to a hummingbird build',
      not _stream_comparable('7.76.1-40.el9', '8.19.0-3.hum1'))
check('F5 two builds of the same layered product remain comparable',
      _stream_comparable('2.9.0-5.el9cp', '2.9.1-1.el9cp'))
check('F6 minor streams of base RHEL remain comparable',
      _stream_comparable('1.26.19-3.el9_8', '1.26.20-1.el9'))

print('\n=== G. evidence labels must reflect RED HAT\'s view, not the engine\'s ===')

from rhacs_vex.audit import evidence_of as _evidence_of      # noqa: E402

ours = pd.Series({'COMPONENT': 'openssl', 'SOURCE': 'OS', 'VEX_STATED': 'True',
                  'JUSTIFICATION': 'UBI9: known_not_affected.'})
check('G3 a real first-party statement is still stated',
      _evidence_of(ours) == 'stated', _evidence_of(ours))

otherbld = pd.Series({'COMPONENT': 'stdlib', 'SOURCE': 'GO', 'VEX_STATED': 'False',
                      'JUSTIFICATION': 'known_not_affected (vulnerable code not '
                                       'present). Red Hat Web Terminal 1.11 — x.'})
check('G4 another build stays other bld', _evidence_of(otherbld) == 'other bld',
      _evidence_of(otherbld))

# Red Hat assesses Go at the PRODUCT level (the operator/component image), and
# it does enumerate affected products — so our product's absence means the same
# thing it means for an rpm.  No separate Go bucket.
go_absent = pd.Series({'COMPONENT': 'stdlib', 'SOURCE': 'GO', 'VEX_STATED': 'False',
                       'JUSTIFICATION': 'web-terminal/x 1.15 not listed as affected.'})
check('G5 Go absence reads as the product not being listed',
      _evidence_of(go_absent) == 'not listed', _evidence_of(go_absent))

rpm_absent = pd.Series({'COMPONENT': 'perl-Encode', 'SOURCE': 'OS', 'VEX_STATED': 'False',
                        'JUSTIFICATION': "'perl-Encode' not listed as affected in VEX."})
check('G6 rpm absence is not listed', _evidence_of(rpm_absent) == 'not listed',
      _evidence_of(rpm_absent))

print('=== I. streams: our minor, inherited mainline fixes, side branches ===')
# Red Hat fixes the current mainline first and backports to EUS/E4S after.  A
# fix in an earlier mainline minor is in the branch ours forked from (inherited);
# a fix only in a later minor or a side branch is not ours (errata policy) —
# unless the installed build is newer than every fix.

_CPE = {'MAIN': 'cpe:/a:redhat:enterprise_linux:9::appstream',
        'EUS': 'cpe:/a:redhat:rhel_eus:9.{m}::appstream',
        'E4S': 'cpe:/a:redhat:rhel_e4s:9.{m}::appstream'}


def _streams_doc(fixes, affected=False):
    """fixes = [(minor, 'MAIN'|'EUS'|'E4S', nevra-version)]."""
    branches, rel, fixed = [{'product': {'product_id': 'red_hat_enterprise_linux_9',
                                         'name': 'Red Hat Enterprise Linux 9',
                                         'product_identification_helper': {
                                             'cpe': 'cpe:/o:redhat:enterprise_linux:9'}}},
                            {'product': {'product_id': 'expat', 'product_identification_helper': {
                                'purl': 'pkg:rpm/redhat/expat'}}}], [], []
    for minor, kind, ver in fixes:
        prod = f'AppStream-9.{minor}.0.Z.{kind}'
        comp = f'expat-0:{ver}.x86_64'
        branches.append({'product': {'product_id': prod, 'name': f'RHEL AppStream {kind} 9.{minor}',
                                     'product_identification_helper': {
                                         'cpe': _CPE[kind].format(m=minor)}}})
        branches.append({'product': {'product_id': comp, 'product_identification_helper': {
            'purl': f'pkg:rpm/redhat/expat@{ver}?arch=x86_64'}}})
        rel.append({'product_reference': comp, 'relates_to_product_reference': prod,
                    'full_product_name': {'product_id': f'{prod}:{comp}'}})
        fixed.append(f'{prod}:{comp}')
    status = {'fixed': fixed}
    if affected:
        rel.append({'product_reference': 'expat', 'relates_to_product_reference': 'red_hat_enterprise_linux_9',
                    'full_product_name': {'product_id': 'red_hat_enterprise_linux_9:expat'}})
        status['known_affected'] = ['red_hat_enterprise_linux_9:expat']
    return {'product_tree': {'branches': branches, 'relationships': rel},
            'vulnerabilities': [{'product_status': status}]}


def _stream(installed, minor, fixes, affected=False):
    doc = _streams_doc(fixes, affected)
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: doc
    try:
        r = audit_row_detailed(pd.Series({
            'COMPONENT': 'expat', 'VERSION': installed, 'CVE': 'CVE-9999-0003', 'SOURCE': 'OS',
            'SEVERITY': '', 'FIXED_VERSION': ''}),
            WorkloadContext(workload_type='ubi', rhel_ver='9', rhel_minor=str(minor), display_name='UBI9'))
        return r.iloc[0], r.iloc[1], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


_v, _f, _n = _stream('2.5.0-6.el9_8.1', 8, [(0, 'E4S', '2.2.10-12.el9_0.4')])
check('I1 newer than an older side-branch backport clears (inferred)', '✅' in _v, f'{_v} {_f} {_n}')
_v, _f, _n = _stream('2.2.10-14.el9_8', 8, [(0, 'E4S', '2.2.10-12.el9_0.4')], affected=True)
check('I2 …but our line known_affected keeps it positive', '❌' in _v, f'{_v} {_f} {_n}')
_v, _f, _n = _stream('3.5.3-9.el9_7', 7, [(8, 'MAIN', '3.5.3-11.el9_8')])
check('I3 a fix only in a later minor is not ours', '❌' in _v and 'No fix in el9_7' in _n
      and _f == '3.5.3-11.el9_8', f'{_v} {_f} {_n}')
_v, _f, _n = _stream('1.0-4.el9_6', 6, [(2, 'MAIN', '1.0-3.el9_2')])
check('I4 an earlier mainline fix is inherited', '✅' in _v and 'inherits' in _n, f'{_v} {_f} {_n}')
_v, _f, _n = _stream('1.0-2.el9', 6, [(2, 'MAIN', '1.0-3.el9_2')])
check('I5 …and an older build is below it', '❌' in _v and _f == '1.0-3.el9_2', f'{_v} {_f} {_n}')
_v, _f, _n = _stream('1.0-2.el9_6', 6, [(2, 'MAIN', '1.0-3.el9_2'), (6, 'EUS', '1.0-2.el9_6.1')])
check('I6 our own minor\'s fix outranks an inherited one', '❌' in _v and _f == '1.0-2.el9_6.1',
      f'{_v} {_f} {_n}')
_v, _f, _n = _stream('8.2.2637-23.el9_7', 7, [(2, 'E4S', '8.2.2637-20.el9_2.3'),
                                              (6, 'EUS', '8.2.2637-22.el9_6.4'),
                                              (8, 'MAIN', '8.2.2637-26.el9_8.21')])
check('I7 no fix in our stream → name the next minor\'s build', '❌' in _v
      and _f == '8.2.2637-26.el9_8.21', f'{_v} {_f} {_n}')
_v, _f, _n = _stream('1.0-5.el9_7', 7, [(2, 'E4S', '1.0-5.el9_2.1'), (4, 'EUS', '1.0-6.el9_4.1')])
check('I8 …and the newest when every fix is older', '❌' in _v and _f == '1.0-6.el9_4.1',
      f'{_v} {_f} {_n}')
_v, _f, _n = _stream('3.18-4.module+el8.9.0+21697', 7, [(8, 'MAIN', '3.18-4.module+el8.9.0+20326'),
                                                         (9, 'MAIN', '3.18-5.module+el8.10.0+22417')])
check('I9 at or past a later minor\'s mainline fix, the build carries it', '✅' in _v, f'{_v} {_f} {_n}')

print()
print('=== J. out-of-scope products never decide an RPM finding ===')


def vex_under(product, nodes, statuses):
    """Same minimal doc, with the statements hanging off an arbitrary product."""
    d = vex(nodes, {})
    d['product_tree']['relationships'] = [
        {'product_reference': pid, 'relates_to_product_reference': product,
         'full_product_name': {'product_id': f'{product}:{pid}'}}
        for pid, _ in nodes]
    d['vulnerabilities'] = [{'product_status': statuses}]
    return d


_ctx_ubi9 = WorkloadContext(workload_type='ubi', rhel_ver='9', display_name='UBI9')


def _verdict(doc, comp, ver, cve='CVE-9999-0002'):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: dict(doc)
    try:
        r = audit_row_detailed(pd.Series({
            'COMPONENT': comp, 'VERSION': ver, 'CVE': cve, 'SOURCE': 'OS',
            'SEVERITY': 'MODERATE_VULNERABILITY_SEVERITY', 'FIXED_VERSION': '',
            'LOCATION': 'var/lib/rpm'}), _ctx_ubi9)
        return r.iloc[0], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


# Red Hat Hardened Images ship their own `hum` build of curl.  CVE-2026-58055
# names those three PIDs and nothing else, and "fix available in Hardened
# Images" is not a statement about a RHEL 9 curl-minimal.
_hum = vex_under('Red Hat Hardened Images',
                 [('curl-main@x86_64',
                   'pkg:rpm/redhat/curl@8.21.0-0.1.1.hum1?arch=x86_64')],
                 {'fixed': ['Red Hat Hardened Images:curl-main@x86_64']})
_v, _n = _verdict(_hum, 'curl-minimal', '7.76.1-40.el9')
check('J1 a `hum` build does not decide an `el` build', '✅' in _v, f'{_v} {_n}')

# POODLE.  RHEL 9 is absent from the file; the only thing linking the CVE to a
# current openssl 3.5.5 is the SRPM name shared with a 2014 middleware product.
_jboss = vex_under('red_hat_jboss_enterprise_application_platform_5',
                   [('openssl.src', 'pkg:rpm/redhat/openssl?arch=src')],
                   {'known_affected':
                    ['red_hat_jboss_enterprise_application_platform_5:openssl.src']})
_v, _n = _verdict(_jboss, 'openssl-libs', '1:3.5.5-4.el9_8')
check('J2 a standalone product\'s source name does not carry to our binary',
      '✅' in _v, f'{_v} {_n}')

# A product PID without a CPE (no version line) says nothing about who ships the
# rpm, so it cannot decide a UBI's package (P7 has the real, CPE-carrying shape).
_ocp = vex_under('red_hat_openshift_container_platform_4',
                 [('openshift-clients', 'pkg:rpm/redhat/openshift-clients')],
                 {'known_affected':
                  ['red_hat_openshift_container_platform_4:openshift-clients']})
_v, _n = _verdict(_ocp, 'openshift-clients', '4.14.0-202501.el9')
check('J3 a matching binary name in an out-of-scope product does not decide',
      '✅' in _v, f'{_v} {_n}')

# CVE-2018-1002105 names only the bare clients package under OpenShift
# Enterprise 3.0.  That product generation is the missing version qualifier;
# it must not make an OCP 4 clients package vulnerable by name alone.
_ose3 = vex_under('red_hat_openshift_enterprise_3.0',
                  [('openshift-clients', 'pkg:rpm/redhat/openshift-clients')],
                  {'known_affected':
                   ['red_hat_openshift_enterprise_3.0:openshift-clients']})
_v, _n = _verdict(_ose3, 'openshift-clients', '4.14.0-202501.el9',
                  'CVE-2018-1002105')
check('J3b an OpenShift 3 bare package does not decide an OpenShift 4 build',
      '✅' in _v, f'{_v} {_n}')

# RHEL 7 tracks `python-requests`, Satellite 6 says `python3-requests`.  On the
# exact-name test the standalone product decided, so a 2015 CVE stayed POSITIVE
# against RHEL 9's 2.25.1 — the enumeration is about our package, whichever name
# Red Hat gave it on which product.
_sat = {
    'product_tree': {
        'branches': [{'branches': [
            {'product': {'product_id': 'red_hat_enterprise_linux_7',
                         'product_identification_helper':
                             {'cpe': 'cpe:/o:redhat:enterprise_linux:7'}}},
            {'product': {'product_id': 'python-requests.src',
                         'product_identification_helper':
                             {'purl': 'pkg:rpm/redhat/python-requests?arch=src'}}},
            {'product': {'product_id': 'python3-requests',
                         'product_identification_helper':
                             {'purl': 'pkg:rpm/redhat/python3-requests'}}}]}],
        'relationships': [
            {'product_reference': 'python-requests.src',
             'relates_to_product_reference': 'red_hat_enterprise_linux_7',
             'full_product_name': {'product_id': 'red_hat_enterprise_linux_7:python-requests.src'}},
            {'product_reference': 'python3-requests',
             'relates_to_product_reference': 'red_hat_satellite_6',
             'full_product_name': {'product_id': 'red_hat_satellite_6:python3-requests'}}],
    },
    'vulnerabilities': [{'product_status': {
        'known_not_affected': ['red_hat_enterprise_linux_7:python-requests.src'],
        'known_affected': ['red_hat_satellite_6:python3-requests']}}],
}
_orig = engine._load_vex
engine._load_vex = lambda cve: dict(_sat)
try:
    _ctx9 = WorkloadContext(workload_type='ubi', rhel_ver='9', display_name='UBI9')
    _r = audit_row_detailed(pd.Series({
        'COMPONENT': 'python3-requests', 'VERSION': '2.25.1-8.el9', 'CVE': 'CVE-9999-0007',
        'SEVERITY': 'MODERATE_VULNERABILITY_SEVERITY', 'FIXED_VERSION': '',
        'SOURCE': 'OS', 'LOCATION': 'var/lib/rpm', 'SRPM': 'python-requests'}), _ctx9)
    check('J7 RHEL tracking our package under its own name closes the standalone route',
          '✅' in str(_r.iloc[0]), f'{_r.iloc[0]} {_r.iloc[2][:60]}')
finally:
    engine._load_vex = _orig

# Pre-RHEL-6 documents name products `3AS` / `4Desktop`, which carry no
# enterprise_linux_N, no .elN, nothing the PID-string tests see — so they read as
# version-neutral and the old ladder admitted them.  That is how CVE-2004-0642 held a
# 2026 krb5 vulnerable.  Their CPE says which RHEL line they really are.
_old = {
    'product_tree': {
        'branches': [{'branches': [
            {'product': {'product_id': '3AS',
                         'product_identification_helper':
                             {'cpe': 'cpe:/o:redhat:enterprise_linux:3::as'}}},
            {'product': {'product_id': 'krb5-libs-0:1.2.7-28.i386',
                         'product_identification_helper':
                             {'purl': 'pkg:rpm/redhat/krb5-libs@1.2.7-28?arch=i386'}}}]}],
        'relationships': [
            {'product_reference': 'krb5-libs-0:1.2.7-28.i386',
             'relates_to_product_reference': '3AS',
             'full_product_name': {'product_id': '3AS:krb5-libs-0:1.2.7-28.i386'}}],
    },
    'vulnerabilities': [{'product_status':
                         {'fixed': ['3AS:krb5-libs-0:1.2.7-28.i386']}}],
}
# Same PID shape as J2, but the component IS named `openssl`, so the binary-name
# guard cannot fire — J2 passed only because `openssl-libs` differs from
# `openssl`.  What settles it is that the PID names the SOURCE package: a
# standalone product's `.src` statement says which source IT ships, never which
# binary of ours is affected.
_v6, _n6 = _verdict(_jboss, 'openssl', '1:3.0.7-29.el9_4')
check('J5 a .src statement does not decide even when the names match exactly',
      '✅' in _v6, f'{_v6} {_n6}')

# ...and the discriminator really is the .src, not the product: the same
# standalone product naming a binary still decides (this is J3's mechanism).
_jboss_bin = vex_under('red_hat_jboss_enterprise_application_platform_5',
                       [('openssl', 'pkg:rpm/redhat/openssl')],
                       {'known_affected':
                        ['red_hat_jboss_enterprise_application_platform_5:openssl']})
_v7, _n7 = _verdict(_jboss_bin, 'openssl', '1:3.0.7-29.el9_4')
check('J6 a binary-named statement from another product does not decide',
      '✅' in _v7, f'{_v7} {_n7}')

_v5, _n5 = _verdict(_old, 'krb5-libs', '1.21.1-10.el9_8')
check('J4 a RHEL 3 product does not decide a RHEL 9 build', '✅' in _v5, f'{_v5} {_n5}')


print('=== K. RHCOS node images are separate builds ===')

# Shape of CVE-2025-6032 (podman): Red Hat says `ose-rhel-coreos-8` is
# known_affected / "Will not fix" under OCP 4, and fixes `rhcos` (the RHEL 9
# node image, pkg:oci/rhcos@sha256… and pkg:generic/redhat/rhcos@4.20…) in the
# 4.16 and 4.20 streams.
_ocp4 = 'red_hat_openshift_container_platform_4'


def _rhcos_doc():
    branches = [
        {'product': {'product_id': _ocp4, 'name': 'Red Hat OpenShift Container Platform 4',
                     'product_identification_helper': {
                         'cpe': 'cpe:/a:redhat:openshift:4'}}},
        {'product': {'product_id': 'RHOSE-4.16', 'name': 'Red Hat OpenShift Container Platform 4.16',
                     'product_identification_helper': {
                         'cpe': 'cpe:/a:redhat:openshift:4.16::el9'}}},
        {'product': {'product_id': 'RHOSE-4.20', 'name': 'Red Hat OpenShift Container Platform 4.20',
                     'product_identification_helper': {
                         'cpe': 'cpe:/a:redhat:openshift:4.20::el9'}}},
        {'product': {'product_id': 'openshift/ose-rhel-coreos-8',
                     'product_identification_helper': {'purl':
                         'pkg:oci/ose-rhel-coreos-8?repository_url=registry.redhat.io/openshift/ose-rhel-coreos-8'}}},
        {'product': {'product_id': 'rhcos@sha256:' + 'a' * 64 + '_x86_64',
                     'product_identification_helper': {'purl':
                         'pkg:oci/rhcos@sha256:' + 'a' * 64 + '?arch=x86_64&repository_url=registry.redhat.io/rhcos&tag=416.94.202507222002-0'}}},
        {'product': {'product_id': 'rhcos-x86_64-4.20.9.6.202509251656-0',
                     'product_identification_helper': {'purl':
                         'pkg:generic/redhat/rhcos@4.20.9.6.202509251656?arch=x86_64'}}},
    ]
    rel = [('openshift/ose-rhel-coreos-8', _ocp4),
           ('rhcos@sha256:' + 'a' * 64 + '_x86_64', 'RHOSE-4.16'),
           ('rhcos-x86_64-4.20.9.6.202509251656-0', 'RHOSE-4.20')]
    ka = f'{_ocp4}:openshift/ose-rhel-coreos-8'
    return {
        'product_tree': {'branches': branches, 'relationships': [
            {'product_reference': c, 'relates_to_product_reference': p,
             'full_product_name': {'product_id': f'{p}:{c}'}} for c, p in rel]},
        'vulnerabilities': [{
            'product_status': {'known_affected': [ka], 'fixed': [
                'RHOSE-4.16:rhcos@sha256:' + 'a' * 64 + '_x86_64',
                'RHOSE-4.20:rhcos-x86_64-4.20.9.6.202509251656-0']},
            'remediations': [{'category': 'no_fix_planned', 'details': 'Will not fix',
                              'product_ids': [ka]}]}],
    }


def _node(component, rhel, ocp):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: _rhcos_doc()
    try:
        ctx = WorkloadContext(workload_type='ocp', ocp_ver=ocp, ocp_component=component,
                              rhel_ver=rhel, display_name=f'OpenShift {ocp}')
        r = audit_row_detailed(pd.Series({
            'COMPONENT': 'github.com/containers/podman/v5', 'VERSION': 'v5.4.0',
            'CVE': 'CVE-9999-0003', 'SOURCE': 'GO', 'LOCATION': 'usr/bin/podman',
            'SEVERITY': 'IMPORTANT_VULNERABILITY_SEVERITY', 'FIXED_VERSION': ''}), ctx)
        return r.iloc[0], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


_v, _n = _node('rhel-coreos-10', '10', '4.20')
check('K1 a statement about rhel-coreos-8 / rhcos does not clear rhel-coreos-10',
      '❌' in _v and 'coreos-8' not in _n and 'rhcos' not in _n, f'{_v} {_n}')
_v, _n = _node('rhel-coreos', '9', '4.16')
check('K2 rhcos@sha256 (an oci purl without a path) names rhel-coreos',
      '✅' in _v and _n.startswith('Fixed'), f'{_v} {_n}')
_v, _n = _node('rhel-coreos', '9', '4.20')
check('K3 pkg:generic/redhat/rhcos names rhel-coreos', '✅' in _v, f'{_v} {_n}')
_v, _n = _node('rhel-coreos', '9', '4.22')
check('K4 a release past the image\'s newest fixed stream clears', '✅' in _v, f'{_v} {_n}')
_v, _n = _node('rhel-coreos', '9', '4.14')
check('K5 …one before the first fixed stream does not', '❌' in _v, f'{_v} {_n}')
_v, _n = _node('rhel-coreos', '8', '4.12')
check('K7 the default node image on RHEL 8 (OCP <= 4.12) is ose-rhel-coreos-8',
      '❌' in _v and 'coreos-8' in _n, f'{_v} {_n}')
_v, _n = _node('rhel-coreos-8', '8', '4.20')
check('K6 "Will not fix" for the image is not reinterpreted by other streams\' fixes',
      '❌' in _v and 'coreos-8' in _n, f'{_v} {_n}')


print('=== L. layered-product version streams and purl identity ===')

# Shape of CVE-2026-33186 / CVE-2025-13465: a layered product is published per
# version (`Red Hat Web Terminal 1.13` = cpe ...:webterminal:1.13::el9), plus a
# version-neutral node (`webterminal:1`).  Statements name builds by digest.
_WT = 'registry.redhat.io/web-terminal/web-terminal-tooling-rhel9'


def _wt_doc(statuses, extra_nodes=()):
    prods = {'wt': ('Red Hat Web Terminal', 'cpe:/a:redhat:webterminal:1'),
             'wt13': ('Red Hat Web Terminal 1.13', 'cpe:/a:redhat:webterminal:1.13::el9'),
             'wt16': ('Red Hat Web Terminal 1.16', 'cpe:/a:redhat:webterminal:1.16::el9')}
    comps = {}
    for st, items in statuses.items():
        for parent, comp, purl in items:
            comps[comp] = purl
    branches = [{'product': {'product_id': k, 'name': n,
                             'product_identification_helper': {'cpe': c}}}
                for k, (n, c) in prods.items()]
    branches += [{'product': {'product_id': c, 'product_identification_helper': {'purl': u}}}
                 for c, u in comps.items()]
    rel, ps = [], {}
    for st, items in statuses.items():
        for parent, comp, _ in items:
            rel.append({'product_reference': comp, 'relates_to_product_reference': parent,
                        'full_product_name': {'product_id': f'{parent}:{comp}'}})
            ps.setdefault(st, []).append(f'{parent}:{comp}')
    return {'product_tree': {'branches': branches, 'relationships': rel},
            'vulnerabilities': [{'product_status': ps}]}


def _wt_build(sha, tag):
    return (f'web-terminal/web-terminal-tooling-rhel9@sha256:{sha * 64}_amd64',
            f'pkg:oci/web-terminal-tooling-rhel9@sha256%3A{sha * 64}?arch=amd64'
            f'&repository_url={_WT}&tag={tag}')


def _wt(doc, build='1773341540', digest='f' * 64, cpe='cpe:/a:redhat:webterminal:1.16::el9'):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: doc
    try:
        ctx = WorkloadContext(workload_type='operator', image_ns='web-terminal',
                              image_name='web-terminal-tooling-rhel9', rhel_ver='9',
                              image_ref=f'{_WT}@sha256:{digest}', cpe=cpe,
                              image_build=build, display_name='Web Terminal 1.16')
        r = audit_row_detailed(pd.Series({
            'COMPONENT': 'google.golang.org/grpc', 'VERSION': 'v1.76.0', 'CVE': 'CVE-9999-0004',
            'SOURCE': 'GO', 'LOCATION': 'usr/bin/x', 'SEVERITY': 'IMPORTANT_VULNERABILITY_SEVERITY',
            'FIXED_VERSION': ''}), ctx)
        global _stated
        _stated = bool(r.iloc[5])
        return r.iloc[0], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


_stated = None
_c13, _p13 = _wt_build('a', '1780000000')          # built after ours
_sibling = ('wt', 'web-terminal/web-terminal-exec-rhel9',
            f'pkg:oci/web-terminal-exec-rhel9?repository_url={_WT[:-len("tooling-rhel9")]}exec-rhel9')
_v, _n = _wt(_wt_doc({'known_not_affected': [('wt13', _c13, _p13)],
                      'known_affected': [_sibling]}))
check('L1 another version\'s not-affected build is only an inference for ours',
      '✅' in _v and 'other versions' in _n and not _stated, f'{_v} {_n}')
_c16, _p16 = _wt_build('b', '1770000000')
_v, _n = _wt(_wt_doc({'known_not_affected': [('wt16', _c16, _p16)]}))
check('L2 a not-affected build of OUR version is evidence', '✅' in _v and '1.16' in _n,
      f'{_v} {_n}')
_v, _n = _wt(_wt_doc({'fixed': [('wt13', _c13, _p13)]}))
check('L3 fixed only in another version, after our build → predates the fix',
      '❌' in _v and 'predates' in _n, f'{_v} {_n}')
_v, _n = _wt(_wt_doc({'fixed': [('wt13', _c13, _p13)]}), build='1790000000')
check('L4 …a build newer than that fix is past it (inferred)', '✅' in _v and not _stated,
      f'{_v} {_n}')
_v, _n = _wt(_wt_doc({'known_affected': [
    ('wt', 'web-terminal/web-terminal-tooling-rhel9',
     f'pkg:oci/web-terminal-tooling-rhel9@sha256%3A{"f" * 64}?repository_url=quay.io/'
     'web-terminal/web-terminal-tooling-rhel9')]}))
check('L5 a digest pinned only in the purl (sha256%3A) is this build', '❌' in _v
      and 'this image build' in _n, f'{_v} {_n}')
# CVE-2025-58183: -rhel8 affected, -rhel9 not affected, both purls say -rhel8.
_bad = f'pkg:oci/web-terminal-tooling-rhel8?repository_url={_WT[:-len("-rhel9")]}'
_rhel = _wt_doc({'known_affected': [('wt', 'web-terminal/web-terminal-tooling-rhel8', _bad)],
                 'known_not_affected': [('wt', 'web-terminal/web-terminal-tooling-rhel9', _bad)]})
_v, _n = _wt(_rhel, digest='e' * 64)
check('L6 the PID\'s -rhelN tells two statements with one purl apart',
      '✅' in _v and 'rhel9' in _n, f'{_v} {_n}')


print('=== M. errata assumption is about OUR product ===')

# Shape of CVE-2024-45490 / CVE-2025-58187 on an OCP 4.20 payload image: RHEL 9
# lists its expat / golang rpm affected; OpenShift 4 lists sibling images
# (under investigation); our image is named nowhere.


def _ocp_doc(statuses):
    prods = {'red_hat_enterprise_linux_9': ('Red Hat Enterprise Linux 9', 'cpe:/o:redhat:enterprise_linux:9'),
             _ocp4: ('Red Hat OpenShift Container Platform 4', 'cpe:/a:redhat:openshift:4'),
             'cert9': ('Red Hat Certification Program for Red Hat Enterprise Linux 9',
                       'cpe:/a:redhat:certifications:1::el9'),
             'ocp420': ('Red Hat OpenShift Container Platform 4.20', 'cpe:/a:redhat:openshift:4.20::el9')}
    branches = [{'product': {'product_id': k, 'name': n, 'product_identification_helper': {'cpe': c}}}
                for k, (n, c) in prods.items()]
    rel, ps, seen = [], {}, set()
    for st, items in statuses.items():
        for parent, comp, purl in items:
            if comp not in seen:
                seen.add(comp)
                branches.append({'product': {'product_id': comp,
                                             'product_identification_helper': {'purl': purl}}})
            rel.append({'product_reference': comp, 'relates_to_product_reference': parent,
                        'full_product_name': {'product_id': f'{parent}:{comp}'}})
            ps.setdefault(st, []).append(f'{parent}:{comp}')
    return {'product_tree': {'branches': branches, 'relationships': rel},
            'vulnerabilities': [{'product_status': ps}]}


def _payload(doc, comp='github.com/thanos-io/thanos', src='GO'):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: doc
    try:
        ctx = WorkloadContext(workload_type='ocp', ocp_ver='4.20', ocp_component='thanos',
                              rhel_ver='9', image_name='openshift/ose-thanos-rhel9',
                              cpe='cpe:/a:redhat:openshift:4.20::el9', display_name='OpenShift 4.20')
        r = audit_row_detailed(pd.Series({
            'COMPONENT': comp, 'VERSION': 'v0.39.0', 'CVE': 'CVE-9999-0005', 'SOURCE': src,
            'LOCATION': 'usr/bin/thanos', 'SEVERITY': 'MODERATE_VULNERABILITY_SEVERITY',
            'FIXED_VERSION': ''}), ctx)
        return r.iloc[0], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


_golang = ('red_hat_enterprise_linux_9', 'golang', 'pkg:rpm/redhat/golang')
_v, _n = _payload(_ocp_doc({'known_affected': [_golang, ('cert9', 'golang', 'pkg:rpm/redhat/golang')]}))
check('M1 RHEL\'s golang rpm being affected does not make an OpenShift binary positive',
      '✅' in _v and 'assumed vulnerable' not in _n, f'{_v} {_n}')
_sib = (_ocp4, 'openshift4/ose-console-rhel9',
        'pkg:oci/ose-console-rhel9?repository_url=registry.redhat.io/openshift4/ose-console-rhel9')
_v, _n = _payload(_ocp_doc({'known_affected': [_golang], 'under_investigation': [_sib]}))
check('M2 sibling images of our product under investigation keep ours positive',
      '❌' in _v and 'under_investigation' in _n, f'{_v} {_n}')
_v, _n = _payload(_ocp_doc({'known_affected': [_sib]}))
check('M3 our product listed affected (sibling image) → errata assumption',
      '❌' in _v and 'OpenShift' in _n, f'{_v} {_n}')

# Shape of CVE-2026-25639 (axios): OCP 4 lists the console images affected,
# "OpenShift Container Platform 4.20" clears 160 builds that lack axios; our
# monitoring-plugin is in neither list.  Not cleared ≠ covered.
_sweep = [('ocp420', f'openshift4/ose-hyperkube-rhel9@sha256:{c * 64}_amd64',
           f'pkg:oci/ose-hyperkube-rhel9@sha256%3A{c * 64}?arch=amd64&repository_url='
           'registry.redhat.io/openshift4/ose-hyperkube-rhel9') for c in 'abc']
_v, _n = _payload(_ocp_doc({'known_affected': [_sib], 'known_not_affected': _sweep}))
check('M4 a not-affected sweep of other builds does not cover an image absent from it',
      '❌' in _v, f'{_v} {_n}')

# CVE-2024-45337 shape: clears under the SAME node that lists siblings affected
# mean Red Hat enumerated the product — our absence is meaningful.
_same = [(_ocp4, f'openshift4/ose-cli-artifacts-rhel9@sha256:{c * 64}_amd64',
          f'pkg:oci/ose-cli-artifacts-rhel9@sha256%3A{c * 64}?arch=amd64&repository_url='
          'registry.redhat.io/openshift4/ose-cli-artifacts-rhel9') for c in 'de']
_v, _n = _payload(_ocp_doc({'known_affected': [_sib], 'known_not_affected': _same}))
check('M5 clears under the node that lists siblings affected → not listed',
      '✅' in _v and 'not listed' in _n, f'{_v} {_n}')


print('=== N. a fix for another stream is not this build\'s fix ===')

# Shape of CVE-2026-103111 (pcre2): fixed only as a 9.6 EUS backport, while the
# version-neutral RHEL 9 node says known_affected / "Affected".


def _pcre2_doc():
    eus = 'AppStream-9.6.0.Z.EUS'
    nevra = 'pcre2-0:10.40-6.el9_6.1.x86_64'
    return {
        'product_tree': {
            'branches': [
                {'product': {'product_id': 'red_hat_enterprise_linux_9', 'name': 'Red Hat Enterprise Linux 9',
                             'product_identification_helper': {'cpe': 'cpe:/o:redhat:enterprise_linux:9'}}},
                {'product': {'product_id': eus, 'name': 'Red Hat Enterprise Linux AppStream EUS (v.9.6)',
                             'product_identification_helper': {'cpe': 'cpe:/a:redhat:rhel_eus:9.6::appstream'}}},
                {'product': {'product_id': 'pcre2', 'product_identification_helper': {'purl': 'pkg:rpm/redhat/pcre2'}}},
                {'product': {'product_id': nevra, 'product_identification_helper': {
                    'purl': 'pkg:rpm/redhat/pcre2@10.40-6.el9_6.1?arch=x86_64'}}}],
            'relationships': [
                {'product_reference': 'pcre2', 'relates_to_product_reference': 'red_hat_enterprise_linux_9',
                 'full_product_name': {'product_id': 'red_hat_enterprise_linux_9:pcre2'}},
                {'product_reference': nevra, 'relates_to_product_reference': eus,
                 'full_product_name': {'product_id': f'{eus}:{nevra}'}}]},
        'vulnerabilities': [{
            'product_status': {'known_affected': ['red_hat_enterprise_linux_9:pcre2'],
                               'fixed': [f'{eus}:{nevra}']},
            'remediations': [{'category': 'none_available', 'details': 'Affected',
                              'product_ids': ['red_hat_enterprise_linux_9:pcre2']}]}],
    }


def _pcre2(ver):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: _pcre2_doc()
    try:
        r = audit_row_detailed(pd.Series({
            'COMPONENT': 'pcre2', 'VERSION': ver, 'CVE': 'CVE-9999-0006', 'SOURCE': 'OS',
            'SEVERITY': 'IMPORTANT_VULNERABILITY_SEVERITY', 'FIXED_VERSION': '',
            'LOCATION': 'var/lib/rpm'}), _ctx_ubi9)
        return r.iloc[0], r.iloc[1], r.iloc[2], r.iloc[4]
    finally:
        engine._load_vex = _orig_load


_v, _f, _n, _st = _pcre2('10.40-6.el9')
check('N1 a mainline build with only an EUS fix: Red Hat\'s "Affected", no fix offered',
      '❌' in _v and _st == 'Affected' and _f in ('N/A', '', '-'), f'{_v} {_f} {_st} {_n}')
_v, _f, _n, _st = _pcre2('10.40-6.el9_6')
check('N2 a 9.6 EUS build still gets its own stream\'s fix', '❌' in _v and '10.40-6.el9_6.1' in _f,
      f'{_v} {_f} {_st} {_n}')
_v, _f, _n, _st = _pcre2('10.40-6.el9_6.1')
check('N3 …and clears at it', '✅' in _v, f'{_v} {_f} {_st} {_n}')

# The image's own minor (os-release 9.6) picks its stream's fix even for a
# package that kept its GA dist tag.
_orig_load = engine._load_vex
engine._load_vex = lambda _c: _pcre2_doc()
try:
    _ctx96 = WorkloadContext(workload_type='ubi', rhel_ver='9', rhel_minor='6', display_name='UBI9')
    _r = audit_row_detailed(pd.Series({
        'COMPONENT': 'pcre2', 'VERSION': '10.40-6.el9', 'CVE': 'CVE-9999-0006', 'SOURCE': 'OS',
        'SEVERITY': 'IMPORTANT_VULNERABILITY_SEVERITY', 'FIXED_VERSION': '', 'LOCATION': 'var/lib/rpm'}), _ctx96)
finally:
    engine._load_vex = _orig_load
check('N4 a 9.6 image takes the el9_6 fix for a GA-tagged package',
      '❌' in _r.iloc[0] and _r.iloc[1] == '10.40-6.el9_6.1', f'{list(_r)[:3]}')


print('=== O. a module shipped in an rpm; other products ===')

# urllib3 (PYTHON) shipped in python3-urllib3: Red Hat fixes the rpm, so the
# rpm's installed version decides; Ansible's same-named package does not.


def _py_doc():
    nodes = [('red_hat_enterprise_linux_9', 'Red Hat Enterprise Linux 9', 'cpe:/o:redhat:enterprise_linux:9', None),
             ('BaseOS-9.4.0.Z.EUS', 'Red Hat Enterprise Linux BaseOS EUS (v.9.4)', 'cpe:/a:redhat:rhel_eus:9.4::baseos', None),
             ('aap', 'Red Hat Ansible Automation Platform 2.4 for RHEL 9', 'cpe:/a:redhat:ansible_automation_platform:2.4::el9', None),
             ('python3-urllib3-0:1.26.5-5.el9_4.4.noarch', None, None,
              'pkg:rpm/redhat/python3-urllib3@1.26.5-5.el9_4.4?arch=noarch'),
             ('python3-urllib3', None, None, 'pkg:rpm/redhat/python3-urllib3')]
    branches = []
    for pid, name, cpe, purl in nodes:
        helper = {'cpe': cpe} if cpe else {'purl': purl}
        prod = {'product_id': pid, 'product_identification_helper': helper}
        if name:
            prod['name'] = name
        branches.append({'product': prod})
    rel = [('python3-urllib3-0:1.26.5-5.el9_4.4.noarch', 'BaseOS-9.4.0.Z.EUS'), ('python3-urllib3', 'aap')]
    return {'product_tree': {'branches': branches, 'relationships': [
                {'product_reference': c, 'relates_to_product_reference': p,
                 'full_product_name': {'product_id': f'{p}:{c}'}} for c, p in rel]},
            'vulnerabilities': [{
                'product_status': {'fixed': ['BaseOS-9.4.0.Z.EUS:python3-urllib3-0:1.26.5-5.el9_4.4.noarch']},
                'flags': [{'label': 'vulnerable_code_not_present', 'product_ids': ['aap:python3-urllib3']}]}]}


def _py(installed_rpm):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: _py_doc()
    try:
        ctx = WorkloadContext(workload_type='ocp', ocp_ver='4.20', ocp_component='thanos', rhel_ver='9',
                              rhel_minor='4', image_name='openshift/ose-thanos-rhel9',
                              display_name='OpenShift 4.20',
                              sbom_src_map={'urllib3': 'python3-urllib3'},
                              sbom_packages={'python3-urllib3': {installed_rpm}})
        r = audit_row_detailed(pd.Series({
            'COMPONENT': 'urllib3', 'VERSION': '1.26.5', 'CVE': 'CVE-9999-0007', 'SOURCE': 'PYTHON',
            'LOCATION': '/usr/lib/python3.9/site-packages/urllib3', 'SEVERITY': '', 'FIXED_VERSION': ''}), ctx)
        return r.iloc[0], r.iloc[1], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


_v, _f, _n = _py('1.26.5-5.el9_4.1')
check('O3 a module in an rpm is decided by the rpm version (below the fix)',
      '❌' in _v and _f == '1.26.5-5.el9_4.4' and 'Ansible' not in _n, f'{_v} {_f} {_n}')
_v, _f, _n = _py('1.26.5-5.el9_4.4')
check('O4 …at the fix it clears', '✅' in _v and 'Ansible' not in _n, f'{_v} {_f} {_n}')


print('=== P. whose statement decides; what Red Hat does not ship ===')


def _doc(products, entries):
    """products = {pid: (name, cpe)}; entries = [(status, parent, leaf, purl)]."""
    branches = [{'product': {'product_id': k, 'name': n, 'product_identification_helper': {'cpe': c}}}
                for k, (n, c) in products.items()]
    rel, ps, seen = [], {}, set()
    for st, parent, leaf, purl in entries:
        if leaf not in seen:
            seen.add(leaf)
            branches.append({'product': {'product_id': leaf, 'product_identification_helper': {'purl': purl}}})
        rel.append({'product_reference': leaf, 'relates_to_product_reference': parent,
                    'full_product_name': {'product_id': f'{parent}:{leaf}'}})
        ps.setdefault(st, []).append(f'{parent}:{leaf}')
    return {'product_tree': {'branches': branches, 'relationships': rel},
            'vulnerabilities': [{'product_status': ps}]}


def _row(doc, ctx, comp, ver, source='OS', **extra):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: doc
    try:
        r = audit_row_detailed(pd.Series({'COMPONENT': comp, 'VERSION': ver, 'CVE': 'CVE-9999-0009',
                                          'SOURCE': source, 'SEVERITY': '', 'FIXED_VERSION': '',
                                          **extra}), ctx)
        return r.iloc[0], r.iloc[1], r.iloc[2], bool(r.iloc[5])
    finally:
        engine._load_vex = _orig_load


_PR = {'red_hat_enterprise_linux_8': ('Red Hat Enterprise Linux 8', 'cpe:/o:redhat:enterprise_linux:8'),
       'red_hat_enterprise_linux_9': ('Red Hat Enterprise Linux 9', 'cpe:/o:redhat:enterprise_linux:9'),
       'BaseOS-9.7.0.Z.MAIN': ('Red Hat Enterprise Linux BaseOS (v. 9)', 'cpe:/o:redhat:enterprise_linux:9::baseos'),
       'BaseOS-9.5.0.GA': ('Red Hat Enterprise Linux BaseOS (v. 9)', 'cpe:/o:redhat:enterprise_linux:9::baseos'),
       _ocp4: ('Red Hat OpenShift Container Platform 4', 'cpe:/a:redhat:openshift:4')}
_ose = WorkloadContext(workload_type='ocp', ocp_ver='4.20', ocp_component='cli', rhel_ver='9', rhel_minor='4',
                       image_name='openshift4/ose-cli-rhel9', display_name='OpenShift 4.20')
_ose8 = WorkloadContext(workload_type='ocp', ocp_ver='4.12', ocp_component='cli', rhel_ver='8',
                        image_name='openshift4/ose-cli', display_name='OpenShift 4.12')

# CVE-2025-4598 shape: RHEL 9 fixed systemd only in 9.7; OpenShift 4 says not affected.
_sd = _doc(_PR, [('fixed', 'BaseOS-9.7.0.Z.MAIN', 'systemd-0:252-55.el9_7.7.x86_64',
                  'pkg:rpm/redhat/systemd@252-55.el9_7.7?arch=x86_64'),
                 ('known_not_affected', _ocp4, 'systemd', 'pkg:rpm/redhat/systemd')])
_v, _f, _n, _s = _row(_sd, _ose, 'systemd', '252-32.el9_4.8')
check('P1 the image\'s own product clears a RHEL rpm RHEL fixed only later', '✅' in _v and _s
      and 'OpenShift' in _n, f'{_v} {_n}')
# CVE-2021-24031 shape: RHEL 8 libzstd not affected; OpenShift 4 known_affected "out of support scope".
_zs = _doc(_PR, [('known_not_affected', 'red_hat_enterprise_linux_8', 'libzstd', 'pkg:rpm/redhat/libzstd'),
                 ('known_affected', _ocp4, 'libzstd', 'pkg:rpm/redhat/libzstd')])
_v, _f, _n, _s = _row(_zs, _ose8, 'libzstd', '1.4.4-1.el8')
check('P2 RHEL\'s not-affected for its own rpm decides a plain .el8 build', '✅' in _v
      and 'Enterprise Linux 8' in _n, f'{_v} {_n}')
# openssl-fips-provider: only a versioned not-affected for the same upstream version.
_fp = _doc(_PR, [('known_not_affected', 'BaseOS-9.5.0.GA', 'openssl-fips-provider-0:3.0.7-6.el9_5.x86_64',
                  'pkg:rpm/redhat/openssl-fips-provider@3.0.7-6.el9_5?arch=x86_64')])
_v, _f, _n, _s = _row(_fp, WorkloadContext(workload_type='ubi', rhel_ver='9', rhel_minor='4'),
                      'openssl-fips-provider', '3.0.7-2.el9')
check('P3 a not-affected build of the same upstream version clears the package', '✅' in _v,
      f'{_v} {_n}')
# MongoDB's own Go binary in a ubi8-based image: Red Hat's VEX does not cover it.
_mongo = WorkloadContext(workload_type='ubi', rhel_ver='8', vendor='MongoDB', display_name='UBI8',
                         image_ref='docker.io/mongodb/mongodb-community-server@sha256:' + '2' * 64,
                         sbom_foreign_rpms={'mongodb-org-server'})
_go = _doc(_PR, [('known_affected', 'red_hat_enterprise_linux_8', 'golang', 'pkg:rpm/redhat/golang')])
_v, _f, _n, _s = _row(_go, _mongo, 'stdlib', 'go1.23.8', source='GO')
check('P4 a module of a non-Red Hat image is not cleared by Red Hat\'s silence', '❌' in _v
      and 'MongoDB' in _n and not _s, f'{_v} {_n}')
_v, _f, _n, _s = _row(_go, _mongo, 'stdlib', 'go1.23.8', source='GO',
                      OWNER_RPM='mongodb-org-server@8.0.3-1.el8')
check('P4b …nor one a third-party rpm ships', '❌' in _v and 'not a Red Hat build' in _n, f'{_v} {_n}')
_mrpm = _doc(_PR, [('fixed', 'BaseOS-9.7.0.Z.MAIN', 'mongodb-org-server-0:9.0-1.el8.x86_64',
                    'pkg:rpm/redhat/mongodb-org-server@9.0-1.el8?arch=x86_64')])
_v, _f, _n, _s = _row(_mrpm, _mongo, 'mongodb-org-server', '8.0.3-1.el8')
check('P4c a third-party rpm is never decided by a Red Hat build of the same name', '❌' in _v
      and 'not a Red Hat build' in _n, f'{_v} {_n}')
_rh = WorkloadContext(workload_type='ubi', rhel_ver='8', vendor='Red Hat, Inc.',
                      image_ref='registry.access.redhat.com/ubi8/ubi@sha256:' + '3' * 64)
_v, _f, _n, _s = _row(_go, _rh, 'stdlib', 'go1.23.8', source='GO')
check('P5 …while in a Red Hat image the unnamed module is not listed', '✅' in _v and 'not listed' in _n,
      f'{_v} {_n}')
_cust = WorkloadContext(workload_type='ubi', rhel_ver='8', vendor='Red Hat, Inc.',
                        image_ref='quay.io/acme/app@sha256:' + '4' * 64)
_v, _f, _n, _s = _row(_go, _cust, 'stdlib', 'go1.23.8', source='GO')
check('P5b an image built FROM ubi (inherited vendor label) is not Red Hat\'s', '❌' in _v, f'{_v} {_n}')
# An operator image without a CPE label: its registry namespace names its product.
_PR2 = dict(_PR, red_hat_openshift_gitops=('Red Hat OpenShift GitOps', 'cpe:/a:redhat:openshift_gitops:1'))
_gd = _doc(_PR2, [('known_affected', 'red_hat_openshift_gitops', 'openshift-gitops-1/argocd-rhel8',
                   'pkg:oci/argocd-rhel8?repository_url=registry.redhat.io/openshift-gitops-1/argocd-rhel8')])
_gitops = WorkloadContext(workload_type='operator', rhel_ver='8', image_ns='openshift-gitops-1',
                          image_name='gitops-rhel8-operator', image_build='v1.6.0-1',
                          image_ref='registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:' + '1' * 64,
                          vendor='Red Hat, Inc.')
_v, _f, _n, _s = _row(_gd, _gitops, 'golang.org/x/net', 'v0.0.1', source='GO')
check('P6 a sibling image of our product (found by namespace) affected → errata assumption',
      '❌' in _v and 'GitOps' in _n, f'{_v} {_n}')

# openshift-clients in a Web Terminal image: RHEL never ships it; OpenShift 4 does.
_PR3 = dict(_PR, red_hat_web_terminal=('Red Hat Web Terminal', 'cpe:/a:redhat:webterminal:1'),
            red_hat_openshift_enterprise_3=('Red Hat OpenShift Enterprise 3.0', 'cpe:/a:redhat:openshift:3.0'))
_oc = _doc(_PR3, [('known_affected', _ocp4, 'openshift-clients', 'pkg:rpm/redhat/openshift-clients')])
_wt9 = WorkloadContext(workload_type='operator', rhel_ver='9', cpe='cpe:/a:redhat:webterminal:1.16::el9',
                       image_ns='web-terminal', image_name='web-terminal-tooling-rhel9',
                       image_ref='registry.redhat.io/web-terminal/web-terminal-tooling-rhel9@sha256:' + '5' * 64)
_v, _f, _n, _s = _row(_oc, _wt9, 'openshift-clients', '4.20.0-202605211651.p2.g02b0b2d.assembly.stream.el9')
check('P7 an rpm RHEL never names is decided by the product that ships it (inferred)',
      '❌' in _v and 'OpenShift' in _n and not _s, f'{_v} {_n}')
_oc3 = _doc(_PR3, [('known_affected', 'red_hat_openshift_enterprise_3', 'openshift-clients',
                    'pkg:rpm/redhat/openshift-clients')])
_v, _f, _n, _s = _row(_oc3, _wt9, 'openshift-clients', '4.20.0-1.el9')
check('P7b …never by a product of another version line', '✅' in _v, f'{_v} {_n}')
# A Go module path carries a '/': it is a package, not an image pseudo-component.
_bd = _doc(_PR, [('fixed', 'BaseOS-9.7.0.Z.MAIN', 'buildah-2:1.41.6-1.el9_7.x86_64',
                  'pkg:rpm/redhat/buildah@1.41.6-1.el9_7?arch=x86_64&epoch=2')])
_v, _f, _n, _s = _row(_bd, WorkloadContext(workload_type='ubi', rhel_ver='9', rhel_minor='7'),
                      'github.com/opencontainers/runc', 'v1.2.4', source='GO',
                      OWNER_RPM='buildah@1.39.4-2.el9_7')
check('P8 a Go module reaches the rpm that ships it', '❌' in _v and 'ships in buildah' in _n, f'{_v} {_n}')
# The image itself stated not affected covers the rpms inside it.
_bi = _doc(_PR, [('known_not_affected', 'red_hat_enterprise_linux_9', 'rhel9/buildah',
                  'pkg:oci/buildah?repository_url=registry.redhat.io/rhel9/buildah'),
                 ('known_affected', 'red_hat_enterprise_linux_9', 'buildah', 'pkg:rpm/redhat/buildah')])
_v, _f, _n, _s = _row(_bi, WorkloadContext(workload_type='ubi', rhel_ver='9', image_ns='rhel9',
                                           image_name='buildah',
                                           image_ref='registry.redhat.io/rhel9/buildah@sha256:' + '6' * 64),
                      'buildah', '2:1.39.4-2.el9_6')
check('P9 an image stated not affected clears the rpm inside it', '✅' in _v and _s
      and 'rhel9/buildah' in _n, f'{_v} {_n}')

# CVE-2024-33599 shape: 8.6 EUS glibc builds "vulnerable code not present", fixed in 8.8.
_PR4 = dict(_PR, **{'BaseOS-8.6.0.Z.EUS': ('Red Hat Enterprise Linux BaseOS EUS (v.8.6)', 'cpe:/o:redhat:rhel_eus:8.6::baseos'),
                    'BaseOS-8.8.0.Z.EUS': ('Red Hat Enterprise Linux BaseOS EUS (v.8.8)', 'cpe:/o:redhat:rhel_eus:8.8::baseos')})
_gl = _doc(_PR4, [('known_not_affected', 'BaseOS-8.6.0.Z.EUS', 'glibc-0:2.28-189.10.el8_6.x86_64',
                   'pkg:rpm/redhat/glibc@2.28-189.10.el8_6?arch=x86_64'),
                  ('fixed', 'BaseOS-8.8.0.Z.EUS', 'glibc-0:2.28-225.el8_8.11.x86_64',
                   'pkg:rpm/redhat/glibc@2.28-225.el8_8.11?arch=x86_64')])
_v, _f, _n, _s = _row(_gl, WorkloadContext(workload_type='ubi', rhel_ver='8', rhel_minor='6'), 'glibc', '2.28-189.5.el8_6')
check('P10 our own stream\'s not-affected build of our upstream version speaks for our code', '✅' in _v,
      f'{_v} {_n}')
_v, _f, _n, _s = _row(_gl, WorkloadContext(workload_type='ubi', rhel_ver='8', rhel_minor='7'), 'glibc', '2.28-211.el8')
check('P10b …but not for another stream\'s build', '❌' in _v, f'{_v} {_n}')

print('=== Q. inferred positives checked against the binaries (OSV) ===')
from rhacs_vex import osv as _osv                             # noqa: E402


class _OsvIndex:
    """Stub index: {(eco, pkg): [(cves, ranges, versions)]}."""
    def __init__(self, recs):
        self.recs = recs

    def osv_packages(self):
        return [(e, p, ' '.join(c)) for (e, p), rs in self.recs.items() for c, _r, _v in rs]

    def osv(self, eco, name):
        return self.recs.get((eco, name), [])


def _sem(fixed):
    return [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': fixed}]}]


_idx = _OsvIndex({('Go', 'github.com/opencontainers/runc'): [(['CVE-9999-0101'], _sem('1.1.12'), ())],
                  ('Go', 'golang.org/x/net'): [(['CVE-9999-0102'], _sem('0.40.0'), ())],
                  ('Go', 'github.com/go-ldap/ldap'): [(['CVE-9999-0103'], _sem('2.5.0'), ())],
                  ('Go', 'github.com/golang-fips/openssl/v2'): [(['CVE-9999-0104'], _sem('2.0.1'), ())]})
_mods = [('Go', 'github.com/opencontainers/runc', 'v1.1.13', 'openshift-clients'),
         ('Go', 'golang.org/x/net', 'v0.38.0', 'openshift-clients')]
_ocq = _doc(_PR3, [('known_affected', _ocp4, 'openshift-clients', 'pkg:rpm/redhat/openshift-clients')])


def _row_cve(doc, ctx, comp, ver, cve):
    _orig_load = engine._load_vex
    engine._load_vex = lambda _c: doc
    try:
        r = audit_row_detailed(pd.Series({'COMPONENT': comp, 'VERSION': ver, 'CVE': cve, 'SOURCE': 'OS',
                                          'SEVERITY': '', 'FIXED_VERSION': ''}), ctx)
        return r.iloc[0], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


_cq = WorkloadContext(**{**_wt9.__dict__, 'osv_evidence': _osv.Evidence(_idx, _mods)})
_v, _n = _row_cve(_ocq, _cq, 'openshift-clients', '4.20.0-1.el9', 'CVE-9999-0101')
check('Q1 the binary\'s module is past the fix → not affected', '✅' in _v and 'past the fix' in _n, f'{_v} {_n}')
_v, _n = _row_cve(_ocq, _cq, 'openshift-clients', '4.20.0-1.el9', 'CVE-9999-0102')
check('Q2 in the vulnerable range → stays POSITIVE, with the proof', '❌' in _v and 'vulnerable range' in _n,
      f'{_v} {_n}')
_v, _n = _row_cve(_ocq, _cq, 'openshift-clients', '4.20.0-1.el9', 'CVE-9999-0103')
check('Q3 the vulnerable package is not compiled in → not affected', '✅' in _v and 'is not in' in _n,
      f'{_v} {_n}')
_v, _n = _row_cve(_ocq, _cq, 'openshift-clients', '4.20.0-1.el9', 'CVE-9999-0104')
check('Q4 toolchain-embedded code (golang-fips) is never "not present"', '❌' in _v, f'{_v} {_n}')
_v, _n = _row_cve(_ocq, _cq, 'openshift-clients', '4.20.0-1.el9', 'CVE-9999-0105')
check('Q5 a CVE OSV does not know keeps Red Hat\'s verdict', '❌' in _v and 'OSV' not in _n, f'{_v} {_n}')
_stated = _doc(_PR3, [('known_affected', 'red_hat_web_terminal', 'web-terminal/web-terminal-tooling-rhel9',
                       'pkg:oci/web-terminal-tooling-rhel9?repository_url=registry.redhat.io/web-terminal/'
                       'web-terminal-tooling-rhel9')])
_orig_load = engine._load_vex
engine._load_vex = lambda _c: _stated
try:
    _r = audit_row_detailed(pd.Series({'COMPONENT': 'web-terminal/web-terminal-tooling-rhel9', 'VERSION': '1',
                                       'CVE': 'CVE-9999-0101', 'SOURCE': 'IMAGE', 'SEVERITY': '',
                                       'FIXED_VERSION': ''}), _cq)
finally:
    engine._load_vex = _orig_load
check('Q6 Red Hat\'s statement about this image is never second-guessed', '❌' in _r.iloc[0]
      and 'OSV' not in _r.iloc[2], f'{list(_r)[:3]}')

print()
if _failures:
    print(f'{len(_failures)} FAILED: {_failures}')
    sys.exit(1)
print('ALL engine-regression tests pass.')
