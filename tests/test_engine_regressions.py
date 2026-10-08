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
from rhacs_vex.core.decide import Decision, compare_fixed, src_aliases  # noqa: E402
from rhacs_vex.core.scope import prefix_matches as _prefix_matches_pid  # noqa: E402
from rhacs_vex.core.vexdoc import VexDocument                        # noqa: E402


def _src_alias_names(data, comp, found_v, srpm=''):
    return src_aliases(VexDocument.of(data), comp, found_v, srpm)

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


print('=== A. src-alias must not override a known SRPM ===')

# python3 ships a version-less .src PID (a wildcard), and python3-chardet shares
# its dash prefix — but chardet is built from python-chardet.  Before the fix the
# wildcard let chardet inherit python3's fixed NEVRA and 4.0.0 >= 3.9.21 cleared
# a package Red Hat never fixed.
DOC = vex(
    [('python3-0:3.9.21-1.el9_5.x86_64', 'pkg:rpm/redhat/python3@3.9.21-1.el9_5?arch=x86_64'),
     ('python3.src', 'pkg:rpm/redhat/python3?arch=src')],
    {'fixed': ['red_hat_enterprise_linux_9:python3-0:3.9.21-1.el9_5.x86_64'],
     'known_affected': ['red_hat_enterprise_linux_9:python3.src']},
)
check('A1 dash-prefix alias still works when no SRPM is known',
      _src_alias_names(dict(DOC), 'python3-libs', '3.9.21-1.el9_5') == {'python3'})
check('A2 a known SRPM overrides the dash-prefix guess',
      _src_alias_names(dict(DOC), 'python3-chardet', '4.0.0-5.el9', 'python-chardet')
      == {'python-chardet'},
      str(_src_alias_names(dict(DOC), 'python3-chardet', '4.0.0-5.el9', 'python-chardet')))
check('A3 a matching SRPM is preserved',
      'python3' in _src_alias_names(dict(DOC), 'python3-libs', '3.9.21-1.el9_5', 'python3'))

print('\n=== B. namespace prefixes must match on token boundaries ===')

# 'ai' is a real CPE token in the namespace map.  A raw substring test matched
# the stream name in BaseOS-8.10.0.Z.M(AI)N.EUS, pulling every RHEL major into an
# operator workload's scope; a cross-major fix then wins the §6b GA comparison
# that an el8 package can never satisfy.
check('B1 short token does not match inside a stream name',
      not _prefix_matches_pid('ai', 'baseos-8.10.0.z.main.eus:systemd-0:239-78.el8.x86_64'))
check('B2 short token still matches its own product',
      _prefix_matches_pid('ai', 'red hat openshift ai 2.25:rhoai/odh-x'))
check('B3 underscored product id still matches',
      _prefix_matches_pid('ai', 'red_hat_openshift_ai:x'))
check('B4 path prefixes keep substring semantics',
      _prefix_matches_pid('rhoai/', 'registry.redhat.io/rhoai/odh-x'))
check('B5 odf does not match a MAIN stream',
      not _prefix_matches_pid('odf', 'baseos-9.1.0.z.main:zlib-0:1.2.11-1.el9.x86_64'))

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
from rhacs_vex.core import decide as _decide                  # noqa: E402
import inspect                                                # noqa: E402

# A product outside the resolved workload scope must never decide an RPM row.
_src = inspect.getsource(_decide._Triage._rpm)
check('G1 RPM decisions contain no related-product fallback',
      'affected in related products' not in _src)

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

print('\n=== H. cross-stream fixes: version may clear, release may not ===')

# A fix backported to a frozen EUS/E4S branch numbers its release independently
# of the current stream, so comparing releases across streams is meaningless
# (§6b).  The upstream VERSION carries no such confound: expat 2.5.0 on 9.8
# cannot be missing a 2013 fix that shipped in 2.2.10-12.el9_0.4, even though
# release 6 < 12.  Equal versions differing only in release keep the confound
# and must stay POSITIVE.
_newer = V.upstream_newer_than_all

check('H1 strictly newer upstream version clears an older-branch backport',
      _newer('2.5.0-6.el9_8.1', ['2.2.10-12.el9_0.4']) is True,
      _newer('2.5.0-6.el9_8.1', ['2.2.10-12.el9_0.4']))

check('H2 …and must beat EVERY listed fix, not just the first',
      _newer('2.4.9-1.el9_1', ['2.2.10-12.el9_0.4', '2.5.0-1.el9_5']) is False,
      _newer('2.4.9-1.el9_1', ['2.2.10-12.el9_0.4', '2.5.0-1.el9_5']))

check('H3 equal version, differing release stays unresolved (release confound)',
      _newer('2.2.10-14.el9_8', ['2.2.10-12.el9_0.4']) is False,
      _newer('2.2.10-14.el9_8', ['2.2.10-12.el9_0.4']))

check('H4 an older upstream version never clears',
      _newer('2.2.10-99.el9_8', ['2.5.0-1.el9_5']) is False,
      _newer('2.2.10-99.el9_8', ['2.5.0-1.el9_5']))

check('H5 epoch is aligned before the version compare',
      _newer('1:1.21.1-10.el9_8', ['1.20.1-8.el9']) is True,
      _newer('1:1.21.1-10.el9_8', ['1.20.1-8.el9']))

check('H6 an empty fix list clears nothing', _newer('2.5.0-6.el9_8', []) is False,
      _newer('2.5.0-6.el9_8', []))

check('H7 letter-suffixed upstream versions still order correctly',
      _newer('1.1.1k-4.el9_8', ['1.1.1-9.el9_0']) is True
      and _newer('1.1.1-9.el9_8', ['1.1.1k-4.el9_0']) is False,
      f"k>bare={_newer('1.1.1k-4.el9_8', ['1.1.1-9.el9_0'])} "
      f"bare>k={_newer('1.1.1-9.el9_8', ['1.1.1k-4.el9_0'])}")

# The clear must actually be reachable through the ladder, not just the helper.
_ctx_rhel9 = WorkloadContext(workload_type='ubi', rhel_ver='9', display_name='UBI9')
_dec = Decision()
_v, _fix, _note = compare_fixed(
    '2.5.0-6.el9_8.1', ['2.2.10-12.el9_0.4'], 'expat', _ctx_rhel9, _dec,
    {'2.2.10-12.el9_0.4': 'AppStream-9.0.0.Z.E4S:expat-0:2.2.10-12.el9_0.4.x86_64'})
check('H8 compare_fixed returns the clear for the newer-upstream case',
      'FALSE POSITIVE' in _v and _dec.kind == 'rpm_fixed_newer_upstream',
      f'{_v} kind={_dec.kind} note={_note}')

print()
print('=== I. later-stream install vs an older-branch-only fix ===')
# Equal upstream version, so H1's exception cannot reach it — glibc 2.34-272.el9_8
# against the 9.0 E4S backport 2.34-28.el9_0.4.  Red Hat fixes the current stream
# first and backports to EUS/E4S after, so a fix living only in older minors was
# already in the branch ours forked from; branch base releases climb with the
# minor, which makes the NEVRA compare meaningful in this direction alone.
_sup = V.later_stream_than_all
_fix_pid = {'2.2.10-12.el9_0.4': 'AppStream-9.0.0.Z.E4S:expat-0:2.2.10-12.el9_0.4.x86_64'}


def _cf(installed, fixes, affected=False):
    d = Decision()
    v, _f, n = compare_fixed(installed, fixes, 'expat', _ctx_rhel9, d, _fix_pid, affected)
    return v, n, d


check('I1 equal version, later stream, higher release clears',
      _sup('2.34-272.el9_8', ['2.34-28.el9_0.4']) is True,
      _sup('2.34-272.el9_8', ['2.34-28.el9_0.4']))

check('I2 a fix in a NEWER stream is "not backported to us yet" — no clear',
      _sup('3.5.3-9.el9_7', ['3.5.3-11.el9_8']) is False,
      _sup('3.5.3-9.el9_7', ['3.5.3-11.el9_8']))

check('I3 same minor is the same-stream path, not this one',
      _sup('2.34-272.el9_8', ['2.34-274.el9_8']) is False,
      _sup('2.34-272.el9_8', ['2.34-274.el9_8']))

check('I4 an el8 backport says nothing about an el9 build',
      _sup('2.34-272.el9_8', ['2.28-189.6.el8_6']) is False,
      _sup('2.34-272.el9_8', ['2.28-189.6.el8_6']))

check('I5 a mainline fix is the ancestor of our branch and orders too',
      _sup('2.9.13-14.el9_8.1', ['2.9.13-3.el9']) is True,
      _sup('2.9.13-14.el9_8.1', ['2.9.13-3.el9']))

check('I5b …but a mainline build ahead of our fork point does not clear',
      _sup('2.9.13-14.el9_8.1', ['2.9.13-20.el9']) is False,
      _sup('2.9.13-14.el9_8.1', ['2.9.13-20.el9']))

check('I6 every fix must be older-stream AND older, not just the first',
      _sup('2.34-272.el9_8', ['2.34-28.el9_0.4', '2.34-300.el9_6']) is False,
      _sup('2.34-272.el9_8', ['2.34-28.el9_0.4', '2.34-300.el9_6']))

check('I7 a GA install (no minor marker) keeps §6b step 4',
      _sup('2.34-60.el9', ['2.34-28.el9_0.4']) is False,
      _sup('2.34-60.el9', ['2.34-28.el9_0.4']))

_v2, _note2, _dec2 = _cf('2.2.10-14.el9_8', ['2.2.10-12.el9_0.4'])
check('I8 compare_fixed reaches the clear through the ladder',
      'FALSE POSITIVE' in _v2 and _dec2.kind == 'rpm_fixed_newer_stream',
      f'{_v2} kind={_dec2.kind} note={_note2}')

_v3, _note3, _dec3 = _cf('2.2.10-14.el9_8', ['2.2.10-12.el9_0.4'], affected=True)
check('I9 an in-scope known_affected vetoes the inference (erratum pending)',
      'FALSE POSITIVE' not in _v3 and 'No fix in el9_8' in _note3,
      f'{_v3} note={_note3}')

_v4, _note4, _dec4 = _cf('3.5.3-9.el9_7', ['3.5.3-11.el9_8'])
check('I10 …and a newer-stream fix still reports the stream gap',
      'FALSE POSITIVE' not in _v4 and 'No fix in el9_7' in _note4,
      f'{_v4} note={_note4}')

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

# The signal this rung exists for survives: RHEL never ships openshift-clients,
# so a version-neutral OCP PID naming it is the only statement there is.
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
# version-neutral and rung 8 admitted them.  That is how CVE-2004-0642 held a
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
        return r.iloc[0], r.iloc[2]
    finally:
        engine._load_vex = _orig_load


_c13, _p13 = _wt_build('a', '1780000000')          # built after ours
_sibling = ('wt', 'web-terminal/web-terminal-exec-rhel9',
            f'pkg:oci/web-terminal-exec-rhel9?repository_url={_WT[:-len("tooling-rhel9")]}exec-rhel9')
_v, _n = _wt(_wt_doc({'known_not_affected': [('wt13', _c13, _p13)],
                      'known_affected': [_sibling]}))
check('L1 another version\'s not-affected build does not clear ours',
      '❌' in _v and '1.13' not in _n, f'{_v} {_n}')
_c16, _p16 = _wt_build('b', '1770000000')
_v, _n = _wt(_wt_doc({'known_not_affected': [('wt16', _c16, _p16)]}))
check('L2 a not-affected build of OUR version is evidence', '✅' in _v and '1.16' in _n,
      f'{_v} {_n}')
_v, _n = _wt(_wt_doc({'fixed': [('wt13', _c13, _p13)]}))
check('L3 fixed only in another version, after our build → predates the fix',
      '❌' in _v and 'predates' in _n, f'{_v} {_n}')
_v, _n = _wt(_wt_doc({'fixed': [('wt13', _c13, _p13)]}), build='1790000000')
check('L4 …a build newer than that fix gets no inference from it', '1.13' not in _n,
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


print()
if _failures:
    print(f'{len(_failures)} FAILED: {_failures}')
    sys.exit(1)
print('ALL engine-regression tests pass.')
