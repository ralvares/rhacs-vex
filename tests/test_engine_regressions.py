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
from rhacs_vex.engine import (WorkloadContext, _src_alias_names,     # noqa: E402
                              _prefix_matches_pid, audit_row_detailed)

_failures = []


def check(name, cond, detail=''):
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ''))
    if not cond:
        _failures.append(name)


def vex(nodes, statuses):
    """Minimal CSAF doc: nodes = [(component_pid, purl)], statuses = {bucket: [pid]}."""
    return {
        'product_tree': {
            'branches': [{'branches': [
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

from rhacs_vex.engine import _rpmvercmp, _evr_compare, compare_versions   # noqa: E402

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

from rhacs_vex.engine import _rpm_stream_family, _stream_comparable   # noqa: E402

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

from rhacs_vex.triage import _evidence_of, _RELATED_MARKER   # noqa: E402
from rhacs_vex import engine as _eng                          # noqa: E402
import inspect                                                # noqa: E402

# The tool presents Red Hat's view.  A rung-8 row carries a genuine statement
# (so VEX_STATED is True) but it is about ANOTHER product that ships the same
# package — labelling it 'stated' would present a third-party claim as Red Hat's
# verdict on this image.
_src = inspect.getsource(_eng._decide_rpm)
check('G1 engine still emits the rung-8 phrase the label keys on',
      _RELATED_MARKER in _src, f'marker={_RELATED_MARKER!r}')

related = pd.Series({'COMPONENT': 'openssl', 'SOURCE': 'OS', 'VEX_STATED': 'True',
                     'JUSTIFICATION': "'openssl' affected in related products "
                                      "(Red Hat Enterprise Linux 7)."})
check('G2 rung-8 row is labelled related, not stated',
      _evidence_of(related) == 'related', _evidence_of(related))

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
_newer = _eng._upstream_newer_than_all

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
_dec = {}
_v, _fix, _note = _eng._compare_fixed(
    '2.5.0-6.el9_8.1', ['2.2.10-12.el9_0.4'], 'expat', _ctx_rhel9, True, _dec,
    {'2.2.10-12.el9_0.4': 'AppStream-9.0.0.Z.E4S:expat-0:2.2.10-12.el9_0.4.x86_64'})
check('H8 _compare_fixed returns the clear for the newer-upstream case',
      'FALSE POSITIVE' in _v and _dec.get('kind') == 'rpm_fixed_newer_upstream',
      f'{_v} kind={_dec.get("kind")} note={_note}')

_dec2 = {}
_v2, _fix2, _note2 = _eng._compare_fixed(
    '2.2.10-14.el9_8', ['2.2.10-12.el9_0.4'], 'expat', _ctx_rhel9, True, _dec2,
    {'2.2.10-12.el9_0.4': 'AppStream-9.0.0.Z.E4S:expat-0:2.2.10-12.el9_0.4.x86_64'})
check('H9 …and keeps POSITIVE when only the release differs',
      'FALSE POSITIVE' not in _v2 and 'No fix in el9_8' in _note2,
      f'{_v2} note={_note2}')

print()
if _failures:
    print(f'{len(_failures)} FAILED: {_failures}')
    sys.exit(1)
print('ALL engine-regression tests pass.')
