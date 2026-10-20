#!/usr/bin/env python3
"""Module-stream guard tests (VEX-MODEL §6d + §9.1a hardening).

Red Hat modular RPMs (el8 perl/nodejs/postgresql streams) publish PIDs like
`AppStream-8.10.0.GA:perl-libs-4:5.32.1-473.module+el8...::perl:5.32`.
Scanners normally report the matching `.module+` release, but the marker can
be normalized away — the engine must still find the statement instead of
falling through to a not-listed FALSE POSITIVE.  Run from the repo root.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))
import pandas as pd

from rhacs_vex import engine
from rhacs_vex.core.versions import module_stream_applies as _module_stream_compatible
from rhacs_vex.engine import audit_row_detailed, parse_image_ref

MOD_PID = 'AppStream-8.10.0.GA:perl-libs-4:5.32.1-473.module+el8.10.0+21354+3ad137bb.x86_64::perl:5.32'

failures = []


def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'{status}  {name}{"  — " + detail if detail else ""}')
    if not cond:
        failures.append(name)


# --- unit: _module_stream_compatible ------------------------------------------

# marker present → compatible (pre-existing behavior)
check('marker: module release matches module PID',
      _module_stream_compatible(MOD_PID, '4:5.32.1-472.module+el8.10.0+21354+3ad137bb'))
# §9.1a: marker stripped, same stream + same el-major → compatible now
check('stripped marker, stream 5.32, el8 install',
      _module_stream_compatible(MOD_PID, '4:5.32.1-472.el8_10'))
# wrong stream → incompatible
check('stripped marker, wrong stream (5.26 install)',
      not _module_stream_compatible(MOD_PID, '4:5.26.3-422.el8'))
# wrong RHEL major → incompatible
check('stripped marker, el9 install vs el8 module PID',
      not _module_stream_compatible(MOD_PID, '4:5.32.1-472.el9'))
# non-numeric stream, no marker → incompatible (nothing to verify)
check('non-numeric stream (container-tools:rhel8)',
      not _module_stream_compatible(
          'AppStream-8.10.0.GA:podman-2:4.4.1-1.module+el8.10.0+1.x86_64::container-tools:rhel8',
          '2:4.4.1-1.el8'))
# non-module PID always applies
check('non-module PID unaffected',
      _module_stream_compatible('AppStream-9.4.0.GA:perl-4:5.32.1-481.el9.x86_64',
                                '4:5.32.1-480.el9'))

# --- end-to-end: synthetic §9.1a row through the real engine -------------------

# CVE-2023-47038 in miniature: the el8 perl:5.32 module build fixed at 473.
_MOD_LEAF = 'perl-libs-4:5.32.1-473.module+el8.10.0+21354+3ad137bb.x86_64::perl:5.32'
_DOC = {
    'product_tree': {
        'branches': [{'branches': [
            {'product': {'product_id': 'AppStream-8.10.0.GA',
                         'name': 'Red Hat Enterprise Linux AppStream (v. 8)',
                         'product_identification_helper': {
                             'cpe': 'cpe:/a:redhat:enterprise_linux:8::appstream'}}},
            {'product': {'product_id': _MOD_LEAF,
                         'product_identification_helper': {'purl':
                             'pkg:rpm/redhat/perl-libs@5.32.1-473.module%2Bel8.10.0%2B21354'
                             '%2B3ad137bb?arch=x86_64&epoch=4&rpmmod=perl:5.32'}}}]}],
        'relationships': [{'product_reference': _MOD_LEAF,
                           'relates_to_product_reference': 'AppStream-8.10.0.GA',
                           'full_product_name': {'product_id': MOD_PID}}],
    },
    'vulnerabilities': [{'product_status': {'fixed': [MOD_PID]}}],
}
engine._load_vex = lambda _cve: _DOC
ctx = parse_image_ref('registry.access.redhat.com/ubi8/ubi@sha256:' + '0' * 64)
ctx.rhel_ver = '8'

row = pd.Series({'CVE': 'CVE-2023-47038', 'COMPONENT': 'perl-libs',
                 'VERSION': '4:5.32.1-472.el8_10', 'SOURCE': 'OS'})
r = audit_row_detailed(row, ctx)
check('synthetic perl-libs 472 (< fix 473, marker stripped) → POSITIVE',
      'POSITIVE' in r.iloc[0] and 'FALSE' not in r.iloc[0],
      f'verdict={r.iloc[0]!r} note={r.iloc[2]!r}')
check('  …decided by version compare, not not-listed',
      'not listed' not in str(r.iloc[2]).lower(), f'note={r.iloc[2]!r}')

# equal release with the marker stripped cannot PROVE it is the fixed module
# build ('473.el8_10' vs '473.module+el8…' diverge after the shared 473) —
# conservative POSITIVE is the correct direction (positive until proven).
row_equal = pd.Series({'CVE': 'CVE-2023-47038', 'COMPONENT': 'perl-libs',
                       'VERSION': '4:5.32.1-473.el8_10', 'SOURCE': 'OS'})
r2 = audit_row_detailed(row_equal, ctx)
check('synthetic perl-libs 473 (== fix, marker stripped) → conservative POSITIVE',
      'POSITIVE' in r2.iloc[0] and 'FALSE' not in r2.iloc[0],
      f'verdict={r2.iloc[0]!r} note={r2.iloc[2]!r}')

row_newer = pd.Series({'CVE': 'CVE-2023-47038', 'COMPONENT': 'perl-libs',
                       'VERSION': '4:5.32.1-474.el8_10', 'SOURCE': 'OS'})
r3 = audit_row_detailed(row_newer, ctx)
check('synthetic perl-libs 474 (> fix 473, marker stripped) → FALSE POSITIVE',
      'FALSE POSITIVE' in r3.iloc[0], f'verdict={r3.iloc[0]!r} note={r3.iloc[2]!r}')

# --- the SBOM's modularityLabel decides streams (syft rows carry MODULE) -------

def _csaf(entries, parents):
    """A CSAF document from [(status, parent, leaf, purl)] and {parent: (name, cpe)}."""
    leaves, rels, status = [], [], {}
    branches = [{'product': {'product_id': pid, 'name': name,
                             'product_identification_helper': {'cpe': cpe}}}
                for pid, (name, cpe) in parents.items()]
    for st, parent, leaf, purl in entries:
        if leaf not in leaves:
            leaves.append(leaf)
            branches.append({'product': {'product_id': leaf, 'product_identification_helper':
                                         ({'purl': purl} if purl else {})}})
        full = f'{parent}:{leaf}'
        rels.append({'product_reference': leaf, 'relates_to_product_reference': parent,
                     'full_product_name': {'product_id': full}})
        status.setdefault(st, []).append(full)
    return {'product_tree': {'branches': [{'branches': branches}], 'relationships': rels},
            'vulnerabilities': [{'product_status': status}]}


_P8 = {'AppStream-8.4.0.Z.AUS': ('Red Hat Enterprise Linux AppStream AUS (v.8.4)',
                                 'cpe:/a:redhat:rhel_aus:8.4::appstream'),
       'AppStream-8.10.0.Z.MAIN.EUS': ('Red Hat Enterprise Linux AppStream (v. 8)',
                                       'cpe:/a:redhat:enterprise_linux:8::appstream'),
       'BaseOS-8.9.0.Z.MAIN': ('Red Hat Enterprise Linux BaseOS (v. 8)',
                               'cpe:/o:redhat:enterprise_linux:8::baseos'),
       'BaseOS-8.3.0.GA': ('Red Hat Enterprise Linux BaseOS (v. 8)',
                           'cpe:/o:redhat:enterprise_linux:8::baseos'),
       'red_hat_enterprise_linux_8': ('Red Hat Enterprise Linux 8',
                                      'cpe:/o:redhat:enterprise_linux:8'),
       'red_hat_enterprise_linux_9': ('Red Hat Enterprise Linux 9',
                                      'cpe:/o:redhat:enterprise_linux:9')}


def _verdict(doc, comp, version, module, rhel='8', minor=None, srpm=''):
    engine._load_vex = lambda _cve: doc
    c = parse_image_ref('registry.access.redhat.com/ubi%s/ubi@sha256:' % rhel + '0' * 64)
    c.rhel_ver, c.rhel_minor = rhel, minor
    r = audit_row_detailed(pd.Series({'CVE': 'CVE-2023-0001', 'COMPONENT': comp,
                                      'VERSION': version, 'SOURCE': 'OS', 'SRPM': srpm,
                                      'MODULE': module}), c)
    return r.iloc[0], r.iloc[1], r.iloc[2]


# python3-ply 3.9 (non-modular, src python-ply) must not take the python39:3.9
# module's fix through the shared source name (CVE-2023-24329, ose-cli el8).
_ply = _csaf([('fixed', 'AppStream-8.4.0.Z.AUS',
               'python-ply-0:3.11-10.module+el8.4.0+9822+20bf1249.src::python39:3.9',
               'pkg:rpm/redhat/python-ply@3.11-10.module%2Bel8.4.0%2B9822%2B20bf1249?arch=src'
               '&rpmmod=python39:3.9')], _P8)
v, fix, note = _verdict(_ply, 'python3-ply', '3.9-9.el8', 'non-modular', srpm='python-ply')
check('S1 non-modular rpm ignores a module stream fix (not listed)',
      'FALSE' in v and fix == 'N/A', f'{v} {fix} {note}')

# nodejs:20 never takes the nodejs:18 fix; it takes its own stream's.
_node = _csaf([('fixed', 'AppStream-8.10.0.Z.MAIN.EUS',
                'nodejs-1:18.20.4-1.module+el8.10.0+22199+56ea0ead.x86_64::nodejs:18',
                'pkg:rpm/redhat/nodejs@18.20.4-1.module%2Bel8.10.0%2B22199%2B56ea0ead'
                '?arch=x86_64&epoch=1&rpmmod=nodejs:18'),
               ('fixed', 'AppStream-8.10.0.Z.MAIN.EUS',
                'nodejs-1:20.18.2-1.module+el8.10.0+22767+a3309b10.x86_64::nodejs:20',
                'pkg:rpm/redhat/nodejs@20.18.2-1.module%2Bel8.10.0%2B22767%2Ba3309b10'
                '?arch=x86_64&epoch=1&rpmmod=nodejs:20')], _P8)
v, fix, note = _verdict(_node, 'nodejs', '1:20.11.1-1.module+el8.9.0+21380+12032667', 'nodejs:20',
                        minor='10')
check('S2 nodejs:20 takes the nodejs:20 fix, never nodejs:18\'s',
      'POSITIVE' in v and 'FALSE' not in v and '20.18.2-' in fix, f'{v} {fix}')

# a version-less statement scoped to a stream is about that stream only
_ka14 = _csaf([('known_affected', 'red_hat_enterprise_linux_8', 'nodejs::nodejs:14', '')], _P8)
v, fix, note = _verdict(_ka14, 'nodejs', '1:20.11.1-1.module+el8.9.0+21380+12032667', 'nodejs:20')
check('S3 known_affected for nodejs:14 does not touch nodejs:20', 'FALSE' in v, f'{v} {note}')

# postgresql:12 known_affected while postgresql:13 is not affected → POSITIVE
_pg = _csaf([('known_affected', 'red_hat_enterprise_linux_8', 'pgaudit::postgresql:12', ''),
             ('known_not_affected', 'red_hat_enterprise_linux_8', 'pgaudit::postgresql:13', '')],
            _P8)
v, fix, note = _verdict(_pg, 'pgaudit', '1.4.0-6.module+el8.4.0+11288+c193d6d7', 'postgresql:12')
check('S4 another stream\'s not-affected does not clear postgresql:12',
      'POSITIVE' in v and 'FALSE' not in v, f'{v} {note}')

# a statement without a stream is about the package in every stream, as written
# (RHEL 8 has no non-modular nodejs: `red_hat_enterprise_linux_8:nodejs`
# known_affected next to nodejs:22 / nodejs:24 fixes covers nodejs:20)
_n8 = _csaf([('known_affected', 'red_hat_enterprise_linux_8', 'nodejs', ''),
             ('fixed', 'AppStream-8.10.0.Z.MAIN.EUS',
              'nodejs-1:22.23.1-1.module+el8.10.0+24500+8eb51621.x86_64::nodejs:22',
              'pkg:rpm/redhat/nodejs@22.23.1-1.module%2Bel8.10.0%2B24500%2B8eb51621'
              '?arch=x86_64&epoch=1&rpmmod=nodejs:22')], _P8)
v, fix, note = _verdict(_n8, 'nodejs', '1:20.11.1-1.module+el8.9.0+21380+12032667', 'nodejs:20',
                        minor='10')
check('S5 stream-less known_affected covers nodejs:20; nodejs:22\'s fix does not',
      'POSITIVE' in v and 'FALSE' not in v and fix == 'N/A', f'{v} {fix} {note}')

# the exact installed build listed fixed is fixed, whichever stream shipped it
_pga = _csaf([('fixed', 'AppStream-8.4.0.Z.AUS',
               'pgaudit-0:1.4.0-6.module+el8.4.0+11288+c193d6d7.x86_64::postgresql:12',
               'pkg:rpm/redhat/pgaudit@1.4.0-6.module%2Bel8.4.0%2B11288%2Bc193d6d7'
               '?arch=x86_64&rpmmod=postgresql:12'),
              ('fixed', 'AppStream-8.10.0.Z.MAIN.EUS',
               'pgaudit-0:1.4.0-7.module+el8.10.0+22214+9beb89d6.x86_64::postgresql:12',
               'pkg:rpm/redhat/pgaudit@1.4.0-7.module%2Bel8.10.0%2B22214%2B9beb89d6'
               '?arch=x86_64&rpmmod=postgresql:12')], _P8)
v, fix, note = _verdict(_pga, 'pgaudit', '1.4.0-6.module+el8.4.0+11288+c193d6d7', 'postgresql:12',
                        minor='7')
check('S9 the installed build is itself a fixed build → FALSE POSITIVE',
      'FALSE' in v and 'fixed build' in note, f'{v} {note}')

# side-stream backports never clear a mainline build while RHEL 8 is affected
_sd = _csaf([('known_affected', 'red_hat_enterprise_linux_8', 'systemd-libs', ''),
             ('fixed', 'AppStream-8.4.0.Z.AUS', 'systemd-libs-0:239-45.el8_4.17.x86_64',
              'pkg:rpm/redhat/systemd-libs@239-45.el8_4.17?arch=x86_64'),
             ('fixed', 'AppStream-8.4.0.Z.AUS', 'systemd-libs-0:239-74.el8_8.7.x86_64',
              'pkg:rpm/redhat/systemd-libs@239-74.el8_8.7?arch=x86_64')], _P8)
v, fix, note = _verdict(_sd, 'systemd-libs', '239-78.el8', 'non-modular', minor='10')
check('S10 a GA build newer than every side-stream backport stays POSITIVE when the '
      'line is affected', 'POSITIVE' in v and 'FALSE' not in v, f'{v} {note}')

# a GA build listed as the fix of the image's own minor
_gmp = _csaf([('fixed', 'BaseOS-8.3.0.GA', 'gmp-1:6.1.2-11.el8.x86_64',
               'pkg:rpm/redhat/gmp@6.1.2-11.el8?arch=x86_64&epoch=1'),
              ('fixed', 'AppStream-8.4.0.Z.AUS', 'gmp-1:6.1.2-11.el8_6.1.x86_64',
               'pkg:rpm/redhat/gmp@6.1.2-11.el8_6.1?arch=x86_64&epoch=1')], _P8)
v, fix, note = _verdict(_gmp, 'gmp', '1:6.1.2-12.el8', 'non-modular', minor='10')
check('S11 a GA build is held to its lineage\'s fix, not to an EUS backport',
      'FALSE' in v, f'{v} {note}')

# mainline fixes are inherited by later minors (the build keeps its dist tag)
_ossl = _csaf([('fixed', 'BaseOS-8.9.0.Z.MAIN', 'openssl-1:1.1.1k-12.el8_9.x86_64',
                'pkg:rpm/redhat/openssl@1.1.1k-12.el8_9?arch=x86_64&epoch=1')], _P8)
v, fix, note = _verdict(_ossl, 'openssl', '1:1.1.1k-14.el8_6', 'non-modular', minor='10')
check('S6 8.10 image inherits the 8.9 mainline fix (1.1.1k-14.el8_6 >= -12.el8_9)',
      'FALSE' in v and 'inherits' in note, f'{v} {note}')
v, fix, note = _verdict(_ossl, 'openssl', '1:1.1.1k-10.el8_6', 'non-modular', minor='10')
check('S7 …and stays POSITIVE below it', 'POSITIVE' in v and 'FALSE' not in v, f'{v} {note}')
_sysd = _csaf([('fixed', 'BaseOS-8.3.0.GA', 'systemd-0:239-40.el8.x86_64',
                'pkg:rpm/redhat/systemd@239-40.el8?arch=x86_64')], _P8)
v, fix, note = _verdict(_sysd, 'systemd', '239-58.el8_6.9', 'non-modular', minor='6')
check('S8 a GA build of an earlier minor is inherited too', 'FALSE' in v, f'{v} {note}')

# CVE-2026-6473 shape: a stream-less "not affected" for RHEL 8 beside a fix for postgresql:12.
_pg = _csaf([('known_not_affected', 'red_hat_enterprise_linux_8', 'postgresql', 'pkg:rpm/redhat/postgresql'),
             ('fixed', 'AppStream-8.10.0.Z.MAIN.EUS',
              'postgresql-0:12.22-7.module+el8.10.0+24362+fcf88eed.x86_64::postgresql:12',
              'pkg:rpm/redhat/postgresql@12.22-7.module%2Bel8.10.0%2B24362%2Bfcf88eed?arch=x86_64'
              '&rpmmod=postgresql:12')], _P8)
v, fix, note = _verdict(_pg, 'postgresql', '12.12-1.module+el8.6.0+16796+0abe6678', 'postgresql:12', minor='7')
check('S9 our stream\'s own statements outrank a stream-less not-affected', 'POSITIVE' in v
      and 'FALSE' not in v, f'{v} {note}')

print()
if failures:
    print(f'{len(failures)} FAILED: {failures}')
    sys.exit(1)
print('ALL module-stream tests pass.')
