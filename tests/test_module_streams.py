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

print()
if failures:
    print(f'{len(failures)} FAILED: {failures}')
    sys.exit(1)
print('ALL module-stream tests pass.')
