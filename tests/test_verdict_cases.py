#!/usr/bin/env python3
"""Verdict case-matrix tests: rpm, golang, image identity, ocp, operator,
duality (openshift-clients RPM providing the golang `oc` binary), states,
and the OpenVEX publication gate.

Every case first checks the VEX file still has the shape it relies on
(Red Hat refreshes these mirrors) — a changed file prints SKIP instead of a
false failure.  Two real scans drive everything:

  * web-terminal-tooling-rhel9 (operator workload, RHEL9, golang binaries
    virtctl/subctl + OCP client rpm)
  * ose-cli (ocp workload, RHEL8, OCP 4.12)

Run from the repo root.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))
import pandas as pd

from rhacs_vex import openvex, triage

WT_SCAN = ('data/scans/registry.redhat.io_web-terminal_web-terminal-tooling-rhel9'
           '@sha256:d2f32f9d478bbf8f140b7ccbbdb113ddc1c58ccb755ae4dd8dfe7d4d04bbc649.json')
WT_REF = ('registry.redhat.io/web-terminal/web-terminal-tooling-rhel9'
          '@sha256:d2f32f9d478bbf8f140b7ccbbdb113ddc1c58ccb755ae4dd8dfe7d4d04bbc649')
CLI_SCAN = ('data/scans/registry.redhat.io_openshift4_ose-cli'
            '@sha256:4f2e216ad46aa75f84e27aa2e6303327b99a4331c7ed8ef65850102898f3a9b0.json')
CLI_REF = ('registry.redhat.io/openshift4/ose-cli'
           '@sha256:4f2e216ad46aa75f84e27aa2e6303327b99a4331c7ed8ef65850102898f3a9b0')

failures, skips = [], []


def check(name, cond, detail=''):
    print(f'{"PASS" if cond else "FAIL"}  {name}{"  — " + detail if detail else ""}')
    if not cond:
        failures.append(name)


def skip(name, why):
    print(f'SKIP  {name}  — VEX shape changed: {why}')
    skips.append(name)


def vex(cve):
    path = f'data/vex/{cve}.json'
    if not os.path.exists(path):
        triage.download_and_convert_with_lib(cve)
    return json.load(open(path)) if os.path.exists(path) else None


def pids(doc, status):
    out = []
    for v in doc.get('vulnerabilities', []):
        out += v.get('product_status', {}).get(status, [])
    return out


def load(scan_path, ref):
    scan = json.load(open(scan_path))
    labels = (scan.get('metadata') or {}).get('v1', {}).get('labels') or {}
    ctx = triage.parse_context_from_labels(labels, ref)
    return triage.rhacs_to_df(scan), ctx


def rows_for(res, cve, comp):
    return res[(res['CVE'] == cve) & (res['COMPONENT'] == comp)]


print('=== auditing both scans (operator + ocp workloads) ===')
wt_df, wt_ctx = load(WT_SCAN, WT_REF)
check('web-terminal context is operator workload', wt_ctx.workload_type == 'operator')
wt = triage._audit_silent(wt_df, wt_ctx)

cli_df, cli_ctx = load(CLI_SCAN, CLI_REF)
check('ose-cli context is ocp workload', cli_ctx.workload_type == 'ocp')
cli = triage._audit_silent(cli_df, cli_ctx)

# ══ A. RPM path ════════════════════════════════════════════════════════════

print('\n=== A. rpm ===')

# A1 — explicit known_affected, versionless (no fix), state verbatim from VEX
d = vex('CVE-2026-43896')
if 'red_hat_enterprise_linux_9:jq' in pids(d, 'known_affected'):
    r = rows_for(wt, 'CVE-2026-43896', 'jq')
    check('A1 rpm explicit KA (jq, rhel9) → POSITIVE',
          len(r) and all('❌' in v for v in r['AUDIT_RESULT']))
    # expected state = the remediation covering the DECISIVE pid (rhel9:jq),
    # rendered the way the engine renders it (none_available 'defer…' →
    # 'Fix deferred'; no_fix_planned details verbatim) — never another pid's.
    expected = set()
    for v in d['vulnerabilities']:
        for rem in v.get('remediations', []):
            if 'red_hat_enterprise_linux_9:jq' not in rem.get('product_ids', []):
                continue
            det = rem.get('details') or ''
            if rem.get('category') == 'no_fix_planned':
                expected.add(det or 'Will not fix')
            elif rem.get('category') == 'none_available':
                expected.add('Fix deferred' if 'defer' in det.lower() else (det or 'Affected'))
    check('A1 state is the decisive PID\'s own remediation, verbatim',
          len(r) and r.iloc[0]['VEX_STATE'] in expected,
          f"state={r.iloc[0]['VEX_STATE']!r} expected∈{expected}")
else:
    skip('A1', 'rhel9:jq no longer known_affected')

# A2 — fixed NEVRA stream compare: installed < fix → POSITIVE with fix version
d = vex('CVE-2026-5450')
fix_el98 = [p for p in pids(d, 'fixed') if 'glibc' in p and '.el9_8' in p]
if fix_el98:
    r = rows_for(wt, 'CVE-2026-5450', 'glibc-minimal-langpack')
    check('A2 rpm fixed-compare fail (glibc 270 < 272) → POSITIVE',
          len(r) and '❌' in r.iloc[0]['AUDIT_RESULT'])
    check('A2 fix version surfaced from the fixed NEVRA',
          len(r) and '2.34-272.el9_8' in str(r.iloc[0]['VEX_FIX_VER']),
          f"fix={r.iloc[0]['VEX_FIX_VER']!r}")
    # A3 — synthetic: installed == fix → FALSE POSITIVE, statement-backed
    row = pd.Series({'CVE': 'CVE-2026-5450', 'COMPONENT': 'glibc-minimal-langpack',
                     'VERSION': '2.34-272.el9_8', 'SOURCE': 'OS'})
    a = triage.audit_row_detailed(row, wt_ctx)
    check('A3 rpm fixed-compare pass (== fix) → FALSE POSITIVE, stated',
          '✅' in a.iloc[0] and a.iloc[5] is True,
          f'verdict={a.iloc[0]!r} stated={a.iloc[5]!r}')
else:
    skip('A2/A3', 'glibc el9_8 fixed NEVRA gone')

# A4 — truly absent rpm → FALSE POSITIVE not-listed, display-only
d = vex('CVE-2026-35469')
if d and 'openshift-clients' not in json.dumps(d):
    r = rows_for(wt, 'CVE-2026-35469', 'openshift-clients')
    check('A4 rpm not listed (openshift-clients) → FALSE POSITIVE',
          len(r) and '✅' in r.iloc[0]['AUDIT_RESULT'])
    check('A4 not-listed is never publishable (VEX_STATED False)',
          len(r) and str(r.iloc[0]['VEX_STATED']) != 'True')
    check('A4 state "Not affected", never invented states',
          len(r) and r.iloc[0]['VEX_STATE'] == 'Not affected',
          f"state={r.iloc[0]['VEX_STATE']!r}")
else:
    skip('A4', 'openshift-clients now appears in CVE-2026-35469')

# A5 — related-products affected (version-neutral OCP4 KA) → conservative POSITIVE
d = vex('CVE-2026-25679')
if 'red_hat_openshift_container_platform_4:openshift-clients' in pids(d, 'known_affected'):
    r = rows_for(wt, 'CVE-2026-25679', 'openshift-clients')
    check('A5 rpm affected in related product (OCP4 neutral KA) → POSITIVE',
          len(r) and '❌' in r.iloc[0]['AUDIT_RESULT'])
else:
    skip('A5', 'OCP4 version-neutral KA gone from CVE-2026-25679')

# ══ B. golang ════════════════════════════════════════════════════════════════

print('\n=== B. golang ===')

# B1 — go module untracked → FALSE POSITIVE not-listed, unstated
d = vex('CVE-2026-35469')
if d and 'spdystream' not in json.dumps(d):
    r = rows_for(wt, 'CVE-2026-35469', 'github.com/moby/spdystream')
    check('B1 go module not listed (spdystream) → FALSE POSITIVE, unstated',
          len(r) and '✅' in r.iloc[0]['AUDIT_RESULT']
          and str(r.iloc[0]['VEX_STATED']) != 'True')
else:
    skip('B1', 'spdystream now in CVE-2026-35469')

# B2 — vendor catch-all → FALSE POSITIVE, PUBLISHED
d = vex('CVE-2026-39836')
if 'red_hat_products' in [p.strip().lower() for p in pids(d, 'known_not_affected')]:
    r = rows_for(wt, 'CVE-2026-39836', 'stdlib')
    check('B2 go stdlib catch-all → FALSE POSITIVE, stated (publishes)',
          len(r) and all('✅' in v for v in r['AUDIT_RESULT'])
          and all(str(s) == 'True' for s in r['VEX_STATED']))
else:
    skip('B2', 'red_hat_products catch-all gone from CVE-2026-39836')

# B3 — other-build image KNA (digest-pinned, ours absent) → FP but NOT published
d = vex('CVE-2025-61726')
tooling_kna = [p for p in pids(d, 'known_not_affected') if 'web-terminal-tooling' in p]
ours_listed = any('d2f32f9d' in p for p in tooling_kna)
if tooling_kna and not ours_listed:
    r = rows_for(wt, 'CVE-2025-61726', 'stdlib')
    check('B3 other-build digest KNA → FALSE POSITIVE display',
          len(r) and all('✅' in v for v in r['AUDIT_RESULT']))
    check('B3 …but unstated: digest claims are build-exact',
          len(r) and all(str(s) != 'True' for s in r['VEX_STATED']))
else:
    skip('B3', 'tooling KNA digests changed (or our build now listed)')

# B4 — under_investigation in scope → POSITIVE (positive until proven)
d = vex('CVE-2026-39831')
if any(p.startswith('red_hat_enterprise_linux_9:') for p in pids(d, 'under_investigation')):
    r = rows_for(wt, 'CVE-2026-39831', 'golang.org/x/crypto')
    check('B4 go module under_investigation (rhel9) → POSITIVE',
          len(r) and '❌' in r.iloc[0]['AUDIT_RESULT'])
    check('B4 state "Under investigation" from VEX status',
          len(r) and r.iloc[0]['VEX_STATE'] == 'Under investigation',
          f"state={r.iloc[0]['VEX_STATE']!r}")
else:
    skip('B4', 'rhel9 under_investigation gone from CVE-2026-39831')

# ══ C. duality: openshift-clients rpm vs the golang binaries it ships ═══════

print('\n=== C. rpm/golang duality ===')

r_rpm = rows_for(wt, 'CVE-2026-25679', 'openshift-clients')
r_go = rows_for(wt, 'CVE-2026-25679', 'stdlib')
if len(r_rpm) and len(r_go):
    check('C1 same CVE: rpm row POSITIVE (OCP4 KA), go row FALSE POSITIVE (image KNA)',
          '❌' in r_rpm.iloc[0]['AUDIT_RESULT'] and '✅' in r_go.iloc[0]['AUDIT_RESULT'],
          f"rpm={r_rpm.iloc[0]['AUDIT_RESULT']!r} go={r_go.iloc[0]['AUDIT_RESULT']!r}")
    stmts = openvex.statements_from_df(wt, WT_REF)
    check('C1 divergent CVE publishes NO statement (open rpm verdict + unstated go)',
          not any(s['vulnerability']['name'] == 'CVE-2026-25679' for s in stmts))
else:
    skip('C1', 'CVE-2026-25679 rows missing from scan result')

# ══ D. missing VEX ═══════════════════════════════════════════════════════════

print('\n=== D. no VEX file ===')
r = wt[wt['CVE'].str.startswith('GO-')]
if len(r):
    check('D1 non-CVE id (GO-…) has no Red Hat VEX → POSITIVE "VEX file missing"',
          all('❌' in v for v in r['AUDIT_RESULT'])
          and all('missing' in j.lower() for j in r['JUSTIFICATION']))
    check('D1 state Unknown, unstated',
          all(s == 'Unknown' for s in r['VEX_STATE'])
          and all(str(s) != 'True' for s in r['VEX_STATED']))
else:
    skip('D1', 'no GO- advisories in scan')

# ══ E. ocp workload (ose-cli) ════════════════════════════════════════════════

print('\n=== E. ocp workload (ose-cli 4.12 — RHACS go-analyzed the oc binary) ===')
check('E1 ose-cli audit produced rows (all-GO scan handled)', len(cli) > 0,
      f'{len(cli)} rows')

# E2 — image enumerated for NEWER OCP minors only (4.17-4.22 ose-cli KNA
# digests), our 4.12 build absent → not-listed FALSE POSITIVE, display-only.
d = vex('CVE-2026-35469')
cli_kna = [p for p in pids(d, 'known_not_affected') if '/ose-cli' in p]
if cli_kna and not any('4f2e216a' in p for p in cli_kna):
    rr = rows_for(cli, 'CVE-2026-35469', 'github.com/moby/spdystream')
    check('E2 other-minor image KNA does not transfer → FALSE POSITIVE, unstated',
          len(rr) and all('✅' in v for v in rr['AUDIT_RESULT'])
          and all(str(s) != 'True' for s in rr['VEX_STATED']),
          f"just={rr.iloc[0]['JUSTIFICATION'][:50]!r}" if len(rr) else 'no rows')
else:
    skip('E2', 'ose-cli KNA digests changed (or our 4.12 build now listed)')

# E3 — catch-all publishes for the ocp workload too
d = vex('CVE-2026-39824')
if 'red_hat_products' in [p.strip().lower() for p in pids(d, 'known_not_affected')]:
    rr = rows_for(cli, 'CVE-2026-39824', 'golang.org/x/sys')
    check('E3 ocp workload catch-all → FALSE POSITIVE, stated (publishes)',
          len(rr) and all('✅' in v for v in rr['AUDIT_RESULT'])
          and all(str(s) == 'True' for s in rr['VEX_STATED']))
else:
    skip('E3', 'catch-all gone from CVE-2026-39824')

# ══ F. structural invariants (both scans, every row) ═══════════════════════

print('\n=== F. invariants ===')
for name, res, ref in (('web-terminal', wt, WT_REF), ('ose-cli', cli, CLI_REF)):
    verdicts = set(res['AUDIT_RESULT'])
    check(f'F1 {name}: only two verdicts exist',
          verdicts <= {'❌ POSITIVE', '✅ FALSE POSITIVE'}, str(verdicts))
    states = set(res['VEX_STATE'].astype(str))
    check(f'F2 {name}: no invented states (no "Not assessed"/"Not listed")',
          not any('not assessed' in s.lower() or s.lower() == 'not listed' for s in states),
          str(sorted(states)))
    stmts = openvex.statements_from_df(res, ref)
    stated_cves = set(res[(res['AUDIT_RESULT'].str.contains('✅'))
                          & (res['VEX_STATED'].astype(str) == 'True')]['CVE'])
    check(f'F3 {name}: every published statement traces to a stated FP row',
          all(s['vulnerability']['name'] in stated_cves for s in stmts),
          f'{len(stmts)} statements')
    check(f'F4 {name}: statements only not_affected/fixed',
          all(s['status'] in ('not_affected', 'fixed') for s in stmts))
    check(f'F5 {name}: every statement product is our digest-pinned OCI purl',
          all(any(pr.get('@id') == openvex.product_id(ref) for pr in s['products'])
              for s in stmts))

print()
if skips:
    print(f'{len(skips)} skipped (VEX data drifted): {skips}')
if failures:
    print(f'{len(failures)} FAILED: {failures}')
    sys.exit(1)
print('ALL verdict-case tests pass.')
