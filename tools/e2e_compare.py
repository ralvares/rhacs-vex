"""tools/e2e.sh's diff: do the findings vextriage clears disappear under --vex, and only those?

    python3 tools/e2e_compare.py data/scans/NAME

Keys are (CVE, package name, version without epoch). A key cleared at one location and
kept at another (two binaries with the same stdlib) counts as kept: it must survive.
"""
import json
import re
import sys

d = sys.argv[1].rstrip('/')
name = d.split('/')[-1]
CVE = re.compile(r'^CVE-\d{4}-\d+$')


def ver(v):
    return re.sub(r'^\d+:', '', v or '')


def grype(f):
    out = set()
    for m in json.load(open(f))['matches']:
        i = m['vulnerability']['id']
        if not CVE.match(i):
            rel = [r['id'] for r in m.get('relatedVulnerabilities') or [] if CVE.match(r['id'])]
            i = rel[0] if rel else i
        out.add((i, m['artifact']['name'], ver(m['artifact']['version'])))
    return out


def trivy(f):
    return {(v['VulnerabilityID'], v['PkgName'], ver(v['InstalledVersion'])) for r in json.load(open(f)).get('Results') or []
            for v in r.get('Vulnerabilities') or []}


for sc, fn, raw, vexes in (('grype', grype, 'grype.raw.json', (('free', 'grype.vex.json'), ('scan', 'grype.vexg.json'))),
                           ('trivy', trivy, 'trivy.raw.json', (('free', 'trivy.vex.json'), ('scan', 'trivy.vext.json')))):
    before = fn(f'{d}/{raw}')
    rows = json.load(open(f'{d}/{sc}-triage.json'))
    keep = {(r['cve'], r['package'], ver(r['version'])) for r in rows if r['status'] not in ('not_affected', 'fixed')}
    clear = {(r['cve'], r['package'], ver(r['version'])) for r in rows if r['status'] in ('not_affected', 'fixed')} - keep
    keep &= before
    for mode, vex in vexes:
        after = fn(f'{d}/{vex}')
        removed = before - after
        print(f'{name:12} {sc} {mode:4}-openvex: {len(before):5} -> {len(after):5}; clears {len(clear):4}: '
              f'gone {len(clear & removed):4}, left {len(clear & after):4}; kept {len(keep):5}: gone {len(keep & removed)}')
        if mode == 'scan' and clear & after:
            print('     clears left:', sorted(clear & after)[:5])
        if keep & removed:
            print('     KEPT BUT GONE (a wrong clear reached the scanner):', sorted(keep & removed)[:5])
