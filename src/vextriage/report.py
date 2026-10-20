"""The triage table: what is left to act on, and why everything else is not."""
from __future__ import annotations

import csv
import json
import sys

SEV_ORDER = {'critical': 0, 'important': 1, 'high': 1, 'moderate': 2, 'medium': 2, 'low': 3}
COLUMNS = ['cve', 'severity', 'package', 'version', 'kind', 'status', 'stated', 'fix', 'plan', 'reason',
           'product', 'rule', 'scanner', 'scanner_fix', 'location', 'purl']


def records(rows) -> list:
    out = []
    for r in rows:
        f, v, p = r.finding, r.verdict, r.finding.package
        out.append({'cve': f.cve, 'severity': v.severity or f.severity, 'package': p.name,
                    'version': (f'{p.epoch}:' if p.epoch else '') + p.version, 'kind': p.kind,
                    'status': v.status, 'stated': v.stated, 'fix': v.fix, 'plan': v.plan, 'reason': v.reason,
                    'product': v.product, 'rule': v.rule, 'scanner': f.scanner, 'scanner_fix': f.fixed_in,
                    'location': p.locations[0] if p.locations else '', 'purl': p.purl,
                    'evidence': list(v.evidence)})
    out.sort(key=lambda d: (d['status'] not in ('affected', 'under_investigation'),
                            SEV_ORDER.get((d['severity'] or '').lower(), 4), d['cve'], d['package']))
    return out


def write_json(recs, fh):
    json.dump(recs, fh, indent=1)
    fh.write('\n')


def write_csv(recs, fh):
    w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction='ignore')
    w.writeheader()
    w.writerows(recs)


def summary(recs) -> dict:
    pos = [r for r in recs if r['status'] in ('affected', 'under_investigation')]
    return {'findings': len(recs), 'positive': len(pos), 'cleared': len(recs) - len(pos),
            'cleared_stated': sum(1 for r in recs if r['status'] not in ('affected', 'under_investigation')
                                  and r['stated']),
            'cves_positive': len({r['cve'] for r in pos})}


def print_table(recs, scope, image, show_all: bool = False, fh=None):
    fh = fh or sys.stdout
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:                                  # plain text
        for r in recs:
            if show_all or r['status'] in ('affected', 'under_investigation'):
                fh.write(f"{r['cve']:16} {r['severity'] or '-':10} {r['package']} {r['version']}  "
                         f"{r['status']}  {r['reason']}\n")
        return
    con = Console(file=fh, width=200 if not fh.isatty() else None)
    s = summary(recs)
    con.print(f"[bold]{image.ref or image.name_label or 'image'}[/bold]  "
              f"RHEL {scope.rhel or '?'}.{scope.minor if scope.minor is not None else '?'}  "
              f"product: {', '.join(sorted(scope.keys)) or ('RHEL' if scope.rhel_image else '-')} "
              f"{scope.version}  red hat image: {'yes' if image.red_hat else 'no'}")
    t = Table(show_lines=False, header_style='bold')
    for c in ('CVE', 'Severity', 'Package', 'Version', 'Status', 'Fix', 'Why'):
        t.add_column(c, overflow='fold')
    for r in recs:
        if not show_all and r['status'] not in ('affected', 'under_investigation'):
            continue
        style = {'affected': 'red', 'under_investigation': 'yellow'}.get(r['status'], 'green')
        status = r['status'].replace('_', ' ') + ('' if r['stated'] else ' *')
        t.add_row(r['cve'], r['severity'] or '-', r['package'], r['version'], f'[{style}]{status}[/{style}]',
                  r['fix'] or r['plan'] or '', r['reason'])
    con.print(t)
    con.print(f"{s['findings']} findings: [red]{s['positive']} to act on[/red] ({s['cves_positive']} CVEs), "
              f"[green]{s['cleared']} cleared[/green] ({s['cleared_stated']} stated by Red Hat, the rest inferred "
              f"from Red Hat's data).  * = inferred")
