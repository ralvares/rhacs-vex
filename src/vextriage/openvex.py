"""Verdicts → an OpenVEX document grype (`--vex`) and trivy (`--vex`) apply.

Matching, as both scanners implement it (go-vex `Component.Matches` /
`PurlMatches`): a product or subcomponent purl without qualifiers matches the
scanner's purl with any qualifiers, and a version must be equal. So:

  product        pkg:oci/<name>@sha256:<digest>   one per digest the image has
                 + the digest as a sha-256 hash   (grype also matches the bare digest)
  subcomponent   pkg:<type>/<ns>/<name>@<version>  the package's purl, qualifiers dropped
                 (Go purls also lowercased: trivy lowercases the module path)
"""
from __future__ import annotations

import hashlib
import json
import time

from . import __version__
from . import purl as purls
from .model import Image, Package

CONTEXT = 'https://openvex.dev/ns/v0.2.0'
STATUSES = ('not_affected', 'affected', 'fixed', 'under_investigation')


def products(image: Image) -> list:
    name = (image.repo or image.name_label or 'image').rsplit('/', 1)[-1]
    out = []
    for d in sorted(image.digests):
        out.append({'@id': purls.build('oci', '', name, f'sha256:{d}'), 'hashes': {'sha-256': d}})
    if not out:
        out.append({'@id': purls.build('oci', '', name, image.labels.get('version', '') or '')})
    return out


def subcomponents(p: Package) -> list:
    """The package's purl without qualifiers (plus trivy's lowercase Go form)."""
    if p.kind == 'image':
        return []
    q = purls.parse(p.purl)
    if not q.type:
        return []
    ids = [purls.build(q.type, q.namespace, q.name, q.version)]
    if q.type == 'golang':
        low = purls.build(q.type, q.namespace.lower(), q.name.lower(), q.version)
        if low not in ids:
            ids.append(low)
    return [{'@id': i} for i in ids]


def statement(image: Image, cve: str, p: Package, v) -> dict:
    prods = products(image)
    subs = subcomponents(p)
    if subs:
        prods = [dict(pr, subcomponents=subs) for pr in prods]
    st = {'vulnerability': {'name': cve}, 'products': prods, 'status': v.status}
    who = 'Red Hat' if v.stated else 'Red Hat (inferred)'
    if v.status == 'not_affected':
        if v.justification:
            st['justification'] = v.justification
        st['impact_statement'] = f'{who}: {v.reason}'
    elif v.status == 'affected':
        if v.fix:
            st['action_statement'] = f'Update {p.name} to {v.fix} or later. {who}: {v.reason}'
        elif v.plan:
            st['action_statement'] = f'{v.plan}. {who}: {v.reason}'
        else:
            st['action_statement'] = f'No fix available from Red Hat. {who}: {v.reason}'
    else:
        st['status_notes'] = f'{who}: {v.reason}'
    return st


def document(image: Image, rows, stated_only: bool = False, statuses=STATUSES) -> dict:
    """rows: iterable of (cve, package, verdict). Inferred verdicts are dropped
    with stated_only."""
    stmts, seen = [], set()
    for cve, p, v in rows:
        if v.status not in statuses or (stated_only and not v.stated):
            continue
        key = (cve, p.kind, p.name, p.version, v.status)
        if key in seen:
            continue
        seen.add(key)
        stmts.append(statement(image, cve, p, v))
    stmts.sort(key=lambda s: (s['vulnerability']['name'], s['status'],
                              s['products'][0].get('subcomponents', [{}])[0].get('@id', '')))
    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    body = json.dumps(stmts, sort_keys=True).encode()
    return {'@context': CONTEXT,
            '@id': f'https://openvex.dev/docs/vextriage/{hashlib.sha256(body).hexdigest()[:32]}',
            'author': 'vextriage (from Red Hat CSAF-VEX)', 'role': 'Document Creator',
            'timestamp': now, 'version': 1, 'tooling': f'vextriage {__version__}', 'statements': stmts}
