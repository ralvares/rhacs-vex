"""One Red Hat CSAF-VEX document as flat statements: status × product × component.

Every status reference in Red Hat's VEX links a product node (name + CPE) to a
component node whose purl is its identity (99.8% of 4.95M references in the
mirror; the rest are product nodes listed bare).  So a statement here is

    status   fixed | known_affected | known_not_affected | under_investigation
    product  what the statement is about (RHEL stream, OpenShift version,
             layered product version) — Product
    component  the purl, parsed: rpm name/version/arch/module, an image's
               repository/digest/tag, a maven/npm/golang/pypi package

and every rule of the engine is a filter over these.  No PID string grammar is
needed except for the few components that carry no purl.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import unquote

from . import versions as V

STATUSES = ('fixed', 'known_affected', 'known_not_affected', 'under_investigation')
OPEN = ('known_affected', 'under_investigation')

# CPE product tokens of Red Hat Enterprise Linux itself (not RHEL AI, not add-ons)
_RHEL_CPE = re.compile(r'^cpe:/[ao]:redhat:(enterprise_linux|rhel_(?:eus|aus|tus|e4s|els|ens|e\d+s)):')
_SIDE = re.compile(r'(?:^|[.-])(EUS|AUS|TUS|E4S|ENS|ELS|EXTENSION)(?:[.-]|$)')


def _mainline(stream: str) -> bool:
    """GA, Z, Z.MAIN, Z.MAIN.EUS (the mainline of an EUS-eligible minor) are
    mainline; EUS / AUS / TUS / E4S / ENS / ELS are side branches."""
    return 'MAIN' in stream or not _SIDE.search(stream)


@dataclass(frozen=True)
class Product:
    """The product a statement is about.

    family   'rhel' | 'ocp' | 'layered' | 'vendor'
    major    the RHEL major it is built on ('9'), when known
    minor    a RHEL minor stream (rhel only; None = the version-neutral line)
    mainline a RHEL GA / Z.MAIN / line product (False = EUS/AUS/E4S/TUS/ELS side branch)
    version  OpenShift '4.20' / layered '1.15' ('' = every version of the product)
    key      the CPE product ('openshift', 'webterminal', 'enterprise_linux', …)
    """
    id: str
    name: str
    cpe: str
    family: str
    major: str = ''
    minor: Optional[int] = None
    mainline: bool = True
    version: str = ''
    key: str = ''


def classify(pid: str, name: str, cpe: str) -> Product:
    parts = cpe.replace('cpe:/', '').split(':') if cpe else []
    key = parts[2] if len(parts) > 2 else ''
    cver = parts[3] if len(parts) > 3 else ''
    el = re.search(r'el(\d+)', cpe.split(':')[-1] if cpe else '')
    if pid == 'red_hat_products' or (cpe and len([p for p in parts if p]) <= 2):
        return Product(pid, name, cpe, 'vendor')
    m = re.fullmatch(r'red_hat_enterprise_linux_(\d+)', pid)
    if m:
        return Product(pid, name, cpe, 'rhel', major=m.group(1), key='enterprise_linux')
    if _RHEL_CPE.match(cpe or ''):
        m = re.match(r'^[A-Za-z]+-(\d+)\.(\d+)(?:\.\d+)?\.(.+)$', pid)       # BaseOS-9.4.0.Z.EUS
        if m:
            return Product(pid, name, cpe, 'rhel', major=m.group(1), minor=int(m.group(2)),
                           mainline=_mainline(m.group(3)), key=key)
        m = re.match(r'^(\d+)[A-Za-z]+(?:-[a-z]+)?-(\d+)\.(\d+)', pid)       # 7Server-7.9.Z
        if m:
            return Product(pid, name, cpe, 'rhel', major=m.group(1), minor=int(m.group(3)),
                           mainline=_mainline(pid), key=key)
        major = cver.split('.')[0] if cver else ''
        return Product(pid, name, cpe, 'rhel', major=major,
                       mainline=_mainline(pid) and not key.startswith('rhel_'), key=key)
    if key == 'openshift' or re.match(r'^\d+Base-RHOSE-\d+\.\d+', pid):
        m = re.search(r'RHOSE-(\d+\.\d+)', pid)
        ver = m.group(1) if m else cver
        major = (el.group(1) if el else '') or (re.match(r'^(\d+)Base', pid).group(1)
                                                if re.match(r'^(\d+)Base', pid) else '')
        return Product(pid, name, cpe, 'ocp', major=major,
                       version='' if ver in ('', '4') else ver, key='openshift')
    return Product(pid, name, cpe, 'layered', major=el.group(1) if el else '',
                   version=cver, key=key)


@dataclass(frozen=True)
class Statement:
    status: str
    product: Product
    pid: str
    kind: str            # rpm | oci | maven | npm | golang | pypi | generic | … | none | product
    name: str            # rpm/package name; image: namespace/name path
    version: str = ''    # rpm '[E:]V-R'; maven/npm/… version; '' = version-less
    arch: str = ''
    module: str = ''     # rpm module stream 'nodejs:20'
    digest: str = ''     # image build
    tag: str = ''
    repo: str = ''       # image repository_url (registry/namespace/name)
    flag: str = ''       # not-affected justification
    plan: str = ''       # remediation: no_fix_planned | none_available | vendor_fix | …
    plan_detail: str = ''
    severity: str = ''

    @property
    def image_keys(self) -> frozenset:
        """The namespace/name path(s) this image statement is about.

        The component's product id names the image (`openshift4/ose-cli-rhel9@
        sha256:…`); its purl is a second opinion that disagrees on 22% of image
        references — usually a Brew component name, sometimes another image
        outright (`fluentd-rhel9` stamped with the rhel8 purl).  So the product
        id decides when it carries a namespace, the purl otherwise (`rhcos@…`).
        """
        if self.kind not in ('oci', 'none') or not self.name:
            return frozenset()
        comp = self.pid[len(self.product.id) + 1:] if self.pid.startswith(self.product.id + ':') else ''
        parts = re.sub(r'@.*$', '', comp).split('/')
        if parts and '.' in parts[0] and len(parts) > 2:
            parts = parts[1:]                       # registry.redhat.io/ns/name
        if len(parts) >= 2 and all(parts):
            return frozenset({'/'.join(parts).lower()})
        keys = {self.name}
        if self.repo:
            path = self.repo.split('/', 1)[1] if '/' in self.repo else self.repo
            last = self.name.split('/')[-1]
            keys.add(path if path.endswith('/' + last) or path == last else f'{path}/{last}')
        return frozenset(k.lower() for k in keys if k)

    @property
    def stamp(self) -> Optional[int]:
        return V.build_stamp(self.tag) if self.tag else None


def _component(purl: str, comp_pid: str):
    """(kind, name, version, arch, module, digest, tag, repo) of a component."""
    if not purl:
        name, _sep, rest = comp_pid.partition('::')
        name = re.sub(r'@sha256:.*$', '', name)
        nm = re.match(r'^(.*?)-(\d+):(.+?)(?:\.(?:x86_64|aarch64|ppc64le|s390x|i686|noarch|src))?$', name)
        if nm:
            return 'none', nm.group(1), nm.group(2) + ':' + nm.group(3), '', rest, '', '', ''
        return ('none', re.sub(r'\.src$', '', name), '', '', ':'.join(rest.split(':')[:2]),
                (re.search(r'sha256:([0-9a-f]{64})', comp_pid) or [None, ''])[1], '', '')
    body, _, query = purl.partition('?')
    q = {k: unquote(v) for k, v in (kv.split('=', 1) for kv in query.split('&') if '=' in kv)}
    kind = body[4:].split('/')[0]
    path, _, ver = unquote(body[len('pkg:') + len(kind) + 1:]).partition('@')
    if kind == 'rpm':
        name = path.split('/', 1)[1] if '/' in path else path
        if ver and q.get('epoch') and q['epoch'] != '0':
            ver = f"{q['epoch']}:{ver}"
        module = ':'.join(q.get('rpmmod', '').split(':')[:2])
        return 'rpm', name, ver, q.get('arch', ''), module, '', '', ''
    if kind == 'oci':
        dg = re.search(r'sha256:([0-9a-f]{64})', ver)
        return 'oci', path, '', q.get('arch', ''), '', dg.group(1) if dg else '', q.get('tag', ''), \
            q.get('repository_url', '').rstrip('/')
    if kind == 'maven':
        group, _, artifact = path.rpartition('/')
        return 'maven', f'{group.replace("/", ".")}:{artifact}' if group else artifact, ver, '', '', '', '', ''
    return kind, path, ver, q.get('arch', ''), '', '', '', ''


class Document:
    """The statements of one CSAF-VEX file, plus document-level facts."""

    def __init__(self, data: dict):
        tree = data.get('product_tree') or {}
        node: Dict[str, tuple] = {}

        def walk(branches):
            for b in branches or []:
                p = b.get('product')
                if p and p.get('product_id'):
                    h = p.get('product_identification_helper') or {}
                    node[p['product_id']] = (p.get('name', ''), h.get('purl', ''), h.get('cpe', ''))
                walk(b.get('branches'))
        walk(tree.get('branches'))
        rel = {r['full_product_name']['product_id']:
               (r.get('relates_to_product_reference', ''), r.get('product_reference', ''))
               for r in tree.get('relationships') or [] if r.get('full_product_name')}
        products: Dict[str, Product] = {}

        def product(pid):
            if pid not in products:
                name, _p, cpe = node.get(pid, ('', '', ''))
                products[pid] = classify(pid, name, cpe)
            return products[pid]

        self.statements: List[Statement] = []
        self.aggregate_severity = ''
        agg = ((data.get('document') or {}).get('aggregate_severity') or {}).get('text', '')
        if agg.strip().lower() not in ('', 'none'):
            self.aggregate_severity = agg.title()
        self.cvss_severity = ''
        for v in data.get('vulnerabilities') or []:
            status = {}
            for st in STATUSES:
                for pid in (v.get('product_status') or {}).get(st, []):
                    status[pid] = st
            flag = {}
            for f in v.get('flags') or []:
                for pid in f.get('product_ids') or []:
                    flag[pid] = f.get('label', '')
                    status.setdefault(pid, 'known_not_affected')
            plan = {}
            for r in v.get('remediations') or []:
                for pid in r.get('product_ids') or []:
                    plan.setdefault(pid, (r.get('category', ''), (r.get('details') or '').strip()))
            sev = {}
            for t in v.get('threats') or []:
                if t.get('category') == 'impact' and t.get('details'):
                    for pid in t.get('product_ids') or []:
                        sev[pid] = t['details'].title()
            if not self.cvss_severity:
                for sc in v.get('scores') or []:
                    base = (sc.get('cvss_v3') or sc.get('cvss_v2') or {}).get('baseSeverity', '')
                    if base:
                        self.cvss_severity = {'CRITICAL': 'Critical', 'HIGH': 'Important',
                                              'MEDIUM': 'Moderate', 'LOW': 'Low'}.get(base.upper(), '')
                        break
            for pid, st in status.items():
                if pid in rel:
                    parent, comp = rel[pid]
                    purl = node.get(comp, ('', '', ''))[1]
                    kind, name, ver, arch, mod, dg, tag, repo = _component(purl, comp)
                elif pid in node:                       # a product listed bare
                    parent, kind, name, ver, arch, mod, dg, tag, repo = pid, 'product', '', '', '', '', '', '', ''
                else:
                    parent, _, comp = pid.partition(':')
                    kind, name, ver, arch, mod, dg, tag, repo = _component('', comp)
                cat, det = plan.get(pid, ('', ''))
                self.statements.append(Statement(
                    st, product(parent), pid, kind, name, ver, arch, mod, dg, tag, repo,
                    flag.get(pid, ''), cat, det, sev.get(pid, '')))
        self.vendor_not_affected = any(
            s.product.family == 'vendor' and s.status == 'known_not_affected' for s in self.statements)
        self._by_name: Dict[str, List[Statement]] = {}
        for s in self.statements:
            self._by_name.setdefault(s.name.lower(), []).append(s)
        self.any_severity = next((s.severity for s in self.statements if s.severity), '')

    def named(self, *names) -> List[Statement]:
        out = []
        for n in dict.fromkeys(x.lower() for x in names if x):
            out += self._by_name.get(n, [])
        return out

    def images(self) -> List[Statement]:
        return [s for s in self.statements if s.kind == 'oci' or (s.kind == 'none' and '/' in s.name)]
