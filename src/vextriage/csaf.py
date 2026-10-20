"""Red Hat CSAF-VEX: one document per CVE → flat statements.

A statement is one status reference resolved to what it is about:

    status × Product (the parent product node: id, name, CPE)
           × Comp    (the component node, read from its purl)

Everything the engine needs is in the purls, the CPEs and the product ids.
Measured over the whole corpus (docs/VEX-MODEL.md): every product node has a
CPE; 99.9% of components have a purl; the rest are image paths, Maven
coordinates or bare upstream names, read from the product id.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Optional

from . import purl as purls
from .rpm import EVR, Dist, dist, parse_evr

FIXED, AFFECTED, INVESTIGATING, NOT_AFFECTED = (
    'fixed', 'known_affected', 'under_investigation', 'known_not_affected')
# a product id listed twice in one entry reads the first of these
STATUSES = (FIXED, AFFECTED, INVESTIGATING, NOT_AFFECTED)
OPEN = (AFFECTED, INVESTIGATING)


# ── products ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Product:
    id: str
    name: str
    cpe: str
    family: str             # rhel | ocp | layered | vendor
    key: str                # 'rhel', 'openshift', or the CPE product ('openshift_gitops' …)
    version: str            # '4.20', '4' (a line), '1.16', '' — RHEL: '9.4' or '9'
    major: Optional[int]    # RHEL major (rhel), else the RHEL the product runs on, when stated
    minor: Optional[int]    # RHEL minor stream (rhel only)
    stream: str             # rhel: 'line' | 'main' | 'side'; else ''

    @property
    def is_line(self) -> bool:
        """Version-neutral: the whole product line (RHEL 9, OpenShift 4, GitOps 1)."""
        return self.stream == 'line' if self.family == 'rhel' else '.' not in self.version


# CPE products that are RHEL itself (verified against every product in the corpus)
_RHEL_KEYS = {'enterprise_linux', 'rhel_eus', 'rhel_aus', 'rhel_tus', 'rhel_e4s', 'rhel_els',
              'enterprise_linux_eus', 'rhel_eus_long_life', 'rhel_extras', 'rhel_extras_other',
              'rhel_extras_rt', 'rhel_extras_rt_els', 'rhel_extras_sap', 'rhel_extras_sap_els',
              'rhel_extras_sap_hana_els', 'rhel_extras_oracle_java'}
# keys whose every product is a side stream (EUS, AUS, …) unless the id says MAIN
_SIDE_KEYS = {'rhel_eus', 'rhel_aus', 'rhel_tus', 'rhel_e4s', 'rhel_els', 'enterprise_linux_eus',
              'rhel_eus_long_life', 'rhel_extras_rt_els', 'rhel_extras_sap_els',
              'rhel_extras_sap_hana_els'}
_SIDE_ID = re.compile(r'(?:^|[.\-_])(EUS|AUS|TUS|E4S|E2S|ELS|EXTENSION)(?:$|[.\-_])', re.I)


def parse_cpe(cpe: str) -> list[str]:
    """cpe:/a:redhat:openshift:4.20::el9 → [a, redhat, openshift, 4.20, '', el9]."""
    if cpe.startswith('cpe:2.3:'):
        f = cpe[8:].split(':')
        f = [x if x not in ('*', '-') else '' for x in f]
        f = f[:4] + [f[4] if len(f) > 4 else '', f[5] if len(f) > 5 else '']
    else:
        f = cpe.replace('cpe:/', '', 1).split(':')
    return (f + [''] * 6)[:6]


def _num(s: str) -> Optional[int]:
    return int(s) if s and s.isdigit() else None


def classify(pid: str, name: str, cpe: str) -> Product:
    part, vendor, prod, ver, _upd, edition = parse_cpe(cpe or '')
    el = re.match(r'el(\d+)$', edition or '')
    base = re.match(r'(\d+)Base-', pid)
    runs_on = _num(el.group(1)) if el else (_num(base.group(1)) if base else None)

    if pid == 'red_hat_products' or (cpe and vendor == 'redhat' and not prod):
        return Product(pid, name, cpe, 'vendor', 'vendor', '', None, None, '')

    if prod in _RHEL_KEYS and edition not in ('fastdatapath', 'hypervisor'):
        vparts = ver.split('.') if ver else []
        major = _num(vparts[0]) if vparts else None
        if major is None:
            m = re.match(r'(\d+)', pid) or re.search(r'linux_(\d+)', pid)
            major = _num(m.group(1)) if m else None
        minor = _num(vparts[1]) if len(vparts) > 1 else None
        if minor is None and major is not None:
            m = re.search(rf'(?<![\d.]){major}\.(\d+)', pid)
            minor = _num(m.group(1)) if m else None
        if re.fullmatch(r'red_hat_enterprise_linux_\d+', pid) or (minor is None and not _SIDE_ID.search(pid)
                                                                  and prod not in _SIDE_KEYS
                                                                  and re.fullmatch(r'Red Hat Enterprise Linux \d+', name or '')):
            stream = 'line'
        elif '.MAIN' in pid.upper():
            stream = 'main'
        elif prod in _SIDE_KEYS or _SIDE_ID.search(pid):
            stream = 'side'
        else:
            stream = 'main'
        version = f'{major}.{minor}' if major is not None and minor is not None else (str(major) if major else '')
        return Product(pid, name, cpe, 'rhel', 'rhel', version, major, minor, stream)

    if prod == 'openshift' or re.match(r'\d+Base-RHOSE-\d', pid):
        version = ver
        if not version:
            m = re.search(r'RHOSE-(\d+(?:\.\d+)?)', pid) or re.search(r'Platform (\d+(?:\.\d+)?)', name or '')
            version = m.group(1) if m else ''
        return Product(pid, name, cpe, 'ocp', 'openshift', version, runs_on, None, '')

    key = prod if edition not in ('fastdatapath', 'hypervisor') else f'{prod}:{edition}'
    return Product(pid, name, cpe, 'layered', key or pid, ver, runs_on, None, '')


# ── components ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Comp:
    kind: str                   # rpm | image | maven | npm | pypi | golang | generic | cargo | gem | name
    name: str                   # rpm name, image path ns/name, maven group:artifact, npm name …
    version: str = ''           # as written ('' = every version)
    evr: Optional[EVR] = None   # rpm only
    arch: str = ''
    module: str = ''            # rpm: module:stream ('' = none stated)
    digest: str = ''            # image: sha256 hex of this build
    stamp: Optional[int] = None  # image: build time (epoch seconds), from the purl tag
    tag: str = ''               # image: the purl tag as written (v1.9.4-1, an NVR, epoch seconds)
    pid: str = ''               # the component's product id, as written

    @property
    def is_src(self) -> bool:
        return self.arch in ('src', 'source', 'nosrc')

    @property
    def dist(self) -> Dist:
        return dist(self.evr.release) if self.evr else Dist(None, None, False, '')


_BUILD_PID = re.compile(r'-\d+:')            # name-EPOCH:version-release: the id names a build
_ARCH_TAIL = re.compile(r'_(amd64|arm64|aarch64|ppc64le|s390x|x86_64)$')
_DIGEST = re.compile(r'sha256(?::|%3[Aa])([0-9a-f]{64})')


def build_stamp(tag: str) -> Optional[int]:
    """Build time from an image tag/release: epoch seconds (Konflux) or the Brew
    YYYYMMDDHHMM stamp (`v4.15.0-202404030309.p0…`), else None."""
    import calendar
    if not tag:
        return None
    m = re.search(r'(?<!\d)(20\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?!\d)', tag)
    if m:
        y, mo, d, h, mi = map(int, m.groups())
        if 1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60:
            return calendar.timegm((y, mo, d, h, mi, 0))
    m = re.search(r'(?<![\d])(1[5-9]\d{8})(?![\d])', tag)
    return int(m.group(1)) if m else None


def image_path(ref: str) -> str:
    """'registry.redhat.io/openshift4/ose-cli-rhel9@sha256:…_amd64' → 'openshift4/ose-cli-rhel9'."""
    ref = re.sub(r'[@:]sha256.*$', '', ref)
    parts = [p for p in ref.split('/') if p]
    if len(parts) > 2 and ('.' in parts[0] or ':' in parts[0]):
        parts = parts[1:]
    return '/'.join(parts).lower() if len(parts) >= 2 else ''


def read_comp(pid: str, purl_s: str) -> Comp:
    """A component node → Comp, from its purl; its product id when it has none."""
    p = purls.parse(purl_s)
    if p.type == 'oci':
        # the product id carries the image's namespace; the purl may name another
        # image (a Brew component, an -rhel8 purl on an -rhel9 id), so the id decides
        path = image_path(pid) or image_path(p.q('repository_url')) or p.name.lower()
        m = _DIGEST.search(p.version) or _DIGEST.search(pid)
        tag = p.q('tag')
        return Comp('image', path, digest=m.group(1) if m else '', stamp=build_stamp(tag), tag=tag,
                    arch=p.q('arch'), pid=pid)
    if p.type == 'rpm':
        name = '/'.join(x for x in (p.namespace.split('/')[1:] + [p.name]) if x)
        if '/' in name:                         # pkg:rpm/redhat/rhoai/odh-… : an image, not an rpm
            return Comp('image', name.lower(), pid=pid)
        epoch = _num(p.q('epoch'))
        evr = parse_evr(p.version, epoch) if p.version else None
        mod = ':'.join(p.q('rpmmod').split(':')[:2])
        return Comp('rpm', name, p.version, evr, p.q('arch'), mod, pid=pid)
    if p.type == 'maven':
        return Comp('maven', f'{p.namespace}:{p.name}' if p.namespace else p.name, p.version, pid=pid)
    if p.type in ('npm', 'pypi', 'golang', 'cargo', 'gem', 'generic', 'github', 'nuget'):
        name = p.name if p.type == 'generic' else '/'.join(x for x in (p.namespace, p.name) if x)
        if p.type == 'pypi':
            name = re.sub(r'[-_.]+', '-', name).lower()
        return Comp(p.type, name, p.version, pid=pid)
    # no purl: an image path under a registry namespace, a Maven coordinate, or a bare name
    bare = pid.split('::')[0]
    if '/' in bare and '.' not in bare.split('/')[0] or re.match(r'[\w.-]+\.(io|com)/', bare):
        m = _DIGEST.search(bare)
        return Comp('image', image_path(_ARCH_TAIL.sub('', bare)), digest=m.group(1) if m else '', pid=pid)
    return Comp('name', bare, pid=pid)


# ── statements ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Remedy:
    category: str               # vendor_fix | workaround | no_fix_planned | none_available
    details: str = ''
    url: str = ''


@dataclass(frozen=True)
class Statement:
    status: str
    product: Product
    comp: Optional[Comp]        # None: the product is named directly ("All supported products")
    pid: str                    # the full product id the status lists
    flag: str = ''              # VEX justification label (not affected)
    remedies: tuple = ()
    severity: str = ''

    @property
    def remedy(self) -> Optional[Remedy]:
        """The plan for an affected product: no_fix_planned / none_available
        before a workaround (125,621 known_affected refs carry both)."""
        for cat in ('no_fix_planned', 'none_available', 'vendor_fix', 'workaround'):
            for r in self.remedies:
                if r.category == cat:
                    return r
        return None


@dataclass
class Document:
    cve: str
    title: str = ''
    severity: str = ''          # aggregate
    statements: list = field(default_factory=list)
    kev: bool = False

    def __post_init__(self):
        self._by: Optional[dict] = None

    def about(self, kind: str, name: str) -> list:
        """Statements whose component is (kind, name) — rpm names exact, image paths lowercase."""
        if self._by is None:
            by: dict = {}
            for s in self.statements:
                if s.comp is not None:
                    by.setdefault((s.comp.kind, s.comp.name), []).append(s)
            self._by = by
        return self._by.get((kind, name), [])

    def by_digest(self, digests) -> list:
        return [s for s in self.statements if s.comp is not None and s.comp.digest and s.comp.digest in digests]

    def products(self) -> list:
        """Statements naming a product directly (no component)."""
        return [s for s in self.statements if s.comp is None]


def encode(d: Document) -> dict:
    """A Document → compact JSON-able form (products, components and remedies
    listed once; statements as index rows). decode() reads it back."""
    P, C, R, rows = {}, {}, {}, []
    for s in d.statements:
        pi = P.setdefault(s.product.id, (len(P), [s.product.id, s.product.name, s.product.cpe]))[0]
        ci = -1
        if s.comp is not None:
            c = s.comp
            row = [c.pid, c.kind, c.name, c.version, c.evr.epoch if c.evr else None, c.arch, c.module, c.digest,
                   c.stamp, c.tag]
            ci = C.setdefault(tuple(row), (len(C), row))[0]     # one id may be read two ways (above)
        ri = [R.setdefault((r.category, r.details, r.url), len(R)) for r in s.remedies]
        rows.append([STATUSES.index(s.status), pi, ci, s.flag, ri, s.severity])
    return {'t': d.title, 's': d.severity, 'k': int(d.kev),
            'P': [v for _, v in sorted(P.values())], 'C': [v for _, v in sorted(C.values())],
            'R': [list(k) for k, _ in sorted(R.items(), key=lambda kv: kv[1])], 'S': rows}


def decode(data: dict, cve: str) -> Document:
    prods = [classify(*p) for p in data['P']]
    comps = [Comp(kind, name, ver, parse_evr(ver, ep) if kind == 'rpm' and ver else None, arch, mod, dg, st, tag, pid)
             for pid, kind, name, ver, ep, arch, mod, dg, st, tag in data['C']]
    rems = [Remedy(*r) for r in data['R']]
    out = Document(cve, data.get('t', ''), data.get('s', ''), kev=bool(data.get('k')))
    for st, pi, ci, flag, ri, sev in data['S']:
        prod = prods[pi]
        comp = comps[ci] if ci >= 0 else None
        out.statements.append(Statement(STATUSES[st], prod, comp, f'{prod.id}:{comp.pid}' if comp else prod.id,
                                        flag, tuple(rems[i] for i in ri), sev))
    return out


def parse(doc: dict, cve: str = '') -> Document:
    """A CSAF-VEX document (parsed JSON) → Document."""
    tree = doc.get('product_tree') or {}
    nodes: dict = {}

    def walk(branches):
        for b in branches or []:
            p = b.get('product')
            if p and p.get('product_id'):
                h = p.get('product_identification_helper') or {}
                nodes[p['product_id']] = (p.get('name', ''), h.get('purl', ''), h.get('cpe', ''))
            walk(b.get('branches'))
    walk(tree.get('branches'))
    for p in tree.get('full_product_names') or []:
        h = p.get('product_identification_helper') or {}
        nodes.setdefault(p.get('product_id', ''), (p.get('name', ''), h.get('purl', ''), h.get('cpe', '')))
    rel = {}
    for r in tree.get('relationships') or []:
        full = (r.get('full_product_name') or {}).get('product_id')
        if full:
            rel[full] = (r.get('relates_to_product_reference', ''), r.get('product_reference', ''))

    products: dict = {}
    comps: dict = {}

    def product(pid):
        if pid not in products:
            name, _, cpe = nodes.get(pid, (pid, '', ''))
            products[pid] = classify(pid, name, cpe)
        return products[pid]

    def comp(pid):
        if pid not in comps:
            comps[pid] = read_comp(pid, nodes.get(pid, ('', '', ''))[1])
        return comps[pid]

    meta = doc.get('document') or {}
    out = Document(cve or (doc.get('vulnerabilities') or [{}])[0].get('cve', ''),
                   meta.get('title', ''), (meta.get('aggregate_severity') or {}).get('text', ''))
    for v in doc.get('vulnerabilities') or []:
        status: dict = {}
        for st in STATUSES:
            for pid in (v.get('product_status') or {}).get(st, []):
                status.setdefault(pid, st)
        flags: dict = {}
        for f in v.get('flags') or []:
            for pid in f.get('product_ids') or []:
                flags.setdefault(pid, f.get('label', ''))
                status.setdefault(pid, NOT_AFFECTED)
        rems: dict = {}
        for r in v.get('remediations') or []:
            rem = Remedy(r.get('category', ''), r.get('details', '') or '', r.get('url', '') or '')
            for pid in r.get('product_ids') or []:
                rems.setdefault(pid, []).append(rem)
        sev: dict = {}
        for t in v.get('threats') or []:
            if t.get('category') == 'impact':
                for pid in t.get('product_ids') or []:
                    sev[pid] = t.get('details', '')
            elif t.get('category') == 'exploit_status':
                out.kev = True
        for pid, st in status.items():
            if pid in rel:
                parent, cpid = rel[pid]
                prod, c = product(parent), comp(cpid)
                if c.kind == 'rpm' and c.evr is not None and prod.family == 'rhel' and prod.major is not None \
                        and c.dist.major not in (None, prod.major) and not _BUILD_PID.search(c.pid):
                    # `red_hat_enterprise_linux_9:libevent.src` with the purl of an el10 build
                    # (786 statements, 317 documents): the product id is version-less and an
                    # el10 build says nothing about RHEL 9 — the statement is about the package
                    c = replace(c, version='', evr=None)
            elif pid in nodes:
                prod, c = product(pid), None
            else:
                continue                        # names nothing in the tree (never seen)
            out.statements.append(Statement(st, prod, c, pid, flags.get(pid, ''), tuple(rems.get(pid, ())),
                                            sev.get(pid, '')))
    return out
