"""A finding + the image + Red Hat's statements → a Verdict.

Order of evidence (docs/RULES.md has the reasoning and the data behind each):

  every finding   no VEX file → stands · the vendor catch-all · a statement about
                  this exact build (digest) · this image not affected in our product
  an rpm          Red Hat's builds only · RHEL stream ladder (exact build, our
                  stream's fix, the inherited mainline fix, open for our line, not
                  affected, fixes only elsewhere → errata policy) · rpms a product
                  makes (rhaos, el9ap …) by that product's statements · not listed
  a module        Red Hat's purl for it in our product · the rpm that ships it ·
  (go, java, …)   the image's statements (builds, line, other versions) · not a Red
                  Hat image → not covered · errata assumption · not listed

`stated` is True only when the deciding statement is about our product and our
package / image / build; everything else is Red Hat's data applied by a rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from . import csaf
from .csaf import AFFECTED, FIXED, INVESTIGATING, NOT_AFFECTED, OPEN, Document, Product, Statement
from .model import VEX_KIND, Finding, Image, Package, Verdict
from .rpm import EVR, ev_cmp, evr_cmp, vercmp
from .version import compare as lang_cmp

AFF, NA, FIX, UI = 'affected', 'not_affected', 'fixed', 'under_investigation'
JUSTIFICATIONS = {'component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path',
                  'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist'}


# ── scope: which Red Hat products are this image's ──────────────────────────

@dataclass
class Scope:
    image: Image
    rhel: Optional[int] = None          # RHEL major (os-release)
    minor: Optional[int] = None         # RHEL minor stream
    keys: set = field(default_factory=set)      # the image's own products ('openshift', 'openshift_gitops' …)
    version: str = ''                   # the image's product version ('4.20', '1.6'), '' unknown
    paths: set = field(default_factory=set)     # the VEX image paths that are this image
    rhel_image: bool = False            # a RHEL image (ubi9/ubi, rhel9/postgresql-16): its product is RHEL

    @property
    def digests(self) -> set:
        return self.image.digests

    def relation(self, p: Product) -> str:
        """vendor | rhel | own | line | newer | older | unordered | foreign."""
        if p.family == 'vendor':
            return 'vendor'
        if p.family == 'rhel':
            return 'rhel' if self.rhel is not None and p.major == self.rhel else 'foreign'
        if p.key not in self.keys:
            return 'foreign'
        if p.major is not None and self.rhel is not None and p.major != self.rhel and p.family == 'ocp' \
                and not p.is_line:
            pass                                    # OpenShift ships one minor on several RHELs: same version
        return version_relation(self.version, p.version)


def version_relation(ours: str, theirs: str) -> str:
    """How a product version relates to ours: own | line | newer | older | unordered."""
    if not theirs:
        return 'line'
    o = [int(x) for x in re.findall(r'\d+', ours)][:2]
    t = [int(x) for x in re.findall(r'\d+', theirs)][:2]
    if not t:
        return 'line'
    if '.' not in theirs:                           # a line: GitOps 1, OpenShift 4
        if not o or o[0] == t[0]:
            return 'line'
        return 'newer' if t[0] > o[0] else 'older'
    if not o:
        return 'unordered'
    if len(o) == 1:
        return 'line' if o[0] == t[0] else ('newer' if t[0] > o[0] else 'older')
    if o == t:
        return 'own'
    return 'newer' if t > o else 'older'


_RHEL_CPE = re.compile(r'cpe:/[ao]:redhat:(enterprise_linux|rhel_\w+)')


def resolve(image: Image, index) -> Scope:
    """Find the image in Red Hat's data: by digest, by path, by name under its product."""
    sc = Scope(image, image.rhel_major, image.rhel_minor)
    hint_key, hint_ver = '', ''
    cpe = image.labels.get('cpe', '') or ''
    if cpe and not _RHEL_CPE.match(cpe):            # a RHEL cpe label is often the base image's
        f = csaf.parse_cpe(cpe)
        hint_key, hint_ver = ('openshift' if f[2] == 'openshift' else f[2]), f[3]
    elif image.payload:
        hint_key = 'openshift'

    cands = []
    if image.repo and not image.payload:
        cands.append(image.repo)
    if '/' in image.name_label:
        cands.append(image.name_label)
    named = index.products_naming(cands) if index else {}
    hits = index.products_with_digest(image.digests) if index and image.digests else []
    products = [p for ps in named.values() for p in ps] + [p for _, p in hits]
    sc.paths = set(named) | {path for path, _ in hits}
    if not sc.paths and index and hint_key:
        # payload images say openshift/ose-cli-rhel9 where Red Hat writes openshift4/…
        for name in {c.rsplit('/', 1)[-1] for c in cands} | {image.name_label.rsplit('/', 1)[-1]} - {''}:
            for path in index.paths_ending(name):
                ps = [p for p in index.products_naming([path]).get(path, []) if p.key == hint_key]
                if ps:
                    sc.paths.add(path)
                    products += ps
    own = {p.key for p in products if p.family in ('ocp', 'layered')}
    if hint_key and (hint_key in own or not own):
        sc.keys = {hint_key}
    else:
        sc.keys = own
    sc.rhel_image = not sc.keys and any(p.family == 'rhel' for p in products)
    if hint_ver and hint_key in sc.keys:
        sc.version = hint_ver
    else:
        mine = {p.version for _, p in hits if p.key in sc.keys and '.' in p.version}
        if len(mine) == 1:
            sc.version = mine.pop()
        else:
            m = re.match(r'v?(\d+\.\d+)', image.labels.get('version', '') or '')
            sc.version = m.group(1) if m else ''
    return sc


# ── helpers ─────────────────────────────────────────────────────────────────

def _plan(s: Statement) -> str:
    r = s.remedy
    if r and r.category in ('no_fix_planned', 'none_available') and r.details:
        return r.details.strip().split('\n')[0][:40]
    return ''


def _short(p: Product) -> str:
    n = p.name or p.id
    return n.replace('Red Hat ', '').replace('OpenShift Container Platform', 'OpenShift').replace('Enterprise Linux', 'RHEL')


def _stream_name(p: Product) -> str:
    if p.family != 'rhel':
        return _short(p)
    if p.stream == 'line':
        return f'RHEL {p.major}'
    side = re.search(r'(EUS|AUS|TUS|E4S|E2S|ELS)', p.id.upper())
    tail = ' ' + side.group(1) if side and p.stream == 'side' else ''
    return f'RHEL {p.version}{tail}'


def _v(status: str, reason: str, stated: bool, s: Optional[Statement] = None, rule: str = '',
       fix: str = '', plan: str = '', evidence=()) -> Verdict:
    just = ''
    if status == NA and stated and s is not None and s.flag in JUSTIFICATIONS:
        just = s.flag
    ev = tuple(evidence) or ((s.pid,) if s is not None else ())
    return Verdict(status, reason, stated, just, fix, plan or (_plan(s) if s is not None and status == AFF else ''),
                   s.severity if s is not None else '', _short(s.product) if s is not None else '', ev, rule)


def _cleared(s: Statement) -> str:
    return FIX if s.status == FIXED else NA


# ── the judge ───────────────────────────────────────────────────────────────

class Engine:
    def __init__(self, index, scope: Scope):
        self.index = index
        self.scope = scope
        self._per_cve: dict = {}

    def judge(self, f: Finding) -> Verdict:
        doc = self.index.doc(f.cve) if self.index else None
        v = self._judge(f.package, doc, f)
        if not v.severity and doc is not None:
            v.severity = doc.severity
        return v

    def _judge(self, pkg: Package, doc: Optional[Document], f: Optional[Finding] = None) -> Verdict:
        if doc is None:
            return Verdict(AFF, 'Red Hat publishes no VEX for this CVE: the finding stands', rule='no_vex')
        for s in doc.products():
            if s.product.family == 'vendor' and s.status == NOT_AFFECTED:
                return _v(NA, 'Red Hat: no supported Red Hat product is affected', True, s, 'vendor')
        key = (doc.cve, 'image-wide')
        if key not in self._per_cve:
            self._per_cve[key] = self._this_build(doc) or self._image_clear(doc)
        if self._per_cve[key]:
            return _copy(self._per_cve[key])
        if pkg.kind == 'rpm':
            return self._rpm(pkg, doc)
        return self._module(pkg, doc)

    # ── every finding ───────────────────────────────────────────────────────
    def _this_build(self, doc: Document) -> Optional[Verdict]:
        mine = doc.by_digest(self.scope.digests)
        if not mine:
            return None
        for s in mine:
            if s.status in OPEN:
                return _v(AFF if s.status == AFFECTED else UI, f'{_short(s.product)}: this build is affected',
                          True, s, 'this_build')
        s = mine[0]
        return _v(_cleared(s), f'{_short(s.product)}: this build ({s.comp.digest[:12]}) is '
                  f'{"fixed" if s.status == FIXED else "not affected"}', True, s, 'this_build')

    def _image_clear(self, doc: Document) -> Optional[Verdict]:
        """This image not affected in our product, nothing open about it: covers what is inside."""
        mine = [s for s in self._image_statements(doc) if not s.comp.digest
                and self._rel(s.product) in ('own', 'line', 'rhel')]
        if mine and not any(s.status in OPEN for s in mine):
            na = [s for s in mine if s.status == NOT_AFFECTED]
            if na:
                return _v(NA, f'{_short(na[0].product)}: {na[0].comp.name} not affected', True, na[0], 'image_clear')
        return None

    def _rel(self, p: Product) -> str:
        r = self.scope.relation(p)
        if r == 'rhel' and self.scope.rhel_image:
            return 'line'
        return r

    def _image_statements(self, doc: Document) -> list:
        out = []
        for path in sorted(self.scope.paths):          # sorted: the same citation every run
            out += doc.about('image', path)
        return out

    # ── rpms ────────────────────────────────────────────────────────────────
    def _rpm_statements(self, pkg: Package, doc: Document) -> list:
        """Statements naming the rpm — by its name, or by its source package
        (version-less or .src). Per product, one naming the binary exactly
        outranks those naming its source (vim-filesystem's own statement over vim's)."""
        binary = list(doc.about('rpm', pkg.name))
        source = []
        if pkg.source and pkg.source != pkg.name:
            source = [s for s in doc.about('rpm', pkg.source) if s.comp.evr is None or s.comp.is_src]
        else:
            binary_src = [s for s in binary if s.comp.is_src]
            binary = [s for s in binary if not s.comp.is_src] + binary_src
        have = {s.product.id for s in binary}
        out = binary + [s for s in source if s.product.id not in have]
        out = [s for s in out if _stream_ok(s, pkg) and _arch_ok(s, pkg)]
        if pkg.module:                              # the SBOM's stream outranks stream-less version-less ones
            if any(s.comp.module == pkg.module for s in out):
                out = [s for s in out if s.comp.module or s.comp.evr is not None]
        return out

    def _rpm(self, pkg: Package, doc: Document, via: str = '') -> Verdict:
        sc = self.scope

        if pkg.red_hat_rpm is False:
            return Verdict(AFF, f'{pkg.name} is not a Red Hat build ({pkg.vendor}): Red Hat VEX does not cover it',
                           rule='not_red_hat')
        S = self._rpm_statements(pkg, doc)
        if not S and pkg.red_hat_rpm is None and not sc.image.red_hat:
            return Verdict(AFF, f'{pkg.name}: not named by Red Hat and its origin is unknown', rule='not_covered')
        major = sc.rhel if sc.rhel is not None else pkg.dist.major
        rhel = [s for s in S if s.product.family == 'rhel' and s.product.major == major]
        tok = pkg.dist.token
        made_by_product = tok.startswith('rhaos') or (tok not in ('el', 'module', '') and tok.startswith('el')) \
            or tok == 'hum'
        if rhel and not made_by_product:
            # the image's product saying the package is not affected in its context still clears
            ctx = [s for s in S if s.status == NOT_AFFECTED and s.comp.evr is None
                   and s.product.family != 'rhel' and self._rel(s.product) in ('own', 'line')]
            if ctx:
                return _v(NA, f'{_short(ctx[0].product)}: {ctx[0].comp.name} not affected', True, ctx[0], 'product_context')
            return self._rhel_ladder(pkg, rhel, major, via, doc)
        makers = self._makers(pkg, S, major)
        if makers:
            vl = [s for s in rhel if s.status == NOT_AFFECTED and s.comp.evr is None]
            if vl:                                  # RHEL's version-less not affected is about the code
                return _v(NA, f'{_stream_name(vl[0].product)}: {vl[0].comp.name} not affected', True, vl[0], 'rhel_code')
            return self._product_ladder(pkg, makers, via)
        if rhel:
            return self._rhel_ladder(pkg, rhel, major, via, doc)
        named = [s for s in S if s.product.family == 'rhel']
        why = f'RHEL {major} does not list {pkg.name}' if named else f'Red Hat does not list {pkg.name}'
        return Verdict(NA, f'{via}not listed as affected: {why}', rule='rpm_not_listed')

    def _makers(self, pkg: Package, S: list, major) -> list:
        """The statements of the products that make this rpm: those listing builds
        with its dist token (rhaos4.20 → OpenShift, el9ap → Ansible …), else — for
        an rpm RHEL does not name — the products naming it on our RHEL."""
        tok = pkg.dist.token
        if tok.startswith('rhaos'):
            return [s for s in S if s.product.family == 'ocp']
        if tok and tok not in ('el', 'module'):
            keys = {s.product.key for s in S if s.comp.evr is not None and s.comp.dist.token == tok}
            return [s for s in S if s.product.key in keys and s.product.family != 'rhel']
        if not any(s.product.family == 'rhel' for s in S):
            # a build of another lineage (Hardened Images' hum, a product's own tag)
            # is never compared with ours; version-less statements need our product
            return [s for s in S if s.product.family != 'vendor'
                    and (s.comp.dist.token == tok and s.comp.dist.major in (None, major) if s.comp.evr is not None
                         else (s.product.major in (None, major) or self._rel(s.product) in ('own', 'line')))]
        return []

    def _rhel_ladder(self, pkg: Package, S: list, major: int, via: str, doc: Document) -> Verdict:
        inst = pkg.evr
        M = self.scope.minor if self.scope.minor is not None else pkg.dist.minor
        fixes = [s for s in S if s.status == FIXED and s.comp.evr is not None]
        clean = [s for s in S if s.status == NOT_AFFECTED and s.comp.evr is not None]
        opens = [s for s in S if s.status in OPEN]
        vl_na = [s for s in S if s.status == NOT_AFFECTED and s.comp.evr is None]

        def minor(s):
            d = s.comp.dist
            return d.minor if d.minor is not None else s.product.minor

        def same(s):                                # the installed build itself?
            return evr_cmp(s.comp.evr, inst) == 0

        # 1. the exact build
        for s in fixes + clean:
            if same(s):
                return _v(_cleared(s), f'{via}{_stream_name(s.product)}: {pkg.name}-{inst} is '
                          f'{"the fix" if s.status == FIXED else "not affected"}',
                          True, s, 'rpm_exact', fix=str(s.comp.evr) if s.status == FIXED else '')
        # Red Hat naming this very binary not affected for our line or stream
        # outranks what it says about the source package (vim-filesystem vs vim)
        own = [s for s in vl_na if s.comp.name == pkg.name != pkg.source
               and (s.product.stream == 'line' or (M is not None and s.product.minor == M))]
        if own:
            return _v(NA, f'{via}{_stream_name(own[0].product)}: {pkg.name} not affected', True, own[0], 'rpm_binary_clear')
        # 2. our stream's fix, else the newest mainline fix of an earlier minor (inherited)
        ours = [s for s in fixes if M is not None and minor(s) == M]
        if ours:
            f0 = min(ours, key=_evr_key)
            if evr_cmp(inst, f0.comp.evr) >= 0:
                return _v(FIX, f'{via}{_stream_name(f0.product)}: fixed in {f0.comp.evr}, installed {inst}',
                          True, f0, 'rpm_stream_fix', fix=str(f0.comp.evr))
            return _v(AFF, f'{via}{_stream_name(f0.product)}: fixed in {f0.comp.evr}, installed {inst}',
                      True, f0, 'rpm_stream_fix', fix=str(f0.comp.evr))
        inherited = [s for s in fixes if s.product.stream == 'main' and M is not None
                     and (minor(s) is None or minor(s) < M)]
        if inherited:
            f0 = max(inherited, key=lambda s: (minor(s) or -1, _evr_key(s)))
            if evr_cmp(inst, f0.comp.evr) >= 0:
                return _v(FIX, f'{via}{_stream_name(f0.product)}: fixed in {f0.comp.evr} (inherited by '
                          f'RHEL {major}.{M}), installed {inst}', False, f0, 'rpm_inherited', fix=str(f0.comp.evr))
            return _v(AFF, f'{via}{_stream_name(f0.product)}: fixed in {f0.comp.evr} (inherited by RHEL {major}.{M}),'
                      f' installed {inst}', False, f0, 'rpm_inherited', fix=str(f0.comp.evr))
        # 3. open for our line or stream
        mine = [s for s in opens if s.product.stream == 'line' or (M is not None and s.product.minor == M)]
        if mine:
            s = mine[0]
            return _v(AFF if s.status == AFFECTED else UI,
                      f'{via}{_stream_name(s.product)}: {s.comp.name} {"affected" if s.status == AFFECTED else "under investigation"}',
                      True, s, 'rpm_open', fix=self._name_fix(fixes, M))
        # 4. not affected: version-less for our line/stream, or a clean build of our upstream version
        na = [s for s in vl_na if s.product.stream == 'line' or (M is not None and s.product.minor == M)]
        if na:
            return _v(NA, f'{via}{_stream_name(na[0].product)}: {na[0].comp.name} not affected', True, na[0], 'rpm_not_affected')
        same_v = [s for s in clean if ev_cmp(s.comp.evr, inst) == 0]
        for s in same_v:
            if M is not None and minor(s) == M:
                return _v(NA, f'{via}{_stream_name(s.product)}: {s.comp.evr} not affected (same upstream version)',
                          True, s, 'rpm_clean_build')
        # a subpackage not affected in the very build that fixes its source: the
        # code is not in it (libacl beside acl, glibc-common beside glibc)
        sub = _subpackage_clear(pkg, clean, doc)
        if sub:
            return _v(NA, f'{via}{_stream_name(sub.product)}: {pkg.name} not affected where {pkg.source} '
                      f'{sub.comp.evr} is fixed (the code is not in this subpackage)', False, sub, 'rpm_subpackage')
        if same_v and not fixes and not opens:
            s = same_v[0]
            return _v(NA, f'{via}{_stream_name(s.product)}: {s.comp.evr} not affected (same upstream version)',
                      False, s, 'rpm_clean_build')
        # 5. fixes only in later minors or side streams: older builds are assumed vulnerable
        if fixes:
            if all(ev_cmp(inst, s.comp.evr) > 0 for s in fixes):
                s = max(fixes, key=_evr_key)
                return _v(FIX, f'{via}newer upstream version than every fix ({s.comp.evr}, {_stream_name(s.product)})',
                          False, s, 'rpm_newer_version', fix=str(s.comp.evr))
            past = [s for s in fixes if s.product.stream == 'main' and evr_cmp(inst, s.comp.evr) >= 0]
            if past:
                s = max(past, key=_evr_key)
                return _v(FIX, f'{via}at or past the mainline fix {s.comp.evr} ({_stream_name(s.product)})',
                          False, s, 'rpm_past_mainline', fix=str(s.comp.evr))
            if M is not None and not opens and all((minor(s) is None or minor(s) < M) for s in fixes) \
                    and all(evr_cmp(inst, s.comp.evr) > 0 for s in fixes):
                s = max(fixes, key=_evr_key)
                return _v(FIX, f'{via}newer than every fix, all in earlier streams ({s.comp.evr}, {_stream_name(s.product)})',
                          False, s, 'rpm_later_stream', fix=str(s.comp.evr))
            fix = self._name_fix(fixes, M)
            s = next((x for x in fixes if str(x.comp.evr) == fix), fixes[0])
            return _v(AFF, f'{via}fixed only in other streams ({fix}, {_stream_name(s.product)}); '
                      f'older builds are assumed vulnerable', False, s, 'rpm_errata', fix=fix)
        if opens or clean or vl_na:
            return Verdict(NA, f'{via}not listed for RHEL {major}.{M}: statements name other streams only',
                           rule='rpm_other_streams', evidence=tuple(s.pid for s in (opens + clean + vl_na)[:3]))
        return Verdict(NA, f'{via}not listed as affected', rule='rpm_not_listed')

    @staticmethod
    def _name_fix(fixes: list, M) -> str:
        """The fix to name: our minor's, else the nearest later minor's (mainline first), else the newest."""
        if not fixes:
            return ''

        def minor(s):
            d = s.comp.dist
            return d.minor if d.minor is not None else s.product.minor
        later = sorted((s for s in fixes if M is not None and minor(s) is not None and minor(s) >= M),
                       key=lambda s: (minor(s), s.product.stream != 'main', _evr_key(s)))
        s = later[0] if later else max(fixes, key=_evr_key)
        return str(s.comp.evr)

    def _product_ladder(self, pkg: Package, S: list, via: str) -> Verdict:
        """An rpm a product makes (rhaos, el9ap …): that product's statements decide."""
        inst = pkg.evr
        tok = pkg.dist.token
        ver = tok[5:] if tok.startswith('rhaos') else ''
        if not ver and any(s.product.key in self.scope.keys for s in S):
            ver = self.scope.version
        if not ver:
            m = re.match(r'(\d+\.\d+)', pkg.version)
            ver = m.group(1) if m else ''
        fixes = [s for s in S if s.status == FIXED and s.comp.evr is not None]
        for s in fixes + [s for s in S if s.status == NOT_AFFECTED and s.comp.evr is not None]:
            if evr_cmp(s.comp.evr, inst) == 0:
                return _v(_cleared(s), f'{via}{_short(s.product)}: {pkg.name}-{inst} is '
                          f'{"the fix" if s.status == FIXED else "not affected"}', True, s, 'product_exact')
        rel = lambda s: version_relation(ver, s.product.version)
        ours = [s for s in fixes if rel(s) == 'own']
        if ours:
            f0 = min(ours, key=_evr_key)
            st = FIX if evr_cmp(inst, f0.comp.evr) >= 0 else AFF
            return _v(st, f'{via}{_short(f0.product)}: fixed in {f0.comp.evr}, installed {inst}', True, f0,
                      'product_fix', fix=str(f0.comp.evr))
        past = [s for s in fixes if evr_cmp(inst, s.comp.evr) >= 0]
        if past:
            s = max(past, key=_evr_key)
            return _v(FIX, f'{via}carries the fix {s.comp.evr} ({_short(s.product)})', False, s, 'product_past_fix',
                      fix=str(s.comp.evr))
        opens = [s for s in S if s.status in OPEN and rel(s) in ('own', 'line')]
        if opens:
            s = opens[0]
            return _v(AFF if s.status == AFFECTED else UI, f'{via}{_short(s.product)}: {s.comp.name} '
                      f'{"affected" if s.status == AFFECTED else "under investigation"}', True, s, 'product_open',
                      fix=str(min(fixes, key=_evr_key).comp.evr) if fixes else '')
        na = [s for s in S if s.status == NOT_AFFECTED and rel(s) in ('own', 'line')]
        if na:
            return _v(NA, f'{via}{_short(na[0].product)}: {na[0].comp.name} not affected', True, na[0], 'product_not_affected')
        if fixes:
            s = min(fixes, key=_evr_key)
            return _v(AFF, f'{via}fixed in {s.comp.evr} ({_short(s.product)}); older builds are assumed vulnerable',
                      False, s, 'product_errata', fix=str(s.comp.evr))
        return Verdict(NA, f'{via}not listed as affected for {pkg.name}', rule='product_not_listed',
                       evidence=tuple(s.pid for s in S[:3]))

    # ── modules inside the image (Go, Java, npm, Python …) ───────────────────
    def _module(self, pkg: Package, doc: Document) -> Verdict:
        sc = self.scope
        v = self._module_purl(pkg, doc)
        if v:
            return v
        owner = pkg.owner
        if owner is not None and owner.red_hat_rpm is not False:
            if self._rpm_statements(owner, doc):
                v = self._rpm(owner, doc, via=f'via rpm {owner.name}: ')
                return v
        v = self._image(doc)
        if v:
            return v
        if not sc.image.red_hat and (owner is None or owner.red_hat_rpm is False):
            return Verdict(AFF, "not a Red Hat image: Red Hat VEX does not cover this image's own content",
                           rule='not_covered')
        if owner is None:
            v = self._errata_assumed(doc)
            if v:
                return v
        return Verdict(NA, 'not listed as affected: Red Hat names neither this image nor what ships it'
                       if owner is None else f'not listed as affected: Red Hat does not list rpm {owner.name}',
                       rule='not_listed')

    def _module_purl(self, pkg: Package, doc: Document) -> Optional[Verdict]:
        kind = VEX_KIND.get(pkg.kind)
        if not kind or kind == 'rpm':
            return None
        names = {pkg.name}
        if kind == 'maven' and ':' in pkg.name:
            names.add(pkg.name.split(':', 1)[1])
        S = [s for n in names for s in doc.about(kind, n) if self._rel(s.product) in ('own', 'line', 'rhel')]
        if not S:
            return None
        for s in S:
            if s.comp.version and lang_cmp(kind, s.comp.version, pkg.version) == 0:
                st = _cleared(s) if s.status in (FIXED, NOT_AFFECTED) else (AFF if s.status == AFFECTED else UI)
                return _v(st, f'{_short(s.product)}: {s.comp.name} {s.comp.version} '
                          f'{ {FIX: "is the fix", NA: "not affected", AFF: "affected", UI: "under investigation"}[st]}',
                          True, s, 'purl_exact')
        fixes = [s for s in S if s.status == FIXED and s.comp.version]
        for s in sorted(fixes, key=lambda s: s.comp.version):
            c = lang_cmp(kind, pkg.version, s.comp.version)
            if c is not None and c >= 0:
                return _v(FIX, f'{_short(s.product)}: fixed in {s.comp.version}, installed {pkg.version}', True, s,
                          'purl_fix', fix=s.comp.version)
        opens = [s for s in S if s.status in OPEN and not s.comp.version]
        if opens:
            s = opens[0]
            return _v(AFF if s.status == AFFECTED else UI, f'{_short(s.product)}: {s.comp.name} affected', True, s,
                      'purl_open', fix=fixes[0].comp.version if fixes else '')
        na = [s for s in S if s.status == NOT_AFFECTED and not s.comp.version]
        if na:
            return _v(NA, f'{_short(na[0].product)}: {na[0].comp.name} not affected', True, na[0], 'purl_not_affected')
        if fixes:
            s = fixes[0]
            return _v(AFF, f'{_short(s.product)}: fixed in {s.comp.version}, installed {pkg.version}', True, s,
                      'purl_fix', fix=s.comp.version)
        return None

    def _image(self, doc: Document) -> Optional[Verdict]:
        """Statements naming this image: our version's builds, open, not affected;
        then the line; then other versions."""
        A = [s for s in self._image_statements(doc)]
        if not A:
            return None
        by: dict = {}
        for s in A:
            by.setdefault(self._rel(s.product), []).append(s)
        own = by.get('own', [])
        builds = [s for s in own if s.comp.digest and s.status in (FIXED, NOT_AFFECTED)]
        before = [(o, s) for s in builds for o in [self._order(s)] if o is not None and o <= 0]
        if before:
            o, s = max(before, key=lambda x: (x[0], x[1].comp.stamp or 0))
            return _v(_cleared(s), f'{_short(s.product)}: build {s.comp.tag or s.comp.digest[:12]} of this image, '
                      f'at or before ours, is {"fixed" if s.status == FIXED else "not affected"}', False, s, 'image_build')
        later = [s for s in builds if s.status == FIXED and (self._order(s) or 0) > 0]
        if later:
            s = min(later, key=lambda s: s.comp.stamp or 0)
            return _v(AFF, f'{_short(s.product)}: fixed in a later build ({s.comp.tag or s.comp.digest[:12]}); '
                      f'this build predates it', False, s, 'image_later_fix', fix=s.comp.tag)
        for group, label in ((own, 'own'), (by.get('line', []), 'line')):
            generic = [s for s in group if not s.comp.digest]
            op = [s for s in generic if s.status in OPEN]
            if op:
                s = op[0]
                return _v(AFF if s.status == AFFECTED else UI, f'{_short(s.product)}: {s.comp.name} '
                          f'{"affected" if s.status == AFFECTED else "under investigation"}', True, s, f'image_{label}_open')
            cl = [s for s in generic if s.status in (FIXED, NOT_AFFECTED)]
            if cl:
                s = cl[0]
                return _v(_cleared(s), f'{_short(s.product)}: {s.comp.name} '
                          f'{"fixed" if s.status == FIXED else "not affected"}', True, s, f'image_{label}_clear')
        if builds and not before:                   # only builds we cannot order against ours
            s = builds[0]
            if s.status == FIXED:
                return _v(AFF, f'{_short(s.product)}: fixed in build {s.comp.tag or s.comp.digest[:12]}, which cannot '
                          f'be ordered against this one', False, s, 'image_unordered_fix', fix=s.comp.tag)
        newer, older = by.get('newer', []), by.get('older', [])
        unordered = by.get('unordered', [])
        bad_newer = [s for s in newer + unordered if s.status in (FIXED, AFFECTED, INVESTIGATING)]
        fixed_older = [s for s in older if s.status == FIXED]
        if bad_newer and not fixed_older:
            s = bad_newer[0]
            word = 'fixed' if s.status == FIXED else 'affected'
            return _v(AFF, f'{_short(s.product)}: {word} in another version; this image predates the fix '
                      f'(older builds are assumed vulnerable)', False, s, 'image_newer_version',
                      fix=s.comp.tag if s.status == FIXED else '')
        if fixed_older:
            ordered = [(self._order(s), s) for s in fixed_older]
            known = [(o, s) for o, s in ordered if o is not None]
            if known:
                o, last = max(known, key=lambda x: (x[0], x[1].comp.stamp or 0))
                if o <= 0:
                    return _v(FIX, f"{_short(last.product)}: fixed in an older version's build "
                              f'{last.comp.tag or last.comp.digest[:12]}, made before this one', False, last,
                              'image_older_fix')
                return _v(AFF, f'{_short(last.product)}: fixed in a build made after this one '
                          f'({last.comp.tag or last.comp.digest[:12]})', False, last, 'image_older_fix', fix=last.comp.tag)
            s = fixed_older[0]
            return _v(AFF, f'{_short(s.product)}: fixed in another version; this build cannot be ordered against it',
                      False, s, 'image_unordered_fix', fix=s.comp.tag)
        na_older = [s for s in older if s.status == NOT_AFFECTED]
        if na_older and not any(s.status in OPEN for s in A):
            s = na_older[0]
            return _v(NA, f'{_short(s.product)}: {s.comp.name} not affected in earlier versions', False, s,
                      'image_older_not_affected')
        # not affected in a newer version, nothing open or fixed about the image anywhere:
        # the code is not there (holdout: 6,900 of 7,099 clear, 192 fixed, 2 affected)
        na_newer = [s for s in newer if s.status == NOT_AFFECTED]
        if na_newer and not any(s.status in OPEN or s.status == FIXED for s in A):
            s = na_newer[0]
            return _v(NA, f'{_short(s.product)}: {s.comp.name} not affected in a newer version, '
                      f'nothing open or fixed about it', False, s, 'image_newer_not_affected')
        return None

    def _order(self, s: Statement) -> Optional[int]:
        """Another build of this image relative to ours: -1 older, 0 same, 1 newer, None unknown."""
        c, img = s.comp, self.scope.image
        if c.digest and c.digest in img.digests:
            return 0
        built = img.built
        if c.stamp and built:
            return (c.stamp > built) - (c.stamp < built)
        m = re.match(r'v?(\d+(?:\.\d+)+)-(\d+(?:\.\d+)*)$', c.tag or '')
        ver = (img.labels.get('version') or '').lstrip('v')
        if not m or not re.match(r'\d+(\.\d+)+$', ver):
            return None
        o = vercmp(m.group(1), ver)
        if o:
            return o
        rel = img.labels.get('release') or ''
        return vercmp(m.group(2), rel) if re.match(r'\d+(\.\d+)*$', rel) else None

    def _errata_assumed(self, doc: Document) -> Optional[Verdict]:
        """Our product lists images affected and cleared nothing under that same
        product node: an unnamed image of it is assumed vulnerable (errata policy)."""
        sc = self.scope
        if not sc.keys:
            return None
        # our version's own node clears images (and does not name ours): Red Hat went
        # through this version's images, so the line's open ones do not speak for ours
        # (holdout: precision 76.7% → 96.7% on 121,244 unnamed-image cases)
        own_open, own_clear = set(), set()
        for s in doc.statements:
            if s.comp is not None and s.comp.kind == 'image' and s.product.key in sc.keys \
                    and self._rel(s.product) == 'own':
                (own_open if s.status in OPEN else own_clear).add((s.product.id, s.comp.name))
        if own_clear - own_open:
            return None
        cleared = {s.product.id for s in doc.statements if s.status in (FIXED, NOT_AFFECTED)}
        for s in doc.statements:
            if s.status in OPEN and s.comp is not None and s.comp.kind == 'image' \
                    and s.product.key in sc.keys and self._rel(s.product) in ('own', 'line', 'newer') \
                    and s.product.id not in cleared:
                return _v(AFF if s.status == AFFECTED else UI,
                          f'{_short(s.product)} lists its images {"affected" if s.status == AFFECTED else "under investigation"} '
                          f'and cleared none: this image is assumed vulnerable', False, s, 'errata_assumed')
        return None


def _subpackage_clear(pkg: Package, clean: list, doc: Document) -> Optional[Statement]:
    """A not-affected build of this binary in a product where the same build of
    its source package is fixed — and the binary itself is fixed on no arch there."""
    if not pkg.source or pkg.source == pkg.name:
        return None
    src = [f for f in doc.about('rpm', pkg.source) if f.status == FIXED and f.comp.evr is not None]
    own_fixed = {(f.product.id, str(f.comp.evr)) for f in doc.about('rpm', pkg.name)
                 if f.status == FIXED and f.comp.evr is not None}
    for s in clean:
        if s.comp.name == pkg.name and (s.product.id, str(s.comp.evr)) not in own_fixed and \
                any(f.product.id == s.product.id and evr_cmp(f.comp.evr, s.comp.evr) == 0 for f in src):
            return s
    return None


def _arch_ok(s: Statement, pkg: Package) -> bool:
    """Statements are per architecture: one about another arch's build says nothing about ours."""
    a = s.comp.arch
    return not a or not pkg.arch or a in ('noarch', 'src', 'source', 'nosrc') or a == pkg.arch \
        or pkg.arch == 'noarch' 


def _copy(v: Verdict) -> Verdict:
    from dataclasses import replace
    return replace(v)


def _evr_key(s: Statement):
    from functools import cmp_to_key
    return cmp_to_key(evr_cmp)(s.comp.evr)


def _stream_ok(s: Statement, pkg: Package) -> bool:
    """Module streams: a statement about one stream says nothing about another;
    a non-module build never clears a module install, nor the reverse."""
    sm, pm = s.comp.module, pkg.module
    pd = pkg.dist
    if pm is None:                                  # stream unknown: read it from the version
        if sm:
            stream = sm.split(':', 1)[1] if ':' in sm else ''
            if not pd.module:
                return False
            if re.match(r'\d', stream):
                return pkg.version.startswith(stream)
            return False
        if s.comp.evr is not None:
            return s.comp.dist.module == pd.module
        return True
    if sm:
        return sm == pm
    if s.comp.evr is not None:                      # a build, no stream stated
        return bool(pm) if s.comp.dist.module else not pm
    return True
