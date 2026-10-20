"""The verdict: one finding × one image × Red Hat's statements about the CVE.

    judge(row, ctx, doc) -> Verdict

A scanner, the VEX index or OSV only proposes a (component, CVE) pair; Red Hat's
statements decide it (VEX-MODEL §10, re-derived from the data).  Each statement
is a status about a component purl in a product (csaf.py).  The rules, per kind
of finding:

  every finding   Red Hat clears every product (vendor catch-all) → not affected;
                  a statement about THIS build (its digest) decides.
  rpm             Red Hat did not build it (SBOM vendor) → POSITIVE, not covered;
                  this image stated not affected (no digest) → FALSE POSITIVE;
                  1 this exact build is a fixed (or not-affected) build;
                  2 a fix in the image's lineage decides: its own minor, else
                    the newest mainline fix of an earlier minor;
                  3 known_affected / under_investigation for its line → POSITIVE;
                  4 known_not_affected → FALSE POSITIVE;
                  5 a fix only in later or side streams → POSITIVE (errata
                    policy), unless past a later mainline fix or newer than all;
                  6 not named → not listed, FALSE POSITIVE (inferred).
                  A plain .elN build is RHEL's to decide, an rhaos one its
                  product's; a not-affected from the other side clears.
  the image       statements naming this image, scoped to its product version:
                  its version (assessed builds ordered by build stamp, then
                  open, then not-affected), else the product line, else other
                  versions (a fix only in newer versions → POSITIVE).
  a package       Red Hat's purl for it (maven / npm / golang / pypi), else the
  inside it       image stated not affected, else the rpm that ships it, else
                  the image's own verdict; else a non-Red Hat image's own
                  module → POSITIVE (not covered); our product listed affected
                  with nothing cleared under it → POSITIVE (errata policy);
                  otherwise not listed.

Products are ours when they are RHEL of the image's major, or the image's own
product (OpenShift / a layered product) at its version or version-neutral.
`stated` is True only when the deciding statement is about our product and our
package / image / build; inferences are published marked as such.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from . import versions as V
from .csaf import OPEN, Document, Statement
from .workload import WorkloadContext, image_core, same_ocp_component

FP = "✅ FALSE POSITIVE"
POS = "❌ POSITIVE"

SEVERITY_FROM_SCANNER = {
    'CRITICAL_VULNERABILITY_SEVERITY': 'Critical', 'HIGH_VULNERABILITY_SEVERITY': 'Important',
    'IMPORTANT_VULNERABILITY_SEVERITY': 'Important', 'MODERATE_VULNERABILITY_SEVERITY': 'Moderate',
    'MEDIUM_VULNERABILITY_SEVERITY': 'Moderate', 'LOW_VULNERABILITY_SEVERITY': 'Low',
    'CRITICAL': 'Critical', 'HIGH': 'Important', 'IMPORTANT': 'Important',
    'MEDIUM': 'Moderate', 'MODERATE': 'Moderate', 'LOW': 'Low',
}
_ECOSYSTEM = {'GO': 'golang', 'PYTHON': 'pypi', 'NODEJS': 'npm', 'JAVA': 'maven',
              'RUBY': 'gem', 'RUST': 'cargo'}


@dataclass
class Verdict:
    result: str
    fix: str
    note: str
    severity: str = 'Unknown'
    state: str = 'Unknown'
    stated: bool = False
    kind: str = ''
    statements: List[Statement] = field(default_factory=list)
    product: str = ''

    def as_list(self) -> list:
        return [self.result, self.fix, self.note, self.severity, self.state, self.stated]


def _col(row, key) -> str:
    v = str(row.get(key, '') or '') if key in row else ''
    return '' if v.lower() in ('nan', 'none') else v


def _flag(s: Statement) -> str:
    return f" ({s.flag.replace('_', ' ')})" if s.flag else ''


def _about(s: Statement) -> str:
    """'<image>, <product>' for an image statement, '<product>' otherwise."""
    keys = sorted(s.image_keys)
    return f"{keys[0]}, {s.product.name}" if keys else s.product.name


def _labels(sts, n=3) -> str:
    return ', '.join(sorted({s.product.name or s.product.id for s in sts})[:n])


# ══════════════════════════════════════════════════════════════════════════════
# the image and its products
# ══════════════════════════════════════════════════════════════════════════════

class Scope:
    """What is ours: the image's identity and the products it ships in."""

    def __init__(self, ctx: WorkloadContext, doc: Document):
        self.ctx, self.doc = ctx, doc
        self.major = str(ctx.rhel_ver or '')
        self.minor = int(ctx.rhel_minor) if str(ctx.rhel_minor or '').isdigit() else None
        self.digests = ctx.own_digests()
        self.paths = self._paths()
        self.core = ctx.image_component() if ctx.workload_type == 'ocp' else None
        self.mine = [s for s in doc.images() if self.names_us(s)]
        cpe = (ctx.cpe or '').replace('cpe:/', '').split(':')
        self.keys = {cpe[2]} if len(cpe) > 2 and cpe[2] else set()
        if ctx.workload_type == 'ocp' or ctx.ocp_ver:
            self.keys.add('openshift')
        self.keys |= {s.product.key for s in self.mine
                      if s.product.family in ('ocp', 'layered') and s.product.key}
        # An image without a CPE label belongs to the product whose images share
        # its registry namespace (openshift-gitops-1/… → OpenShift GitOps).
        spaces = {p.split('/')[0] for p in self.paths
                  if not re.fullmatch(r'(rhel|ubi)\d*', p.split('/')[0])}
        if not self.keys and spaces:
            self.keys |= {s.product.key for s in doc.images()
                          if s.product.family in ('ocp', 'layered') and s.product.key
                          and any(k.split('/')[0] in spaces for k in s.image_keys if '/' in k)}
        self.version = ctx.ocp_ver if 'openshift' in self.keys and ctx.ocp_ver else \
            (cpe[3] if len(cpe) > 3 and cpe[3] else self._label_version())
        self.stamp = V.build_stamp(ctx.image_build)

    def _paths(self) -> set:
        out = set()
        if self.ctx.image_ref:
            bare = re.sub(r'@.*$', '', self.ctx.image_ref)
            bare = re.sub(r':[^/]*$', '', bare)
            parts = bare.split('/')
            if len(parts) >= 3 or (len(parts) == 2 and '.' not in parts[0]):
                out.add('/'.join(parts[1:] if '.' in parts[0] or ':' in parts[0] else parts))
        if self.ctx.image_ns and self.ctx.image_name:
            out.add(f'{self.ctx.image_ns}/{self.ctx.image_name}')
        return {p.lower() for p in out if '/' in p and 'ocp-v4.0-art-dev' not in p}

    def _label_version(self) -> str:
        m = re.match(r'v?(\d+\.\d+)', str(self.ctx.image_build or ''))
        return m.group(1) if m else ''

    @property
    def stream(self) -> str:
        return f'el{self.major}_{self.minor}' if self.minor is not None else f'RHEL {self.major}'

    def names_us(self, s: Statement) -> bool:
        """Does an image statement name this image (any build of it)?"""
        if s.digest and s.digest in self.digests:
            return True
        keys = s.image_keys
        if keys & self.paths:
            return True
        if self.core:                       # OCP payload component (art-dev pulls)
            return any(same_ocp_component(self.core, image_core(k), self.major) for k in keys)
        return False

    def relation(self, p) -> str:
        """'ours' | 'other-version' | 'other' for a statement's product."""
        if p.family == 'vendor':
            return 'ours'
        if p.family == 'rhel':
            return 'ours' if p.major == self.major else 'other'
        if p.key not in self.keys:
            return 'other'
        if not p.version or not self.version:
            return 'ours'
        return 'ours' if _same_version(p.version, self.version) else 'other-version'

    def ours(self, s: Statement) -> bool:
        return self.relation(s.product) == 'ours'

    def rhel_stream(self, s: Statement) -> Optional[str]:
        """How a RHEL statement relates to the image's stream: 'line' (the
        version-neutral product), 'same' (our minor), 'earlier-main', 'later-main',
        'side' (another minor's EUS/AUS/…), None (not RHEL of our major)."""
        p = s.product
        if p.family != 'rhel' or p.major != self.major:
            return None
        if p.minor is None:
            return 'line'
        minor = self.minor
        if p.minor == minor:
            return 'same'
        if not p.mainline:
            return 'side'
        if minor is None:                   # minor unknown: the current mainline,
            return 'earlier-main'           # which carries every mainline fix
        return 'earlier-main' if p.minor < minor else 'later-main'


def _same_version(a: str, b: str) -> bool:
    ka, kb = a.lstrip('v').split('.')[:2], b.lstrip('v').split('.')[:2]
    return ka == kb[:len(ka)] or kb == ka[:len(kb)]


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r'\d+', v)[:3])


# ══════════════════════════════════════════════════════════════════════════════
# entry point
# ══════════════════════════════════════════════════════════════════════════════

def judge(row, ctx: WorkloadContext, doc: Optional[Document]) -> Verdict:
    if doc is None:
        return Verdict(POS, 'N/A', 'VEX file missing.', 'Unknown', 'Unknown', False, 'vex_missing')
    t = _Judge(row, ctx, doc)
    v = t.osv_check(t.decide())
    v.severity = t.severity(v)
    v.state = t.state(v)
    v.product = _labels(v.statements, 3) if v.statements else ''
    return v


class _Judge:
    def __init__(self, row, ctx, doc):
        self.row, self.ctx, self.doc = row, ctx, doc
        self.comp = str(row.get('COMPONENT', ''))
        self.version = str(row.get('VERSION', ''))
        self.source = _col(row, 'SOURCE').upper()
        self.srpm = _col(row, 'SRPM')
        self.module = _col(row, 'MODULE')
        self.owner = _col(row, 'OWNER_RPM')
        rpm_major = V.rhel_major(self.version)
        if rpm_major and self.source == 'OS' and rpm_major != ctx.rhel_ver:
            ctx = ctx.with_rhel(rpm_major)         # the rpm's own .elN is authoritative
            self.ctx = ctx
        self.scope = Scope(self.ctx, doc)
        if self.scope.minor is None and self.source == 'OS':
            m = V.rhel_minor(self.version)          # el9_6: at least 9.6
            if m and m.isdigit():
                self.scope.minor = int(m)

    # ── the binary's own modules (OSV) ────────────────────────────────────
    def osv_check(self, v: Verdict) -> Verdict:
        """An inferred POSITIVE (the shipping product's version-neutral line,
        the errata assumption, another version's fix) checked against what
        the binaries really contain: the SBOM lists the modules compiled into
        them and OSV the CVE's vulnerable ranges.  Red Hat's statements about
        this build are never second-guessed.

          the CVE's packages present, all past the fix  → FALSE POSITIVE
          OSV names them, none is in these binaries     → FALSE POSITIVE
          one is in the vulnerable range                → POSITIVE, with the proof
        """
        ev = self.ctx.osv_evidence
        if ev is None or v.result != POS or v.stated or v.kind in ('vex_missing', 'not_red_hat'):
            return v
        cve = str(self.row.get('CVE', '')).strip().upper()
        if self.source == 'IMAGE' or ('/' in self.comp and self.source in ('OS', '')):
            got, where = ev.judge(cve), 'this image'
        elif self.source == 'OS':
            got, where = ev.judge(cve, owner=self.comp), f"{self.comp}'s binaries"
        else:
            got, where = ev.judge(cve, module=(self.comp, self.version)), self.comp
        if got is None:
            return v
        state, what = got
        if state == 'affected':
            v.note += f" OSV: {_mods(what)} in the vulnerable range."
            return v
        if state == 'clear':
            note = f"OSV: {_mods(what)} past the fix. Red Hat (inferred): {v.note}"
            kind = 'osv_past_fix'
        else:
            note = (f"OSV: the vulnerable package ({', '.join(what[:3])}) is not in {where}. "
                    f"Red Hat (inferred): {v.note}")
            kind = 'osv_not_present'
        return Verdict(FP, 'N/A', note, stated=False, kind=kind, statements=v.statements)

    # ── the ladder ─────────────────────────────────────────────────────────
    def decide(self) -> Verdict:
        doc, scope = self.doc, self.scope
        if doc.vendor_not_affected:
            st = [s for s in doc.statements if s.product.family == 'vendor']
            return Verdict(FP, 'N/A', 'No supported Red Hat product affected.', stated=True,
                           kind='vendor', statements=st)
        own = [s for s in doc.statements if s.digest and s.digest in scope.digests]
        if own:
            return self._own_build(own)
        # an image pseudo-component: SOURCE=IMAGE, or RHACS's `rhel9/buildah` OS
        # row (Go module paths carry a '/' too, under their own ecosystem)
        if self.source == 'IMAGE' or ('/' in self.comp and self.source in ('OS', '')):
            return self._image() or self._errata_assumed() or self._not_listed()
        if self.source == 'OS' or (V.rhel_major(self.version) and not self.source):
            if self.comp in (self.ctx.sbom_foreign_rpms or ()):
                return self._not_red_hat(self.comp)
            v = self._image_clear() or self._rpm(self.comp, self.version, self.srpm, self.module)
            # not named: RHEL lists every affected rpm.  The image's own verdict
            # belongs to its IMAGE row, not to every rpm inside it.
            return v or self._not_listed()
        return self._package()

    def _image_clear(self) -> Optional[Verdict]:
        """Red Hat states this image (not one build: no digest) not affected in
        our product, and nothing open about it: that covers what is inside it
        (rhel9/buildah under RHEL 9 for CVE-2025-65637, while the buildah rpm
        itself is known_affected)."""
        sts = [s for s in self.scope.mine if not s.digest and self.scope.ours(s)]
        if not sts or any(s.status != 'known_not_affected' for s in sts):
            return None
        s = sts[0]
        return Verdict(FP, 'N/A', f"known_not_affected{_flag(s)} for this image ({_about(s)}).",
                       stated=True, kind='img_kna_contents', statements=[s])

    def _own_build(self, own) -> Verdict:
        for st in ('known_affected', 'under_investigation', 'known_not_affected', 'fixed'):
            hit = [s for s in own if s.status == st]
            if not hit:
                continue
            s = hit[0]
            what = f"this image build ({s.product.name})"
            if st in OPEN:
                return Verdict(POS, 'N/A', f"{st} — {what}.", stated=True, kind='own_' + st,
                               statements=hit)
            if st == 'known_not_affected':
                return Verdict(FP, 'N/A', f"known_not_affected{_flag(s)} — {what}.", stated=True,
                               kind='own_kna', statements=hit)
            return Verdict(FP, 'N/A', f"This image build is a fixed build ({s.product.name}).",
                           stated=True, kind='own_fixed', statements=hit)

    def _errata_assumed(self) -> Optional[Verdict]:
        """Nothing names this image / module, but Red Hat lists our product as
        affected (or under investigation) and cleared nothing under that same
        product node: the list is not an enumeration of our product, and the
        errata policy assumes its unnamed packages vulnerable (VEX-MODEL §5g).
        A clear under the same node means Red Hat did enumerate it (CVE-2024-45337:
        74 images affected, 8,476 cleared) and our absence is meaningful.
        Sweeps under sibling nodes do not count (§10e)."""
        scope = self.scope
        mine = _vkey(scope.version) if scope.version else None

        def counts(s):
            """Our product at our version, the line, or a newer version (a
            previous version is assumed vulnerable: RHACS 3 under RHACS 4)."""
            rel = scope.relation(s.product)
            return rel == 'ours' or (rel == 'other-version' and mine is not None
                                     and _vkey(s.product.version) > mine)
        ours = [s for s in self.doc.statements if s.product.family in ('ocp', 'layered')
                and s.product.key in scope.keys and counts(s)]
        for status in ('known_affected', 'under_investigation'):
            hit = [s for s in ours if s.status == status]
            nodes = {s.product.id for s in hit}
            if not hit or any(s.product.id in nodes and s.status not in OPEN for s in ours):
                continue
            if status == 'under_investigation':
                note = f"under_investigation in {_labels(hit)} — Red Hat has not finished " \
                       f"assessing this product."
            else:
                note = f"Not explicitly cleared; Red Hat lists {_labels(hit)} as affected and " \
                       f"cleared nothing under it — assumed vulnerable (errata policy)."
            return Verdict(POS, 'N/A', note, stated=False, kind='errata_assumed_' + status,
                           statements=hit[:1])
        return None

    def _not_red_hat(self, comp) -> Verdict:
        """Red Hat neither built it nor shipped it: its VEX covers Red Hat's
        builds only, and its silence about a third party's is no clear."""
        who = self.ctx.vendor if self.ctx.vendor and not self.ctx.vendor.lower().startswith('red hat') \
            else 'a third party'
        return Verdict(POS, 'N/A', f"{comp} is not a Red Hat build (shipped by {who}) — Red Hat's "
                                   f"VEX does not cover it.", stated=False, kind='not_red_hat')

    def _not_listed(self) -> Verdict:
        return Verdict(FP, 'N/A', f"'{self.comp}' not listed as affected in Red Hat's VEX.",
                       stated=False, kind='not_listed')

    # ── rpm ────────────────────────────────────────────────────────────────
    def _rpm_statements(self, name, version, srpm, module, foreign=False) -> List[Statement]:
        """Statements about this rpm in our products — or, with *foreign*, in
        the product that ships it: an rpm RHEL never names belongs to the
        product whose version line it carries (openshift-clients 4.20.0 →
        OpenShift 4, openshift-serverless-clients 1.17.0 → Serverless 1),
        wherever the image comes from.  A product of another version line is
        not its maker (JBoss EAP 5's openssl, OpenShift 3.0's clients)."""
        scope = self.scope
        upstream = re.sub(r'^\d+:', '', version).split('-')[0]
        out = []
        for s in self.doc.named(name, srpm):
            if s.kind not in ('rpm', 'none') or '/' in s.name:
                continue
            if foreign:
                cpe = (s.product.cpe or '').replace('cpe:/', '').split(':')
                pv = s.product.version or (cpe[3] if len(cpe) > 3 else '')
                if s.product.family not in ('ocp', 'layered') or scope.ours(s) or not pv or \
                        s.product.major not in ('', scope.major) or \
                        pv.split('.')[0] != upstream.split('.')[0] or \
                        not _made_by(name, version, s.product):
                    continue
                # a version-neutral statement speaks for the line or for the
                # rpm's own minor; builds of any minor compare by NEVRA (4.20's
                # client carries a fix 4.13 shipped)
                if not s.version and not ('.' not in pv or upstream == pv
                                          or upstream.startswith(pv + '.')):
                    continue
            elif not scope.ours(s):
                continue
            if s.product.family == 'rhel' and scope.rhel_stream(s) is None:
                continue
            if s.name != name and s.version and \
                    re.sub(r'^\d+:', '', s.version).split('-')[0] != upstream:
                continue                    # a source build's version is not this binary's
            if not self._module_applies(s, module, version):
                continue
            if s.version and s.status not in OPEN and not V.same_lineage(version, s.version):
                continue
            out.append(s)
        # Statements about our module stream outrank the stream-less version-less
        # ones (RHEL 8 "postgresql: not affected" beside fixes for every
        # postgresql:12 stream).
        if module and module != 'non-modular' and any(s.module == module for s in out):
            out = [s for s in out if s.module or s.version]
        return out

    @staticmethod
    def _module_applies(s: Statement, module: str, version: str) -> bool:
        """With the SBOM's modularityLabel: a versioned statement only for the
        same stream, a version-less one for its stream or (no stream) for all.
        Without it, the version heuristic (VEX-MODEL §9.1a)."""
        if not module:
            return V.module_stream_applies(s.pid, version)
        if not s.version and not s.module:
            return True
        return s.module == ('' if module == 'non-modular' else module)

    def _rpm(self, name, version, srpm='', module='') -> Optional[Verdict]:
        sts = self._rpm_statements(name, version, srpm, module)
        if not sts and not any(s.product.family == 'rhel' for s in self.doc.named(name, srpm)):
            sts = self._rpm_statements(name, version, srpm, module, foreign=True)
            if sts:                         # the rpm's own product, not the image's
                v = self._rpm_decide(name, version, sts)
                if v:
                    v.stated = False
                    v.kind += '_shipping_product'
                return v
        if not sts:
            return None
        return self._rpm_decide(name, version, sts)

    def _rpm_decide(self, name, version, sts) -> Optional[Verdict]:
        prefix = self._sbom_prefix(name, version)
        # A versioned known_not_affected marks that build clean, like a fix: RHEL
        # backports, so one upstream version holds different code per stream
        # (glibc 2.28: the 8.6 EUS builds "vulnerable code not present", fixed in
        # 8.8 and 8.10).  A not-affected build of our upstream version speaks for
        # the code we have when it is our own stream's (glibc 2.28-189.5.el8_6
        # under 8.6 EUS's 189.10), or when nothing is fixed or open for the
        # package at all (openssl-fips-provider 3.0.7-6.el9_5 for 3.0.7-2.el9).
        upstream = _upstream(version)
        settled = not any(s.status == 'fixed' or s.status in OPEN for s in sts)
        same_code = [s for s in sts if s.status == 'known_not_affected' and s.version
                     and _upstream(s.version) == upstream
                     and (settled or self.scope.rhel_stream(s) == 'same')]
        fixed = [s for s in sts if s.version and (s.status == 'fixed' or (
            s.status == 'known_not_affected' and s not in same_code))]
        # 1. this exact build
        for s in sts:
            if s.version and s.status in ('fixed', 'known_not_affected') and \
                    V.installed_cmp(version, s.version) == 0:
                what = 'a fixed build' if s.status == 'fixed' else f"not affected{_flag(s)}"
                return Verdict(FP, s.version if s.status == 'fixed' else 'N/A',
                               f"{prefix}This build is {what} ({s.product.name}).", stated=True,
                               kind='rpm_exact_' + s.status, statements=[s])
        # The rpm's provenance picks whose statements decide: a plain .elN build
        # comes from RHEL's repositories, so RHEL's ladder does; an rhaos /
        # el8pc / … build comes from its product.  A not-affected from the
        # other side still clears: RHEL's is about the code (libzstd for the
        # zstd CLI's CVE-2021-24031, whatever OpenShift's blanket "out of support
        # scope"), the image's own product's about its context (systemd's
        # CVE-2025-4598 in OpenShift 4, fixed in RHEL only from 9.7).
        rhel = [s for s in sts if s.product.family == 'rhel']
        layered = [s for s in sts if s.product.family not in ('rhel', 'vendor')]
        other_kna = []
        if rhel and layered:
            sts, other = (rhel, layered) if V.lineage(version) == ('el', None) else (layered, rhel)
            fixed = [s for s in fixed if s in sts]
            same_code = [s for s in same_code if s in sts]
            other_kna = [s for s in other if s.status == 'known_not_affected' and not s.version]
        v = self._rpm_ladder(version, sts, fixed, same_code, prefix)
        if v and v.result == POS and other_kna:
            k = other_kna[0]
            return Verdict(FP, 'N/A', f"{prefix}known_not_affected{_flag(k)} ({k.product.name}) — "
                                      f"otherwise: {v.note[len(prefix):]}", stated=True, kind='rpm_kna_product',
                           statements=[k])
        return v

    def _rpm_ladder(self, version, sts, fixed, same_code, prefix) -> Optional[Verdict]:
        scope = self.scope

        def stream(s):
            return scope.rhel_stream(s) if s.product.family == 'rhel' else 'same'

        def against(fixes, why=''):
            fixes = sorted(fixes, key=lambda s: _vsort(s.version))
            failing = next((s for s in fixes if V.installed_cmp(version, s.version) < 0), None)
            if failing is None:
                s = fixes[-1]
                return Verdict(FP, s.version, f"{prefix}Installed {version} >= fix {s.version}{why}.",
                               stated=True, kind='rpm_fixed', statements=[s])
            return Verdict(POS, failing.version,
                           f"{prefix}Installed {version} < fix {failing.version}{why}.",
                           stated=True, kind='rpm_fix_pending', statements=[failing])

        # 2. a fix in the image's lineage
        same = [s for s in fixed if stream(s) in ('same', 'line')]
        if same:
            return against(same)
        earlier = [s for s in fixed if stream(s) == 'earlier-main']
        if earlier:
            newest = max(earlier, key=lambda s: _vsort(s.version))
            return against([newest], f", a mainline fix the {scope.stream} image inherits")
        # 3. open for our line / stream / product
        mine = [s for s in sts if stream(s) in ('same', 'line')]
        opened = [s for s in mine if s.status in OPEN]
        if opened:
            return self._open(opened, prefix, others=fixed)
        # 4. not affected
        kna = [s for s in mine if s.status == 'known_not_affected' and not s.version] + same_code
        if kna:
            return Verdict(FP, 'N/A', f"{prefix}known_not_affected{_flag(kna[0])} "
                                      f"({kna[0].product.name}).", stated=True, kind='rpm_kna',
                           statements=kna)
        # 5. a fix only in later or side streams
        if fixed:
            ref = _upgrade(fixed, scope.minor, version)
            # mainline builds are cumulative: at or past a later minor's mainline
            # fix, the build carries it (criu 3.18-4.module+el8.9.0+21697 is a
            # rebuild of the 8.10 GA fix +20326).  Side branches number their
            # releases on their own, so only newer than all of them counts.
            later = [s for s in fixed if stream(s) == 'later-main']
            low = min(later, key=lambda s: _vsort(s.version)) if later else None
            if low is not None and V.installed_cmp(version, low.version) >= 0:
                return Verdict(FP, low.version, f"{prefix}Installed {version} >= mainline fix "
                                                f"{low.version} ({low.product.name}).",
                               stated=False, kind='rpm_past_mainline_fix', statements=[low])
            if all(V.installed_cmp(version, s.version) >= 0 for s in fixed):
                return Verdict(FP, ref.version, f"{prefix}Installed {version} is newer than every "
                                                f"fix Red Hat shipped ({ref.version}).",
                               stated=False, kind='rpm_newer_than_fixes', statements=[ref])
            return Verdict(POS, ref.version, f"{prefix}No fix in {scope.stream}. "
                                             f"Fix in other streams: {ref.version}.",
                           stated=True, kind='rpm_fix_elsewhere', statements=[ref])
        return None

    def _open(self, opened, prefix, others=()) -> Verdict:
        s = next((x for x in opened if x.status == 'known_affected'), opened[0])
        if s.status == 'under_investigation':
            return Verdict(POS, 'N/A', f"{prefix}under_investigation ({_about(s)}) — Red Hat "
                                       f"has not assessed this yet.", stated=True, kind='ui',
                           statements=[s])
        elsewhere = sorted({x.product.name for x in others if x not in opened})
        plan = f" {s.plan_detail or 'no_fix_planned'}." if s.plan == 'no_fix_planned' else ''
        tail = f" Fix only in: {', '.join(elsewhere[:3])}." if elsewhere else \
            ('' if plan else ' No fix available.')
        return Verdict(POS, 'N/A', f"{prefix}known_affected ({_about(s)}).{plan}{tail}",
                       stated=True, kind='ka', statements=[s])

    # ── the image ──────────────────────────────────────────────────────────
    def _image(self) -> Optional[Verdict]:
        scope = self.scope
        if not scope.mine:
            return None
        rel = {}
        for s in scope.mine:
            rel.setdefault(scope.relation(s.product), []).append(s)
        ours = rel.get('ours', [])
        versioned = [s for s in ours if s.product.family != 'rhel' and s.product.version]
        line = [s for s in ours if s not in versioned]
        for group in (versioned, line):
            if not group:
                continue
            v = self._image_group(group)
            if v:
                return v
        other = rel.get('other-version', [])
        return self._image_other_versions(other) if other else None

    def _image_group(self, group) -> Optional[Verdict]:
        scope = self.scope
        fixed = [s for s in group if s.status == 'fixed']
        opened = [s for s in group if s.status in OPEN and not s.digest]
        kna = [s for s in group if s.status == 'known_not_affected']
        if fixed:
            builds = [s for s in fixed if s.digest]
            if not builds or len(builds) < len(fixed):
                s = next(x for x in fixed if not x.digest)
                return Verdict(FP, 'N/A', f"Fixed ({_about(s)}).", stated=True,
                               kind='img_fixed', statements=[s])
            # Order this version's assessed builds (fixed and not affected) by
            # build stamp: the nearest one at or before ours speaks for ours;
            # with none that old, a later fix means ours predates it.
            assessed = sorted((s for s in builds + [k for k in kna if k.digest] if s.stamp),
                              key=lambda s: s.stamp)
            if scope.stamp and assessed:
                before = [s for s in assessed if s.stamp <= scope.stamp]
                if before:
                    s = before[-1]
                    what = 'fixed' if s.status == 'fixed' else f"not affected{_flag(s)}"
                    return Verdict(FP, 'N/A', f"Built after {s.tag}, a {what} build "
                                              f"({_about(s)}).", stated=False,
                                   kind='img_after_fix' if s.status == 'fixed' else 'img_after_kna',
                                   statements=[s])
                first = next((s for s in assessed if s.status == 'fixed'), None)
                if first:
                    return Verdict(POS, f"build {first.tag}",
                                   f"Fixed build exists ({first.tag}, {first.product.name}); "
                                   f"this build predates it.", stated=True,
                                   kind='img_before_fix', statements=[first])
        if opened:
            return self._open(opened, '', fixed)
        if kna:
            s = next((x for x in kna if not x.digest), kna[0])
            other = ' (other builds of this image)' if s.digest else ''
            return Verdict(FP, 'N/A', f"known_not_affected{_flag(s)} ({_about(s)}){other}.",
                           stated=not s.digest, kind='img_kna', statements=[s])
        if fixed:                         # fixed builds we cannot order against ours
            return Verdict(FP, 'N/A', f"Fixed in {_labels(fixed)}; this build's order "
                                      f"unknown.", stated=False, kind='img_fixed_unordered',
                           statements=fixed[:1])
        return None

    def _image_other_versions(self, other) -> Optional[Verdict]:
        """Statements about this image only in other versions of its product."""
        scope = self.scope
        if not scope.version:
            return None
        ours = _vkey(scope.version)
        fixed = [s for s in other if s.status == 'fixed']
        newer_fix = [s for s in fixed if _vkey(s.product.version) > ours]
        if newer_fix:
            s = min(newer_fix, key=lambda s: _vkey(s.product.version))
            return Verdict(POS, 'N/A', f"Fixed only in a newer version ({s.product.name}); "
                                       f"{scope.version} is a previous version (errata policy).",
                           stated=False, kind='img_fixed_newer_version', statements=[s])
        opened = [s for s in other if s.status in OPEN and _vkey(s.product.version) > ours]
        if opened:
            return Verdict(POS, 'N/A', f"known_affected in a newer version "
                                       f"({opened[0].product.name}).", stated=False,
                           kind='img_open_newer_version', statements=opened[:1])
        if fixed:
            # Fixed only in older versions, maintained in parallel: whether the fix
            # existed when this build was made is a question of build time.
            stamped = sorted((s for s in fixed if s.stamp), key=lambda s: s.stamp)
            if scope.stamp and stamped and scope.stamp < stamped[0].stamp:
                s = stamped[0]
                return Verdict(POS, 'N/A', f"Fixed in an earlier version's build {s.tag} "
                                           f"({s.product.name}); this build predates it.",
                               stated=False, kind='img_predates_fix', statements=[s])
            s = max(fixed, key=lambda s: _vkey(s.product.version))
            return Verdict(FP, 'N/A', f"Newer than every fixed version ({s.product.name}).",
                           stated=False, kind='img_newer_than_fixes', statements=[s])
        kna = [s for s in other if s.status == 'known_not_affected']
        if kna:
            return Verdict(FP, 'N/A', f"known_not_affected in other versions "
                                      f"({_labels(kna)}).", stated=False,
                           kind='img_kna_other_version', statements=kna[:1])
        return None

    # ── a package inside the image ─────────────────────────────────────────
    def _package(self) -> Verdict:
        scope, comp = self.scope, self.comp
        eco = _ECOSYSTEM.get(self.source, '')
        names = {comp}
        if eco == 'maven' and ':' not in comp:
            purl = _col(self.row, 'PURL')
            m = re.match(r'pkg:maven/([^/]+)/([^@?]+)', purl)
            if m:
                names.add(f'{m.group(1)}:{m.group(2)}')
        sts = [s for s in self.doc.named(*names)
               if s.kind == eco and eco and scope.ours(s)]
        if sts:
            v = self._package_statements(sts)
            if v:
                return v
        v = self._image_clear()
        if v:
            return v
        owner = self.owner or (self.ctx.sbom_owner_map or {}).get(comp) or \
            (self.ctx.sbom_src_map or {}).get(comp)
        in_rhel_rpm = False
        if owner and owner.partition('@')[0] in (self.ctx.sbom_foreign_rpms or ()):
            owner = ''                      # shipped by a third-party rpm: not Red Hat's
        if owner:
            oname, _, over = owner.partition('@')
            if not over:
                have = sorted((self.ctx.sbom_packages or {}).get(oname) or [])
                over = max(have, key=_vsort) if have else ''
            if over:
                osrc = (self.ctx.sbom_src_map or {}).get(oname, '')
                v = self._rpm(oname, over, osrc)
                if v:
                    v.note = f"{comp} ships in {oname}-{over}: {v.note}"
                    return v
                # shipped in an rpm RHEL tracks: RHEL is its product and lists
                # every affected rpm — nothing to assume
                in_rhel_rpm = any(s.product.family == 'rhel' for s in self.doc.named(oname, osrc))
        img = self._image()
        if img:
            return img
        if not owner and self.ctx.red_hat_image() is False:
            return self._not_red_hat(comp)
        return (None if in_rhel_rpm else self._errata_assumed()) or self._not_listed()

    def _package_statements(self, sts) -> Optional[Verdict]:
        fixed = [s for s in sts if s.status == 'fixed' and s.version]
        for s in sts:
            if s.version and s.status in ('fixed', 'known_not_affected') and \
                    V.pkg_cmp(self.version, s.version) == 0:
                return Verdict(FP, s.version if s.status == 'fixed' else 'N/A',
                               f"This version is {'fixed' if s.status == 'fixed' else 'not affected'} "
                               f"({s.product.name}).", stated=True, kind='pkg_exact', statements=[s])
        if fixed:
            low = min(fixed, key=lambda s: _pkg_key(s.version))
            if V.pkg_cmp(self.version, low.version) >= 0:
                return Verdict(FP, low.version, f"Installed {self.version} >= fix {low.version} "
                                                f"({low.product.name}).", stated=True,
                               kind='pkg_fixed', statements=[low])
            return Verdict(POS, low.version, f"Installed {self.version} < fix {low.version} "
                                             f"({low.product.name}).", stated=True,
                           kind='pkg_fix_pending', statements=[low])
        opened = [s for s in sts if s.status in OPEN]
        if opened:
            return self._open(opened, '')
        kna = [s for s in sts if s.status == 'known_not_affected']
        if kna:
            return Verdict(FP, 'N/A', f"known_not_affected{_flag(kna[0])} ({kna[0].product.name}).",
                           stated=True, kind='pkg_kna', statements=kna[:1])
        return None

    # ── severity / state ───────────────────────────────────────────────────
    def severity(self, v: Verdict) -> str:
        for s in v.statements:
            if s.severity:
                return s.severity
        scope = self.scope
        related = [s for s in self.doc.named(self.comp, self.srpm) if scope.ours(s) and s.severity]
        related += [s for s in scope.mine if scope.ours(s) and s.severity]
        if related:
            return min((s.severity for s in related), key=lambda x: _SEV_RANK.get(x, 9))
        sev = self.doc.aggregate_severity or self.doc.any_severity or self.doc.cvss_severity
        if not sev:
            sev = SEVERITY_FROM_SCANNER.get(str(self.row.get('SEVERITY', '')).strip().upper(), '')
        return sev or 'Unknown'

    def state(self, v: Verdict) -> str:
        """Red Hat's CVE-page wording, from the deciding statement's own plan."""
        if v.kind == 'vex_missing':
            return 'Unknown'
        if v.result == FP:
            return 'Fixed' if any(s.status == 'fixed' for s in v.statements) and \
                v.kind not in ('rpm_newer_than_fixes', 'img_newer_than_fixes',
                               'img_kna_other_version', 'osv_past_fix',
                               'osv_not_present') else 'Not affected'
        if v.kind == 'ui' or any(s.status == 'under_investigation' for s in v.statements):
            return 'Under investigation'
        for s in v.statements:
            if s.plan == 'no_fix_planned':
                return s.plan_detail or 'Will not fix'
            if s.plan == 'none_available':
                d = s.plan_detail or 'Affected'
                return 'Fix deferred' if 'defer' in d.lower() else d
        if v.fix not in ('', 'N/A'):
            return 'Fix available'
        return 'Affected'

    # ── SBOM note ──────────────────────────────────────────────────────────
    def _sbom_prefix(self, name, version) -> str:
        have = (self.ctx.sbom_packages or {}).get(name)
        if not self.ctx.sbom_packages:
            return ''
        if have is None:
            return f"{name}-{version} (not in SBOM); "
        if str(version) in have or any(_same_rpm(version, h) for h in have):
            return f"{name}-{version} (SBOM verified); "
        best = max(have, key=_vsort)
        return f"{name}-{version} (SBOM has: {best}); "


_SEV_RANK = {'Critical': 0, 'Important': 1, 'Moderate': 2, 'Low': 3}


def _made_by(name: str, version: str, product) -> bool:
    """Is this rpm the product's own?  Its name carries the product's
    (openshift-clients, openshift-serverless-clients), or its dist tag is
    OpenShift's (rhaos).  A version line alone is a coincidence waiting to
    happen: python3-decorator 4.4.2 is RHEL's, not OpenShift 4's."""
    if V.lineage(version)[0] == 'rhaos' and product.key == 'openshift':
        return True
    generic = {'red', 'hat', 'container', 'platform', 'for', 'and', 'enterprise'}
    words = [w for w in product.key.split('_') if w and w not in generic]
    return bool(words) and all(w in name.lower() for w in words)


def _mods(mods) -> str:
    names = sorted({f'{m[1]} {m[2]}' for m in mods})
    return ', '.join(names[:3]) + (f' (+{len(names) - 3})' if len(names) > 3 else '')


def _upstream(v: str) -> str:
    return re.sub(r'^\d+:', '', v).split('-')[0]


def _same_rpm(a, b) -> bool:
    try:
        return V.installed_cmp(a, b) == 0
    except Exception:
        return False


def _vsort(v):
    """Sort key for rpm versions (rpm order via a comparison wrapper)."""
    import functools
    return functools.cmp_to_key(V.installed_cmp)(v)


def _pkg_key(v):
    import functools
    return functools.cmp_to_key(V.pkg_cmp)(v)


def _upgrade(fixed, minor, installed) -> Statement:
    """The fix to name when our stream has none: among the fixes the build is
    below, the nearest later minor's, else the newest (never a side-branch
    backport numbered below the installed build)."""
    fixed = [s for s in fixed if V.installed_cmp(installed, s.version) < 0] or fixed
    later = [s for s in fixed if s.product.minor is not None and minor is not None
             and s.product.minor > minor]
    if later:
        return min(later, key=lambda s: s.product.minor)
    return max(fixed, key=lambda s: _vsort(s.version))
