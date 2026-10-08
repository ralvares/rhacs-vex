"""The triage decision: one scanner finding × one workload × one VEX document.

    triage(row, ctx, data) -> Verdict

A scanner (RHACS, grype, trivy, or the scan-free SBOM index) only proposes a
(component, CVE) pair.  This module decides whether Red Hat's own VEX says the
pair is a real vulnerability in THIS image, and with what evidence.  The
verdict, its severity, its state and its fix version all come from the same
decisive statement (VEX-MODEL §8d).

Why it is more than a CVE lookup — Red Hat does not assess every component the
way scanners report it:

  * rpms are enumerated exhaustively, per binary subpackage and minor stream,
    so a version compare against the right stream decides (§6);
  * Go / Python / npm modules are effectively never tracked as purls (2 golang
    purls in the whole corpus).  Red Hat assesses vendored code at the image
    that ships it (an OCI purl or image path under the operator/OCP product) or
    at the rpm that vendors it (buildah for golang.org/x/net).  So a non-rpm
    finding is decided by the IMAGE's statements first, then the owning rpm;
  * absence means different things: an rpm missing from an exhaustive
    enumeration is not affected, but a product Red Hat lists as affected and
    never cleared for this image stays assumed-vulnerable (errata policy §5g).

Decision ladder, first decisive rung wins (VEX-MODEL §8b):

    1  vendor catch-all not-affected                         → FALSE POSITIVE
    2  a statement carries this build's exact digest          → per-build verdict
       — split: rpm (has an .elN marker or SOURCE=OS) vs everything else —
    rpm      5  component (or its source rpm) in scope: KNA > fixed > KA > UI,
                fixed → stream-aware version compare (§6b)
             9  not named: image-level open statement / scoped UI → POSITIVE,
                else not listed → FALSE POSITIVE (unstated)
    non-rpm  3  image identity (OCI purl, image path, generic) incl. other builds
             -  not-affected flags naming this component or digest
             4  digest-pinned image statements about this image path
             -  product_status naming the component (or owning rpm)
             6  product-family fallthrough / errata assumption / not listed

`stated` is True only when a statement names this product/image/component; the
OpenVEX exporter publishes nothing else.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from . import versions as V
from .scope import in_scope, is_rhel_base, mentions_rhel
from .vexdoc import (CLEAR, OPEN, STATUSES, VexDocument, component_of, digest_of,
                     parent_of)
from .workload import WorkloadContext, image_core, image_rhel, same_ocp_component

FP = "✅ FALSE POSITIVE"
POS = "❌ POSITIVE"

SEVERITY_FROM_SCANNER = {
    'CRITICAL_VULNERABILITY_SEVERITY':  'Critical',
    'HIGH_VULNERABILITY_SEVERITY':      'Important',
    'IMPORTANT_VULNERABILITY_SEVERITY': 'Important',
    'MODERATE_VULNERABILITY_SEVERITY':  'Moderate',
    'MEDIUM_VULNERABILITY_SEVERITY':    'Moderate',
    'LOW_VULNERABILITY_SEVERITY':       'Low',
    'CRITICAL':  'Critical', 'HIGH': 'Important', 'IMPORTANT': 'Important',
    'MEDIUM':    'Moderate',  'MODERATE': 'Moderate', 'LOW': 'Low',
}
_SEV_RANK = {'Critical': 0, 'Important': 1, 'Moderate': 2, 'Low': 3}

# Clear verdicts whose meaning is "this build carries the fix" (state Fixed).
_FIXED_KINDS = {'digest_fixed', 'rpm_fixed_pass', 'errata_fixed', 'img_sha_fixed'}

# Decisions that rest on ABSENCE (or on statements naming other products only):
# shown in triage, never published as a vendor claim.
UNSTATED_KINDS = {
    'rpm_not_listed', 'nonrpm_not_listed', 'img_not_listed',
    'ft_other', 'ft_novex_scoped', 'ft_operator_novex', 'ft_not_affected',
    'ft_clear', 'ft_rhel_clear', 'errata_newer',
}


@dataclass
class Decision:
    """The decisive match: what severity/state/fix are read from."""
    kind: str = ''
    status: str = ''
    pids: List[str] = field(default_factory=list)
    fix_set: bool = False
    unstated: bool = False

    def set(self, kind, status=None, pids=None, fix_set=None):
        self.kind = kind
        if status is not None:
            self.status = status
        if pids is not None:
            self.pids = list(pids)
        if fix_set is not None:
            self.fix_set = fix_set


@dataclass
class Verdict:
    result: str              # FP / POS
    fix: str
    note: str
    severity: str
    state: str
    stated: bool
    decision: Decision

    def as_list(self) -> list:
        return [self.result, self.fix, self.note, self.severity, self.state, self.stated]


def _col(row, key) -> str:
    """Optional string column of a Series or mapping; '' for missing/NaN."""
    if key not in row:
        return ''
    v = str(row.get(key, '') or '')
    return '' if v.lower() in ('nan', 'none') else v


# ══════════════════════════════════════════════════════════════════════════════
# entry point
# ══════════════════════════════════════════════════════════════════════════════

def triage(row, ctx: WorkloadContext, data) -> Verdict:
    """Decide one finding.  *data* is a VexDocument or the raw CSAF dict
    (None = no VEX file)."""
    if data is None:
        return Verdict(POS, "N/A", "VEX file missing.", "Unknown", "Unknown", False,
                       Decision(kind='vex_missing'))
    doc = VexDocument.of(data)
    t = _Triage(doc, ctx, row)
    result, fix, note = t.decide()
    dec = t.dec
    return Verdict(result, fix, note,
                   severity=_severity(doc, dec, t.ctx0, row),
                   state=_state(doc, dec, result, t.ctx0),
                   stated=dec.kind not in UNSTATED_KINDS and not dec.unstated,
                   decision=dec)


class _Triage:
    def __init__(self, doc: VexDocument, ctx: WorkloadContext, row):
        self.doc, self.ctx0, self.ctx = doc, ctx, ctx
        self.comp = str(row['COMPONENT'])
        self.version = str(row['VERSION'])
        self.source = _col(row, 'SOURCE')
        self.srpm = _col(row, 'SRPM')
        self.fixed_version = str(row.get('FIXED_VERSION', '')) if 'FIXED_VERSION' in row else None
        self.dec = Decision()

    def scoped(self, pid) -> bool:
        return in_scope(pid, self.ctx, self.doc)

    def names(self) -> set:
        return component_names(self.comp, self.ctx)

    # ── rungs 1-2, then the split ──────────────────────────────────────────
    def decide(self):
        doc, ctx, dec = self.doc, self.ctx, self.dec
        if doc.catchall_not_affected:
            dec.set('catchall')
            return FP, "N/A", "No supported Red Hat product affected."

        own = ctx.own_digests()
        if own:
            hits = {}
            for st, pid in doc.pids('known_affected', 'under_investigation', 'fixed',
                                    'known_not_affected'):
                if any(sh in pid for sh in own):
                    hits.setdefault(st, pid)
            if hits:
                return self._own_build(hits)

        rpm_rhel = None
        if '/' not in self.comp:
            rpm_rhel = V.rhel_major(self.version) or (ctx.rhel_ver if self.source == 'OS' else None)
        if not rpm_rhel:
            result, fix, note = self._nonrpm()
            if not ('/' in self.comp and self.source == 'OS'):
                sn = sbom_note(self.comp, self.version, self.ctx)
                if sn:
                    note = f"{note} {sn}." if note.endswith('.') else f"{note}; {sn}."
            return result, fix, note
        if rpm_rhel != ctx.rhel_ver:
            # the rpm's own .elN marker is authoritative (mixed images)
            self.ctx = ctx.with_rhel(rpm_rhel)
        return self._rpm()

    def _own_build(self, hits):
        """Rung 2: Red Hat assessed this exact build (digest in the PID)."""
        for st in OPEN:
            if st in hits:
                pid = hits[st]
                self.dec.set('digest_' + ('ka' if st == 'known_affected' else 'ui'),
                             status=st, pids=[pid])
                return POS, "N/A", f"{st} — this image build ({self.doc.label(pid)})."
        if 'known_not_affected' in hits:
            pid = hits['known_not_affected']
            self.dec.set('digest_kna', status='known_not_affected', pids=[pid])
            return FP, "N/A", f"known_not_affected — this image build ({self.doc.label(pid)})."
        pid = hits['fixed']
        self.dec.set('digest_fixed', status='fixed', pids=[pid])
        return FP, "N/A", f"This image build is the fixed build ({self.doc.label(pid)})."

    # ══════════════════════════════════════════════════════════════════════
    # rpm path (rungs 5, 5s, 9)
    # ══════════════════════════════════════════════════════════════════════
    def _rpm(self):
        doc, ctx, dec = self.doc, self.ctx, self.dec
        found_v, comp = self.version, self.comp
        names = self.names() | src_aliases(doc, comp, found_v, self.srpm)
        minor = V.rhel_minor(found_v)
        if not doc.vulns:
            dec.set('no_vulns')
            return POS, "N/A", "No vulnerability entries in VEX."
        # Red Hat publishes one vulnerability entry per CVE file; the rpm
        # statements are read from it.
        vuln = doc.vulns[0]
        cands = self._rpm_candidates(vuln, names)
        prefix = self._sbom_prefix()

        # A not-affected claim never clears a build with an applicable fix
        # pending: KNA rows often describe the fixed build or the product line,
        # not the older NEVRA installed.
        def fix_pending():
            for st, _pid, ver in cands:
                if st != 'fixed' or not ver:
                    continue
                fminor = V.rhel_minor(ver)
                if minor and fminor and fminor != minor:
                    continue
                if V.installed_cmp(found_v, ver) < 0:
                    return True
            return False

        if not fix_pending():
            for st, pid, ver in cands:
                if st != 'known_not_affected':
                    continue
                kminor = V.rhel_minor(ver) if (minor and ver) else None
                if kminor and kminor != minor:
                    continue                        # KNA of another minor stream
                dec.set('rpm_kna', status='known_not_affected', pids=[pid])
                return FP, "N/A", f"{prefix}{ctx.display_name}: known_not_affected."

        fixed = [(ver, parent_of(pid) in doc.rhel_base, pid)
                 for st, pid, ver in cands if st == 'fixed' and ver]
        if fixed:
            fixed.sort(key=lambda t: not t[1])      # RHEL base-repo fix as reference
            unique, pid_by_ver = [], {}
            for ver, _base, pid in fixed:
                if ver not in pid_by_ver:
                    unique.append(ver)
                    pid_by_ver[ver] = pid
            affected = any(st in OPEN for st, _p, _v in cands)
            return compare_fixed(found_v, unique, comp, ctx, dec, pid_by_ver, affected)

        ka = [pid for st, pid, _v in cands if st == 'known_affected']
        if ka:
            pid = ka[0]
            dec.set('rpm_ka', status='known_affected', pids=[pid])
            no_fix = {p for r in vuln.remediations if r.get('category') == 'no_fix_planned'
                      for p in r.get('product_ids', [])}
            elsewhere = set()
            for _st, fpid in vuln.pids('fixed'):
                if mentions_rhel(fpid, ctx.rhel_ver) and not self.scoped(fpid):
                    fpkg, _ = doc.package(fpid)
                    if fpkg and fpkg in names:
                        elsewhere.add(doc.label(fpid))
            if pid in no_fix:
                return POS, "N/A", f"{prefix}known_affected. no_fix_planned."
            if elsewhere:
                return POS, "N/A", (f"{prefix}known_affected. Fix only in: "
                                    f"{', '.join(sorted(elsewhere))}.")
            return POS, "N/A", f"{prefix}known_affected. No fix available."

        ui = [pid for st, pid, _v in cands if st == 'under_investigation']
        if ui:
            dec.set('rpm_ui', status='under_investigation', pids=[ui[0]])
            return POS, "N/A", f"under_investigation for {ctx.display_name}."

        # rung 9 — the package is not named.  A statement about OUR IMAGE still
        # outranks silence about the package.
        st, labels, pids = self._image_open()
        if st:
            dec.set('rpm_img_open', status=st, pids=pids)
            return POS, "N/A", f"{_open_phrase(st)}. This image: {_first(labels, 2)}."
        labels, pids = self._scoped_ui(names)
        if labels:
            dec.set('rpm_ui_scope', status='under_investigation', pids=pids)
            return POS, "N/A", (f"under_investigation in {_first(labels, 3)} — "
                                f"Red Hat has not assessed this yet.")
        dec.set('rpm_not_listed')
        return FP, "N/A", f"'{comp}' not listed as affected in VEX."

    def _rpm_candidates(self, vuln, names):
        """[(status, pid, version)] naming one of *names*, in scope, module-stream
        compatible, ordered KNA > fixed > KA > UI with exact-name matches first
        inside a status; cross-lineage versioned clears dropped (§6b)."""
        doc, found_v = self.doc, self.version
        rank = {'known_not_affected': 0, 'fixed': 1, 'known_affected': 2,
                'under_investigation': 3}
        stream = [('known_not_affected', p) for p in vuln.status['known_not_affected']]
        stream += [('known_not_affected', p) for _l, p in vuln.flag_pids()]
        stream += list(vuln.pids('fixed', 'known_affected', 'under_investigation'))
        out = []
        for st, pid in stream:
            if not self.scoped(pid) or not V.module_stream_applies(pid, found_v):
                continue
            name, ver = doc.package(pid)
            if name in names:
                out.append((st, pid, ver, name))
        out.sort(key=lambda t: (rank[t[0]], 0 if t[3] == self.comp else 1))
        return [(s, p, v) for s, p, v, _n in out
                if not v or s in OPEN or V.same_lineage(found_v, v)]

    def _sbom_prefix(self) -> str:
        sn = sbom_note(self.comp, self.version, self.ctx)
        return f"{sn}; " if sn else ''

    # ══════════════════════════════════════════════════════════════════════
    # non-rpm path (rungs 3, 4, 6, 7, 9)
    # ══════════════════════════════════════════════════════════════════════
    def _nonrpm(self):
        doc, ctx, dec, comp = self.doc, self.ctx, self.dec, self.comp
        affected, fixed, not_affected, investigating = doc.product_summary()
        if not (affected or fixed or not_affected or investigating):
            dec.set('nonrpm_not_listed')
            return FP, "N/A", "Not listed as affected; VEX names no products for this CVE."

        if ctx.workload_type != "ubi":
            if ctx.workload_type in ("ocp", "operator"):
                got = self._image_identity()
                if got is not None:
                    decided = self._from_image_identity(*got)
                    if decided is not None:
                        return decided

            got = self._component_flag()
            if got is not None:
                return got
            if '/' in comp:
                got = self._image_digest_statements()
                if got is not None:
                    return got
            got = self._component_status()
            if got is not None:
                return got
        return self._fallthrough(affected, fixed, not_affected, investigating)

    # ── rung 3/4/7: the image's own statements ─────────────────────────────
    def _image_identity(self):
        """Statements naming THIS image (any build), ranked (rungs 3a/3b, 4, 7).

        Returns (token, pid, extra) with token ∈ FALSE_POSITIVE / POSITIVE /
        POSITIVE_OTHER_RHEL / NOT_LISTED, or None when nothing about the image
        family exists in scope.
        """
        doc, ctx = self.doc, self.ctx
        own = ctx.own_digests()
        matched = doc.oci_matches(ctx.oci_candidates())
        if own:
            for _st, pid in doc.pids('known_not_affected', 'known_affected', 'fixed',
                                     'under_investigation'):
                if digest_of(pid) in own:
                    leaf, _ = doc.package(pid)
                    if leaf:
                        matched.add(leaf)

        if ctx.workload_type == "ocp":
            core = ctx.ocp_component or (image_core(ctx.image_name) if ctx.image_name else None)
            if not core:
                return None
            def names_us(pkg):
                if pkg in matched:
                    return True
                return same_ocp_component(core, image_core(pkg) if '/' in pkg else pkg,
                                          ctx.rhel_ver)
        elif ctx.workload_type == "operator":
            if not ctx.image_name:
                return None

            def names_us(pkg):
                return pkg in matched or pkg.split('/')[-1] == ctx.image_name
        else:
            return None

        matches = []                      # (status, pid, rhel_quality, flag, own_digest)
        family = False
        own_streams = set()               # OCP minors where Red Hat fixed THIS image
        for vuln in doc.vulns:
            flag_of = vuln.flag_label()

            def consider(st, pid, flag):
                nonlocal family
                pkg, _ = doc.package(pid)
                if not pkg:
                    return
                is_path = '/' in pkg
                # a bare image name with an oci purl (`rhcos@sha256:…`) is an
                # image identity too, named without its digest
                is_oci = not is_path and doc.purl.get(pkg, '').startswith('pkg:oci/')
                generic = not (is_path or is_oci) and doc.is_generic(pkg)
                if not (is_path or is_oci or generic):
                    return
                ours = names_us(_purl_name(doc.purl.get(pkg, '')) or pkg
                                if (is_oci or generic) else pkg)
                if not self.scoped(pid):
                    # our image, fixed in another OCP stream: remembered for
                    # the errata ordering below
                    m = re.search(r'RHOSE[.-](\d+\.\d+)', pid)
                    if ours and st == 'fixed' and m:
                        own_streams.add(m.group(1))
                    return
                if is_path:
                    family = True
                if not ours:
                    return
                if generic or is_oci:
                    family = True
                prh = image_rhel(pkg)
                quality = 2 if prh == ctx.rhel_ver else (1 if prh is None else 0)
                d = digest_of(pid)
                matches.append((st, pid, quality, flag, bool(d and d in own)))

            for st, pid in vuln.pids('known_not_affected', 'known_affected', 'fixed',
                                     'under_investigation'):
                consider(st, pid, flag_of.get(pid, ''))
            for label, pid in vuln.flag_pids():
                if any(p == pid and s == 'known_not_affected' for s, p, *_ in matches):
                    continue
                consider('known_not_affected', pid, label)

        if any(m[4] for m in matches):     # this build's own assessment wins
            matches = [m for m in matches if m[4]]
        not_listed = ('NOT_LISTED', '', '') if family else None

        if not matches:
            if ctx.workload_type == "ocp" and ctx.ocp_ver and (own_streams or not family):
                streams = own_streams or doc.fixed_ocp_streams()
                if streams:
                    cur = [int(x) for x in ctx.ocp_ver.split('.') if x.isdigit()]
                    newest = max(streams, key=_vkey)
                    if _vkey(newest) == cur:
                        return 'FALSE_POSITIVE', '', f'errata_fixed:{newest}'
                    if _vkey(newest) < cur:
                        return 'FALSE_POSITIVE', '', f'errata_not_previous:{newest}'
            return not_listed

        best = max(m[2] for m in matches)
        if best == 0:
            aff = [(p, fl) for s, p, _q, fl, _o in matches if s in OPEN]
            return ('POSITIVE_OTHER_RHEL', aff[0][0], aff[0][1]) if aff else not_listed

        cands = [(s, p, fl) for s, p, q, fl, _o in matches if q >= max(best, 1)]
        if not cands:
            return not_listed

        open_ = [(s, p) for s, p, _fl in cands if s in OPEN]
        if open_:
            st, pid = open_[0]
            # A generic known_affected (no RHOSE stream) covers all of OCP 4; a
            # release at or past the newest fixed stream is not a "previous
            # version" under the errata policy (§5g).  Not when Red Hat says
            # "Will not fix" for this image: no later stream carries a fix for
            # it (ose-rhel-coreos-8 stays affected while rhcos is fixed in 4.16).
            no_fix = any(cat == 'no_fix_planned' for cat, _d in doc.remediation.get(pid, []))
            if ctx.workload_type == "ocp" and ctx.ocp_ver and not no_fix and not any(
                    re.search(r'RHOSE[.-]\d+\.\d+', p)
                    for s, p, *_ in matches if s in OPEN):
                streams = doc.fixed_ocp_streams()
                if streams:
                    cur = [int(x) for x in ctx.ocp_ver.split('.') if x.isdigit()]
                    cur_minor = '.'.join(str(x) for x in cur[:2])
                    if cur_minor in streams:
                        return 'FALSE_POSITIVE', pid, f'errata_fixed:{cur_minor}'
                    newest = max(streams, key=_vkey)
                    if _vkey(newest) < cur:
                        return 'FALSE_POSITIVE', pid, f'errata_not_previous:{newest}'
            return 'POSITIVE', pid, st

        kna = [(p, fl) for s, p, fl in cands if s == 'known_not_affected']
        if kna:
            flag = next((fl for _p, fl in kna if fl), '')
            return 'FALSE_POSITIVE', kna[0][0], flag

        # fixed only.  A digest-less fixed PID clears the stream outright.  A
        # fixed PID pinned to ANOTHER build is ordered by Brew build stamp:
        # ours ≥ newest fix → the rebuild carries it; older → still vulnerable.
        fixed = [p for s, p, _fl in cands if s == 'fixed']
        generic = [p for p in fixed if not digest_of(p)]
        if generic:
            return 'FALSE_POSITIVE', generic[0], 'fixed'
        if fixed:
            ours = V.build_stamp(ctx.image_build)
            stamps = [t for t in (self._purl_stamp(p) for p in fixed) if t]
            if ours and stamps and ours < max(stamps):
                return 'POSITIVE', fixed[0], 'fixed'
            return 'FALSE_POSITIVE', fixed[0], 'fixed'
        return not_listed

    def _purl_stamp(self, pid):
        purl = self.doc.purl_for(pid)
        m = re.search(r'[?&]tag=([^&]+)', purl) if purl else None
        return V.build_stamp(m.group(1)) if m else None

    def _from_image_identity(self, token, pid, extra):
        """Turn an image-identity result into a verdict; None = keep going."""
        doc, ctx, dec, comp = self.doc, self.ctx, self.dec, self.comp
        pids = [pid] if pid else []
        if pid:
            lbl = doc.label(pid)
            pkg = component_of(pid)
            img_lbl = f"{lbl} — {pkg}" if pkg not in lbl else lbl
        else:
            img_lbl = ctx.display_name

        if token == 'FALSE_POSITIVE':
            if extra.startswith('errata_'):
                tag, ver = extra.split(':', 1)
                if tag == 'errata_fixed':
                    dec.set('errata_fixed', status='fixed', pids=pids)
                    return FP, "N/A", f"Fixed in OCP {ver}."
                dec.set('errata_newer', pids=pids)   # §5g inference, never published
                return FP, "N/A", f"Build newer than newest fixed stream (OCP {ver})."
            fixed = extra == 'fixed'
            flag = f" ({extra.replace('_', ' ')})" if extra and not fixed else ""
            sha = digest_of(pid) if pid else None
            if sha and sha not in ctx.own_digests():
                # Pinned to ANOTHER build of this image.  It is Red Hat's verdict
                # for the vendored Go inside that build, but build stamps order
                # time, not content — our build may have added the dependency —
                # so it is shown, never published as a claim about ours.
                dec.unstated = True
            elif not sha and pid and re.search(r'\d+\.\d+$', parent_of(pid).strip()):
                # versionless image PID under a minor-versioned product ("Web
                # Terminal 1.11"): our build's membership in it is unproven
                dec.unstated = True
            if fixed:
                dec.set('img_fp_fixed', status='fixed', pids=pids)
                return FP, "N/A", f"Fixed. {img_lbl}."
            dec.set('img_fp_kna', pids=pids)
            return FP, "N/A", f"known_not_affected{flag}. {img_lbl}."

        if token == 'POSITIVE':
            st = extra if extra in ('known_affected', 'under_investigation', 'fixed') \
                else 'known_affected'
            if st == 'under_investigation':
                dec.set('img_pos_ui', status=st, pids=pids)
                return POS, "N/A", f"under_investigation. {img_lbl}."
            if st == 'fixed':
                dec.set('img_pos_fixed_older', status='known_affected', pids=pids,
                        fix_set=False)
                return POS, "N/A", f"Fixed build exists ({img_lbl}); this build predates it."
            dec.set('img_pos', status='known_affected', pids=pids)
            return POS, "N/A", f"{st}. {img_lbl}."

        if token == 'POSITIVE_OTHER_RHEL':
            dec.set('img_pos', status='known_affected', pids=pids)
            return POS, "N/A", f"known_affected for different RHEL ({img_lbl})."

        # NOT_LISTED: the image family was assessed but this image is not named.
        if ctx.sbom_src_map and ctx.sbom_src_map.get(comp):
            # A vendoring rpm is known (go binary inside an rpm): Red Hat may
            # track the CVE on that rpm — let the component rungs decide.
            return None
        ref = ctx.ocp_component or ctx.display_name
        st, labels, opids = self._image_open()
        if st:
            dec.set('img_open', status=st, pids=opids)
            return POS, "N/A", f"{_open_phrase(st)}. This image: {_first(labels, 2)}."
        labels, upids = self._scoped_ui(self.names())
        if labels:
            dec.set('img_ui_scope', status='under_investigation', pids=upids)
            return POS, "N/A", (f"under_investigation in {_first(labels, 3)} — Red Hat "
                                f"has not assessed this yet.")
        labels, apids = self._scoped_affected()
        if labels and not self._clears_under(apids):
            return self._errata_assumed(labels, apids, ref)
        dec.set('img_not_listed', pids=[])
        return FP, "N/A", f"{ref} not listed as affected."

    # ── not-affected flags / component statements ──────────────────────────
    def _component_flag(self):
        """A not-affected flag naming this component (or this build's digest)."""
        doc, ctx, comp = self.doc, self.ctx, self.comp
        own = ctx.own_digests()
        is_image = '/' in comp
        for vuln in doc.vulns:
            for label, pid in vuln.flag_pids():
                if not self.scoped(pid):
                    continue
                sha = digest_of(pid)
                if sha:
                    if sha not in own:
                        continue
                elif is_image and is_rhel_base(pid, ctx.rhel_ver, doc):
                    continue
                else:
                    pkg, _ = doc.package(pid)
                    if pkg and pkg not in self.names():
                        continue
                self.dec.set('nonrpm_flag', status='known_not_affected', pids=[pid])
                return FP, "N/A", (f"Not affected in {ctx.display_name} ({doc.label(pid)}): "
                                   f"{label.replace('_', ' ')}.")
        return None

    def _image_digest_statements(self):
        """Rung 4 for an image pseudo-component: digest PIDs of the same image path."""
        doc, ctx, dec = self.doc, self.ctx, self.dec
        own = ctx.own_digests()
        base = re.sub(r'[@:][^/]*$', '', self.comp)
        other_clear = False
        fixed_lbl = fixed_pid = None
        fix_ver = self.fixed_version
        for _st, pid in doc.pids('known_not_affected', 'fixed', 'known_affected',
                                 'under_investigation'):
            st = _st
            if not self.scoped(pid):
                continue
            sha = digest_of(pid)
            if not sha:
                continue
            if re.sub(r'@sha256:[a-f0-9]+.*$', '', component_of(pid)) != base:
                continue
            lbl = doc.label(pid)
            ours = sha in own
            if st == 'known_not_affected':
                if ours:
                    dec.set('img_sha_kna', status=st, pids=[pid])
                    return FP, "N/A", f"Image build not affected ({lbl})."
                other_clear = True
            elif st == 'fixed':
                if ours:
                    dec.set('img_sha_fixed', status=st, pids=[pid])
                    return FP, "N/A", f"Image build is the fixed version ({lbl})."
                fixed_lbl, fixed_pid = lbl, pid
            elif st == 'known_affected' and ours:
                dec.set('img_sha_ka', status=st, pids=[pid], fix_set=bool(fix_ver))
                note = f"; fix: {fix_ver}" if fix_ver else ""
                return POS, fix_ver or "N/A", f"Image build affected ({lbl}){note}."
            elif st == 'under_investigation' and ours:
                dec.set('img_sha_ui', status=st, pids=[pid])
                return POS, "N/A", f"under_investigation for {ctx.display_name}."
        if fixed_lbl and not other_clear:
            dec.set('img_sha_fixed_older', pids=[fixed_pid] if fixed_pid else [],
                    fix_set=bool(fix_ver))
            note = f" Fix: {fix_ver}." if fix_ver else ""
            return POS, fix_ver or "N/A", (f"Fixed build exists ({fixed_lbl}); installed "
                                           f"{self.version} is older.{note}")
        return None

    def _component_status(self):
        """product_status naming this component (or its owning rpm) in scope."""
        doc, ctx, dec = self.doc, self.ctx, self.dec
        own = ctx.own_digests()
        for st, pid in doc.pids('known_not_affected', 'known_affected', 'fixed',
                                'under_investigation'):
            if not self.scoped(pid):
                continue
            sha = digest_of(pid)
            if sha:
                if sha not in own:
                    continue
            else:
                pkg, _ = doc.package(pid)
                if pkg and pkg not in self.names():
                    continue
            lbl = doc.label(pid)
            if st == 'under_investigation':
                dec.set('nonrpm_ps_ui', status=st, pids=[pid])
                return POS, "N/A", f"under_investigation for {ctx.display_name}."
            if st == 'known_not_affected':
                dec.set('nonrpm_ps_kna', status=st, pids=[pid])
                return FP, "N/A", f"known_not_affected ({lbl})."
            if st == 'fixed':
                dec.set('nonrpm_ps_fixed', status=st, pids=[pid])
                return POS, "N/A", f"Fix exists ({lbl}); installed version not verified."
            dec.set('nonrpm_ps_ka', status=st, pids=[pid])
            return POS, "N/A", f"known_affected ({lbl})."
        return None

    # ── rung 6/9: nothing names this component ─────────────────────────────
    def _fallthrough(self, affected, fixed, not_affected, investigating):
        """Every statement naming this component or image was consumed above."""
        doc, ctx, dec = self.doc, self.ctx, self.dec
        if ctx.workload_type != "ubi":
            aff_lbl, aff_pids = self._scoped_affected()
            inv_lbl, inv_pids, clr_lbl, clr_pids = [], [], [], []
            for vuln in doc.vulns:
                for st, pid in vuln.pids('under_investigation'):
                    if self.scoped(pid):
                        inv_lbl.append(doc.label(pid))
                        inv_pids.append(pid)
                for st, pid in vuln.pids(*CLEAR):
                    if self.scoped(pid):
                        clr_lbl.append(doc.label(pid))
                        clr_pids.append(pid)
            if inv_lbl and not aff_lbl:
                dec.set('ft_ui', status='under_investigation', pids=inv_pids)
                return POS, "N/A", f"under_investigation in {_first(inv_lbl, 3)}."
            if clr_lbl and not aff_lbl and not inv_lbl:
                dec.set('ft_clear', pids=clr_pids)
                return FP, "N/A", (f"No affected entry in {_first(clr_lbl, 3)} "
                                   f"(known_not_affected/fixed only).")
            if aff_lbl:
                if self._clears_under(aff_pids):
                    # Red Hat cleared builds under our product for this CVE: the
                    # enumeration covered us, so our absence is meaningful.
                    dec.set('ft_novex_scoped')
                    return FP, "N/A", (f"Not listed as affected; known_affected in "
                                       f"{_first(aff_lbl, 3)} names other components only.")
                return self._errata_assumed(aff_lbl, aff_pids, self.comp)

        if ctx.workload_type == "operator" and (affected or investigating or fixed):
            dec.set('ft_operator_novex')
            return FP, "N/A", f"Not listed as affected; no VEX statement for {ctx.display_name}."
        if investigating:
            dec.set('ft_investigating_ui', status='under_investigation')
            return POS, "N/A", f"under_investigation in {', '.join(investigating[:3])}."
        if not_affected and not affected and not fixed:
            dec.set('ft_not_affected')
            return FP, "N/A", f"known_not_affected in {', '.join(not_affected[:3])}."
        if affected and not_affected and ctx.rhel_ver:
            tags = (f"RHEL {ctx.rhel_ver}", f"Red Hat Enterprise Linux {ctx.rhel_ver}")
            if (any(t in x for x in not_affected for t in tags)
                    and not any(t in x for x in affected for t in tags)):
                dec.set('ft_rhel_clear')
                return FP, "N/A", (f"RHEL {ctx.rhel_ver} not affected. Only affects: "
                                   f"{', '.join(affected[:2])}.")
        parts = []
        if affected:
            parts.append(f"affected: {', '.join(affected[:3])}")
        if fixed:
            parts.append(f"fixed: {', '.join(fixed[:3])}")
        if not_affected:
            parts.append(f"not affected: {', '.join(not_affected[:3])}")
        dec.set('ft_other')
        return FP, "N/A", (f"Not listed as affected; no VEX entry for {ctx.display_name}. "
                           f"Other products: {'; '.join(parts)}.")

    def _errata_assumed(self, labels, pids, what):
        """Red Hat lists our product as affected and cleared nothing under it:
        the errata policy assumes every unnamed package of it vulnerable (§5g)."""
        self.dec.set('ft_errata_assumed', status='known_affected', pids=pids)
        return POS, "N/A", (f"{what} not explicitly cleared; Red Hat lists "
                            f"{_first(labels, 3)} as affected and cleared nothing in "
                            f"this scope — per Red Hat's errata policy, assumed vulnerable.")

    # ── scoped statement sweeps ────────────────────────────────────────────
    def _names_our_image(self, pid) -> bool:
        """Does this PID name OUR image (not a sibling image of the product)?"""
        ctx = self.ctx
        comp = component_of(pid)
        sha = digest_of(pid)
        if sha:
            return sha in ctx.own_digests()
        if '/' not in comp and '@' not in comp:
            return False
        base = re.sub(r'@sha256:.*$', '', comp).split('/')[-1].lower()
        ours = {x.lower() for x in (ctx.image_name or '', ctx.ocp_component or '') if x}
        if base in ours:
            return True
        core = image_core(comp)
        return bool(core) and (core.lower() in ours or bool(
            ctx.ocp_component and same_ocp_component(ctx.ocp_component, core, ctx.rhel_ver)))

    def _image_open(self):
        """(status, labels, pids) when a statement about OUR image leaves it open."""
        for st in OPEN:
            labels, pids = [], []
            for _s, pid in self.doc.pids(st):
                if self._names_our_image(pid) and self.scoped(pid):
                    labels.append(self.doc.label(pid))
                    pids.append(pid)
            if labels:
                return st, labels, pids
        return None, [], []

    def _scoped_ui(self, names):
        """under_investigation about our image or one of our component names."""
        want = {n for n in set(names) | {self.comp} if n}
        labels, pids = [], []
        for _s, pid in self.doc.pids('under_investigation'):
            if not self.scoped(pid):
                continue
            pkg, _ = self.doc.package(pid)
            if self._names_our_image(pid) or (pkg and pkg in want):
                labels.append(self.doc.label(pid))
                pids.append(pid)
        return labels, pids

    def _scoped_affected(self):
        labels, pids = [], []
        for _s, pid in self.doc.pids('known_affected'):
            if self.scoped(pid):
                labels.append(self.doc.label(pid))
                pids.append(pid)
        return labels, pids

    def _clears_under(self, affected_pids) -> list:
        """In-scope clears under the SAME parent products listed as affected.

        Scope admits any product carrying our RHEL major, so a plain sweep for an
        OCP image also returns RHACM/MCE/RHACS clears — which say nothing about
        whether Red Hat assessed us.
        """
        parents = {parent_of(p) for p in affected_pids}
        if not parents:
            return []
        return [pid for _s, pid in self.doc.pids(*CLEAR)
                if parent_of(pid) in parents and self.scoped(pid)]


# ══════════════════════════════════════════════════════════════════════════════
# rpm version comparison against fixes (§6b)
# ══════════════════════════════════════════════════════════════════════════════

def compare_fixed(found_v, fixes, comp, ctx, dec, pid_by_ver, affected_in_scope=False):
    """Stream-aware comparison of the installed rpm against in-scope fixed NEVRAs.

    Minor-stream install (el9_4): only same-minor fixes count.  No fix in our
    stream: clear only when we are a strictly newer upstream version than every
    fix, or on a later minor than every fix with nothing of ours listed open;
    otherwise POSITIVE.  GA install (el9): must be ≥ every stream fix.
    """
    minor = V.rhel_minor(found_v)
    sn = sbom_note(comp, found_v, ctx)
    prefix = f"{sn}; " if sn else ''

    def decide(ver, kind, fix_set):
        dec.set(kind, status='fixed', fix_set=fix_set,
                pids=[pid_by_ver[ver]] if pid_by_ver.get(ver) else [])

    if minor:
        same = [v for v in fixes if V.rhel_minor(v) == minor]
        if not same:
            ref = fixes[0]
            if V.upstream_newer_than_all(found_v, fixes):
                decide(ref, 'rpm_fixed_newer_upstream', False)
                return FP, ref, (f"{prefix}Installed {found_v} is a newer upstream version "
                                 f"than every fix Red Hat shipped ({ref}).")
            if not affected_in_scope and V.later_stream_than_all(found_v, fixes):
                decide(ref, 'rpm_fixed_newer_stream', False)
                return FP, ref, (f"{prefix}Every fix Red Hat shipped predates el{ctx.rhel_ver}_"
                                 f"{minor} ({ref}) and installed {found_v} is newer than all "
                                 f"of them; no product of ours is listed affected.")
            decide(ref, 'rpm_fixed_fail', True)
            return POS, ref, (f"{prefix}No fix in el{ctx.rhel_ver}_{minor}. "
                              f"Fix in other streams: {ref}.")
        fixes = same

    failing = next((v for v in fixes if V.installed_cmp(found_v, v) < 0), None)
    if failing is None:
        decide(fixes[0], 'rpm_fixed_pass', False)
        return FP, fixes[0], f"{prefix}Installed {found_v} >= fix {fixes[0]}."
    decide(failing, 'rpm_fixed_fail', True)
    return POS, failing, f"{prefix}Installed {found_v} < fix {failing}."


# ══════════════════════════════════════════════════════════════════════════════
# component names
# ══════════════════════════════════════════════════════════════════════════════

def _purl_name(purl: str) -> str:
    """Name segment of a purl: `pkg:generic/redhat/rhcos@4.20…` → `rhcos`."""
    return purl.split('?')[0].split('@')[0].rsplit('/', 1)[-1] if purl else ''


def component_names(comp: str, ctx: WorkloadContext) -> set:
    """Names a VEX PID may use for this component (§7a).

    The SBOM's source/owning rpm (`python3-urllib3` → `python-urllib3`, a Go
    module → the rpm that vendors the binary) and Maven `group:artifact` →
    `artifact` (':' without '/', so Go paths and image refs are untouched).
    """
    names = {comp}
    src = ctx.sbom_src_map.get(comp) if ctx.sbom_src_map else None
    if src and src != comp:
        names.add(src)
    if ':' in comp and '/' not in comp and not comp.startswith('cpe:'):
        artifact = comp.rsplit(':', 1)[-1]
        if artifact and artifact != comp:
            names.add(artifact)
    return names


def src_aliases(doc: VexDocument, comp: str, found_v: str, srpm: str = '') -> set:
    """Source-rpm names a binary subpackage may be tracked under (§3f, rung 5s).

    A `.src` PID that dash-prefixes the component AND shares its
    version-release (or is version-less) built it.  The shared VR is
    load-bearing: python3-urllib3 is not built from python3.  A known SRPM (the
    purl's `upstream=`) always wins over the dash-prefix guess.
    """
    vr = found_v.split(':', 1)[-1] if ':' in found_v else found_v
    aliases = {src for src, vrs in doc.src_versions().items()
               if comp.startswith(src + '-') and (vr in vrs or None in vrs)}
    if srpm:
        aliases = {a for a in aliases if a == srpm} | {srpm}
    return aliases


def sbom_note(comp: str, version: str, ctx: WorkloadContext) -> str:
    """How the scanner's version relates to the image SBOM ('' without an SBOM)."""
    if not ctx.sbom_packages:
        return ''
    for name in component_names(comp, ctx):
        have = ctx.sbom_packages.get(name)
        if have is None:
            continue
        if not version or str(version) in ('nan', 'None'):
            return f"{comp} (in SBOM, version not reported)"
        ordered = sorted(have)
        best = ordered[0]
        for sv in ordered[1:]:
            try:
                if V.installed_cmp(sv, best) > 0:
                    best = sv
            except Exception:
                pass
        try:
            c = V.installed_cmp(version, best)
        except Exception:
            c = None
        if c == 0:
            return f"{comp}-{version} (SBOM verified)"
        if c is not None and c > 0:
            return f"{comp}-{version} (scanner reports newer than SBOM: {best})"
        if c is not None and c < 0:
            return f"{comp}-{version} (SBOM has newer: {best})"
        return f"{comp}-{version} (SBOM has: {best})"
    return f"{comp}-{version} (not in SBOM)"


# ══════════════════════════════════════════════════════════════════════════════
# severity and state — from the decisive statement (§8d)
# ══════════════════════════════════════════════════════════════════════════════

def _severity(doc: VexDocument, dec: Decision, ctx: WorkloadContext, row) -> str:
    """Decisive PID's impact (own digest > generic > uniform other builds), else
    the fallback chain: image → component → highest in-scope affected/fixed →
    aggregate → any impact → CVSS → scanner."""
    own = ctx.own_digests()
    if dec.pids:
        mine = [p for p in dec.pids if any(sh in p for sh in own)]
        generic = [p for p in dec.pids if '@sha256:' not in p]
        for p in mine + generic:
            s = doc.pid_severity(p)
            if s:
                return s
        rest = {s for s in (doc.pid_severity(p) for p in dec.pids
                            if p not in mine and p not in generic) if s}
        if len(rest) == 1:
            return rest.pop()
    return _severity_fallback(doc, ctx, str(row['COMPONENT']), row)


def _severity_fallback(doc: VexDocument, ctx: WorkloadContext, comp: str, row) -> str:
    sev = None
    if ctx.workload_type in ("ocp", "operator"):
        if doc.purl:
            own = ctx.own_digests()
            matched = doc.oci_matches(ctx.oci_candidates())
            mine = [p for p in matched if any(sh in p for sh in own)]
            generic = [p for p in matched if '@sha256:' not in p]
            sev = next((s for s in (doc.pid_severity(p) for p in mine + generic) if s), None)
            if not sev:
                other = {s for s in (doc.pid_severity(p) for p in matched
                                     if '@sha256:' in p and p not in mine) if s}
                if len(other) == 1:
                    sev = other.pop()
        if not sev:
            core = ctx.image_component()
            if core:
                for pid, s in doc.severity.items():
                    if '@sha256:' in pid or not in_scope(pid, ctx, doc):
                        continue
                    pkg, _ = doc.package(pid)
                    if pkg and same_ocp_component(core, image_core(pkg) if '/' in pkg else pkg,
                                                  ctx.rhel_ver):
                        sev = s
                        break
    if not sev:
        names = component_names(comp, ctx)
        for pid, s in doc.severity.items():
            if in_scope(pid, ctx, doc):
                pkg, _ = doc.package(pid)
                if pkg and pkg in names:
                    sev = s
                    break
    if not sev:
        found = {doc.severity[pid] for _st, pid in doc.pids('known_affected', 'fixed')
                 if pid in doc.severity and in_scope(pid, ctx, doc)}
        if found:
            sev = min(found, key=lambda s: _SEV_RANK.get(s, 9))
    if not sev:
        sev = doc.aggregate_severity or doc.any_impact
    if not sev and doc.any_cvss:
        sev = {'CRITICAL': 'Critical', 'HIGH': 'Important', 'MEDIUM': 'Moderate',
               'LOW': 'Low'}.get(doc.any_cvss, doc.any_cvss.title())
    if sev in (None, "None", ""):
        sev = SEVERITY_FROM_SCANNER.get(str(row.get('SEVERITY', '')).strip().upper())
    return sev if sev not in (None, "None", "", "nan") else "Unknown"


def _state(doc: VexDocument, dec: Decision, result: str, ctx: WorkloadContext) -> str:
    """Red Hat's CVE-page wording, from the decisive PID's own remediation.

    Never borrow another package's plan: openssl-fips-provider is "Affected"
    even when openssl in the same file is "Will not fix".
    """
    if dec.kind == 'vex_missing':
        return 'Unknown'
    if result == FP:
        return 'Fixed' if dec.kind in _FIXED_KINDS or dec.status == 'fixed' else 'Not affected'
    if dec.status == 'under_investigation' or dec.kind.endswith('_ui'):
        return 'Under investigation'

    def plan(pids):
        no_fix = none_avail = vendor = None
        for pid in pids:
            for cat, det in doc.remediation.get(pid, []):
                if cat == 'no_fix_planned' and no_fix is None:
                    no_fix = det or 'Will not fix'
                elif cat == 'none_available' and none_avail is None:
                    none_avail = det or 'Affected'
                elif cat == 'vendor_fix':
                    vendor = True
        return no_fix, none_avail, vendor

    no_fix, none_avail, vendor = plan(dec.pids)
    if no_fix:
        return no_fix
    if none_avail:
        return 'Fix deferred' if 'defer' in none_avail.lower() else none_avail
    if vendor or dec.fix_set:
        return 'Fix available'
    no_fix, none_avail, _ = plan([pid for _s, pid in doc.pids('known_affected')
                                  if in_scope(pid, ctx, doc)])
    if no_fix:
        return no_fix
    if none_avail:
        return 'Fix deferred' if 'defer' in none_avail.lower() else none_avail
    return 'Affected'


# ══════════════════════════════════════════════════════════════════════════════
# VEX_PRODUCT display label
# ══════════════════════════════════════════════════════════════════════════════

def vex_product(data, comp: str, ctx: WorkloadContext) -> str:
    """Product label(s) of the in-scope statements naming *comp* ('' if none)."""
    if not data:
        return ''
    try:
        doc = VexDocument.of(data)
        names = component_names(comp, ctx)
        labels, any_scoped = set(), False
        for v in doc.vulns:
            pids = {p for _s, p in v.pids(*STATUSES)} | {p for _l, p in v.flag_pids()}
            for pid in pids:
                if not in_scope(pid, ctx, doc):
                    continue
                any_scoped = True
                pkg, _ = doc.package(pid)
                if pkg in names and pid in doc.parent_label:
                    labels.add(doc.parent_label[pid])
        if labels:
            return ', '.join(sorted(labels))
        return ctx.display_name if any_scoped and ctx.display_name else ''
    except Exception:
        return ''


# ── small helpers ────────────────────────────────────────────────────────────

def _vkey(v: str) -> list:
    return [int(x) for x in v.split('.')]


def _first(labels, n) -> str:
    return ', '.join(sorted(set(labels))[:n])


def _open_phrase(status: str) -> str:
    return ('under_investigation — Red Hat has not assessed this yet'
            if status == 'under_investigation' else 'known_affected')
