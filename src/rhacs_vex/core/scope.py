"""Is a VEX product the scanned workload's product? (VEX-MODEL §8a)

Every statement is filtered through this before it may decide anything:

  ubi      RHEL base repos of the workload's RHEL major
  ocp      + "Red Hat OpenShift Container Platform <v>" (version prefix-matched)
           + image-label CPE prefix-covered by the parent's CPE
           + any product carrying the workload's RHEL major (Fast Datapath …)
  operator + catalog / namespace prefixes (token-boundary matched)
           + the document's own registry-namespace → product map
"""
from __future__ import annotations

import functools
import re

from .vexdoc import VexDocument, parent_of
from .workload import WorkloadContext


def other_version(image_cpe: str, vex_cpe: str) -> bool:
    """Same product, another version stream (§1e).

    Layered products are published per version — `Red Hat Web Terminal 1.13`
    is `cpe:/a:redhat:webterminal:1.13::el9` — and the image says which one it
    is (`cpe` label `…:webterminal:1.16::el9`).  A statement about 1.13's
    builds says nothing about 1.16, exactly as an el9_4 fix says nothing
    about el9_6.  The version-neutral product (`webterminal:1`) still covers.
    """
    if not image_cpe or not vex_cpe:
        return False

    def parts(cpe):
        return re.sub(r'^cpe:[/\d.]*:*', '', cpe).strip(':').split(':')

    img, vex = parts(image_cpe), parts(vex_cpe)
    if len(img) < 4 or len(vex) < 4 or not img[3] or not vex[3]:
        return False
    if [x.lower() for x in img[:3]] != [x.lower() for x in vex[:3]]:
        return False
    return not cpe_covers(image_cpe, ':'.join(['cpe:/' + vex[0]] + vex[1:4]))


def cpe_covers(image_cpe: str, vex_cpe: str) -> bool:
    """Image CPE prefix-covered by a VEX CPE, component-wise (§4b).

    Empty VEX components are wildcards; a shorter VEX version covers a longer
    image version ('4' covers '4.12').
    """
    def parts(cpe):
        return re.sub(r'^cpe:[/\d.]*:*', '', cpe).strip(':').split(':')

    img, vex = parts(image_cpe), parts(vex_cpe)
    while vex and vex[-1] == '':
        vex.pop()
    if len(vex) < 3 or len(img) < 3:
        return False
    for i, comp in enumerate(vex):
        if i >= len(img):
            return False
        if not comp:
            continue
        if i == 3:
            if img[i].split('.')[:len(comp.split('.'))] != comp.split('.'):
                return False
        elif comp.lower() != img[i].lower():
            return False
    return True


def is_rhel_base(pid: str, rhel: str, doc: VexDocument) -> bool:
    """A RHEL base repo PID of this major (names from the product tree, §1a)."""
    if parent_of(pid) not in doc.rhel_base and pid not in doc.rhel_base:
        return False
    return _names_rhel(pid, rhel, broad=False)


def mentions_rhel(pid: str, rhel: str) -> bool:
    """Any PID carrying this RHEL major, layered/middleware included."""
    return _names_rhel(pid, rhel, broad=True)


def _names_rhel(pid: str, rhel: str, broad: bool) -> bool:
    low = pid.lower()
    if f'enterprise_linux_{rhel}' in low:
        return True
    if broad and (f'_rhel_{rhel}' in low or f'_rhel{rhel}' in low):
        return True
    if re.search(rf'\.el{rhel}[_.\-a-z]', pid) or re.search(rf'\.el{rhel}$', pid):
        return True
    if re.search(rf'^[a-zA-Z]+-{rhel}[.\-]', pid):
        return True
    return broad and bool(re.search(rf'^{rhel}[A-Za-z]', pid))


@functools.lru_cache(maxsize=4096)
def _token_re(prefix: str):
    return re.compile(rf'(?:^|[^a-z0-9]){re.escape(prefix)}(?:[^a-z0-9]|$)')


def prefix_matches(prefix: str, pid_lower: str) -> bool:
    """Does a catalog/namespace prefix name this PID's product?

    Path prefixes ('rhoai/') keep substring semantics; bare tokens ('ai',
    'odf') must sit on a token boundary — 'ai' must not match the stream name
    `BaseOS-8.10.0.Z.M(AI)N.EUS`.
    """
    p = prefix.lower()
    if not p:
        return False
    if p.endswith('/'):
        return p in pid_lower
    return bool(_token_re(p).search(pid_lower))


def in_scope(pid: str, ctx: WorkloadContext, doc: VexDocument) -> bool:
    """Memoised per (document, workload scope key, pid)."""
    cache = doc.scope_cache.setdefault(ctx.scope_key(), {})
    hit = cache.get(pid)
    if hit is None:
        hit = cache[pid] = _in_scope(pid, ctx, doc)
    return hit


def _in_scope(pid: str, ctx: WorkloadContext, doc: VexDocument) -> bool:
    if is_rhel_base(pid, ctx.rhel_ver, doc):
        return True
    if ctx.workload_type == "ubi":
        return False

    parent = parent_of(pid)
    if ctx.workload_type == "ocp":
        pname = doc.name.get(parent) or doc.name.get(pid, '')
        if 'openshift container platform' in pname.lower():
            want = (ctx.ocp_ver or "4").split('.')
            have = pname.split()[-1].split('.')
            return want[:len(have)] == have
        vcpe = doc.cpe.get(parent, '')
        if ctx.cpe and vcpe and cpe_covers(ctx.cpe, vcpe):
            return True
        return mentions_rhel(pid, ctx.rhel_ver)

    if ctx.cpe and other_version(ctx.cpe, doc.cpe.get(parent, '')):
        return False
    low = pid.lower()
    if any(prefix_matches(p, low) for p in ctx.extra_prefixes):
        return True
    if ctx.image_ns:
        products = doc.ns_products.get(ctx.image_ns.lower(), set())
        if parent in products or any(prefix_matches(p, low) for p in products):
            return True
    return False
