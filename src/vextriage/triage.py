"""Put it together: an image (+ scanner findings, or none: the scan of the image
against Red Hat's VEX alone) → verdicts."""
from __future__ import annotations

from dataclasses import dataclass

from .engine import Engine, Scope, resolve
from .model import VEX_KIND, Finding, Image, Package, Verdict


@dataclass
class Row:
    finding: Finding
    verdict: Verdict


class View:
    """What Red Hat says that concerns one image, read from the index in a few
    queries: the statements about its rpms (binary and source names), its
    modules (purl names), its image paths and digests, the statements naming a
    product directly, and those of the image's own products (errata assumption)."""

    def __init__(self, image: Image, index, scope: Scope, cves=()):
        self.names: dict = {}                       # (kind, name) → comp ids
        ids = set()
        rpms = image.rpms()
        wanted = {'rpm': {p.name for p in rpms} | {p.source for p in rpms if p.source}}
        for p in image.packages:
            kind = VEX_KIND.get(p.kind)
            if kind and kind != 'rpm':
                wanted.setdefault(kind, set()).add(p.name)
                if kind == 'maven' and ':' in p.name:
                    wanted[kind].add(p.name.split(':', 1)[1])
        wanted.setdefault('image', set()).update(scope.paths)
        for kind, names in wanted.items():
            for i, name in index.comp_ids(kind, names).items():
                ids.add(i)
        ids |= index.digest_comp_ids(image.digests)
        self.docs = index.select(ids, cves, index.product_ids(scope.keys) if scope.keys else ())

    def doc(self, cve: str):
        return self.docs.get(cve.upper())

    def cves_naming(self, kind: str, names) -> dict:
        """{name: {cve, …}} of the documents whose statements name each (kind, name)."""
        names = set(names)
        out: dict = {}
        for cve, d in self.docs.items():
            for s in d.statements:
                if s.comp is not None and s.comp.kind == kind and s.comp.name in names:
                    out.setdefault(s.comp.name, set()).add(cve)
        return out

    def cves_for_image(self, paths, digests) -> set:
        paths, digests = set(paths), set(digests)
        return {cve for cve, d in self.docs.items() for s in d.statements
                if s.comp is not None and s.comp.kind == 'image'
                and (s.comp.name in paths or (s.comp.digest and s.comp.digest in digests))}


def candidates(image: Image, view: View, scope: Scope) -> list:
    """The scan: every (CVE, package) Red Hat's statements could be about —
    rpms by binary and source name, modules by their purl names, and the image
    itself by its paths and digests."""
    out = []
    rpms = image.rpms()
    hits = view.cves_naming('rpm', {p.name for p in rpms} | {p.source for p in rpms if p.source})
    for p in rpms:
        for cve in sorted(hits.get(p.name, set()) | hits.get(p.source, set())):
            out.append(Finding(cve, p, 'vex'))
    by_kind: dict = {}
    for p in image.packages:
        kind = VEX_KIND.get(p.kind)
        if kind and kind != 'rpm':
            by_kind.setdefault(kind, []).append(p)
    for kind, pkgs in by_kind.items():
        names = {p.name for p in pkgs} | {p.name.split(':', 1)[1] for p in pkgs if kind == 'maven' and ':' in p.name}
        hits = view.cves_naming(kind, names)
        for p in pkgs:
            cves = hits.get(p.name, set()) | (hits.get(p.name.split(':', 1)[1], set()) if kind == 'maven' else set())
            for cve in sorted(cves):
                out.append(Finding(cve, p, 'vex'))
    me = image_package(image, scope)
    for cve in sorted(view.cves_for_image(scope.paths, image.digests)):
        out.append(Finding(cve, me, 'vex'))
    return out


def image_package(image: Image, scope: Scope) -> Package:
    """The image itself, as the subject of image-level statements."""
    path = sorted(scope.paths)[0] if scope.paths else (image.name_label or image.repo)
    tag = '-'.join(x for x in (image.labels.get('version', ''), image.labels.get('release', '')) if x)
    return Package('image', path, tag, purl='')


def triage(image: Image, index, findings: list | None = None) -> tuple:
    """→ (Scope, [Row]). Without findings, the scan's candidates are judged."""
    scope = resolve(image, index)
    view = View(image, index, scope, {f.cve for f in findings} if findings else ())
    engine = Engine(view, scope)
    if findings is None:
        findings = candidates(image, view, scope)
    return scope, [Row(f, engine.judge(f)) for f in findings]
