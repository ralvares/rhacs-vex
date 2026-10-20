"""Put it together: an image (+ scanner findings, or none: the free scan) → verdicts."""
from __future__ import annotations

from dataclasses import dataclass

from .engine import Engine, Scope, resolve
from .model import VEX_KIND, Finding, Image, Package, Verdict


@dataclass
class Row:
    finding: Finding
    verdict: Verdict


def candidates(image: Image, index, scope: Scope) -> list:
    """The free scan: every (CVE, package) Red Hat's statements could be about —
    rpms by binary and source name, modules by their purl names, and the image
    itself by its paths and digests."""
    out = []
    rpms = image.rpms()
    names = {p.name for p in rpms} | {p.source for p in rpms if p.source}
    hits = index.cves_naming('rpm', names)
    for p in rpms:
        for cve in sorted(hits.get(p.name, set()) | hits.get(p.source, set())):
            out.append(Finding(cve, p, 'free'))
    by_kind: dict = {}
    for p in image.packages:
        kind = VEX_KIND.get(p.kind)
        if kind and kind != 'rpm':
            by_kind.setdefault(kind, []).append(p)
    for kind, pkgs in by_kind.items():
        names = {p.name for p in pkgs} | {p.name.split(':', 1)[1] for p in pkgs if kind == 'maven' and ':' in p.name}
        hits = index.cves_naming(kind, names)
        for p in pkgs:
            cves = hits.get(p.name, set()) | (hits.get(p.name.split(':', 1)[1], set()) if kind == 'maven' else set())
            for cve in sorted(cves):
                out.append(Finding(cve, p, 'free'))
    me = image_package(image, scope)
    for cve in sorted(index.cves_for_image(scope.paths, image.digests)):
        out.append(Finding(cve, me, 'free'))
    return out


def image_package(image: Image, scope: Scope) -> Package:
    """The image itself, as the subject of image-level statements."""
    path = sorted(scope.paths)[0] if scope.paths else (image.name_label or image.repo)
    tag = '-'.join(x for x in (image.labels.get('version', ''), image.labels.get('release', '')) if x)
    return Package('image', path, tag, purl='')


def triage(image: Image, index, findings: list | None = None) -> tuple:
    """→ (Scope, [Row]). Without findings, the free scan's candidates are judged."""
    scope = resolve(image, index)
    engine = Engine(index, scope)
    if findings is None:
        findings = candidates(image, index, scope)
    return scope, [Row(f, engine.judge(f)) for f in findings]
