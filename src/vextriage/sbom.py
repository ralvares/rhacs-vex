"""syft JSON → Image (identity, labels, os-release, packages, who owns what)."""
from __future__ import annotations

import json
import re
from typing import Optional

from .model import Image, Package
from .rpm import source_name

_KIND = {'rpm': 'rpm', 'go-module': 'go', 'java-archive': 'java', 'jenkins-plugin': 'java',
         'npm': 'npm', 'python': 'python', 'gem': 'gem', 'rust-crate': 'rust', 'dotnet': 'dotnet',
         'binary': 'binary', 'php-composer': 'php'}


def split_ref(ref: str) -> tuple:
    """'registry.redhat.io/openshift4/ose-cli-rhel9@sha256:…' → (registry, repo, digest hex)."""
    digest = ''
    m = re.search(r'@sha256:([0-9a-f]{64})', ref or '')
    if m:
        digest = m.group(1)
    bare = re.sub(r'@.*$', '', ref or '')
    parts = bare.split('/')
    if len(parts) > 1 and ('.' in parts[0] or ':' in parts[0] or parts[0] == 'localhost'):
        registry, rest = parts[0], parts[1:]
    else:
        registry, rest = ('docker.io' if bare else ''), parts
    if rest and ':' in rest[-1]:
        rest[-1] = rest[-1].split(':')[0]
    if registry in ('docker.io', 'index.docker.io') and len(rest) == 1:
        rest = ['library'] + rest
    return registry, '/'.join(rest).lower(), digest


def _hex(d: str) -> str:
    m = re.search(r'sha256:([0-9a-f]{64})', d or '')
    return m.group(1) if m else ''


def maven_name(purl_s: str, name: str) -> str:
    from .purl import parse
    p = parse(purl_s)
    if p.type == 'maven' and p.namespace:
        return f'{p.namespace}:{p.name}'
    return name


def python_name(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def package_name(kind: str, name: str, purl_s: str) -> str:
    if kind == 'java':
        return maven_name(purl_s, name)
    if kind == 'python':
        return python_name(name)
    return name


def image_from_source(target: dict, distro: Optional[dict] = None) -> Image:
    """The image half of a syft or grype document (source.metadata / source.target)."""
    target = target or {}
    ref = target.get('userInput', '') or ''
    registry, repo, ref_digest = split_ref(ref)
    digests = {d for d in [ref_digest, _hex(target.get('manifestDigest', ''))] if d}
    for rd in target.get('repoDigests') or []:
        r2, p2, d2 = split_ref(rd)
        if d2:
            digests.add(d2)
        if not registry and r2:
            registry, repo = r2, p2
    labels = target.get('labels') or {}
    img = Image(ref=ref, registry=registry, repo=repo, labels=dict(labels), digests=digests,
                arch=target.get('architecture', '') or '')
    distro = distro or {}
    img.os_id = (distro.get('id') or distro.get('name') or '').lower()
    ver = distro.get('versionID') or distro.get('version') or ''
    m = re.match(r'(\d+)(?:\.(\d+))?', ver)
    if m and img.os_id in ('rhel', 'redhat', 'red hat enterprise linux'):
        img.os_id = 'rhel'
        img.rhel_major = int(m.group(1))
        img.rhel_minor = int(m.group(2)) if m.group(2) else None
    return img


def settle_stream(img: Image) -> None:
    """No os-release minor: the newest elN_M among the image's rpms is its stream."""
    rpms = img.rpms()
    if img.rhel_major is None:
        majors = [p.dist.major for p in rpms if p.dist.token == 'el' and p.dist.major]
        if majors and not img.os_id:
            img.rhel_major = max(set(majors), key=majors.count)
            img.os_id = 'rhel'
    if img.rhel_major is not None and img.rhel_minor is None:
        minors = [p.dist.minor for p in rpms if p.dist.major == img.rhel_major and p.dist.minor is not None]
        if minors:
            img.rhel_minor = max(minors)


def read_syft(doc) -> Image:
    """A syft JSON document (path, dict or str) → Image with every package."""
    if isinstance(doc, str):
        with open(doc) as fh:
            doc = json.load(fh)
    src = doc.get('source') or {}
    img = image_from_source(src.get('metadata') or src.get('target') or {}, doc.get('distro'))
    if not img.ref and src.get('name'):
        img.ref = src['name']
    by_id = {}
    for a in doc.get('artifacts') or []:
        kind = _KIND.get(a.get('type', ''), 'other')
        meta = a.get('metadata') or {}
        locs = tuple(l.get('accessPath') or l.get('path', '') for l in a.get('locations') or [])
        p = Package(kind, package_name(kind, a.get('name', ''), a.get('purl', '')), a.get('version', ''),
                    purl=a.get('purl', ''), id=a.get('id', ''), locations=locs)
        if kind == 'rpm':
            p.epoch = meta.get('epoch')
            p.arch = meta.get('architecture', '') or ''
            p.source = source_name(meta.get('sourceRpm', ''))
            ml = meta.get('modularityLabel')
            p.module = ':'.join(ml.split(':')[:2]) if ml else ('' if ml is not None else None)
            p.vendor = meta.get('vendor', '') or ''
            p.files = frozenset(f.get('path', '') for f in meta.get('files') or [])
            if meta.get('version') and meta.get('release'):
                p.version = f"{meta['version']}-{meta['release']}"
        elif kind == 'go':
            p.main = meta.get('mainModule', '') or ''
        img.packages.append(p)
        by_id[p.id] = p
    _owners(img, doc.get('artifactRelationships') or [], by_id)
    settle_stream(img)
    return img


def _owners(img: Image, relationships: list, by_id: dict) -> None:
    """The rpm whose files carry each non-rpm package: syft's ownership
    relationships, then exact file ownership of the package's location."""
    for r in relationships:
        if r.get('type') == 'ownership-by-file-overlap':
            parent, child = by_id.get(r.get('parent')), by_id.get(r.get('child'))
            if parent and child and parent.kind == 'rpm' and child.kind != 'rpm':
                child.owner = parent
    owner_of = {}
    for p in img.rpms():
        for f in p.files:
            owner_of.setdefault(f, p)
    for p in img.packages:
        if p.kind != 'rpm' and p.owner is None:
            for loc in p.locations:
                if loc in owner_of:
                    p.owner = owner_of[loc]
                    break
