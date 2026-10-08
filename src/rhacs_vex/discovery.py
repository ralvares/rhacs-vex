"""What to scan: OCP release payloads and OLM operator catalogs.

Two artifacts on disk, produced by `vextriage pipeline` stages 1 and 3:

    data/pullspecs/<ver>.txt        `oc adm release info --pullspecs`
    data/catalogs/catalog-<minor>.json   `opm render` of the operator index

Every command that needs an image list reads it from here.
"""
from __future__ import annotations

import glob
import json
import os
import re
from typing import Iterator, List, Optional, Tuple

PULLSPEC_DIR = os.path.join('data', 'pullspecs')
CATALOG_DIR = os.path.join('data', 'catalogs')

_DIGEST_REF = re.compile(r'(\S+@sha256:[a-f0-9]{64})')


def digest_of(ref: str) -> Optional[str]:
    """'sha256:<hex>' of a digest-pinned ref, else None."""
    m = re.search(r'@(sha256:[a-f0-9]+)', ref or '')
    return m.group(1) if m else None


def refs_in_file(path: str) -> List[str]:
    """Every digest-pinned image ref anywhere in a text file, in order."""
    out = []
    with open(path) as fh:
        for line in fh:
            m = _DIGEST_REF.search(line)
            if m:
                out.append(m.group(1))
    return out


# ── OCP release payloads ─────────────────────────────────────────────────────

def pullspec_path(version: str) -> str:
    return os.path.join(PULLSPEC_DIR, f'{version}.txt')


def read_pullspecs(path: str) -> Tuple[Optional[str], List[Tuple[str, str]]]:
    """(release version, [(component, image_ref)]) — one entry per digest."""
    version, images, seen = None, [], set()
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            m = re.match(r'^Name:\s+(\d+\.\d+(?:\.\d+)*)', line)
            if m and version is None:
                version = m.group(1)
                continue
            m = re.match(r'^(\S+)\s+(\S+@sha256:[a-f0-9]+)', line)
            if m and digest_of(m.group(2)) not in seen:
                seen.add(digest_of(m.group(2)))
                images.append((m.group(1), m.group(2)))
    if version is None:
        version = os.path.splitext(os.path.basename(path))[0]
    return version, images


def pullspec_files(versions=None) -> List[str]:
    """Pullspec files for the given versions (all on disk when None), version-sorted."""
    if versions:
        return [pullspec_path(v.strip()) for v in versions if v.strip()]
    return sorted(glob.glob(os.path.join(PULLSPEC_DIR, '*.txt')),
                  key=lambda f: tuple(int(x) for x in re.findall(r'\d+', os.path.basename(f))))


def release_by_digest() -> dict:
    """'sha256:…' → release version, over every pullspec file on disk.

    Payload images carry no usable version label; the release manifest is the
    authority for which OCP release an image belongs to.
    """
    out = {}
    for path in pullspec_files():
        try:
            version, images = read_pullspecs(path)
        except OSError:
            continue
        for _comp, ref in images:
            out.setdefault(digest_of(ref), version)
    return out


# ── OLM operator catalogs ────────────────────────────────────────────────────

def catalog_path(minor: str) -> str:
    return os.path.join(CATALOG_DIR, f'catalog-{minor}.json')


def catalog_versions() -> List[str]:
    """OCP minors with a rendered catalog on disk."""
    out = []
    for path in glob.glob(os.path.join(CATALOG_DIR, 'catalog-*.json')):
        m = re.match(r'^catalog-(\d+\.\d+)\.json$', os.path.basename(path))
        if m:
            out.append(m.group(1))
    return sorted(out, key=lambda v: tuple(int(x) for x in v.split('.')))


def catalog_objects(path: str) -> Iterator[dict]:
    """The sequential top-level JSON objects of an `opm render` file."""
    dec = json.JSONDecoder()
    with open(path) as fh:
        text = fh.read()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except json.JSONDecodeError:
            nxt = text.find('\n{', i + 1)
            if nxt < 0:
                break
            i = nxt + 1
            continue
        if isinstance(obj, dict):
            yield obj


def _channel_head(channel: dict) -> Optional[str]:
    """The entry nothing in the channel replaces or skips (highest name on ties)."""
    entries = channel.get('entries', [])
    if not entries:
        return None
    pointed = set()
    for e in entries:
        if e.get('replaces'):
            pointed.add(e['replaces'])
        pointed.update(e.get('skips', []))
    heads = {e['name'] for e in entries} - pointed
    return sorted(heads)[-1] if heads else entries[-1]['name']


def channel_heads(path: str) -> dict:
    """package → [{'channel', 'is_default', 'head_bundle'}], default channel first."""
    packages, channels, bundles = {}, [], {}
    for obj in catalog_objects(path):
        schema = obj.get('schema')
        if schema == 'olm.package':
            packages[obj.get('name')] = obj.get('defaultChannel', '')
        elif schema == 'olm.channel':
            channels.append(obj)
        elif schema == 'olm.bundle':
            bundles[obj.get('name')] = obj
    out: dict = {}
    for ch in channels:
        pkg = ch.get('package', '')
        head = bundles.get(_channel_head(ch))
        if pkg and head:
            out.setdefault(pkg, []).append({
                'channel': ch.get('name', ''),
                'is_default': ch.get('name', '') == packages.get(pkg, ''),
                'head_bundle': head,
            })
    for entries in out.values():
        entries.sort(key=lambda e: (not e['is_default'], e['channel']))
    return out


def workload_images(bundle: dict) -> List[Tuple[str, str]]:
    """(role, image_ref) of a bundle's relatedImages, minus the bundle image itself
    and repeated digests."""
    bundle_sha = digest_of(bundle.get('image', ''))
    seen, out = set(), []
    for ri in bundle.get('relatedImages', []):
        img = ri.get('image', '')
        sha = digest_of(img)
        if (bundle_sha and sha == bundle_sha) or (sha and sha in seen):
            continue
        if sha:
            seen.add(sha)
        out.append((ri.get('name', '') or '', img))
    return out


def bundle_version(op_name: str, bundle_name: str) -> str:
    """'foo-operator.v1.2.3' → 'v1.2.3'."""
    m = re.search(r'\.v(\d)', bundle_name)
    if m:
        return bundle_name[m.start() + 1:]
    if bundle_name.startswith(op_name + '.'):
        return bundle_name[len(op_name) + 1:]
    return bundle_name


def operator_refs(minors=None) -> List[str]:
    """Every digest-pinned channel-head workload image across the catalogs."""
    refs = []
    for minor in (minors or catalog_versions()):
        path = catalog_path(minor)
        if not os.path.exists(path):
            continue
        for entries in channel_heads(path).values():
            for entry in entries:
                refs += [img for _role, img in workload_images(entry['head_bundle'])
                         if re.search(r'@sha256:[a-f0-9]{64}$', img)]
    return list(dict.fromkeys(refs))


def release_refs(versions=None) -> List[str]:
    """Every digest-pinned image of the given OCP releases (all when None)."""
    refs = []
    for path in pullspec_files(versions):
        if os.path.exists(path):
            refs += refs_in_file(path)
    return list(dict.fromkeys(refs))
